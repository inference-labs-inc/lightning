use super::response::rejected_handshake;
use super::ServerContext;
use crate::error::{LightningError, Result};
use crate::signing::Signer;
use crate::types::{
    handshake_request_message, handshake_response_message, HandshakeRequest, HandshakeResponse,
};
use crate::util::unix_timestamp_secs;
use base64::{prelude::BASE64_STANDARD, Engine};
use indexmap::IndexMap;
use sp_core::{crypto::Ss58Codec, sr25519, Pair};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

const HANDSHAKE_RATE_WINDOW_SECS: u64 = 60;
const MAX_FUTURE_CLOCK_SKEW_SECS: u64 = 60;

pub(super) async fn process_handshake(
    request: HandshakeRequest,
    connection: Arc<quinn::Connection>,
    ctx: &ServerContext,
) -> HandshakeResponse {
    let cert_fp = match *ctx.cert_fingerprint.read().await {
        Some(fp) => fp,
        None => {
            error!("Certificate fingerprint unavailable during handshake");
            return rejected_handshake(&ctx.miner_hotkey, unix_timestamp_secs());
        }
    };

    let is_valid = verify_validator_signature(
        &request,
        ctx.used_nonces.clone(),
        &cert_fp,
        ctx.config.max_signature_age_secs,
        ctx.config.max_nonce_entries,
    )
    .await;

    if !is_valid {
        error!("Handshake failed: invalid signature");
        return rejected_handshake(&ctx.miner_hotkey, unix_timestamp_secs());
    }

    if ctx.config.require_validator_permit {
        if ctx.permit_resolver.is_none() {
            error!(
                "Validator permit required but no resolver configured, rejecting {}",
                request.validator_hotkey
            );
            return rejected_handshake(&ctx.miner_hotkey, unix_timestamp_secs());
        }
        let permitted = ctx.permitted_validators.read().await;
        if !permitted.contains(&request.validator_hotkey) {
            warn!(
                "Handshake rejected: hotkey {} does not hold a validator permit",
                request.validator_hotkey
            );
            return rejected_handshake(&ctx.miner_hotkey, unix_timestamp_secs());
        }
    }

    let now = unix_timestamp_secs();
    let signature = match sign_handshake_response(
        &request,
        &ctx.miner_hotkey,
        ctx.miner_signer.clone(),
        now,
        &cert_fp,
    )
    .await
    {
        Ok(sig) => sig,
        Err(e) => {
            error!("Handshake signing failed: {}", e);
            return rejected_handshake(&ctx.miner_hotkey, now);
        }
    };

    let connection_id = format!(
        "conn_{}_{}",
        request.validator_hotkey,
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_millis()
    );

    let remote_addr = connection.remote_address();
    let mut connections_guard = ctx.connections.write().await;
    let is_reconnect = connections_guard.contains_key(&request.validator_hotkey);
    if !is_reconnect && connections_guard.len() >= ctx.config.max_connections {
        error!(
            "Connection limit reached ({}/{}), rejecting validator {}",
            connections_guard.len(),
            ctx.config.max_connections,
            request.validator_hotkey
        );
        return rejected_handshake(&ctx.miner_hotkey, now);
    }
    let mut addr_index = ctx.addr_to_hotkey.write().await;
    let mut validator_conn = super::ValidatorConnection::new(
        request.validator_hotkey.clone(),
        connection_id.clone(),
        connection.clone(),
    );
    validator_conn.verify();
    if let Some(prev_conn) =
        connections_guard.insert(request.validator_hotkey.clone(), validator_conn)
    {
        if !Arc::ptr_eq(&prev_conn.connection, &connection) {
            prev_conn.connection.close(0u32.into(), b"replaced");
            let prev_addr = prev_conn.connection.remote_address();
            if prev_addr != remote_addr {
                addr_index.remove(&prev_addr);
            }
        }
    }
    addr_index.insert(remote_addr, request.validator_hotkey.clone());
    drop(addr_index);
    drop(connections_guard);

    info!(
        "Handshake successful, established connection: {}",
        connection_id
    );

    HandshakeResponse {
        miner_hotkey: ctx.miner_hotkey.clone(),
        timestamp: now,
        signature,
        accepted: true,
        connection_id,
        cert_fingerprint: Some(BASE64_STANDARD.encode(cert_fp)),
    }
}

pub(super) async fn verify_validator_signature(
    request: &HandshakeRequest,
    used_nonces: Arc<RwLock<IndexMap<String, u64>>>,
    cert_fingerprint: &[u8; 32],
    max_signature_age: u64,
    max_nonce_entries: usize,
) -> bool {
    let current_time = unix_timestamp_secs();

    if current_time > request.timestamp && (current_time - request.timestamp) >= max_signature_age {
        error!(
            "Signature timestamp too old: {} (current: {})",
            request.timestamp, current_time
        );
        return false;
    }

    if request.timestamp > current_time + MAX_FUTURE_CLOCK_SKEW_SECS {
        error!(
            "Signature timestamp too far in future: {} (current: {})",
            request.timestamp, current_time
        );
        return false;
    }

    {
        let mut nonces = used_nonces.write().await;
        if nonces.contains_key(&request.nonce) {
            error!("Nonce already used: {}", request.nonce);
            return false;
        }
        nonces.insert(request.nonce.clone(), current_time);
        if nonces.len() > max_nonce_entries {
            let cutoff = current_time.saturating_sub(max_signature_age);
            nonces.retain(|_, ts| *ts >= cutoff);
            while nonces.len() > max_nonce_entries {
                nonces.shift_remove_index(0);
            }
        }
    }

    let fp_b64 = BASE64_STANDARD.encode(cert_fingerprint);
    let expected_message = handshake_request_message(
        &request.validator_hotkey,
        request.timestamp,
        &request.nonce,
        &fp_b64,
    );

    let public_key = match sr25519::Public::from_ss58check(&request.validator_hotkey) {
        Ok(pk) => pk,
        Err(e) => {
            error!("Invalid SS58 address {}: {}", request.validator_hotkey, e);
            return false;
        }
    };

    let signature_bytes = match BASE64_STANDARD.decode(&request.signature) {
        Ok(bytes) => bytes,
        Err(e) => {
            error!("Failed to decode base64 signature: {}", e);
            return false;
        }
    };

    if signature_bytes.len() != 64 {
        error!("Invalid signature length: {}", signature_bytes.len());
        return false;
    }

    let mut signature_array = [0u8; 64];
    signature_array.copy_from_slice(&signature_bytes);
    let signature = sr25519::Signature::from_raw(signature_array);

    match tokio::task::spawn_blocking(move || {
        sr25519::Pair::verify(&signature, expected_message.as_bytes(), &public_key)
    })
    .await
    {
        Ok(v) => v,
        Err(e) => {
            error!("signature verification task failed: {}", e);
            false
        }
    }
}

pub(super) async fn sign_handshake_response(
    request: &HandshakeRequest,
    miner_hotkey: &str,
    miner_signer: Option<Arc<dyn Signer>>,
    timestamp: u64,
    cert_fingerprint: &[u8; 32],
) -> Result<String> {
    let signer = miner_signer
        .ok_or_else(|| LightningError::Signing("no miner signer configured".to_string()))?;
    let fp_b64 = BASE64_STANDARD.encode(cert_fingerprint);
    let message = handshake_response_message(
        &request.validator_hotkey,
        miner_hotkey,
        timestamp,
        &request.nonce,
        &fp_b64,
    );
    let msg_bytes = message.into_bytes();
    let sig = tokio::task::spawn_blocking(move || signer.sign(&msg_bytes))
        .await
        .map_err(|e| LightningError::Signing(format!("signer task failed: {}", e)))??;
    Ok(BASE64_STANDARD.encode(sig))
}

pub(super) async fn check_handshake_rate(ctx: &ServerContext, ip: IpAddr) -> bool {
    let now = unix_timestamp_secs();
    let cutoff = now.saturating_sub(HANDSHAKE_RATE_WINDOW_SECS);
    let mut rates = ctx.handshake_rate.write().await;
    if !rates.contains_key(&ip) && rates.len() >= ctx.config.max_tracked_rate_ips {
        let oldest_ip = rates
            .iter()
            .min_by_key(|(_, attempts)| attempts.iter().copied().max().unwrap_or(0))
            .map(|(ip, _)| *ip);
        if let Some(evict_ip) = oldest_ip {
            rates.remove(&evict_ip);
        }
    }
    let attempts = rates.entry(ip).or_default();
    attempts.retain(|ts| *ts >= cutoff);
    if attempts.len() >= ctx.config.max_handshake_attempts_per_minute as usize {
        return false;
    }
    attempts.push(now);
    true
}
