use crate::error::{LightningError, Result};
use crate::types::QuicAxonInfo;
use futures_util::stream::{self, StreamExt};
use parity_scale_codec::{Compact, Decode, Encode};
use sp_core::crypto::Ss58Codec;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Duration;
use subxt::dynamic::Value;
use subxt::ext::scale_value::At;
use subxt::storage::Storage;
use subxt::{OnlineClient, PolkadotConfig};
use tracing::{debug, info, warn};

const METAGRAPH_SYNC_CONCURRENCY: usize = 32;
const QUIC_PROTOCOL: u8 = 4;

fn format_ipv4(ip_raw: u128, ip_type: u8) -> String {
    if ip_type != 4 {
        return String::new();
    }
    let v = ip_raw as u32;
    format!(
        "{}.{}.{}.{}",
        (v >> 24) & 0xFF,
        (v >> 16) & 0xFF,
        (v >> 8) & 0xFF,
        v & 0xFF,
    )
}

pub const FINNEY_ENDPOINT: &str = "wss://entrypoint-finney.opentensor.ai:443";
pub const TESTNET_ENDPOINT: &str = "wss://test.finney.opentensor.ai:443";

#[derive(Decode)]
struct AxonInfoRaw {
    _block: u64,
    _version: u32,
    ip: u128,
    port: u16,
    ip_type: u8,
    protocol: u8,
    _placeholder1: u8,
    _placeholder2: u8,
}

#[derive(Decode)]
struct PrometheusInfoRaw {
    _block: u64,
    _version: u32,
    _ip: u128,
    _port: u16,
    _ip_type: u8,
}

#[derive(Decode)]
struct NeuronInfoLiteRaw {
    hotkey: [u8; 32],
    _coldkey: [u8; 32],
    uid: Compact<u16>,
    _netuid: Compact<u16>,
    active: bool,
    axon_info: AxonInfoRaw,
    _prometheus_info: PrometheusInfoRaw,
    stake: Vec<([u8; 32], Compact<u64>)>,
    _rank: Compact<u16>,
    _emission: Compact<u64>,
    _incentive: Compact<u16>,
    _consensus: Compact<u16>,
    _trust: Compact<u16>,
    _validator_trust: Compact<u16>,
    _dividends: Compact<u16>,
    _last_update: Compact<u64>,
    validator_permit: bool,
    _pruning_score: Compact<u16>,
}

#[derive(Debug, Clone)]
pub struct NeuronInfo {
    pub uid: u16,
    pub hotkey: String,
    pub stake: u64,
    pub is_active: bool,
    pub axon_ip: String,
    pub axon_port: u16,
    pub axon_protocol: u8,
    pub validator_permit: bool,
}

pub struct Metagraph {
    pub netuid: u16,
    pub neurons: Vec<NeuronInfo>,
    pub n: u16,
    pub block: u64,
    hotkey_to_uid: HashMap<String, u16>,
}

impl Metagraph {
    pub fn new(netuid: u16) -> Self {
        Self {
            netuid,
            neurons: Vec::new(),
            n: 0,
            block: 0,
            hotkey_to_uid: HashMap::new(),
        }
    }

    pub async fn sync(&mut self, client: &OnlineClient<PolkadotConfig>) -> Result<()> {
        let block_ref = client
            .blocks()
            .at_latest()
            .await
            .map_err(|e| LightningError::Handler(format!("fetching latest block: {}", e)))?;
        self.block = block_ref.number() as u64;
        let block_hash = block_ref.hash();

        let storage = client
            .storage()
            .at(block_hash);

        let n = query_subnet_n(&storage, self.netuid).await?;
        self.n = n;

        info!(
            netuid = self.netuid,
            n = n,
            block = self.block,
            "syncing metagraph"
        );

        let neurons = match self.sync_via_runtime_api(client, block_hash).await {
            Ok(neurons) => {
                info!(
                    netuid = self.netuid,
                    neurons = neurons.len(),
                    "synced via runtime API"
                );
                neurons
            }
            Err(e) => {
                warn!(
                    netuid = self.netuid,
                    error = %e,
                    "runtime API unavailable, falling back to storage queries"
                );
                self.sync_via_storage(&storage, n).await?
            }
        };

        self.hotkey_to_uid.clear();
        for neuron in &neurons {
            self.hotkey_to_uid
                .insert(neuron.hotkey.clone(), neuron.uid);
        }

        self.neurons = neurons;
        info!(
            netuid = self.netuid,
            neurons = self.neurons.len(),
            "metagraph synced"
        );
        Ok(())
    }

    async fn sync_via_runtime_api(
        &self,
        client: &OnlineClient<PolkadotConfig>,
        block_hash: <PolkadotConfig as subxt::Config>::Hash,
    ) -> Result<Vec<NeuronInfo>> {
        let params = Encode::encode(&self.netuid);
        let items: Vec<NeuronInfoLiteRaw> = client
            .runtime_api()
            .at(block_hash)
            .call_raw("NeuronInfoRuntimeApi_get_neurons_lite", Some(&params))
            .await
            .map_err(|e| {
                LightningError::Handler(format!("calling get_neurons_lite: {}", e))
            })?;

        let neurons: Vec<NeuronInfo> = items
            .into_iter()
            .map(|raw| {
                let hotkey =
                    sp_core::crypto::AccountId32::new(raw.hotkey).to_ss58check();
                let total_stake: u64 = raw.stake.iter().map(|(_, s)| s.0).sum();

                let axon_ip = format_ipv4(raw.axon_info.ip, raw.axon_info.ip_type);

                NeuronInfo {
                    uid: raw.uid.0,
                    hotkey,
                    stake: total_stake,
                    is_active: raw.active,
                    axon_ip,
                    axon_port: raw.axon_info.port,
                    axon_protocol: raw.axon_info.protocol,
                    validator_permit: raw.validator_permit,
                }
            })
            .collect();

        Ok(neurons)
    }

    async fn sync_via_storage(
        &self,
        storage: &Storage<PolkadotConfig, OnlineClient<PolkadotConfig>>,
        n: u16,
    ) -> Result<Vec<NeuronInfo>> {
        let netuid = self.netuid;

        let (validator_permits, active_flags) = tokio::join!(
            async {
                query_vec::<bool>(storage, "ValidatorPermit", netuid)
                    .await
                    .unwrap_or_default()
            },
            async {
                query_vec::<bool>(storage, "Active", netuid)
                    .await
                    .unwrap_or_default()
            },
        );

        let neurons: Vec<Option<NeuronInfo>> = stream::iter(0..n)
            .map(|uid| {
                let validator_permits = &validator_permits;
                let active_flags = &active_flags;
                async move {
                    match query_neuron_core(storage, netuid, uid).await {
                        Ok(mut neuron) => {
                            neuron.validator_permit = validator_permits
                                .get(uid as usize)
                                .copied()
                                .unwrap_or(false);
                            neuron.is_active = active_flags
                                .get(uid as usize)
                                .copied()
                                .unwrap_or(false);
                            debug!(uid = uid, hotkey = %neuron.hotkey, "synced neuron");
                            Some(neuron)
                        }
                        Err(e) => {
                            warn!(uid = uid, error = %e, "skipping neuron");
                            None
                        }
                    }
                }
            })
            .buffer_unordered(METAGRAPH_SYNC_CONCURRENCY)
            .collect()
            .await;

        Ok(neurons.into_iter().flatten().collect())
    }

    pub fn quic_miners(&self) -> Vec<QuicAxonInfo> {
        self.neurons
            .iter()
            .filter(|n| n.is_active)
            .filter(|n| !n.validator_permit)
            .filter(|n| !n.axon_ip.is_empty() && n.axon_port > 0)
            .filter(|n| is_valid_ip(&n.axon_ip))
            .filter(|n| n.axon_protocol == QUIC_PROTOCOL)
            .map(|n| {
                QuicAxonInfo::new(
                    n.hotkey.clone(),
                    n.axon_ip.clone(),
                    n.axon_port,
                    n.axon_protocol,
                    0,
                    0,
                )
            })
            .collect()
    }

    pub fn get_neuron(&self, uid: u16) -> Option<&NeuronInfo> {
        self.neurons.iter().find(|n| n.uid == uid)
    }

    pub fn get_uid_by_hotkey(&self, hotkey: &str) -> Option<u16> {
        self.hotkey_to_uid.get(hotkey).copied()
    }
}

/// Validates that an IP address string is globally routable IPv4.
///
/// Rejects: private (RFC 1918), loopback, link-local, multicast, broadcast, unspecified,
/// CGNAT (100.64/10), documentation (TEST-NET-1/2/3), benchmarking (198.18/15), IETF
/// protocol assignments (192.0.0/24), 6to4 relay (192.88.99/24), and reserved/Class E
/// (240/4). IPv6 and unparseable inputs return false — Bittensor axons currently only
/// advertise IPv4.
pub fn is_valid_ip(ip_str: &str) -> bool {
    let addr: Ipv4Addr = match ip_str.parse() {
        Ok(a) => a,
        Err(_) => return false,
    };
    if addr.is_private()
        || addr.is_loopback()
        || addr.is_link_local()
        || addr.is_multicast()
        || addr.is_broadcast()
        || addr.is_unspecified()
    {
        return false;
    }
    let o = addr.octets();
    if o[0] == 0 {
        return false;
    }
    if o[0] == 100 && (o[1] & 0xC0) == 64 {
        return false;
    }
    if o[0] == 192 && o[1] == 0 && o[2] == 0 {
        return false;
    }
    if o[0] == 192 && o[1] == 0 && o[2] == 2 {
        return false;
    }
    if o[0] == 192 && o[1] == 88 && o[2] == 99 {
        return false;
    }
    if o[0] == 198 && (o[1] & 0xFE) == 18 {
        return false;
    }
    if o[0] == 198 && o[1] == 51 && o[2] == 100 {
        return false;
    }
    if o[0] == 203 && o[1] == 0 && o[2] == 113 {
        return false;
    }
    if o[0] >= 240 {
        return false;
    }
    true
}

#[derive(Clone)]
pub struct MetagraphMonitorConfig {
    pub netuid: u16,
    pub subtensor_endpoint: String,
    pub sync_interval: Duration,
}

impl MetagraphMonitorConfig {
    pub fn new(netuid: u16, subtensor_endpoint: String, sync_interval: Duration) -> Self {
        Self {
            netuid,
            subtensor_endpoint,
            sync_interval,
        }
    }

    pub fn finney(netuid: u16) -> Self {
        Self {
            netuid,
            subtensor_endpoint: FINNEY_ENDPOINT.to_string(),
            sync_interval: Duration::from_secs(600),
        }
    }

    pub fn testnet(netuid: u16) -> Self {
        Self {
            netuid,
            subtensor_endpoint: TESTNET_ENDPOINT.to_string(),
            sync_interval: Duration::from_secs(600),
        }
    }
}

async fn query_subnet_n(
    storage: &Storage<PolkadotConfig, OnlineClient<PolkadotConfig>>,
    netuid: u16,
) -> Result<u16> {
    let query = subxt::dynamic::storage(
        "SubtensorModule",
        "SubnetworkN",
        vec![Value::from(netuid as u64)],
    );

    let result = storage
        .fetch(&query)
        .await
        .map_err(|e| LightningError::Handler(e.to_string()))?;

    match result {
        Some(val) => {
            let n = val
                .to_value()
                .map_err(|e| LightningError::Handler(e.to_string()))?
                .as_u128()
                .ok_or_else(|| {
                    LightningError::Handler("SubnetworkN not u128".to_string())
                })? as u16;
            Ok(n)
        }
        None => Ok(0),
    }
}

async fn query_neuron_core(
    storage: &Storage<PolkadotConfig, OnlineClient<PolkadotConfig>>,
    netuid: u16,
    uid: u16,
) -> Result<NeuronInfo> {
    let (hotkey_bytes, hotkey) = query_hotkey(storage, netuid, uid).await?;

    let (stake, axon) = tokio::join!(
        async { query_stake(storage, &hotkey_bytes).await.unwrap_or(0) },
        async {
            query_axon(storage, netuid, &hotkey_bytes)
                .await
                .unwrap_or_default()
        },
    );

    Ok(NeuronInfo {
        uid,
        hotkey,
        stake,
        is_active: false,
        axon_ip: axon.0,
        axon_port: axon.1,
        axon_protocol: axon.2,
        validator_permit: false,
    })
}

async fn query_hotkey(
    storage: &Storage<PolkadotConfig, OnlineClient<PolkadotConfig>>,
    netuid: u16,
    uid: u16,
) -> Result<([u8; 32], String)> {
    let query = subxt::dynamic::storage(
        "SubtensorModule",
        "Keys",
        vec![Value::from(netuid as u64), Value::from(uid as u64)],
    );

    let result = storage
        .fetch(&query)
        .await
        .map_err(|e| LightningError::Handler(e.to_string()))?
        .ok_or_else(|| LightningError::Handler("hotkey not found".to_string()))?;

    let account_id: subxt::utils::AccountId32 = result
        .as_type()
        .map_err(|e| LightningError::Handler(format!("decode Keys: {}", e)))?;
    let bytes = account_id.0;
    let ss58 = sp_core::crypto::AccountId32::new(bytes).to_ss58check();
    Ok((bytes, ss58))
}

async fn query_stake(
    storage: &Storage<PolkadotConfig, OnlineClient<PolkadotConfig>>,
    hotkey_bytes: &[u8; 32],
) -> Result<u64> {
    let query = subxt::dynamic::storage(
        "SubtensorModule",
        "TotalHotkeyStake",
        vec![Value::from_bytes(hotkey_bytes)],
    );

    let result = storage
        .fetch(&query)
        .await
        .map_err(|e| LightningError::Handler(e.to_string()))?;

    match result {
        Some(val) => Ok(val
            .to_value()
            .map_err(|e| LightningError::Handler(e.to_string()))?
            .as_u128()
            .unwrap_or(0) as u64),
        None => Ok(0),
    }
}

async fn query_vec<T: subxt::ext::scale_decode::IntoVisitor>(
    storage: &Storage<PolkadotConfig, OnlineClient<PolkadotConfig>>,
    storage_name: &str,
    netuid: u16,
) -> Result<Vec<T>> {
    let query = subxt::dynamic::storage(
        "SubtensorModule",
        storage_name,
        vec![Value::from(netuid as u64)],
    );

    let result = storage
        .fetch(&query)
        .await
        .map_err(|e| LightningError::Handler(e.to_string()))?;

    match result {
        Some(val) => val
            .as_type::<Vec<T>>()
            .map_err(|e| LightningError::Handler(format!("decoding {} vec: {}", storage_name, e))),
        None => Ok(Vec::new()),
    }
}

async fn query_axon(
    storage: &Storage<PolkadotConfig, OnlineClient<PolkadotConfig>>,
    netuid: u16,
    hotkey_bytes: &[u8; 32],
) -> Result<(String, u16, u8)> {
    let query = subxt::dynamic::storage(
        "SubtensorModule",
        "Axons",
        vec![
            Value::from(netuid as u64),
            Value::from_bytes(hotkey_bytes),
        ],
    );

    let result = storage
        .fetch(&query)
        .await
        .map_err(|e| LightningError::Handler(e.to_string()))?;

    match result {
        Some(val) => {
            let v = val
                .to_value()
                .map_err(|e| LightningError::Handler(e.to_string()))?;
            let ip_type = v
                .at("ip_type")
                .and_then(|v| v.as_u128())
                .unwrap_or(0) as u8;
            let ip_raw = v.at("ip").and_then(|v| v.as_u128()).unwrap_or(0);
            let port = v.at("port").and_then(|v| v.as_u128()).unwrap_or(0) as u16;
            let protocol = v
                .at("protocol")
                .and_then(|v| v.as_u128())
                .unwrap_or(0) as u8;

            let ip = format_ipv4(ip_raw, ip_type);

            Ok((ip, port, protocol))
        }
        None => Ok((String::new(), 0, 0)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_public_ips() {
        assert!(is_valid_ip("1.2.3.4"));
        assert!(is_valid_ip("8.8.8.8"));
        assert!(is_valid_ip("45.33.32.156"));
    }

    #[test]
    fn rejects_cgnat() {
        assert!(!is_valid_ip("100.64.0.1"));
        assert!(!is_valid_ip("100.127.255.254"));
    }

    #[test]
    fn rejects_documentation_ranges() {
        assert!(!is_valid_ip("192.0.2.1"));
        assert!(!is_valid_ip("198.51.100.1"));
        assert!(!is_valid_ip("203.0.113.1"));
    }

    #[test]
    fn rejects_reserved_class_e() {
        assert!(!is_valid_ip("240.0.0.1"));
        assert!(!is_valid_ip("254.255.255.255"));
    }

    #[test]
    fn rejects_private_ips() {
        assert!(!is_valid_ip("10.0.0.1"));
        assert!(!is_valid_ip("10.255.255.255"));
        assert!(!is_valid_ip("172.16.0.1"));
        assert!(!is_valid_ip("172.31.255.255"));
        assert!(!is_valid_ip("192.168.0.1"));
        assert!(!is_valid_ip("192.168.255.255"));
    }

    #[test]
    fn rejects_loopback() {
        assert!(!is_valid_ip("127.0.0.1"));
        assert!(!is_valid_ip("127.255.255.255"));
    }

    #[test]
    fn rejects_link_local() {
        assert!(!is_valid_ip("169.254.0.1"));
        assert!(!is_valid_ip("169.254.255.255"));
    }

    #[test]
    fn rejects_multicast() {
        assert!(!is_valid_ip("224.0.0.1"));
        assert!(!is_valid_ip("239.255.255.255"));
    }

    #[test]
    fn rejects_broadcast() {
        assert!(!is_valid_ip("255.255.255.255"));
    }

    #[test]
    fn rejects_zero_first_octet() {
        assert!(!is_valid_ip("0.0.0.0"));
        assert!(!is_valid_ip("0.1.2.3"));
    }

    #[test]
    fn rejects_invalid_strings() {
        assert!(!is_valid_ip(""));
        assert!(!is_valid_ip("not-an-ip"));
        assert!(!is_valid_ip("::1"));
    }

    #[test]
    fn accepts_non_private_172() {
        assert!(is_valid_ip("172.15.0.1"));
        assert!(is_valid_ip("172.32.0.1"));
    }

    #[test]
    fn quic_miners_filters_correctly() {
        let metagraph = Metagraph {
            netuid: 1,
            n: 5,
            block: 100,
            hotkey_to_uid: HashMap::new(),
            neurons: vec![
                NeuronInfo {
                    uid: 0,
                    hotkey: "validator".into(),
                    stake: 1000,
                    is_active: true,
                    axon_ip: "1.2.3.4".into(),
                    axon_port: 8080,
                    axon_protocol: 4,
                    validator_permit: true,
                },
                NeuronInfo {
                    uid: 1,
                    hotkey: "miner_quic".into(),
                    stake: 0,
                    is_active: true,
                    axon_ip: "5.6.7.8".into(),
                    axon_port: 8080,
                    axon_protocol: 4,
                    validator_permit: false,
                },
                NeuronInfo {
                    uid: 2,
                    hotkey: "miner_http".into(),
                    stake: 0,
                    is_active: true,
                    axon_ip: "9.10.11.12".into(),
                    axon_port: 8080,
                    axon_protocol: 0,
                    validator_permit: false,
                },
                NeuronInfo {
                    uid: 3,
                    hotkey: "miner_private_ip".into(),
                    stake: 0,
                    is_active: true,
                    axon_ip: "10.0.0.1".into(),
                    axon_port: 8080,
                    axon_protocol: 4,
                    validator_permit: false,
                },
                NeuronInfo {
                    uid: 4,
                    hotkey: "miner_no_port".into(),
                    stake: 0,
                    is_active: true,
                    axon_ip: "13.14.15.16".into(),
                    axon_port: 0,
                    axon_protocol: 4,
                    validator_permit: false,
                },
            ],
        };

        let miners = metagraph.quic_miners();
        assert_eq!(miners.len(), 1);
        assert_eq!(miners[0].hotkey, "miner_quic");
        assert_eq!(miners[0].ip, "5.6.7.8");
        assert_eq!(miners[0].port, 8080);
    }

    #[test]
    fn quic_miners_excludes_inactive() {
        let metagraph = Metagraph {
            netuid: 1,
            n: 1,
            block: 100,
            hotkey_to_uid: HashMap::new(),
            neurons: vec![NeuronInfo {
                uid: 0,
                hotkey: "inactive_miner".into(),
                stake: 0,
                is_active: false,
                axon_ip: "5.6.7.8".into(),
                axon_port: 8080,
                axon_protocol: 4,
                validator_permit: false,
            }],
        };

        assert!(metagraph.quic_miners().is_empty());
    }
}
