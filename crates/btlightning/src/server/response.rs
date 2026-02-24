use crate::types::{HandshakeResponse, StreamEnd, SynapseResponse};
use crate::util::unix_timestamp_secs;
use std::collections::HashMap;

pub(super) fn rejected_handshake_preauth() -> HandshakeResponse {
    HandshakeResponse {
        miner_hotkey: String::new(),
        timestamp: unix_timestamp_secs(),
        signature: String::new(),
        accepted: false,
        connection_id: String::new(),
        cert_fingerprint: None,
    }
}

pub(super) fn rejected_handshake(miner_hotkey: &str, timestamp: u64) -> HandshakeResponse {
    HandshakeResponse {
        miner_hotkey: miner_hotkey.to_string(),
        timestamp,
        signature: String::new(),
        accepted: false,
        connection_id: String::new(),
        cert_fingerprint: None,
    }
}

pub(super) fn error_synapse_response(msg: &str) -> SynapseResponse {
    SynapseResponse {
        success: false,
        data: HashMap::new(),
        timestamp: unix_timestamp_secs(),
        error: Some(msg.to_string()),
    }
}

pub(super) fn error_stream_end(msg: &str) -> StreamEnd {
    StreamEnd {
        success: false,
        error: Some(msg.to_string()),
    }
}
