use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicAxonInfo {
    pub hotkey: String,
    pub ip: String,
    pub port: u16,
    pub protocol: u8,
    pub placeholder1: u8,
    pub placeholder2: u8,
}

impl QuicAxonInfo {
    pub fn new(
        hotkey: String,
        ip: String,
        port: u16,
        protocol: u8,
        placeholder1: u8,
        placeholder2: u8,
    ) -> Self {
        Self {
            hotkey,
            ip,
            port,
            protocol,
            placeholder1,
            placeholder2,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicRequest {
    pub synapse_type: String,
    pub data: HashMap<String, serde_json::Value>,
}

impl QuicRequest {
    pub fn new(synapse_type: String, data: HashMap<String, serde_json::Value>) -> Self {
        Self { synapse_type, data }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicResponse {
    pub success: bool,
    pub data: HashMap<String, serde_json::Value>,
    pub latency_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeRequest {
    pub validator_hotkey: String,
    pub timestamp: u64,
    pub nonce: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeResponse {
    pub miner_hotkey: String,
    pub timestamp: u64,
    pub signature: String,
    pub accepted: bool,
    pub connection_id: String,
    #[serde(default)]
    pub cert_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynapsePacket {
    pub synapse_type: String,
    pub data: HashMap<String, serde_json::Value>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynapseResponse {
    pub success: bool,
    pub data: HashMap<String, serde_json::Value>,
    pub timestamp: u64,
    pub error: Option<String>,
}
