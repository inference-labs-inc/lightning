use crate::error::{LightningError, Result};
use quinn::{RecvStream, SendStream};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const MAX_FRAME_SIZE: usize = 64 * 1024 * 1024;

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
    pub data: HashMap<String, rmpv::Value>,
}

impl QuicRequest {
    pub fn new(synapse_type: String, data: HashMap<String, rmpv::Value>) -> Self {
        Self { synapse_type, data }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicResponse {
    pub success: bool,
    pub data: HashMap<String, rmpv::Value>,
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
    pub data: HashMap<String, rmpv::Value>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynapseResponse {
    pub success: bool,
    pub data: HashMap<String, rmpv::Value>,
    pub timestamp: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamChunk {
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamEnd {
    pub success: bool,
    pub error: Option<String>,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MessageType {
    HandshakeRequest = 0x01,
    HandshakeResponse = 0x02,
    SynapsePacket = 0x03,
    SynapseResponse = 0x04,
    StreamChunk = 0x05,
    StreamEnd = 0x06,
}

impl TryFrom<u8> for MessageType {
    type Error = LightningError;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x01 => Ok(MessageType::HandshakeRequest),
            0x02 => Ok(MessageType::HandshakeResponse),
            0x03 => Ok(MessageType::SynapsePacket),
            0x04 => Ok(MessageType::SynapseResponse),
            0x05 => Ok(MessageType::StreamChunk),
            0x06 => Ok(MessageType::StreamEnd),
            _ => Err(LightningError::Transport(format!(
                "unknown message type: 0x{:02x}",
                value
            ))),
        }
    }
}

const FRAME_HEADER_SIZE: usize = 5;

async fn read_exact_from_recv(recv: &mut RecvStream, buf: &mut [u8]) -> Result<()> {
    let mut offset = 0;
    while offset < buf.len() {
        match recv.read(&mut buf[offset..]).await {
            Ok(Some(n)) => offset += n,
            Ok(None) => {
                return Err(LightningError::Transport(format!(
                    "stream closed after {} of {} bytes",
                    offset,
                    buf.len()
                )));
            }
            Err(e) => {
                return Err(LightningError::Transport(format!("read error: {}", e)));
            }
        }
    }
    Ok(())
}

pub async fn read_frame(recv: &mut RecvStream) -> Result<(MessageType, Vec<u8>)> {
    let mut header = [0u8; FRAME_HEADER_SIZE];
    read_exact_from_recv(recv, &mut header).await?;

    let msg_type = MessageType::try_from(header[0])?;
    let payload_len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;

    if payload_len > MAX_FRAME_SIZE {
        return Err(LightningError::Transport(format!(
            "frame payload {} bytes exceeds maximum {}",
            payload_len, MAX_FRAME_SIZE
        )));
    }

    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        read_exact_from_recv(recv, &mut payload).await?;
    }

    Ok((msg_type, payload))
}

pub async fn write_frame(
    send: &mut SendStream,
    msg_type: MessageType,
    payload: &[u8],
) -> Result<()> {
    let payload_len: u32 = payload.len().try_into().map_err(|_| {
        LightningError::Transport(format!(
            "frame payload {} bytes exceeds u32::MAX",
            payload.len()
        ))
    })?;

    let mut header = [0u8; FRAME_HEADER_SIZE];
    header[0] = msg_type as u8;
    header[1..5].copy_from_slice(&payload_len.to_be_bytes());

    send.write_all(&header)
        .await
        .map_err(|e| LightningError::Transport(format!("failed to write frame header: {}", e)))?;
    if !payload.is_empty() {
        send.write_all(payload).await.map_err(|e| {
            LightningError::Transport(format!("failed to write frame payload: {}", e))
        })?;
    }
    Ok(())
}

pub async fn write_frame_and_finish(
    send: &mut SendStream,
    msg_type: MessageType,
    payload: &[u8],
) -> Result<()> {
    write_frame(send, msg_type, payload).await?;
    send.finish()
        .await
        .map_err(|e| LightningError::Transport(format!("failed to finish stream: {}", e)))?;
    Ok(())
}
