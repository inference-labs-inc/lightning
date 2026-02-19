use crate::error::{LightningError, Result};
use quinn::{RecvStream, SendStream};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const MAX_FRAME_PAYLOAD: usize = 64 * 1024 * 1024;
pub const MAX_RESPONSE_SIZE: usize = 64 * 1024 * 1024;

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

pub(crate) fn hashmap_to_rmpv_map(data: HashMap<String, rmpv::Value>) -> rmpv::Value {
    rmpv::Value::Map(
        data.into_iter()
            .map(|(k, v)| (rmpv::Value::String(k.into()), v))
            .collect(),
    )
}

pub fn serialize_to_rmpv_map<T: serde::Serialize>(val: &T) -> Result<HashMap<String, rmpv::Value>> {
    let rmpv_val = val
        .serialize(NamedSerializer)
        .map_err(|e| LightningError::Serialization(e.to_string()))?;
    match rmpv_val {
        rmpv::Value::Map(entries) => entries
            .into_iter()
            .map(|(k, v)| {
                let key = match k {
                    rmpv::Value::String(s) => s
                        .into_str()
                        .ok_or_else(|| LightningError::Serialization("non-UTF8 map key".into())),
                    other => Ok(other.to_string()),
                };
                key.map(|k| (k, v))
            })
            .collect(),
        _ => Err(LightningError::Serialization(
            "expected map from serialized struct".into(),
        )),
    }
}

pub(crate) fn handshake_request_message(
    validator_hotkey: &str,
    timestamp: u64,
    nonce: &str,
    cert_fp_b64: &str,
) -> String {
    format!(
        "handshake:{}:{}:{}:{}",
        validator_hotkey, timestamp, nonce, cert_fp_b64
    )
}

pub(crate) fn handshake_response_message(
    validator_hotkey: &str,
    miner_hotkey: &str,
    timestamp: u64,
    nonce: &str,
    cert_fp_b64: &str,
) -> String {
    format!(
        "handshake_response:{}:{}:{}:{}:{}",
        validator_hotkey, miner_hotkey, timestamp, nonce, cert_fp_b64
    )
}

struct NamedSerializer;

impl serde::Serializer for NamedSerializer {
    type Ok = rmpv::Value;
    type Error = rmpv::ext::Error;

    type SerializeSeq = SerializeVec;
    type SerializeTuple = SerializeVec;
    type SerializeTupleStruct = SerializeVec;
    type SerializeTupleVariant = SerializeTupleVariant;
    type SerializeMap = SerializeMap;
    type SerializeStruct = SerializeMap;
    type SerializeStructVariant = SerializeStructVariant;

    fn serialize_bool(self, v: bool) -> std::result::Result<rmpv::Value, Self::Error> {
        Ok(rmpv::Value::Boolean(v))
    }

    fn serialize_i8(self, v: i8) -> std::result::Result<rmpv::Value, Self::Error> {
        self.serialize_i64(v as i64)
    }

    fn serialize_i16(self, v: i16) -> std::result::Result<rmpv::Value, Self::Error> {
        self.serialize_i64(v as i64)
    }

    fn serialize_i32(self, v: i32) -> std::result::Result<rmpv::Value, Self::Error> {
        self.serialize_i64(v as i64)
    }

    fn serialize_i64(self, v: i64) -> std::result::Result<rmpv::Value, Self::Error> {
        Ok(rmpv::Value::Integer(rmpv::Integer::from(v)))
    }

    fn serialize_u8(self, v: u8) -> std::result::Result<rmpv::Value, Self::Error> {
        self.serialize_u64(v as u64)
    }

    fn serialize_u16(self, v: u16) -> std::result::Result<rmpv::Value, Self::Error> {
        self.serialize_u64(v as u64)
    }

    fn serialize_u32(self, v: u32) -> std::result::Result<rmpv::Value, Self::Error> {
        self.serialize_u64(v as u64)
    }

    fn serialize_u64(self, v: u64) -> std::result::Result<rmpv::Value, Self::Error> {
        Ok(rmpv::Value::Integer(rmpv::Integer::from(v)))
    }

    fn serialize_f32(self, v: f32) -> std::result::Result<rmpv::Value, Self::Error> {
        Ok(rmpv::Value::F32(v))
    }

    fn serialize_f64(self, v: f64) -> std::result::Result<rmpv::Value, Self::Error> {
        Ok(rmpv::Value::F64(v))
    }

    fn serialize_char(self, v: char) -> std::result::Result<rmpv::Value, Self::Error> {
        let mut s = String::new();
        s.push(v);
        self.serialize_str(&s)
    }

    fn serialize_str(self, v: &str) -> std::result::Result<rmpv::Value, Self::Error> {
        Ok(rmpv::Value::String(rmpv::Utf8String::from(v)))
    }

    fn serialize_bytes(self, v: &[u8]) -> std::result::Result<rmpv::Value, Self::Error> {
        Ok(rmpv::Value::Binary(v.to_vec()))
    }

    fn serialize_none(self) -> std::result::Result<rmpv::Value, Self::Error> {
        Ok(rmpv::Value::Nil)
    }

    fn serialize_some<T: ?Sized + serde::Serialize>(
        self,
        value: &T,
    ) -> std::result::Result<rmpv::Value, Self::Error> {
        value.serialize(self)
    }

    fn serialize_unit(self) -> std::result::Result<rmpv::Value, Self::Error> {
        Ok(rmpv::Value::Nil)
    }

    fn serialize_unit_struct(
        self,
        _name: &'static str,
    ) -> std::result::Result<rmpv::Value, Self::Error> {
        Ok(rmpv::Value::Nil)
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        idx: u32,
        _variant: &'static str,
    ) -> std::result::Result<rmpv::Value, Self::Error> {
        Ok(rmpv::Value::Integer(rmpv::Integer::from(idx)))
    }

    fn serialize_newtype_struct<T: ?Sized + serde::Serialize>(
        self,
        _name: &'static str,
        value: &T,
    ) -> std::result::Result<rmpv::Value, Self::Error> {
        value.serialize(self)
    }

    fn serialize_newtype_variant<T: ?Sized + serde::Serialize>(
        self,
        _name: &'static str,
        idx: u32,
        _variant: &'static str,
        value: &T,
    ) -> std::result::Result<rmpv::Value, Self::Error> {
        let inner = value.serialize(NamedSerializer)?;
        Ok(rmpv::Value::Map(vec![(
            rmpv::Value::Integer(rmpv::Integer::from(idx)),
            inner,
        )]))
    }

    fn serialize_seq(
        self,
        len: Option<usize>,
    ) -> std::result::Result<Self::SerializeSeq, Self::Error> {
        Ok(SerializeVec {
            vec: Vec::with_capacity(len.unwrap_or(0)),
        })
    }

    fn serialize_tuple(self, len: usize) -> std::result::Result<Self::SerializeTuple, Self::Error> {
        self.serialize_seq(Some(len))
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> std::result::Result<Self::SerializeTupleStruct, Self::Error> {
        self.serialize_seq(Some(len))
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        idx: u32,
        _variant: &'static str,
        len: usize,
    ) -> std::result::Result<Self::SerializeTupleVariant, Self::Error> {
        Ok(SerializeTupleVariant {
            idx,
            vec: Vec::with_capacity(len),
        })
    }

    fn serialize_map(
        self,
        len: Option<usize>,
    ) -> std::result::Result<Self::SerializeMap, Self::Error> {
        Ok(SerializeMap {
            entries: Vec::with_capacity(len.unwrap_or(0)),
            cur_key: None,
        })
    }

    fn serialize_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> std::result::Result<Self::SerializeStruct, Self::Error> {
        self.serialize_map(Some(len))
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        idx: u32,
        _variant: &'static str,
        len: usize,
    ) -> std::result::Result<Self::SerializeStructVariant, Self::Error> {
        Ok(SerializeStructVariant {
            idx,
            entries: Vec::with_capacity(len),
        })
    }
}

struct SerializeVec {
    vec: Vec<rmpv::Value>,
}

impl serde::ser::SerializeSeq for SerializeVec {
    type Ok = rmpv::Value;
    type Error = rmpv::ext::Error;

    fn serialize_element<T: ?Sized + serde::Serialize>(
        &mut self,
        value: &T,
    ) -> std::result::Result<(), Self::Error> {
        self.vec.push(value.serialize(NamedSerializer)?);
        Ok(())
    }

    fn end(self) -> std::result::Result<rmpv::Value, Self::Error> {
        Ok(rmpv::Value::Array(self.vec))
    }
}

impl serde::ser::SerializeTuple for SerializeVec {
    type Ok = rmpv::Value;
    type Error = rmpv::ext::Error;

    fn serialize_element<T: ?Sized + serde::Serialize>(
        &mut self,
        value: &T,
    ) -> std::result::Result<(), Self::Error> {
        serde::ser::SerializeSeq::serialize_element(self, value)
    }

    fn end(self) -> std::result::Result<rmpv::Value, Self::Error> {
        serde::ser::SerializeSeq::end(self)
    }
}

impl serde::ser::SerializeTupleStruct for SerializeVec {
    type Ok = rmpv::Value;
    type Error = rmpv::ext::Error;

    fn serialize_field<T: ?Sized + serde::Serialize>(
        &mut self,
        value: &T,
    ) -> std::result::Result<(), Self::Error> {
        serde::ser::SerializeSeq::serialize_element(self, value)
    }

    fn end(self) -> std::result::Result<rmpv::Value, Self::Error> {
        serde::ser::SerializeSeq::end(self)
    }
}

struct SerializeTupleVariant {
    idx: u32,
    vec: Vec<rmpv::Value>,
}

impl serde::ser::SerializeTupleVariant for SerializeTupleVariant {
    type Ok = rmpv::Value;
    type Error = rmpv::ext::Error;

    fn serialize_field<T: ?Sized + serde::Serialize>(
        &mut self,
        value: &T,
    ) -> std::result::Result<(), Self::Error> {
        self.vec.push(value.serialize(NamedSerializer)?);
        Ok(())
    }

    fn end(self) -> std::result::Result<rmpv::Value, Self::Error> {
        Ok(rmpv::Value::Map(vec![(
            rmpv::Value::Integer(rmpv::Integer::from(self.idx)),
            rmpv::Value::Array(self.vec),
        )]))
    }
}

struct SerializeMap {
    entries: Vec<(rmpv::Value, rmpv::Value)>,
    cur_key: Option<rmpv::Value>,
}

impl serde::ser::SerializeMap for SerializeMap {
    type Ok = rmpv::Value;
    type Error = rmpv::ext::Error;

    fn serialize_key<T: ?Sized + serde::Serialize>(
        &mut self,
        key: &T,
    ) -> std::result::Result<(), Self::Error> {
        self.cur_key = Some(key.serialize(NamedSerializer)?);
        Ok(())
    }

    fn serialize_value<T: ?Sized + serde::Serialize>(
        &mut self,
        value: &T,
    ) -> std::result::Result<(), Self::Error> {
        let key = self.cur_key.take().ok_or_else(|| {
            <Self::Error as serde::ser::Error>::custom(
                "serialize_value called before serialize_key",
            )
        })?;
        self.entries.push((key, value.serialize(NamedSerializer)?));
        Ok(())
    }

    fn end(self) -> std::result::Result<rmpv::Value, Self::Error> {
        Ok(rmpv::Value::Map(self.entries))
    }
}

impl serde::ser::SerializeStruct for SerializeMap {
    type Ok = rmpv::Value;
    type Error = rmpv::ext::Error;

    fn serialize_field<T: ?Sized + serde::Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> std::result::Result<(), Self::Error> {
        let k = rmpv::Value::String(rmpv::Utf8String::from(key));
        let v = value.serialize(NamedSerializer)?;
        self.entries.push((k, v));
        Ok(())
    }

    fn end(self) -> std::result::Result<rmpv::Value, Self::Error> {
        Ok(rmpv::Value::Map(self.entries))
    }
}

struct SerializeStructVariant {
    idx: u32,
    entries: Vec<(rmpv::Value, rmpv::Value)>,
}

impl serde::ser::SerializeStructVariant for SerializeStructVariant {
    type Ok = rmpv::Value;
    type Error = rmpv::ext::Error;

    fn serialize_field<T: ?Sized + serde::Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> std::result::Result<(), Self::Error> {
        let k = rmpv::Value::String(rmpv::Utf8String::from(key));
        let v = value.serialize(NamedSerializer)?;
        self.entries.push((k, v));
        Ok(())
    }

    fn end(self) -> std::result::Result<rmpv::Value, Self::Error> {
        Ok(rmpv::Value::Map(vec![(
            rmpv::Value::Integer(rmpv::Integer::from(self.idx)),
            rmpv::Value::Map(self.entries),
        )]))
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

    pub fn from_typed<T: serde::Serialize>(
        synapse_type: impl Into<String>,
        data: &T,
    ) -> Result<Self> {
        Ok(Self {
            synapse_type: synapse_type.into(),
            data: serialize_to_rmpv_map(data)?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicResponse {
    pub success: bool,
    pub data: HashMap<String, rmpv::Value>,
    pub latency_ms: f64,
    #[serde(default)]
    pub error: Option<String>,
}

impl QuicResponse {
    pub fn into_result(self) -> Result<Self> {
        if self.success {
            Ok(self)
        } else {
            Err(LightningError::Handler(
                self.error.unwrap_or_else(|| "request failed".into()),
            ))
        }
    }

    pub fn deserialize_data<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        let map_value = hashmap_to_rmpv_map(self.data.clone());
        rmpv::ext::from_value(map_value).map_err(|e| LightningError::Serialization(e.to_string()))
    }
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

    if payload_len > MAX_FRAME_PAYLOAD {
        return Err(LightningError::Transport(format!(
            "frame payload {} bytes exceeds maximum {}",
            payload_len, MAX_FRAME_PAYLOAD
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quic_request_from_typed_serializes_struct() {
        #[derive(serde::Serialize)]
        struct MyReq {
            name: String,
            count: u32,
        }

        let req = QuicRequest::from_typed(
            "test_synapse",
            &MyReq {
                name: "hello".into(),
                count: 42,
            },
        )
        .unwrap();

        assert_eq!(req.synapse_type, "test_synapse");
        assert_eq!(
            req.data.get("name").unwrap(),
            &rmpv::Value::String("hello".into())
        );
        assert_eq!(
            req.data.get("count").unwrap(),
            &rmpv::Value::Integer(42.into())
        );
    }

    #[test]
    fn quic_response_into_result_ok_on_success() {
        let resp = QuicResponse {
            success: true,
            data: HashMap::new(),
            latency_ms: 1.0,
            error: None,
        };
        assert!(resp.into_result().is_ok());
    }

    #[test]
    fn quic_response_into_result_err_on_failure() {
        let resp = QuicResponse {
            success: false,
            data: HashMap::new(),
            latency_ms: 1.0,
            error: Some("bad request".into()),
        };
        let err = resp.into_result().unwrap_err();
        assert!(err.to_string().contains("bad request"));
    }

    #[test]
    fn quic_response_into_result_uses_default_message() {
        let resp = QuicResponse {
            success: false,
            data: HashMap::new(),
            latency_ms: 1.0,
            error: None,
        };
        let err = resp.into_result().unwrap_err();
        assert!(err.to_string().contains("request failed"));
    }

    #[test]
    fn quic_response_deserialize_data_roundtrips() {
        #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
        struct MyResp {
            value: i32,
            label: String,
        }

        let original = MyResp {
            value: 99,
            label: "test".into(),
        };

        let data = serialize_to_rmpv_map(&original).unwrap();

        let resp = QuicResponse {
            success: true,
            data,
            latency_ms: 1.0,
            error: None,
        };

        let deserialized: MyResp = resp.deserialize_data().unwrap();
        assert_eq!(deserialized, original);
    }

    #[test]
    fn serialize_to_rmpv_map_handles_nested_structs() {
        #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
        struct Inner {
            x: i32,
            y: String,
        }

        #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
        struct Outer {
            name: String,
            inner: Inner,
            values: Vec<u32>,
        }

        let original = Outer {
            name: "test".into(),
            inner: Inner {
                x: 42,
                y: "nested".into(),
            },
            values: vec![1, 2, 3],
        };

        let map = serialize_to_rmpv_map(&original).unwrap();
        assert_eq!(
            map.get("name").unwrap(),
            &rmpv::Value::String("test".into())
        );
        assert!(matches!(map.get("inner").unwrap(), rmpv::Value::Map(_)));
        assert!(matches!(map.get("values").unwrap(), rmpv::Value::Array(_)));

        let resp = QuicResponse {
            success: true,
            data: map,
            latency_ms: 0.0,
            error: None,
        };
        let deserialized: Outer = resp.deserialize_data().unwrap();
        assert_eq!(deserialized, original);
    }

    #[test]
    fn handshake_request_message_format() {
        let msg = handshake_request_message("5GrwvaEF", 1234567890, "abc123", "fp_b64");
        assert_eq!(msg, "handshake:5GrwvaEF:1234567890:abc123:fp_b64");
    }

    #[test]
    fn handshake_response_message_format() {
        let msg =
            handshake_response_message("5GrwvaEF", "5FHneW46", 1234567890, "abc123", "fp_b64");
        assert_eq!(
            msg,
            "handshake_response:5GrwvaEF:5FHneW46:1234567890:abc123:fp_b64"
        );
    }
}
