use btlightning::{
    typed_async_handler, typed_handler, AsyncSynapseHandler, LightningClient, LightningError,
    LightningServer, LightningServerConfig, QuicAxonInfo, QuicRequest, Result, Sr25519Signer,
    StreamingSynapseHandler, SynapseHandler,
};
use sp_core::{crypto::Ss58Codec, sr25519, Pair};
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

const MINER_SEED: [u8; 32] = [1u8; 32];
const VALIDATOR_SEED: [u8; 32] = [2u8; 32];

fn miner_hotkey() -> String {
    sr25519::Pair::from_seed(&MINER_SEED)
        .public()
        .to_ss58check()
}

fn validator_hotkey() -> String {
    sr25519::Pair::from_seed(&VALIDATOR_SEED)
        .public()
        .to_ss58check()
}

struct TestEnv {
    server_handle: tokio::task::JoinHandle<Result<()>>,
    client: LightningClient,
    axon_info: QuicAxonInfo,
}

impl TestEnv {
    async fn shutdown(self) {
        self.server_handle.abort();
        let _ = self.client.close_all_connections().await;
    }
}

async fn setup() -> TestEnv {
    setup_with_config(LightningServerConfig::default()).await
}

async fn setup_with_config(config: LightningServerConfig) -> TestEnv {
    setup_with_register(|_| Box::pin(async { Ok(()) }), Some(config)).await
}

async fn setup_with_register<F>(register: F, config: Option<LightningServerConfig>) -> TestEnv
where
    F: for<'a> FnOnce(
        &'a LightningServer,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<()>> + 'a>>,
{
    let mut server = LightningServer::with_config(
        miner_hotkey(),
        "127.0.0.1".into(),
        0,
        config.unwrap_or_default(),
    )
    .unwrap();
    server.set_miner_keypair(MINER_SEED);
    register(&server).await.unwrap();
    server.start().await.unwrap();
    let port = server.local_addr().unwrap().port();

    let server_handle = tokio::spawn(async move { server.serve_forever().await });

    let mut client = LightningClient::new(validator_hotkey());
    client.set_signer(Box::new(Sr25519Signer::from_seed(VALIDATOR_SEED)));
    client.create_endpoint().await.unwrap();

    let axon_info = QuicAxonInfo {
        hotkey: miner_hotkey(),
        ip: "127.0.0.1".into(),
        port,
        protocol: 4,
        placeholder1: 0,
        placeholder2: 0,
    };

    TestEnv {
        server_handle,
        client,
        axon_info,
    }
}

async fn setup_with_handler<H: SynapseHandler + 'static>(
    synapse_type: &str,
    handler: H,
) -> TestEnv {
    let st = synapse_type.to_string();
    let h = Arc::new(handler);
    setup_with_register(|s| Box::pin(s.register_synapse_handler(st, h)), None).await
}

async fn setup_with_async_handler<H: AsyncSynapseHandler + 'static>(
    synapse_type: &str,
    handler: H,
) -> TestEnv {
    let st = synapse_type.to_string();
    let h = Arc::new(handler);
    setup_with_register(|s| Box::pin(s.register_async_synapse_handler(st, h)), None).await
}

async fn setup_with_streaming_handler<H: StreamingSynapseHandler + 'static>(
    synapse_type: &str,
    handler: H,
) -> TestEnv {
    let st = synapse_type.to_string();
    let h = Arc::new(handler);
    setup_with_register(|s| Box::pin(s.register_streaming_handler(st, h)), None).await
}

struct EchoHandler;
impl SynapseHandler for EchoHandler {
    fn handle(
        &self,
        _synapse_type: &str,
        data: HashMap<String, rmpv::Value>,
    ) -> Result<HashMap<String, rmpv::Value>> {
        Ok(data)
    }
}

struct ErrorHandler;
impl SynapseHandler for ErrorHandler {
    fn handle(
        &self,
        _synapse_type: &str,
        _data: HashMap<String, rmpv::Value>,
    ) -> Result<HashMap<String, rmpv::Value>> {
        Err(LightningError::Handler("deliberate error".to_string()))
    }
}

struct AsyncEchoHandler;
#[async_trait::async_trait]
impl AsyncSynapseHandler for AsyncEchoHandler {
    async fn handle(
        &self,
        _synapse_type: &str,
        data: HashMap<String, rmpv::Value>,
    ) -> Result<HashMap<String, rmpv::Value>> {
        tokio::time::sleep(Duration::from_millis(10)).await;
        Ok(data)
    }
}

struct AsyncErrorHandler;
#[async_trait::async_trait]
impl AsyncSynapseHandler for AsyncErrorHandler {
    async fn handle(
        &self,
        _synapse_type: &str,
        _data: HashMap<String, rmpv::Value>,
    ) -> Result<HashMap<String, rmpv::Value>> {
        Err(LightningError::Handler(
            "async deliberate error".to_string(),
        ))
    }
}

struct ChunkStreamHandler {
    chunks: Vec<Vec<u8>>,
}
#[async_trait::async_trait]
impl StreamingSynapseHandler for ChunkStreamHandler {
    async fn handle(
        &self,
        _synapse_type: &str,
        _data: HashMap<String, rmpv::Value>,
        sender: mpsc::Sender<Vec<u8>>,
    ) -> Result<()> {
        for chunk in &self.chunks {
            sender
                .send(chunk.clone())
                .await
                .map_err(|_| LightningError::Stream("send failed".to_string()))?;
        }
        Ok(())
    }
}

struct EmptyStreamHandler;
#[async_trait::async_trait]
impl StreamingSynapseHandler for EmptyStreamHandler {
    async fn handle(
        &self,
        _synapse_type: &str,
        _data: HashMap<String, rmpv::Value>,
        _sender: mpsc::Sender<Vec<u8>>,
    ) -> Result<()> {
        Ok(())
    }
}

struct ErrorStreamHandler;
#[async_trait::async_trait]
impl StreamingSynapseHandler for ErrorStreamHandler {
    async fn handle(
        &self,
        _synapse_type: &str,
        _data: HashMap<String, rmpv::Value>,
        sender: mpsc::Sender<Vec<u8>>,
    ) -> Result<()> {
        sender
            .send(b"partial".to_vec())
            .await
            .map_err(|_| LightningError::Stream("send failed".to_string()))?;
        Err(LightningError::Handler("stream error mid-way".to_string()))
    }
}

fn build_request(synapse_type: &str) -> QuicRequest {
    QuicRequest {
        synapse_type: synapse_type.to_string(),
        data: HashMap::new(),
    }
}

fn build_request_with_data(synapse_type: &str, key: &str, val: &str) -> QuicRequest {
    let mut data = HashMap::new();
    data.insert(
        key.to_string(),
        rmpv::Value::String(rmpv::Utf8String::from(val)),
    );
    QuicRequest {
        synapse_type: synapse_type.to_string(),
        data,
    }
}

// --- Connection Lifecycle ---

#[tokio::test]
async fn server_starts_and_binds() {
    let mut server = LightningServer::new(miner_hotkey(), "127.0.0.1".into(), 0).unwrap();
    server.set_miner_keypair(MINER_SEED);
    server.start().await.unwrap();
    let addr = server.local_addr().unwrap();
    assert_ne!(addr.port(), 0);
    server.stop().await.unwrap();
}

#[tokio::test]
async fn client_handshake_succeeds() {
    let env = setup().await;

    let miners = vec![env.axon_info.clone()];
    let mut client = LightningClient::new(validator_hotkey());
    client.set_signer(Box::new(Sr25519Signer::from_seed(VALIDATOR_SEED)));
    client.create_endpoint().await.unwrap();
    client.initialize_connections(miners).await.unwrap();

    let stats = client.get_connection_stats().await.unwrap();
    assert_eq!(stats.get("total_connections").unwrap(), "1");

    client.close_all_connections().await.unwrap();
    env.shutdown().await;
}

// The client uses a different validator keypair that the server has never seen,
// but the keypair is valid for its own claimed hotkey so the sr25519 handshake
// signature verifies and the connection succeeds.
#[tokio::test]
async fn client_with_different_validator_key_connects() {
    let env = setup().await;

    let other_seed = [99u8; 32];
    let other_hotkey = sr25519::Pair::from_seed(&other_seed)
        .public()
        .to_ss58check();

    let mut client = LightningClient::new(other_hotkey);
    client.set_signer(Box::new(Sr25519Signer::from_seed(other_seed)));
    client.create_endpoint().await.unwrap();

    let mut axon = env.axon_info.clone();
    axon.hotkey = miner_hotkey();
    client.initialize_connections(vec![axon]).await.unwrap();

    let stats = client.get_connection_stats().await.unwrap();
    assert_eq!(stats.get("total_connections").unwrap(), "1");

    client.close_all_connections().await.unwrap();
    env.shutdown().await;
}

#[tokio::test]
async fn max_connections_enforcement() {
    let config = LightningServerConfig {
        max_connections: 1,
        ..Default::default()
    };
    let env = setup_with_config(config).await;

    let mut client1 = LightningClient::new(validator_hotkey());
    client1.set_signer(Box::new(Sr25519Signer::from_seed(VALIDATOR_SEED)));
    client1.create_endpoint().await.unwrap();
    client1
        .initialize_connections(vec![env.axon_info.clone()])
        .await
        .unwrap();

    let third_seed = [3u8; 32];
    let third_hotkey = sr25519::Pair::from_seed(&third_seed)
        .public()
        .to_ss58check();
    let mut client2 = LightningClient::new(third_hotkey);
    client2.set_signer(Box::new(Sr25519Signer::from_seed(third_seed)));
    client2.create_endpoint().await.unwrap();
    client2
        .initialize_connections(vec![env.axon_info.clone()])
        .await
        .unwrap();
    let stats2 = client2.get_connection_stats().await.unwrap();
    assert_eq!(
        stats2.get("total_connections").unwrap(),
        "0",
        "second client should be rejected when max_connections=1"
    );

    client1.close_all_connections().await.unwrap();
    client2.close_all_connections().await.unwrap();
    env.shutdown().await;
}

#[tokio::test]
async fn server_stop_closes_connections() {
    let mut server = LightningServer::new(miner_hotkey(), "127.0.0.1".into(), 0).unwrap();
    server.set_miner_keypair(MINER_SEED);
    server.start().await.unwrap();
    let addr = server.local_addr().unwrap();
    let port = addr.port();

    let server_handle = tokio::spawn(async move { server.serve_forever().await });

    let mut client = LightningClient::new(validator_hotkey());
    client.set_signer(Box::new(Sr25519Signer::from_seed(VALIDATOR_SEED)));
    client.create_endpoint().await.unwrap();
    let axon = QuicAxonInfo {
        hotkey: miner_hotkey(),
        ip: "127.0.0.1".into(),
        port,
        protocol: 4,
        placeholder1: 0,
        placeholder2: 0,
    };
    client.initialize_connections(vec![axon]).await.unwrap();

    server_handle.abort();
    let _ = server_handle.await;

    client.close_all_connections().await.unwrap();
}

#[tokio::test]
async fn client_reconnects_after_disconnect() {
    let env = setup_with_handler("echo", EchoHandler).await;

    let mut client = LightningClient::new(validator_hotkey());
    client.set_signer(Box::new(Sr25519Signer::from_seed(VALIDATOR_SEED)));
    client.create_endpoint().await.unwrap();
    client
        .initialize_connections(vec![env.axon_info.clone()])
        .await
        .unwrap();

    let resp = client
        .query_axon(env.axon_info.clone(), build_request("echo"))
        .await;
    assert!(resp.is_ok(), "first query should succeed");

    client.close_all_connections().await.unwrap();

    let resp2 = client
        .query_axon(env.axon_info.clone(), build_request("echo"))
        .await;
    assert!(resp2.is_ok(), "query after reconnect should succeed");

    client.close_all_connections().await.unwrap();
    env.shutdown().await;
}

// --- Handshake Security ---

// Nonce replay rejection is tested at the unit level in
// server::tests::verify_rejects_nonce_replay. This integration test verifies
// that successive handshakes each consume a unique nonce on the server side.
#[tokio::test]
async fn nonce_accounting_increments() {
    let mut server = LightningServer::new(miner_hotkey(), "127.0.0.1".into(), 0).unwrap();
    server.set_miner_keypair(MINER_SEED);
    server
        .register_synapse_handler("echo".to_string(), Arc::new(EchoHandler))
        .await
        .unwrap();
    server.start().await.unwrap();
    let port = server.local_addr().unwrap().port();

    let server = Arc::new(server);
    let s = server.clone();
    let server_handle = tokio::spawn(async move { s.serve_forever().await });

    let axon = QuicAxonInfo {
        hotkey: miner_hotkey(),
        ip: "127.0.0.1".into(),
        port,
        protocol: 4,
        placeholder1: 0,
        placeholder2: 0,
    };

    let mut client = LightningClient::new(validator_hotkey());
    client.set_signer(Box::new(Sr25519Signer::from_seed(VALIDATOR_SEED)));
    client.create_endpoint().await.unwrap();
    client
        .initialize_connections(vec![axon.clone()])
        .await
        .unwrap();

    let count_after_first = server.get_active_nonce_count().await;
    assert!(
        count_after_first >= 1,
        "handshake must record at least one nonce"
    );

    client.close_all_connections().await.unwrap();
    client
        .initialize_connections(vec![axon.clone()])
        .await
        .unwrap();

    let count_after_second = server.get_active_nonce_count().await;
    assert!(
        count_after_second >= 2,
        "each handshake must consume a unique nonce, got {}",
        count_after_second
    );

    client.close_all_connections().await.unwrap();
    server_handle.abort();
}

// --- Sync Handler Dispatch ---

#[tokio::test]
async fn sync_handler_echo_roundtrip() {
    let env = setup_with_handler("echo", EchoHandler).await;

    let mut client = LightningClient::new(validator_hotkey());
    client.set_signer(Box::new(Sr25519Signer::from_seed(VALIDATOR_SEED)));
    client.create_endpoint().await.unwrap();
    client
        .initialize_connections(vec![env.axon_info.clone()])
        .await
        .unwrap();

    let req = build_request_with_data("echo", "greeting", "hello");
    let resp = client.query_axon(env.axon_info.clone(), req).await.unwrap();
    assert!(resp.success);
    let val = resp.data.get("greeting").unwrap();
    assert_eq!(val.as_str().unwrap(), "hello");

    client.close_all_connections().await.unwrap();
    env.shutdown().await;
}

#[tokio::test]
async fn sync_handler_error_propagation() {
    let env = setup_with_handler("fail", ErrorHandler).await;

    let mut client = LightningClient::new(validator_hotkey());
    client.set_signer(Box::new(Sr25519Signer::from_seed(VALIDATOR_SEED)));
    client.create_endpoint().await.unwrap();
    client
        .initialize_connections(vec![env.axon_info.clone()])
        .await
        .unwrap();

    let resp = client
        .query_axon(env.axon_info.clone(), build_request("fail"))
        .await
        .unwrap();
    assert!(!resp.success);
    assert!(resp.error.is_some());

    client.close_all_connections().await.unwrap();
    env.shutdown().await;
}

#[tokio::test]
async fn unregistered_synapse_type_returns_error() {
    let env = setup_with_handler("echo", EchoHandler).await;

    let mut client = LightningClient::new(validator_hotkey());
    client.set_signer(Box::new(Sr25519Signer::from_seed(VALIDATOR_SEED)));
    client.create_endpoint().await.unwrap();
    client
        .initialize_connections(vec![env.axon_info.clone()])
        .await
        .unwrap();

    let resp = client
        .query_axon(env.axon_info.clone(), build_request("nonexistent"))
        .await
        .unwrap();
    assert!(!resp.success);

    client.close_all_connections().await.unwrap();
    env.shutdown().await;
}

#[tokio::test]
async fn multiple_synapse_handlers() {
    let mut server = LightningServer::new(miner_hotkey(), "127.0.0.1".into(), 0).unwrap();
    server.set_miner_keypair(MINER_SEED);
    server
        .register_synapse_handler("echo".to_string(), Arc::new(EchoHandler))
        .await
        .unwrap();
    server
        .register_synapse_handler("fail".to_string(), Arc::new(ErrorHandler))
        .await
        .unwrap();
    server.start().await.unwrap();
    let port = server.local_addr().unwrap().port();

    let _server_handle = tokio::spawn(async move { server.serve_forever().await });

    let axon = QuicAxonInfo {
        hotkey: miner_hotkey(),
        ip: "127.0.0.1".into(),
        port,
        protocol: 4,
        placeholder1: 0,
        placeholder2: 0,
    };

    let mut client = LightningClient::new(validator_hotkey());
    client.set_signer(Box::new(Sr25519Signer::from_seed(VALIDATOR_SEED)));
    client.create_endpoint().await.unwrap();
    client
        .initialize_connections(vec![axon.clone()])
        .await
        .unwrap();

    let resp1 = client
        .query_axon(axon.clone(), build_request("echo"))
        .await
        .unwrap();
    assert!(resp1.success);

    let resp2 = client
        .query_axon(axon.clone(), build_request("fail"))
        .await
        .unwrap();
    assert!(!resp2.success);

    client.close_all_connections().await.unwrap();
}

// --- Async Handler Dispatch ---

#[tokio::test]
async fn async_handler_echo_roundtrip() {
    let env = setup_with_async_handler("async_echo", AsyncEchoHandler).await;

    let mut client = LightningClient::new(validator_hotkey());
    client.set_signer(Box::new(Sr25519Signer::from_seed(VALIDATOR_SEED)));
    client.create_endpoint().await.unwrap();
    client
        .initialize_connections(vec![env.axon_info.clone()])
        .await
        .unwrap();

    let req = build_request_with_data("async_echo", "key", "value");
    let resp = client.query_axon(env.axon_info.clone(), req).await.unwrap();
    assert!(resp.success);
    assert_eq!(resp.data.get("key").unwrap().as_str().unwrap(), "value");

    client.close_all_connections().await.unwrap();
    env.shutdown().await;
}

#[tokio::test]
async fn async_handler_error_propagation() {
    let mut server = LightningServer::new(miner_hotkey(), "127.0.0.1".into(), 0).unwrap();
    server.set_miner_keypair(MINER_SEED);
    server
        .register_async_synapse_handler("async_fail".to_string(), Arc::new(AsyncErrorHandler))
        .await
        .unwrap();
    server.start().await.unwrap();
    let port = server.local_addr().unwrap().port();
    let server_handle = tokio::spawn(async move { server.serve_forever().await });

    let axon = QuicAxonInfo {
        hotkey: miner_hotkey(),
        ip: "127.0.0.1".into(),
        port,
        protocol: 4,
        placeholder1: 0,
        placeholder2: 0,
    };

    let mut client = LightningClient::new(validator_hotkey());
    client.set_signer(Box::new(Sr25519Signer::from_seed(VALIDATOR_SEED)));
    client.create_endpoint().await.unwrap();
    client
        .initialize_connections(vec![axon.clone()])
        .await
        .unwrap();

    let resp = client
        .query_axon(axon, build_request("async_fail"))
        .await
        .unwrap();
    assert!(!resp.success);
    assert!(resp.error.is_some());

    client.close_all_connections().await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn mixed_sync_async_handlers() {
    let mut server = LightningServer::new(miner_hotkey(), "127.0.0.1".into(), 0).unwrap();
    server.set_miner_keypair(MINER_SEED);
    server
        .register_synapse_handler("sync_echo".to_string(), Arc::new(EchoHandler))
        .await
        .unwrap();
    server
        .register_async_synapse_handler("async_echo".to_string(), Arc::new(AsyncEchoHandler))
        .await
        .unwrap();
    server.start().await.unwrap();
    let port = server.local_addr().unwrap().port();
    let server_handle = tokio::spawn(async move { server.serve_forever().await });

    let axon = QuicAxonInfo {
        hotkey: miner_hotkey(),
        ip: "127.0.0.1".into(),
        port,
        protocol: 4,
        placeholder1: 0,
        placeholder2: 0,
    };

    let mut client = LightningClient::new(validator_hotkey());
    client.set_signer(Box::new(Sr25519Signer::from_seed(VALIDATOR_SEED)));
    client.create_endpoint().await.unwrap();
    client
        .initialize_connections(vec![axon.clone()])
        .await
        .unwrap();

    let r1 = client
        .query_axon(axon.clone(), build_request_with_data("sync_echo", "k", "v"))
        .await
        .unwrap();
    assert!(r1.success);

    let r2 = client
        .query_axon(axon, build_request_with_data("async_echo", "k", "v"))
        .await
        .unwrap();
    assert!(r2.success);

    client.close_all_connections().await.unwrap();
    server_handle.abort();
}

// --- Streaming Handler Dispatch ---

#[tokio::test]
async fn streaming_handler_receives_chunks() {
    let chunks = vec![b"chunk1".to_vec(), b"chunk2".to_vec(), b"chunk3".to_vec()];
    let mut server = LightningServer::new(miner_hotkey(), "127.0.0.1".into(), 0).unwrap();
    server.set_miner_keypair(MINER_SEED);
    server
        .register_streaming_handler(
            "stream".to_string(),
            Arc::new(ChunkStreamHandler {
                chunks: chunks.clone(),
            }),
        )
        .await
        .unwrap();
    server.start().await.unwrap();
    let port = server.local_addr().unwrap().port();
    let server_handle = tokio::spawn(async move { server.serve_forever().await });

    let axon = QuicAxonInfo {
        hotkey: miner_hotkey(),
        ip: "127.0.0.1".into(),
        port,
        protocol: 4,
        placeholder1: 0,
        placeholder2: 0,
    };

    let mut client = LightningClient::new(validator_hotkey());
    client.set_signer(Box::new(Sr25519Signer::from_seed(VALIDATOR_SEED)));
    client.create_endpoint().await.unwrap();
    client
        .initialize_connections(vec![axon.clone()])
        .await
        .unwrap();

    let mut stream = client
        .query_axon_stream(axon, build_request("stream"))
        .await
        .unwrap();

    let mut received = Vec::new();
    while let Some(chunk) = stream.next_chunk().await.unwrap() {
        received.push(chunk);
    }

    assert_eq!(received.len(), 3);
    assert_eq!(received[0], b"chunk1");
    assert_eq!(received[1], b"chunk2");
    assert_eq!(received[2], b"chunk3");

    client.close_all_connections().await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn streaming_handler_zero_chunks() {
    let env = setup_with_streaming_handler("empty", EmptyStreamHandler).await;

    let mut client = LightningClient::new(validator_hotkey());
    client.set_signer(Box::new(Sr25519Signer::from_seed(VALIDATOR_SEED)));
    client.create_endpoint().await.unwrap();
    client
        .initialize_connections(vec![env.axon_info.clone()])
        .await
        .unwrap();

    let mut stream = client
        .query_axon_stream(env.axon_info.clone(), build_request("empty"))
        .await
        .unwrap();

    let chunk = stream.next_chunk().await.unwrap();
    assert!(
        chunk.is_none(),
        "empty stream should return None immediately"
    );

    client.close_all_connections().await.unwrap();
    env.shutdown().await;
}

#[tokio::test]
async fn streaming_handler_error_midstream() {
    let mut server = LightningServer::new(miner_hotkey(), "127.0.0.1".into(), 0).unwrap();
    server.set_miner_keypair(MINER_SEED);
    server
        .register_streaming_handler("errstream".to_string(), Arc::new(ErrorStreamHandler))
        .await
        .unwrap();
    server.start().await.unwrap();
    let port = server.local_addr().unwrap().port();
    let server_handle = tokio::spawn(async move { server.serve_forever().await });

    let axon = QuicAxonInfo {
        hotkey: miner_hotkey(),
        ip: "127.0.0.1".into(),
        port,
        protocol: 4,
        placeholder1: 0,
        placeholder2: 0,
    };

    let mut client = LightningClient::new(validator_hotkey());
    client.set_signer(Box::new(Sr25519Signer::from_seed(VALIDATOR_SEED)));
    client.create_endpoint().await.unwrap();
    client
        .initialize_connections(vec![axon.clone()])
        .await
        .unwrap();

    let mut stream = client
        .query_axon_stream(axon, build_request("errstream"))
        .await
        .unwrap();

    let first = stream.next_chunk().await.unwrap();
    assert!(first.is_some(), "should receive partial chunk before error");

    let mut found_error = false;
    loop {
        match stream.next_chunk().await {
            Ok(Some(_)) => continue,
            Ok(None) => break,
            Err(_) => {
                found_error = true;
                break;
            }
        }
    }
    assert!(found_error, "should receive error after partial data");

    client.close_all_connections().await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn streaming_collect_all() {
    let chunks = vec![b"a".to_vec(), b"bb".to_vec(), b"ccc".to_vec()];
    let mut server = LightningServer::new(miner_hotkey(), "127.0.0.1".into(), 0).unwrap();
    server.set_miner_keypair(MINER_SEED);
    server
        .register_streaming_handler(
            "stream".to_string(),
            Arc::new(ChunkStreamHandler {
                chunks: chunks.clone(),
            }),
        )
        .await
        .unwrap();
    server.start().await.unwrap();
    let port = server.local_addr().unwrap().port();
    let server_handle = tokio::spawn(async move { server.serve_forever().await });

    let axon = QuicAxonInfo {
        hotkey: miner_hotkey(),
        ip: "127.0.0.1".into(),
        port,
        protocol: 4,
        placeholder1: 0,
        placeholder2: 0,
    };

    let mut client = LightningClient::new(validator_hotkey());
    client.set_signer(Box::new(Sr25519Signer::from_seed(VALIDATOR_SEED)));
    client.create_endpoint().await.unwrap();
    client
        .initialize_connections(vec![axon.clone()])
        .await
        .unwrap();

    let mut stream = client
        .query_axon_stream(axon, build_request("stream"))
        .await
        .unwrap();
    let all = stream.collect_all().await.unwrap();
    assert_eq!(all.len(), 3);

    client.close_all_connections().await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn streaming_client_drops_early() {
    let chunks = vec![b"data".to_vec(); 100];
    let mut server = LightningServer::new(miner_hotkey(), "127.0.0.1".into(), 0).unwrap();
    server.set_miner_keypair(MINER_SEED);
    server
        .register_streaming_handler(
            "bigstream".to_string(),
            Arc::new(ChunkStreamHandler { chunks }),
        )
        .await
        .unwrap();
    server.start().await.unwrap();
    let port = server.local_addr().unwrap().port();
    let server_handle = tokio::spawn(async move { server.serve_forever().await });

    let axon = QuicAxonInfo {
        hotkey: miner_hotkey(),
        ip: "127.0.0.1".into(),
        port,
        protocol: 4,
        placeholder1: 0,
        placeholder2: 0,
    };

    let mut client = LightningClient::new(validator_hotkey());
    client.set_signer(Box::new(Sr25519Signer::from_seed(VALIDATOR_SEED)));
    client.create_endpoint().await.unwrap();
    client
        .initialize_connections(vec![axon.clone()])
        .await
        .unwrap();

    let mut stream = client
        .query_axon_stream(axon, build_request("bigstream"))
        .await
        .unwrap();
    let _ = stream.next_chunk().await;
    drop(stream);

    tokio::time::sleep(Duration::from_millis(100)).await;

    client.close_all_connections().await.unwrap();
    server_handle.abort();
}

// --- Edge Cases ---

#[tokio::test]
async fn concurrent_requests_on_same_connection() {
    let env = setup_with_handler("echo", EchoHandler).await;

    let mut client = LightningClient::new(validator_hotkey());
    client.set_signer(Box::new(Sr25519Signer::from_seed(VALIDATOR_SEED)));
    client.create_endpoint().await.unwrap();
    client
        .initialize_connections(vec![env.axon_info.clone()])
        .await
        .unwrap();

    let client = Arc::new(client);
    let mut handles = Vec::new();
    for i in 0..10 {
        let c = client.clone();
        let axon = env.axon_info.clone();
        handles.push(tokio::spawn(async move {
            let req = build_request_with_data("echo", "idx", &i.to_string());
            c.query_axon(axon, req).await
        }));
    }

    let mut successes = 0;
    for h in handles {
        if let Ok(Ok(resp)) = h.await {
            if resp.success {
                successes += 1;
            }
        }
    }
    assert_eq!(successes, 10, "all concurrent requests should succeed");

    client.close_all_connections().await.unwrap();
    env.shutdown().await;
}

#[tokio::test]
async fn query_timeout_triggers() {
    let env = setup_with_handler("echo", EchoHandler).await;

    let mut client = LightningClient::new(validator_hotkey());
    client.set_signer(Box::new(Sr25519Signer::from_seed(VALIDATOR_SEED)));
    client.create_endpoint().await.unwrap();

    let bad_axon = QuicAxonInfo {
        hotkey: miner_hotkey(),
        ip: "192.0.2.1".into(),
        port: 1,
        protocol: 4,
        placeholder1: 0,
        placeholder2: 0,
    };

    let result = client
        .query_axon_with_timeout(bad_axon, build_request("echo"), Duration::from_millis(100))
        .await;
    assert!(result.is_err());

    env.shutdown().await;
}

// --- Typed Handler Roundtrips ---

#[tokio::test]
async fn typed_sync_handler_integration() {
    #[derive(serde::Serialize, serde::Deserialize)]
    struct AddReq {
        a: i32,
        b: i32,
    }
    #[derive(serde::Serialize, serde::Deserialize)]
    struct AddResp {
        sum: i32,
    }

    let handler = typed_handler(|req: AddReq| -> std::result::Result<AddResp, String> {
        Ok(AddResp { sum: req.a + req.b })
    });

    let mut server = LightningServer::new(miner_hotkey(), "127.0.0.1".into(), 0).unwrap();
    server.set_miner_keypair(MINER_SEED);
    server
        .register_synapse_handler("add".to_string(), handler)
        .await
        .unwrap();
    server.start().await.unwrap();
    let port = server.local_addr().unwrap().port();
    let server_handle = tokio::spawn(async move { server.serve_forever().await });

    let axon = QuicAxonInfo {
        hotkey: miner_hotkey(),
        ip: "127.0.0.1".into(),
        port,
        protocol: 4,
        placeholder1: 0,
        placeholder2: 0,
    };

    let mut client = LightningClient::new(validator_hotkey());
    client.set_signer(Box::new(Sr25519Signer::from_seed(VALIDATOR_SEED)));
    client.create_endpoint().await.unwrap();
    client
        .initialize_connections(vec![axon.clone()])
        .await
        .unwrap();

    let req = QuicRequest::from_typed("add", &AddReq { a: 3, b: 4 }).unwrap();
    let resp = client.query_axon(axon, req).await.unwrap();
    assert!(resp.success);
    let result: AddResp = resp.deserialize_data().unwrap();
    assert_eq!(result.sum, 7);

    client.close_all_connections().await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn typed_async_handler_integration() {
    #[derive(serde::Serialize, serde::Deserialize)]
    struct DoubleReq {
        value: i32,
    }
    #[derive(serde::Serialize, serde::Deserialize)]
    struct DoubleResp {
        doubled: i32,
    }

    let handler = typed_async_handler(|req: DoubleReq| async move {
        Ok::<_, String>(DoubleResp {
            doubled: req.value * 2,
        })
    });

    let mut server = LightningServer::new(miner_hotkey(), "127.0.0.1".into(), 0).unwrap();
    server.set_miner_keypair(MINER_SEED);
    server
        .register_async_synapse_handler("double".to_string(), handler)
        .await
        .unwrap();
    server.start().await.unwrap();
    let port = server.local_addr().unwrap().port();
    let server_handle = tokio::spawn(async move { server.serve_forever().await });

    let axon = QuicAxonInfo {
        hotkey: miner_hotkey(),
        ip: "127.0.0.1".into(),
        port,
        protocol: 4,
        placeholder1: 0,
        placeholder2: 0,
    };

    let mut client = LightningClient::new(validator_hotkey());
    client.set_signer(Box::new(Sr25519Signer::from_seed(VALIDATOR_SEED)));
    client.create_endpoint().await.unwrap();
    client
        .initialize_connections(vec![axon.clone()])
        .await
        .unwrap();

    let req = QuicRequest::from_typed("double", &DoubleReq { value: 21 }).unwrap();
    let resp = client.query_axon(axon, req).await.unwrap();
    assert!(resp.success);
    let result: DoubleResp = resp.deserialize_data().unwrap();
    assert_eq!(result.doubled, 42);

    client.close_all_connections().await.unwrap();
    server_handle.abort();
}

// --- Nonce Management ---

#[tokio::test]
async fn nonce_cleanup_removes_expired() {
    let config = LightningServerConfig {
        max_signature_age_secs: 1,
        nonce_cleanup_interval_secs: 1,
        ..Default::default()
    };
    let mut server =
        LightningServer::with_config(miner_hotkey(), "127.0.0.1".into(), 0, config).unwrap();
    server.set_miner_keypair(MINER_SEED);
    server.start().await.unwrap();
    let port = server.local_addr().unwrap().port();

    let server = Arc::new(server);
    let s = server.clone();
    let server_handle = tokio::spawn(async move { s.serve_forever().await });

    let axon = QuicAxonInfo {
        hotkey: miner_hotkey(),
        ip: "127.0.0.1".into(),
        port,
        protocol: 4,
        placeholder1: 0,
        placeholder2: 0,
    };

    let mut client = LightningClient::new(validator_hotkey());
    client.set_signer(Box::new(Sr25519Signer::from_seed(VALIDATOR_SEED)));
    client.create_endpoint().await.unwrap();
    client
        .initialize_connections(vec![axon.clone()])
        .await
        .unwrap();

    let count_before = server.get_active_nonce_count().await;
    assert!(
        count_before > 0,
        "handshake should record at least one nonce"
    );

    tokio::time::sleep(Duration::from_secs(3)).await;

    let count_after = server.get_active_nonce_count().await;
    assert_eq!(
        count_after, 0,
        "expired nonces should be cleaned up by background task"
    );

    client.close_all_connections().await.unwrap();
    server_handle.abort();
}
