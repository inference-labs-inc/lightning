use btlightning::{
    typed_async_handler, typed_handler, AsyncSynapseHandler, CallbackSigner, LightningClient,
    LightningError, LightningServer, LightningServerConfig, QuicAxonInfo, QuicRequest, Result,
    Signer, Sr25519Signer, StreamingSynapseHandler, SynapseHandler, ValidatorPermitResolver,
};
use sp_core::{crypto::Ss58Codec, sr25519, Pair};
use std::collections::HashMap;
use std::collections::HashSet;
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
    server: Arc<LightningServer>,
    server_handle: tokio::task::JoinHandle<Result<()>>,
    client: LightningClient,
    axon_info: QuicAxonInfo,
}

impl TestEnv {
    async fn shutdown(self) {
        let _ = self.server.stop().await;
        let _ = self.server_handle.await;
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
    let cfg = match config {
        Some(c) => {
            assert!(
                !c.require_validator_permit,
                "setup_with_register disables permit checking; \
                 permit-enabled servers must be constructed explicitly"
            );
            c
        }
        None => {
            let mut c = LightningServerConfig::default();
            c.require_validator_permit = false;
            c
        }
    };
    let mut server =
        LightningServer::with_config(miner_hotkey(), "127.0.0.1".into(), 0, cfg).unwrap();
    server.set_miner_keypair(MINER_SEED);
    register(&server).await.unwrap();
    server.start().await.unwrap();
    let port = server.local_addr().unwrap().port();

    let server = Arc::new(server);
    let s = server.clone();
    let server_handle = tokio::spawn(async move { s.serve_forever().await });

    let (client, axon_info) = connect_client(port).await;

    TestEnv {
        server,
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

async fn connect_client(port: u16) -> (LightningClient, QuicAxonInfo) {
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
    client
        .initialize_connections(vec![axon.clone()])
        .await
        .unwrap();
    (client, axon)
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

struct SlowHandler;
#[async_trait::async_trait]
impl AsyncSynapseHandler for SlowHandler {
    async fn handle(
        &self,
        _synapse_type: &str,
        _data: HashMap<String, rmpv::Value>,
    ) -> Result<HashMap<String, rmpv::Value>> {
        tokio::time::sleep(Duration::from_secs(60)).await;
        Ok(HashMap::new())
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

struct SlowStreamHandler;
#[async_trait::async_trait]
impl StreamingSynapseHandler for SlowStreamHandler {
    async fn handle(
        &self,
        _synapse_type: &str,
        _data: HashMap<String, rmpv::Value>,
        _sender: mpsc::Sender<Vec<u8>>,
    ) -> Result<()> {
        tokio::time::sleep(Duration::from_secs(60)).await;
        Ok(())
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

    let stats = env.client.get_connection_stats().await.unwrap();
    assert_eq!(stats.get("total_connections").unwrap(), "1");

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
    let mut config = LightningServerConfig::default();
    config.max_connections = 1;
    let env = setup_with_config(config).await;

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

    client2.close_all_connections().await.unwrap();
    env.shutdown().await;
}

#[tokio::test]
async fn server_stop_closes_connections() {
    let mut server = LightningServer::new(miner_hotkey(), "127.0.0.1".into(), 0).unwrap();
    server.set_miner_keypair(MINER_SEED);
    server.start().await.unwrap();
    let port = server.local_addr().unwrap().port();

    let server = Arc::new(server);
    let s = server.clone();
    let server_handle = tokio::spawn(async move { s.serve_forever().await });

    let (client, axon) = connect_client(port).await;

    server.stop().await.unwrap();
    let _ = server_handle.await;

    let result = client.query_axon(axon, build_request("echo")).await;
    assert!(result.is_err(), "query should fail after server stop");

    let _ = client.close_all_connections().await;
}

#[tokio::test]
async fn client_reconnects_after_disconnect() {
    let env = setup_with_handler("echo", EchoHandler).await;

    let resp = env
        .client
        .query_axon(env.axon_info.clone(), build_request("echo"))
        .await;
    assert!(resp.is_ok(), "first query should succeed");

    env.client.close_all_connections().await.unwrap();

    let resp2 = env
        .client
        .query_axon(env.axon_info.clone(), build_request("echo"))
        .await;
    assert!(resp2.is_ok(), "query after reconnect should succeed");

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

    let (mut client, axon) = connect_client(port).await;

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
    let _ = server.stop().await;
    let _ = server_handle.await;
}

// --- Sync Handler Dispatch ---

#[tokio::test]
async fn sync_handler_echo_roundtrip() {
    let env = setup_with_handler("echo", EchoHandler).await;

    let req = build_request_with_data("echo", "greeting", "hello");
    let resp = env
        .client
        .query_axon(env.axon_info.clone(), req)
        .await
        .unwrap();
    assert!(resp.success);
    let val = resp.data.get("greeting").unwrap();
    assert_eq!(val.as_str().unwrap(), "hello");

    env.shutdown().await;
}

#[tokio::test]
async fn sync_handler_error_propagation() {
    let env = setup_with_handler("fail", ErrorHandler).await;

    let resp = env
        .client
        .query_axon(env.axon_info.clone(), build_request("fail"))
        .await
        .unwrap();
    assert!(!resp.success);
    assert!(resp.error.is_some());

    env.shutdown().await;
}

#[tokio::test]
async fn unregistered_synapse_type_returns_error() {
    let env = setup_with_handler("echo", EchoHandler).await;

    let resp = env
        .client
        .query_axon(env.axon_info.clone(), build_request("nonexistent"))
        .await
        .unwrap();
    assert!(!resp.success);

    env.shutdown().await;
}

#[tokio::test]
async fn multiple_synapse_handlers() {
    let env = setup_with_register(
        |s| {
            Box::pin(async {
                s.register_synapse_handler("echo".to_string(), Arc::new(EchoHandler))
                    .await?;
                s.register_synapse_handler("fail".to_string(), Arc::new(ErrorHandler))
                    .await?;
                Ok(())
            })
        },
        None,
    )
    .await;

    let resp1 = env
        .client
        .query_axon(env.axon_info.clone(), build_request("echo"))
        .await
        .unwrap();
    assert!(resp1.success);

    let resp2 = env
        .client
        .query_axon(env.axon_info.clone(), build_request("fail"))
        .await
        .unwrap();
    assert!(!resp2.success);

    env.shutdown().await;
}

// --- Async Handler Dispatch ---

#[tokio::test]
async fn async_handler_echo_roundtrip() {
    let env = setup_with_async_handler("async_echo", AsyncEchoHandler).await;

    let req = build_request_with_data("async_echo", "key", "value");
    let resp = env
        .client
        .query_axon(env.axon_info.clone(), req)
        .await
        .unwrap();
    assert!(resp.success);
    assert_eq!(resp.data.get("key").unwrap().as_str().unwrap(), "value");

    env.shutdown().await;
}

#[tokio::test]
async fn async_handler_error_propagation() {
    let env = setup_with_async_handler("async_fail", AsyncErrorHandler).await;

    let resp = env
        .client
        .query_axon(env.axon_info.clone(), build_request("async_fail"))
        .await
        .unwrap();
    assert!(!resp.success);
    assert!(resp.error.is_some());

    env.shutdown().await;
}

#[tokio::test]
async fn mixed_sync_async_handlers() {
    let env = setup_with_register(
        |s| {
            Box::pin(async {
                s.register_synapse_handler("sync_echo".to_string(), Arc::new(EchoHandler))
                    .await?;
                s.register_async_synapse_handler(
                    "async_echo".to_string(),
                    Arc::new(AsyncEchoHandler),
                )
                .await?;
                Ok(())
            })
        },
        None,
    )
    .await;

    let r1 = env
        .client
        .query_axon(
            env.axon_info.clone(),
            build_request_with_data("sync_echo", "k", "v"),
        )
        .await
        .unwrap();
    assert!(r1.success);

    let r2 = env
        .client
        .query_axon(
            env.axon_info.clone(),
            build_request_with_data("async_echo", "k", "v"),
        )
        .await
        .unwrap();
    assert!(r2.success);

    env.shutdown().await;
}

// --- Streaming Handler Dispatch ---

#[tokio::test]
async fn streaming_handler_receives_chunks() {
    let chunks = vec![b"chunk1".to_vec(), b"chunk2".to_vec(), b"chunk3".to_vec()];
    let env = setup_with_streaming_handler(
        "stream",
        ChunkStreamHandler {
            chunks: chunks.clone(),
        },
    )
    .await;

    let mut stream = env
        .client
        .query_axon_stream(env.axon_info.clone(), build_request("stream"))
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

    env.shutdown().await;
}

#[tokio::test]
async fn streaming_handler_zero_chunks() {
    let env = setup_with_streaming_handler("empty", EmptyStreamHandler).await;

    let mut stream = env
        .client
        .query_axon_stream(env.axon_info.clone(), build_request("empty"))
        .await
        .unwrap();

    let chunk = stream.next_chunk().await.unwrap();
    assert!(
        chunk.is_none(),
        "empty stream should return None immediately"
    );

    env.shutdown().await;
}

#[tokio::test]
async fn streaming_handler_error_midstream() {
    let env = setup_with_streaming_handler("errstream", ErrorStreamHandler).await;

    let mut stream = env
        .client
        .query_axon_stream(env.axon_info.clone(), build_request("errstream"))
        .await
        .unwrap();

    let first = stream.next_chunk().await.unwrap();
    assert!(first.is_some(), "should receive partial chunk before error");

    let mut found_error = false;
    for _ in 0..100 {
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

    env.shutdown().await;
}

#[tokio::test]
async fn streaming_collect_all() {
    let chunks = vec![b"a".to_vec(), b"bb".to_vec(), b"ccc".to_vec()];
    let env = setup_with_streaming_handler("stream", ChunkStreamHandler { chunks }).await;

    let mut stream = env
        .client
        .query_axon_stream(env.axon_info.clone(), build_request("stream"))
        .await
        .unwrap();
    let all = stream.collect_all().await.unwrap();
    assert_eq!(all.len(), 3);

    env.shutdown().await;
}

#[tokio::test]
async fn streaming_client_drops_early() {
    let chunks = vec![b"data".to_vec(); 100];
    let env = setup_with_streaming_handler("bigstream", ChunkStreamHandler { chunks }).await;

    let mut stream = env
        .client
        .query_axon_stream(env.axon_info.clone(), build_request("bigstream"))
        .await
        .unwrap();
    let _ = stream.next_chunk().await;
    drop(stream);

    let mut stream2 = env
        .client
        .query_axon_stream(env.axon_info.clone(), build_request("bigstream"))
        .await
        .unwrap();
    let chunk = stream2.next_chunk().await.unwrap();
    assert!(
        chunk.is_some(),
        "server should remain operational after client drops stream"
    );

    env.shutdown().await;
}

// --- Edge Cases ---

#[tokio::test]
async fn concurrent_requests_on_same_connection() {
    let TestEnv {
        server,
        server_handle,
        client,
        axon_info,
    } = setup_with_handler("echo", EchoHandler).await;

    let client = Arc::new(client);
    let mut handles = Vec::new();
    for i in 0..10 {
        let c = client.clone();
        let axon = axon_info.clone();
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
    let _ = server.stop().await;
    let _ = server_handle.await;
}

#[tokio::test]
async fn query_timeout_triggers() {
    let env = setup_with_async_handler("slow", SlowHandler).await;

    let result = env
        .client
        .query_axon_with_timeout(
            env.axon_info.clone(),
            build_request("slow"),
            Duration::from_millis(500),
        )
        .await;
    assert!(result.is_err());

    env.shutdown().await;
}

#[tokio::test]
async fn server_handler_timeout_returns_error() {
    let mut config = LightningServerConfig::default();
    config.handler_timeout_secs = 1;
    let st = "slow".to_string();
    let h: Arc<dyn AsyncSynapseHandler> = Arc::new(SlowHandler);
    let env = setup_with_register(
        |s| Box::pin(s.register_async_synapse_handler(st, h)),
        Some(config),
    )
    .await;

    let resp = tokio::time::timeout(
        Duration::from_secs(5),
        env.client
            .query_axon(env.axon_info.clone(), build_request("slow")),
    )
    .await
    .expect("server-side handler timeout did not fire within 5s")
    .unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error.as_deref(), Some("handler timed out"));

    env.shutdown().await;
}

#[tokio::test]
async fn server_streaming_handler_timeout_returns_error() {
    let mut config = LightningServerConfig::default();
    config.handler_timeout_secs = 1;
    let st = "slowstream".to_string();
    let h: Arc<dyn StreamingSynapseHandler> = Arc::new(SlowStreamHandler);
    let env = setup_with_register(
        |s| Box::pin(s.register_streaming_handler(st, h)),
        Some(config),
    )
    .await;

    let mut stream = env
        .client
        .query_axon_stream(env.axon_info.clone(), build_request("slowstream"))
        .await
        .unwrap();
    let err = tokio::time::timeout(Duration::from_secs(5), stream.next_chunk())
        .await
        .expect("server-side streaming timeout did not fire within 5s")
        .unwrap_err();
    assert!(
        err.to_string().contains("handler timed out"),
        "expected timeout error, got: {err}"
    );

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

    let mut config = LightningServerConfig::default();
    config.require_validator_permit = false;
    let mut server =
        LightningServer::with_config(miner_hotkey(), "127.0.0.1".into(), 0, config).unwrap();
    server.set_miner_keypair(MINER_SEED);
    server
        .register_synapse_handler("add".to_string(), handler)
        .await
        .unwrap();
    server.start().await.unwrap();
    let port = server.local_addr().unwrap().port();

    let server = Arc::new(server);
    let s = server.clone();
    let server_handle = tokio::spawn(async move { s.serve_forever().await });

    let (client, axon) = connect_client(port).await;

    let req = QuicRequest::from_typed("add", &AddReq { a: 3, b: 4 }).unwrap();
    let resp = client.query_axon(axon, req).await.unwrap();
    assert!(resp.success);
    let result: AddResp = resp.deserialize_data().unwrap();
    assert_eq!(result.sum, 7);

    client.close_all_connections().await.unwrap();
    let _ = server.stop().await;
    let _ = server_handle.await;
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

    let mut config = LightningServerConfig::default();
    config.require_validator_permit = false;
    let mut server =
        LightningServer::with_config(miner_hotkey(), "127.0.0.1".into(), 0, config).unwrap();
    server.set_miner_keypair(MINER_SEED);
    server
        .register_async_synapse_handler("double".to_string(), handler)
        .await
        .unwrap();
    server.start().await.unwrap();
    let port = server.local_addr().unwrap().port();

    let server = Arc::new(server);
    let s = server.clone();
    let server_handle = tokio::spawn(async move { s.serve_forever().await });

    let (client, axon) = connect_client(port).await;

    let req = QuicRequest::from_typed("double", &DoubleReq { value: 21 }).unwrap();
    let resp = client.query_axon(axon, req).await.unwrap();
    assert!(resp.success);
    let result: DoubleResp = resp.deserialize_data().unwrap();
    assert_eq!(result.doubled, 42);

    client.close_all_connections().await.unwrap();
    let _ = server.stop().await;
    let _ = server_handle.await;
}

// --- Nonce Management ---

#[tokio::test]
async fn nonce_cleanup_removes_expired() {
    let mut config = LightningServerConfig::default();
    config.max_signature_age_secs = 1;
    config.nonce_cleanup_interval_secs = 1;
    let mut server =
        LightningServer::with_config(miner_hotkey(), "127.0.0.1".into(), 0, config).unwrap();
    server.set_miner_keypair(MINER_SEED);
    server.start().await.unwrap();
    let port = server.local_addr().unwrap().port();

    let server = Arc::new(server);
    let s = server.clone();
    let server_handle = tokio::spawn(async move { s.serve_forever().await });

    let (client, _axon) = connect_client(port).await;

    let populated = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if server.get_active_nonce_count().await > 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        populated.is_ok(),
        "handshake should record at least one nonce"
    );

    let drained = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if server.get_active_nonce_count().await == 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    assert!(
        drained.is_ok(),
        "expired nonces should be cleaned up by background task"
    );

    client.close_all_connections().await.unwrap();
    let _ = server.stop().await;
    let _ = server_handle.await;
}

// --- Error Sanitization ---

#[tokio::test]
async fn handler_error_does_not_leak_internal_details() {
    let env = setup_with_handler("fail", ErrorHandler).await;

    let resp = env
        .client
        .query_axon(env.axon_info.clone(), build_request("fail"))
        .await
        .unwrap();
    assert!(!resp.success);
    let error_msg = resp.error.unwrap();
    assert_eq!(error_msg, "request processing failed");
    assert!(
        !error_msg.contains("deliberate error"),
        "handler error details must not appear in wire response"
    );

    env.shutdown().await;
}

#[tokio::test]
async fn unregistered_synapse_type_uses_generic_error() {
    let env = setup_with_handler("echo", EchoHandler).await;

    let resp = env
        .client
        .query_axon(env.axon_info.clone(), build_request("nonexistent"))
        .await
        .unwrap();
    assert!(!resp.success);
    let error_msg = resp.error.unwrap();
    assert_eq!(error_msg, "unrecognized synapse type");
    assert!(
        !error_msg.contains("nonexistent"),
        "synapse type name must not appear in wire response"
    );

    env.shutdown().await;
}

#[tokio::test]
async fn streaming_error_does_not_leak_handler_details() {
    let env = setup_with_streaming_handler("errstream", ErrorStreamHandler).await;

    let mut stream = env
        .client
        .query_axon_stream(env.axon_info.clone(), build_request("errstream"))
        .await
        .unwrap();

    let mut found_error = false;
    let mut error_msg = String::new();
    for _ in 0..100 {
        match stream.next_chunk().await {
            Ok(Some(_)) => continue,
            Ok(None) => break,
            Err(e) => {
                error_msg = e.to_string();
                found_error = true;
                break;
            }
        }
    }
    assert!(found_error, "should receive error from streaming handler");
    assert!(
        error_msg.contains("stream processing failed"),
        "wire error should use generic message, got: {}",
        error_msg
    );
    assert!(
        !error_msg.contains("stream error mid-way"),
        "handler error details must not appear in wire response"
    );

    env.shutdown().await;
}

// --- Rate Limiting ---

#[tokio::test]
async fn handshake_rate_limiting_rejects_excess_attempts() {
    let mut config = LightningServerConfig::default();
    config.max_handshake_attempts_per_minute = 2;
    config.require_validator_permit = false;
    let mut server =
        LightningServer::with_config(miner_hotkey(), "127.0.0.1".into(), 0, config).unwrap();
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

    let (mut client, axon) = connect_client(port).await;

    let stats = client.get_connection_stats().await.unwrap();
    assert_eq!(stats.get("total_connections").unwrap(), "1");

    client.close_all_connections().await.unwrap();
    client
        .initialize_connections(vec![axon.clone()])
        .await
        .unwrap();
    let stats = client.get_connection_stats().await.unwrap();
    assert_eq!(stats.get("total_connections").unwrap(), "1");

    client.close_all_connections().await.unwrap();
    client
        .initialize_connections(vec![axon.clone()])
        .await
        .unwrap();
    let stats = client.get_connection_stats().await.unwrap();
    assert_eq!(
        stats.get("total_connections").unwrap(),
        "0",
        "third handshake attempt should be rejected by rate limiter"
    );

    client.close_all_connections().await.unwrap();
    let _ = server.stop().await;
    let _ = server_handle.await;
}

// --- Handshake Timeout ---

#[tokio::test]
async fn handshake_timeout_rejects_slow_signing() {
    let real_signer = Sr25519Signer::from_seed(MINER_SEED);
    // std::thread::sleep is intentional: the signer runs via spawn_blocking
    // on the blocking thread pool, so tokio::time::sleep would not work.
    let slow_signer = CallbackSigner::new(move |msg: &[u8]| {
        let sig = real_signer.sign(msg);
        std::thread::sleep(Duration::from_millis(1100));
        sig
    });

    let mut config = LightningServerConfig::default();
    config.handshake_timeout_secs = 1;
    config.require_validator_permit = false;
    let mut server =
        LightningServer::with_config(miner_hotkey(), "127.0.0.1".into(), 0, config).unwrap();
    server.set_miner_signer(Box::new(slow_signer));
    server.start().await.unwrap();
    let port = server.local_addr().unwrap().port();

    let server = Arc::new(server);
    let s = server.clone();
    let server_handle = tokio::spawn(async move { s.serve_forever().await });

    let (client, _axon) = connect_client(port).await;
    let stats = client.get_connection_stats().await.unwrap();
    assert_eq!(
        stats.get("total_connections").unwrap(),
        "0",
        "handshake should be rejected when signing exceeds timeout"
    );

    client.close_all_connections().await.unwrap();
    let _ = server.stop().await;
    let _ = server_handle.await;
}

// --- Validator Permit Checking ---

struct StaticPermitResolver {
    permitted: HashSet<String>,
}

impl ValidatorPermitResolver for StaticPermitResolver {
    fn resolve_permitted_validators(&self) -> Result<HashSet<String>> {
        Ok(self.permitted.clone())
    }
}

struct DynamicPermitResolver {
    permitted: Arc<std::sync::RwLock<HashSet<String>>>,
}

impl ValidatorPermitResolver for DynamicPermitResolver {
    fn resolve_permitted_validators(&self) -> Result<HashSet<String>> {
        Ok(self.permitted.read().unwrap().clone())
    }
}

struct FailingPermitResolver;

impl ValidatorPermitResolver for FailingPermitResolver {
    fn resolve_permitted_validators(&self) -> Result<HashSet<String>> {
        Err(LightningError::Handler("chain unreachable".into()))
    }
}

#[tokio::test]
async fn validator_without_permit_rejected() {
    let mut config = LightningServerConfig::default();
    config.require_validator_permit = true;
    config.validator_permit_refresh_secs = 3600;
    let mut server =
        LightningServer::with_config(miner_hotkey(), "127.0.0.1".into(), 0, config).unwrap();
    server.set_miner_keypair(MINER_SEED);
    server.set_validator_permit_resolver(Box::new(StaticPermitResolver {
        permitted: HashSet::new(),
    }));
    server.start().await.unwrap();
    let port = server.local_addr().unwrap().port();

    let server = Arc::new(server);
    let s = server.clone();
    let server_handle = tokio::spawn(async move { s.serve_forever().await });

    assert_eq!(
        server.get_permitted_validator_count().await,
        0,
        "permit cache should be empty when resolver returns no validators"
    );

    let (client, _axon) = connect_client(port).await;
    let stats = client.get_connection_stats().await.unwrap();
    assert_eq!(
        stats.get("total_connections").unwrap(),
        "0",
        "validator without permit should be rejected"
    );

    client.close_all_connections().await.unwrap();
    let _ = server.stop().await;
    let _ = server_handle.await;
}

#[tokio::test]
async fn validator_with_permit_accepted() {
    let mut permitted = HashSet::new();
    permitted.insert(validator_hotkey());

    let mut config = LightningServerConfig::default();
    config.require_validator_permit = true;
    config.validator_permit_refresh_secs = 3600;
    let mut server =
        LightningServer::with_config(miner_hotkey(), "127.0.0.1".into(), 0, config).unwrap();
    server.set_miner_keypair(MINER_SEED);
    server.set_validator_permit_resolver(Box::new(StaticPermitResolver { permitted }));
    server.start().await.unwrap();
    let port = server.local_addr().unwrap().port();

    let server = Arc::new(server);
    let s = server.clone();
    let server_handle = tokio::spawn(async move { s.serve_forever().await });

    let srv = server.clone();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if srv.get_permitted_validator_count().await > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("permit cache should be populated within 5s");

    let (client, _axon) = connect_client(port).await;
    let stats = client.get_connection_stats().await.unwrap();
    assert_eq!(
        stats.get("total_connections").unwrap(),
        "1",
        "validator with permit should be accepted"
    );

    client.close_all_connections().await.unwrap();
    let _ = server.stop().await;
    let _ = server_handle.await;
}

#[tokio::test]
async fn permit_check_bypassed_when_disabled() {
    let mut config = LightningServerConfig::default();
    config.require_validator_permit = false;
    let env = setup_with_config(config).await;

    let stats = env.client.get_connection_stats().await.unwrap();
    assert_eq!(
        stats.get("total_connections").unwrap(),
        "1",
        "handshake should succeed when require_validator_permit is false"
    );

    env.shutdown().await;
}

#[tokio::test]
async fn no_resolver_configured_rejects_when_required() {
    let mut config = LightningServerConfig::default();
    config.require_validator_permit = true;
    let mut server =
        LightningServer::with_config(miner_hotkey(), "127.0.0.1".into(), 0, config).unwrap();
    server.set_miner_keypair(MINER_SEED);
    server.start().await.unwrap();
    let port = server.local_addr().unwrap().port();

    let server = Arc::new(server);
    let s = server.clone();
    let server_handle = tokio::spawn(async move { s.serve_forever().await });

    let (client, _axon) = connect_client(port).await;
    let stats = client.get_connection_stats().await.unwrap();
    assert_eq!(
        stats.get("total_connections").unwrap(),
        "0",
        "handshake should be rejected when permit required but no resolver configured (fail closed)"
    );

    client.close_all_connections().await.unwrap();
    let _ = server.stop().await;
    let _ = server_handle.await;
}

#[tokio::test]
async fn resolver_error_preserves_server_availability() {
    let mut config = LightningServerConfig::default();
    config.require_validator_permit = true;
    config.validator_permit_refresh_secs = 3600;
    let mut server =
        LightningServer::with_config(miner_hotkey(), "127.0.0.1".into(), 0, config).unwrap();
    server.set_miner_keypair(MINER_SEED);
    server.set_validator_permit_resolver(Box::new(FailingPermitResolver));
    server.start().await.unwrap();
    let port = server.local_addr().unwrap().port();

    let server = Arc::new(server);
    let s = server.clone();
    let server_handle = tokio::spawn(async move { s.serve_forever().await });

    let (client, _axon) = connect_client(port).await;
    let stats = client.get_connection_stats().await.unwrap();
    assert_eq!(
        stats.get("total_connections").unwrap(),
        "0",
        "validator should be rejected when resolver fails (empty cache)"
    );
    assert_eq!(
        server.get_permitted_validator_count().await,
        0,
        "permit cache should remain empty after resolver error"
    );

    client.close_all_connections().await.unwrap();
    let _ = server.stop().await;
    let _ = server_handle.await;
}

#[tokio::test]
async fn permit_cache_refresh_adds_validator() {
    let permitted = Arc::new(std::sync::RwLock::new(HashSet::new()));
    let resolver = DynamicPermitResolver {
        permitted: permitted.clone(),
    };

    let mut config = LightningServerConfig::default();
    config.require_validator_permit = true;
    config.validator_permit_refresh_secs = 1;
    let mut server =
        LightningServer::with_config(miner_hotkey(), "127.0.0.1".into(), 0, config).unwrap();
    server.set_miner_keypair(MINER_SEED);
    server.set_validator_permit_resolver(Box::new(resolver));
    server.start().await.unwrap();
    let port = server.local_addr().unwrap().port();

    let server = Arc::new(server);
    let s = server.clone();
    let server_handle = tokio::spawn(async move { s.serve_forever().await });

    assert_eq!(
        server.get_permitted_validator_count().await,
        0,
        "initial resolution should yield empty set"
    );

    let (client1, _axon) = connect_client(port).await;
    let stats = client1.get_connection_stats().await.unwrap();
    assert_eq!(
        stats.get("total_connections").unwrap(),
        "0",
        "validator should be rejected before being added to permit set"
    );
    client1.close_all_connections().await.unwrap();

    permitted.write().unwrap().insert(validator_hotkey());

    let srv = server.clone();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if srv.get_permitted_validator_count().await > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("permit cache should refresh within 5s");

    let (client2, _axon) = connect_client(port).await;
    let stats = client2.get_connection_stats().await.unwrap();
    assert_eq!(
        stats.get("total_connections").unwrap(),
        "1",
        "validator should be accepted after being added to permit set via refresh"
    );

    client2.close_all_connections().await.unwrap();
    let _ = server.stop().await;
    let _ = server_handle.await;
}

#[tokio::test]
async fn permit_cache_refresh_removes_validator() {
    let mut initial = HashSet::new();
    initial.insert(validator_hotkey());
    let permitted = Arc::new(std::sync::RwLock::new(initial));
    let resolver = DynamicPermitResolver {
        permitted: permitted.clone(),
    };

    let mut config = LightningServerConfig::default();
    config.require_validator_permit = true;
    config.validator_permit_refresh_secs = 1;
    let mut server =
        LightningServer::with_config(miner_hotkey(), "127.0.0.1".into(), 0, config).unwrap();
    server.set_miner_keypair(MINER_SEED);
    server.set_validator_permit_resolver(Box::new(resolver));
    server.start().await.unwrap();
    let port = server.local_addr().unwrap().port();

    let server = Arc::new(server);
    let s = server.clone();
    let server_handle = tokio::spawn(async move { s.serve_forever().await });

    let srv = server.clone();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if srv.get_permitted_validator_count().await > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("permit cache should be populated after initial resolution");

    let (client1, _axon) = connect_client(port).await;
    let stats = client1.get_connection_stats().await.unwrap();
    assert_eq!(
        stats.get("total_connections").unwrap(),
        "1",
        "validator should be accepted while in permit set"
    );
    client1.close_all_connections().await.unwrap();

    permitted.write().unwrap().clear();

    let srv = server.clone();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if srv.get_permitted_validator_count().await == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("permit cache should be cleared after refresh");

    let (client2, _axon) = connect_client(port).await;
    let stats = client2.get_connection_stats().await.unwrap();
    assert_eq!(
        stats.get("total_connections").unwrap(),
        "0",
        "validator should be rejected after being removed from permit set"
    );

    client2.close_all_connections().await.unwrap();
    let _ = server.stop().await;
    let _ = server_handle.await;
}

#[tokio::test]
async fn large_permit_set_handles_correctly() {
    let mut permitted = HashSet::new();
    for i in 0..10_000u64 {
        let seed = {
            let bytes = i.to_le_bytes();
            let mut s = [0u8; 32];
            s[..8].copy_from_slice(&bytes);
            s[8] = 0xff;
            s
        };
        let hotkey = sr25519::Pair::from_seed(&seed).public().to_ss58check();
        permitted.insert(hotkey);
    }
    permitted.insert(validator_hotkey());

    let mut config = LightningServerConfig::default();
    config.require_validator_permit = true;
    config.validator_permit_refresh_secs = 3600;
    let mut server =
        LightningServer::with_config(miner_hotkey(), "127.0.0.1".into(), 0, config).unwrap();
    server.set_miner_keypair(MINER_SEED);
    server.set_validator_permit_resolver(Box::new(StaticPermitResolver { permitted }));
    server.start().await.unwrap();
    let port = server.local_addr().unwrap().port();

    let server = Arc::new(server);
    let s = server.clone();
    let server_handle = tokio::spawn(async move { s.serve_forever().await });

    let srv = server.clone();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if srv.get_permitted_validator_count().await > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("large permit set should load within 10s");

    assert_eq!(server.get_permitted_validator_count().await, 10_001);

    let (client, _axon) = connect_client(port).await;
    let stats = client.get_connection_stats().await.unwrap();
    assert_eq!(
        stats.get("total_connections").unwrap(),
        "1",
        "validator should be found in large permit set"
    );

    client.close_all_connections().await.unwrap();
    let _ = server.stop().await;
    let _ = server_handle.await;
}

// --- Abuse Resilience ---

#[tokio::test]
async fn server_processes_queries_during_rate_limiting() {
    let mut config = LightningServerConfig::default();
    config.max_handshake_attempts_per_minute = 3;
    config.require_validator_permit = false;
    let mut server =
        LightningServer::with_config(miner_hotkey(), "127.0.0.1".into(), 0, config).unwrap();
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

    let (mut client, axon) = connect_client(port).await;

    let resp = client
        .query_axon(axon.clone(), build_request_with_data("echo", "k", "v"))
        .await
        .unwrap();
    assert!(resp.success, "query should succeed before rate limit");

    client.close_all_connections().await.unwrap();
    client
        .initialize_connections(vec![axon.clone()])
        .await
        .unwrap();
    client.close_all_connections().await.unwrap();
    client
        .initialize_connections(vec![axon.clone()])
        .await
        .unwrap();
    client.close_all_connections().await.unwrap();
    client
        .initialize_connections(vec![axon.clone()])
        .await
        .unwrap();

    let stats = client.get_connection_stats().await.unwrap();
    assert_eq!(
        stats.get("total_connections").unwrap(),
        "0",
        "fourth handshake should be rate-limited"
    );

    let other_seed = [77u8; 32];
    let other_hotkey = sr25519::Pair::from_seed(&other_seed)
        .public()
        .to_ss58check();
    let mut client2 = LightningClient::new(other_hotkey);
    client2.set_signer(Box::new(Sr25519Signer::from_seed(other_seed)));
    client2.create_endpoint().await.unwrap();
    client2
        .initialize_connections(vec![axon.clone()])
        .await
        .unwrap();

    let resp2 = client2
        .query_axon(
            axon.clone(),
            build_request_with_data("echo", "k", "after-burst"),
        )
        .await;

    match resp2 {
        Ok(r) if r.success => {}
        _ => {
            let stats2 = client2.get_connection_stats().await.unwrap();
            assert_eq!(
                stats2.get("total_connections").unwrap(),
                "0",
                "all clients share 127.0.0.1 so rate limit applies globally in test"
            );
        }
    }

    client.close_all_connections().await.unwrap();
    client2.close_all_connections().await.unwrap();
    let _ = server.stop().await;
    let _ = server_handle.await;
}

#[tokio::test]
async fn connection_churn_preserves_server_health() {
    let mut env = setup_with_handler("echo", EchoHandler).await;

    for _ in 0..20 {
        env.client.close_all_connections().await.unwrap();
        env.client
            .initialize_connections(vec![env.axon_info.clone()])
            .await
            .unwrap();
    }

    let resp = env
        .client
        .query_axon(
            env.axon_info.clone(),
            build_request_with_data("echo", "after", "churn"),
        )
        .await;
    match resp {
        Ok(r) => assert!(r.success, "query should succeed after connection churn"),
        Err(_) => {
            let (fresh_client, fresh_axon) = connect_client(env.axon_info.port).await;
            let resp = fresh_client
                .query_axon(fresh_axon, build_request_with_data("echo", "k", "v"))
                .await
                .unwrap();
            assert!(
                resp.success,
                "fresh client should succeed even if churned client is rate-limited"
            );
            fresh_client.close_all_connections().await.unwrap();
        }
    }

    env.shutdown().await;
}

#[tokio::test]
async fn permit_rejected_does_not_degrade_permitted_client() {
    let mut permitted = HashSet::new();
    permitted.insert(validator_hotkey());

    let mut config = LightningServerConfig::default();
    config.require_validator_permit = true;
    config.validator_permit_refresh_secs = 3600;
    let mut server =
        LightningServer::with_config(miner_hotkey(), "127.0.0.1".into(), 0, config).unwrap();
    server.set_miner_keypair(MINER_SEED);
    server
        .register_synapse_handler("echo".to_string(), Arc::new(EchoHandler))
        .await
        .unwrap();
    server.set_validator_permit_resolver(Box::new(StaticPermitResolver { permitted }));
    server.start().await.unwrap();
    let port = server.local_addr().unwrap().port();

    let server = Arc::new(server);
    let s = server.clone();
    let server_handle = tokio::spawn(async move { s.serve_forever().await });

    let srv = server.clone();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if srv.get_permitted_validator_count().await > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("permit cache should populate");

    let (good_client, axon) = connect_client(port).await;
    let stats = good_client.get_connection_stats().await.unwrap();
    assert_eq!(stats.get("total_connections").unwrap(), "1");

    for i in 0..5u8 {
        let bad_seed = [100 + i; 32];
        let bad_hotkey = sr25519::Pair::from_seed(&bad_seed).public().to_ss58check();
        let mut bad_client = LightningClient::new(bad_hotkey);
        bad_client.set_signer(Box::new(Sr25519Signer::from_seed(bad_seed)));
        bad_client.create_endpoint().await.unwrap();
        bad_client
            .initialize_connections(vec![axon.clone()])
            .await
            .unwrap();
        let stats = bad_client.get_connection_stats().await.unwrap();
        assert_eq!(
            stats.get("total_connections").unwrap(),
            "0",
            "unpermitted client {} should be rejected",
            i
        );
        bad_client.close_all_connections().await.unwrap();
    }

    let resp = good_client
        .query_axon(
            axon.clone(),
            build_request_with_data("echo", "still", "working"),
        )
        .await
        .unwrap();
    assert!(
        resp.success,
        "permitted client must remain functional after unpermitted rejections"
    );
    assert_eq!(resp.data.get("still").unwrap().as_str().unwrap(), "working");

    good_client.close_all_connections().await.unwrap();
    let _ = server.stop().await;
    let _ = server_handle.await;
}

// --- Multi-Hotkey Per Address ---

#[tokio::test]
async fn multiple_hotkeys_same_address_authenticates_matching_only() {
    let env = setup_with_handler("echo", EchoHandler).await;
    let port = env.axon_info.port;

    let fake_hotkey = sr25519::Pair::from_seed(&[99u8; 32])
        .public()
        .to_ss58check();

    let mut client = LightningClient::new(validator_hotkey());
    client.set_signer(Box::new(Sr25519Signer::from_seed(VALIDATOR_SEED)));
    client.create_endpoint().await.unwrap();
    client
        .initialize_connections(vec![
            QuicAxonInfo {
                hotkey: miner_hotkey(),
                ip: "127.0.0.1".into(),
                port,
                protocol: 4,
                placeholder1: 0,
                placeholder2: 0,
            },
            QuicAxonInfo {
                hotkey: fake_hotkey,
                ip: "127.0.0.1".into(),
                port,
                protocol: 4,
                placeholder1: 0,
                placeholder2: 0,
            },
        ])
        .await
        .unwrap();

    let stats = client.get_connection_stats().await.unwrap();
    assert_eq!(
        stats.get("total_connections").unwrap(),
        "1",
        "one QUIC connection for the shared address"
    );
    assert_eq!(
        stats.get("active_miners").unwrap(),
        "1",
        "only the real miner hotkey should be authenticated"
    );

    let resp = client
        .query_axon(env.axon_info.clone(), build_request("echo"))
        .await
        .unwrap();
    assert!(resp.success);

    client.close_all_connections().await.unwrap();
    env.shutdown().await;
}

#[tokio::test]
async fn fake_hotkey_only_at_address_no_connection_retained() {
    let env = setup_with_handler("echo", EchoHandler).await;
    let port = env.axon_info.port;

    let fake_hotkey = sr25519::Pair::from_seed(&[99u8; 32])
        .public()
        .to_ss58check();

    let mut client = LightningClient::new(validator_hotkey());
    client.set_signer(Box::new(Sr25519Signer::from_seed(VALIDATOR_SEED)));
    client.create_endpoint().await.unwrap();
    client
        .initialize_connections(vec![QuicAxonInfo {
            hotkey: fake_hotkey,
            ip: "127.0.0.1".into(),
            port,
            protocol: 4,
            placeholder1: 0,
            placeholder2: 0,
        }])
        .await
        .unwrap();

    let stats = client.get_connection_stats().await.unwrap();
    assert_eq!(
        stats.get("total_connections").unwrap(),
        "0",
        "connection dropped when no hotkeys authenticate"
    );
    assert_eq!(stats.get("active_miners").unwrap(), "0");

    client.close_all_connections().await.unwrap();
    env.shutdown().await;
}

#[tokio::test]
async fn update_registry_removes_last_hotkey_closes_connection() {
    let env = setup_with_handler("echo", EchoHandler).await;

    let stats = env.client.get_connection_stats().await.unwrap();
    assert_eq!(stats.get("total_connections").unwrap(), "1");

    env.client.update_miner_registry(vec![]).await.unwrap();

    let stats = env.client.get_connection_stats().await.unwrap();
    assert_eq!(
        stats.get("total_connections").unwrap(),
        "0",
        "connection must be closed when all hotkeys are deregistered"
    );

    env.shutdown().await;
}

#[tokio::test]
async fn update_registry_adds_fake_hotkey_at_existing_address() {
    let env = setup_with_handler("echo", EchoHandler).await;
    let port = env.axon_info.port;

    let fake_hotkey = sr25519::Pair::from_seed(&[99u8; 32])
        .public()
        .to_ss58check();

    env.client
        .update_miner_registry(vec![
            env.axon_info.clone(),
            QuicAxonInfo {
                hotkey: fake_hotkey.clone(),
                ip: "127.0.0.1".into(),
                port,
                protocol: 4,
                placeholder1: 0,
                placeholder2: 0,
            },
        ])
        .await
        .unwrap();

    let stats = env.client.get_connection_stats().await.unwrap();
    assert_eq!(
        stats.get("total_connections").unwrap(),
        "1",
        "no new connection needed for same address"
    );
    assert_eq!(
        stats.get("active_miners").unwrap(),
        "1",
        "fake hotkey should not be registered"
    );

    let resp = env
        .client
        .query_axon(env.axon_info.clone(), build_request("echo"))
        .await
        .unwrap();
    assert!(resp.success);

    env.shutdown().await;
}

#[tokio::test]
async fn max_connections_counts_addresses_not_hotkeys() {
    let env = setup_with_handler("echo", EchoHandler).await;
    let port = env.axon_info.port;

    let fake1 = sr25519::Pair::from_seed(&[90u8; 32])
        .public()
        .to_ss58check();
    let fake2 = sr25519::Pair::from_seed(&[91u8; 32])
        .public()
        .to_ss58check();

    let mut client =
        LightningClient::with_config(validator_hotkey(), btlightning::LightningClientConfig {
            max_connections: 1,
            ..Default::default()
        });
    client.set_signer(Box::new(Sr25519Signer::from_seed(VALIDATOR_SEED)));
    client.create_endpoint().await.unwrap();

    client
        .initialize_connections(vec![
            QuicAxonInfo {
                hotkey: miner_hotkey(),
                ip: "127.0.0.1".into(),
                port,
                protocol: 4,
                placeholder1: 0,
                placeholder2: 0,
            },
            QuicAxonInfo {
                hotkey: fake1,
                ip: "127.0.0.1".into(),
                port,
                protocol: 4,
                placeholder1: 0,
                placeholder2: 0,
            },
            QuicAxonInfo {
                hotkey: fake2,
                ip: "127.0.0.1".into(),
                port,
                protocol: 4,
                placeholder1: 0,
                placeholder2: 0,
            },
        ])
        .await
        .unwrap();

    let stats = client.get_connection_stats().await.unwrap();
    assert_eq!(
        stats.get("total_connections").unwrap(),
        "1",
        "3 hotkeys at one address = 1 connection"
    );
    assert_eq!(
        stats.get("active_miners").unwrap(),
        "1",
        "only the real hotkey authenticates"
    );

    let resp = client
        .query_axon(
            QuicAxonInfo {
                hotkey: miner_hotkey(),
                ip: "127.0.0.1".into(),
                port,
                protocol: 4,
                placeholder1: 0,
                placeholder2: 0,
            },
            build_request("echo"),
        )
        .await
        .unwrap();
    assert!(resp.success);

    client.close_all_connections().await.unwrap();
    env.shutdown().await;
}
