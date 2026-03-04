#![cfg(feature = "localnet-tests")]

use btlightning::{
    typed_async_handler, LightningClient, LightningServer, LightningServerConfig, Metagraph,
    QuicAxonInfo, QuicRequest, Sr25519Signer,
};
use sp_core::{crypto::Ss58Codec, sr25519, Pair};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use subxt::dynamic::Value;
use subxt::{OnlineClient, PolkadotConfig};

const LOCALNET_ENDPOINT: &str = "ws://127.0.0.1:9944";

const MINER_SEED: [u8; 32] = [10u8; 32];
const VALIDATOR_SEED: [u8; 32] = [20u8; 32];

fn miner_hotkey() -> (sr25519::Pair, String, [u8; 32]) {
    let pair = sr25519::Pair::from_seed(&MINER_SEED);
    let ss58 = pair.public().to_ss58check();
    let bytes = pair.public().0;
    (pair, ss58, bytes)
}

fn validator_hotkey() -> (sr25519::Pair, String, [u8; 32]) {
    let pair = sr25519::Pair::from_seed(&VALIDATOR_SEED);
    let ss58 = pair.public().to_ss58check();
    let bytes = pair.public().0;
    (pair, ss58, bytes)
}

fn ip_to_int(a: u8, b: u8, c: u8, d: u8) -> u128 {
    ((a as u128) << 24) | ((b as u128) << 16) | ((c as u128) << 8) | (d as u128)
}

fn threshold_ms(env_var: &str, default: u64) -> Duration {
    Duration::from_millis(
        std::env::var(env_var)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default),
    )
}

async fn submit_extrinsic(
    api: &OnlineClient<PolkadotConfig>,
    call: subxt::tx::DynamicPayload,
    signer: &subxt_signer::sr25519::Keypair,
    label: &str,
) {
    let progress = tokio::time::timeout(
        Duration::from_secs(30),
        api.tx().sign_and_submit_then_watch_default(&call, signer),
    )
    .await
    .unwrap_or_else(|_| panic!("{label} submission timed out after 30s"))
    .unwrap_or_else(|e| panic!("{label} submission failed: {e}"));

    tokio::time::timeout(
        Duration::from_secs(60),
        progress.wait_for_finalized_success(),
    )
    .await
    .unwrap_or_else(|_| panic!("{label} finalization timed out after 60s"))
    .unwrap_or_else(|e| panic!("{label} finalization failed: {e}"));
}

async fn query_total_networks(api: &OnlineClient<PolkadotConfig>) -> u16 {
    let query = subxt::dynamic::storage("SubtensorModule", "TotalNetworks", vec![]);
    let storage = api.storage().at_latest().await.unwrap();
    storage
        .fetch(&query)
        .await
        .unwrap()
        .unwrap()
        .to_value()
        .unwrap()
        .as_u128()
        .and_then(|v| u16::try_from(v).ok())
        .expect("TotalNetworks exceeds u16::MAX")
}

#[tokio::test]
#[ignore]
async fn localnet_full_integration() {
    let api = OnlineClient::<PolkadotConfig>::from_url(LOCALNET_ENDPOINT)
        .await
        .expect("subtensor localnet must be reachable at ws://127.0.0.1:9944");

    let alice = subxt_signer::sr25519::dev::alice();
    let alice_pair = sr25519::Pair::from_string("//Alice", None).unwrap();
    let alice_hotkey_bytes = alice_pair.public().0;

    let (_miner_pair, miner_ss58, miner_bytes) = miner_hotkey();
    let (_validator_pair, validator_ss58, validator_bytes) = validator_hotkey();

    // --- Phase A: Register subnet ---

    let register_network = subxt::dynamic::tx(
        "SubtensorModule",
        "register_network",
        vec![Value::from_bytes(alice_hotkey_bytes)],
    );
    submit_extrinsic(&api, register_network, &alice, "register_network").await;

    let total_networks = query_total_networks(&api).await;
    assert!(
        total_networks > 0,
        "TotalNetworks is 0 after register_network — extrinsic may have failed silently"
    );
    let netuid = total_networks - 1;
    eprintln!("registered subnet netuid={netuid}");

    // --- Phase A: Register miner and validator neurons ---

    let register_miner = subxt::dynamic::tx(
        "SubtensorModule",
        "burned_register",
        vec![Value::u128(netuid as u128), Value::from_bytes(miner_bytes)],
    );
    submit_extrinsic(&api, register_miner, &alice, "burned_register(miner)").await;
    eprintln!("registered miner hotkey={miner_ss58}");

    let register_validator = subxt::dynamic::tx(
        "SubtensorModule",
        "burned_register",
        vec![
            Value::u128(netuid as u128),
            Value::from_bytes(validator_bytes),
        ],
    );
    submit_extrinsic(
        &api,
        register_validator,
        &alice,
        "burned_register(validator)",
    )
    .await;
    eprintln!("registered validator hotkey={validator_ss58}");

    let miner_signer = subxt_signer::sr25519::Keypair::from_secret_key(MINER_SEED).unwrap();

    let fund_miner = subxt::dynamic::tx(
        "Balances",
        "transfer_allow_death",
        vec![
            Value::unnamed_variant("Id", vec![Value::from_bytes(miner_bytes)]),
            Value::u128(1_000_000_000_000),
        ],
    );
    submit_extrinsic(&api, fund_miner, &alice, "fund_miner").await;
    eprintln!("funded miner hotkey for serve_axon tx fees");

    // --- Phase B: Start miner Lightning server ---

    let request_counter = Arc::new(AtomicU64::new(0));
    let counter_clone = request_counter.clone();

    let mut config = LightningServerConfig::default();
    config.require_validator_permit = false;
    let mut server =
        LightningServer::with_config(miner_ss58.clone(), "127.0.0.1".into(), 0, config).unwrap();
    server.set_miner_keypair(MINER_SEED);
    server
        .register_async_synapse_handler(
            "echo".to_string(),
            typed_async_handler(move |req: HashMap<String, serde_json::Value>| {
                let ctr = counter_clone.clone();
                async move {
                    ctr.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, String>(req)
                }
            }),
        )
        .await
        .unwrap();
    server.start().await.unwrap();
    let actual_port = server.local_addr().unwrap().port();
    eprintln!("miner Lightning server listening on 127.0.0.1:{actual_port}");

    let server = Arc::new(server);
    let s = server.clone();
    let server_handle = tokio::spawn(async move { s.serve_forever().await });

    // --- Phase B: Serve axon on-chain ---

    let serve_axon = subxt::dynamic::tx(
        "SubtensorModule",
        "serve_axon",
        vec![
            Value::u128(netuid as u128),
            Value::u128(0),
            Value::u128(ip_to_int(127, 0, 0, 2)),
            Value::u128(actual_port as u128),
            Value::u128(4),
            Value::u128(4),
            Value::u128(0),
            Value::u128(0),
        ],
    );
    submit_extrinsic(&api, serve_axon, &miner_signer, "serve_axon").await;
    eprintln!("served axon: 127.0.0.2:{actual_port} protocol=4");

    // --- Phase C: Metagraph verification ---

    let mut metagraph = Metagraph::new(netuid);
    metagraph.sync(&api).await.expect("metagraph sync");

    assert!(
        metagraph.n >= 2,
        "subnet should have at least 2 neurons, got {}",
        metagraph.n
    );

    let miner_uid = metagraph
        .get_uid_by_hotkey(&miner_ss58)
        .expect("miner must be in metagraph");
    let miner_neuron = metagraph.get_neuron(miner_uid).unwrap();
    assert_eq!(miner_neuron.axon_ip, "127.0.0.2");
    assert_eq!(miner_neuron.axon_port, actual_port);
    assert_eq!(miner_neuron.axon_protocol, 4);
    eprintln!(
        "metagraph: miner uid={miner_uid} axon={}:{} protocol={}",
        miner_neuron.axon_ip, miner_neuron.axon_port, miner_neuron.axon_protocol
    );

    let validator_uid = metagraph
        .get_uid_by_hotkey(&validator_ss58)
        .expect("validator must be in metagraph");
    eprintln!("metagraph: validator uid={validator_uid}");

    let quic_miners = metagraph.quic_miners();
    assert!(
        quic_miners.is_empty(),
        "loopback IP should be filtered by quic_miners()"
    );

    // --- Phase D: QUIC transport invariants ---

    let axon = QuicAxonInfo {
        hotkey: miner_ss58.clone(),
        ip: "127.0.0.1".into(),
        port: actual_port,
        protocol: 4,
    };

    let mut client = LightningClient::new(validator_ss58.clone());
    client.set_signer(Box::new(Sr25519Signer::from_seed(VALIDATOR_SEED)));

    // D.1: Connection establishment time
    let connect_threshold = threshold_ms("CONNECT_THRESHOLD_MS", 100);
    let connect_start = Instant::now();
    client
        .initialize_connections(vec![axon.clone()])
        .await
        .unwrap();
    let connect_elapsed = connect_start.elapsed();
    eprintln!("connection establishment: {:?}", connect_elapsed);
    assert!(
        connect_elapsed < connect_threshold,
        "QUIC connection to localhost took {connect_elapsed:?}, expected < {connect_threshold:?}",
    );

    // D.2: Single connection per address
    let stats = client.get_connection_stats().await.unwrap();
    let total_conns: usize = stats["total_connections"].parse().unwrap();
    assert_eq!(total_conns, 1, "should have exactly 1 connection");

    // D.3 + D.4: Send 200 requests — validator always gets responses, miner always gets requests
    let mut latencies = Vec::with_capacity(200);
    for i in 0..200u64 {
        let mut data = HashMap::new();
        data.insert("seq".to_string(), serde_json::json!(i));
        let req = QuicRequest::from_typed("echo", &data).unwrap();
        let req_start = Instant::now();
        let resp = client
            .query_axon(axon.clone(), req)
            .await
            .unwrap_or_else(|e| panic!("request {i} failed: {e}"));
        latencies.push(req_start.elapsed());
        assert!(resp.success, "request {i} was not successful");
    }

    assert_eq!(
        request_counter.load(Ordering::SeqCst),
        200,
        "miner must have received all 200 requests"
    );

    // D.5: Latency percentiles
    let p99_threshold = threshold_ms("P99_THRESHOLD_MS", 10);
    latencies.sort();
    let p50 = latencies[latencies.len() * 50 / 100];
    let p95 = latencies[latencies.len() * 95 / 100];
    let p99 = latencies[latencies.len() * 99 / 100];
    eprintln!("latency: p50={p50:?} p95={p95:?} p99={p99:?}");
    assert!(
        p99 < p99_threshold,
        "p99 latency {p99:?} exceeds {p99_threshold:?} on localhost",
    );

    // D.6: Connection still alive after sustained load
    let mut data = HashMap::new();
    data.insert("alive_check".to_string(), serde_json::json!(true));
    let req = QuicRequest::from_typed("echo", &data).unwrap();
    let resp = client.query_axon(axon.clone(), req).await.unwrap();
    assert!(
        resp.success,
        "connection should still be alive after 200 requests"
    );

    // D.7: Connection reuse after idle period
    tokio::time::sleep(Duration::from_secs(5)).await;

    for i in 0..10u64 {
        let mut data = HashMap::new();
        data.insert("burst".to_string(), serde_json::json!(i));
        let req = QuicRequest::from_typed("echo", &data).unwrap();
        let resp = client
            .query_axon(axon.clone(), req)
            .await
            .unwrap_or_else(|e| panic!("burst request {i} failed: {e}"));
        assert!(resp.success);
    }

    let stats = client.get_connection_stats().await.unwrap();
    let total_conns_after: usize = stats["total_connections"].parse().unwrap();
    assert_eq!(
        total_conns_after, 1,
        "connection_count should still be 1 after idle + burst (reuse, no reconnect)"
    );

    // D.8: Total delivery count
    assert_eq!(
        request_counter.load(Ordering::SeqCst),
        211,
        "total miner counter must be 211 (200 + 1 alive + 10 burst)"
    );

    // --- Cleanup ---
    let _ = client.close_all_connections().await;
    let _ = server.stop().await;
    let _ = server_handle.await;
}
