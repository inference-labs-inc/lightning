use btlightning::{
    LightningClient, LightningServer, LightningServerConfig, QuicAxonInfo, QuicRequest, Result,
    Sr25519Signer, SynapseHandler, SynapsePacket,
};
use serde::Serialize;
use sp_core::{crypto::Ss58Codec, sr25519, Pair};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

const MINER_SEED: [u8; 32] = [1u8; 32];
const VALIDATOR_SEED: [u8; 32] = [2u8; 32];
const LATENCY_ITERATIONS: usize = 1000;
const SETUP_ITERATIONS: usize = 100;
const CONCURRENCY: usize = 32;
const THROUGHPUT_TOTAL: usize = 10000;

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

fn payload(size: usize) -> HashMap<String, rmpv::Value> {
    let mut data = HashMap::new();
    data.insert(
        "payload".to_string(),
        rmpv::Value::Binary(vec![0x42u8; size]),
    );
    data
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = (p / 100.0 * (sorted.len() - 1) as f64).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

#[derive(Serialize)]
struct Percentiles {
    p50: f64,
    p95: f64,
    p99: f64,
}

#[derive(Serialize)]
struct BenchResults {
    connection_setup_ms: Percentiles,
    latency_ms: HashMap<String, Percentiles>,
    throughput_rps: HashMap<String, f64>,
    wire_bytes: HashMap<String, usize>,
}

async fn start_server() -> (
    Arc<LightningServer>,
    tokio::task::JoinHandle<Result<()>>,
    u16,
) {
    let config = LightningServerConfig {
        require_validator_permit: false,
        ..Default::default()
    };
    let mut server =
        LightningServer::with_config(miner_hotkey(), "127.0.0.1".into(), 0, config).unwrap();
    server.set_miner_keypair(MINER_SEED);
    server
        .register_synapse_handler("echo".into(), Arc::new(EchoHandler))
        .await
        .unwrap();
    server.start().await.unwrap();
    let port = server.local_addr().unwrap().port();
    let server = Arc::new(server);
    let s = server.clone();
    let handle = tokio::spawn(async move { s.serve_forever().await });
    (server, handle, port)
}

async fn make_client(port: u16) -> (LightningClient, QuicAxonInfo) {
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

fn request(data: HashMap<String, rmpv::Value>) -> QuicRequest {
    QuicRequest {
        synapse_type: "echo".to_string(),
        data,
    }
}

fn wire_size(data: &HashMap<String, rmpv::Value>) -> usize {
    let packet = SynapsePacket {
        synapse_type: "echo".to_string(),
        data: data.clone(),
        timestamp: 1700000000,
    };
    let encoded = rmp_serde::to_vec(&packet).unwrap();
    5 + encoded.len()
}

const PAYLOAD_SIZES: &[(&str, usize)] = &[
    ("256B", 256),
    ("1KB", 1024),
    ("10KB", 10240),
    ("100KB", 102400),
    ("1MB", 1048576),
];

#[tokio::main]
async fn main() {
    eprintln!("lightning benchmark");

    eprintln!("  measuring connection setup ({SETUP_ITERATIONS} iterations)...");
    let mut setup_times = Vec::with_capacity(SETUP_ITERATIONS);
    let warmup_data = payload(64);
    for i in 0..SETUP_ITERATIONS {
        let (server, handle, port) = start_server().await;
        let start = Instant::now();
        let (client, axon) = make_client(port).await;
        let resp = client
            .query_axon(axon, request(warmup_data.clone()))
            .await
            .unwrap();
        let elapsed = start.elapsed().as_secs_f64() * 1000.0;
        assert!(resp.success);
        setup_times.push(elapsed);
        let _ = client.close_all_connections().await;
        let _ = server.stop().await;
        let _ = handle.await;
        if (i + 1) % 20 == 0 {
            eprintln!("    {}/{SETUP_ITERATIONS}", i + 1);
        }
    }
    setup_times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let connection_setup_ms = Percentiles {
        p50: percentile(&setup_times, 50.0),
        p95: percentile(&setup_times, 95.0),
        p99: percentile(&setup_times, 99.0),
    };

    let (server, handle, port) = start_server().await;
    let (client, axon) = make_client(port).await;
    let client = Arc::new(client);

    let mut latency_ms = HashMap::new();
    let mut throughput_rps = HashMap::new();
    let mut wire_bytes_map = HashMap::new();

    for (label, size) in PAYLOAD_SIZES {
        let data = payload(*size);

        wire_bytes_map.insert(label.to_string(), wire_size(&data));

        eprintln!("  measuring latency {label} ({LATENCY_ITERATIONS} iterations)...");
        let mut times = Vec::with_capacity(LATENCY_ITERATIONS);
        for _ in 0..LATENCY_ITERATIONS {
            let start = Instant::now();
            let resp = client
                .query_axon(axon.clone(), request(data.clone()))
                .await
                .unwrap();
            let elapsed = start.elapsed().as_secs_f64() * 1000.0;
            assert!(resp.success);
            times.push(elapsed);
        }
        times.sort_by(|a, b| a.partial_cmp(b).unwrap());
        latency_ms.insert(
            label.to_string(),
            Percentiles {
                p50: percentile(&times, 50.0),
                p95: percentile(&times, 95.0),
                p99: percentile(&times, 99.0),
            },
        );

        eprintln!("  measuring throughput {label} ({THROUGHPUT_TOTAL} requests, {CONCURRENCY} concurrent)...");
        let start = Instant::now();
        let mut handles = Vec::new();
        let sem = Arc::new(tokio::sync::Semaphore::new(CONCURRENCY));
        for _ in 0..THROUGHPUT_TOTAL {
            let permit = sem.clone().acquire_owned().await.unwrap();
            let c = Arc::clone(&client);
            let a = axon.clone();
            let d = data.clone();
            handles.push(tokio::spawn(async move {
                let resp = c.query_axon(a, request(d)).await.unwrap();
                assert!(resp.success);
                drop(permit);
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        let elapsed = start.elapsed().as_secs_f64();
        throughput_rps.insert(label.to_string(), THROUGHPUT_TOTAL as f64 / elapsed);
    }

    let _ = client.close_all_connections().await;
    let _ = server.stop().await;
    let _ = handle.await;

    let results = BenchResults {
        connection_setup_ms,
        latency_ms,
        throughput_rps,
        wire_bytes: wire_bytes_map,
    };

    println!("{}", serde_json::to_string_pretty(&results).unwrap());
}
