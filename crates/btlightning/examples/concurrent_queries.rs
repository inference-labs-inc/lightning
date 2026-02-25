use btlightning::{
    LightningClient, LightningServer, QuicAxonInfo, QuicRequest, Result, Sr25519Signer,
    SynapseHandler,
};
use sp_core::{crypto::Ss58Codec, sr25519, Pair};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::task::JoinSet;

const VALIDATOR_SEED: [u8; 32] = [2u8; 32];

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

async fn spawn_miner(seed: [u8; 32]) -> anyhow::Result<(Arc<LightningServer>, String, u16)> {
    let hotkey = sr25519::Pair::from_seed(&seed).public().to_ss58check();
    let mut server = LightningServer::new(hotkey.clone(), "127.0.0.1".into(), 0)?;
    server.set_miner_keypair(seed);
    server
        .register_synapse_handler("echo".to_string(), Arc::new(EchoHandler))
        .await?;
    server.start().await?;
    let port = server.local_addr()?.port();
    let server = Arc::new(server);
    let s = server.clone();
    tokio::spawn(async move {
        if let Err(e) = s.serve_forever().await {
            eprintln!("serve_forever exited: {e:?}");
        }
    });
    Ok((server, hotkey, port))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let validator_hotkey = sr25519::Pair::from_seed(&VALIDATOR_SEED)
        .public()
        .to_ss58check();

    let (srv1, hk1, p1) = spawn_miner([10u8; 32]).await?;
    let (srv2, hk2, p2) = spawn_miner([11u8; 32]).await?;
    let (srv3, hk3, p3) = spawn_miner([12u8; 32]).await?;
    println!("3 miners running on ports {p1}, {p2}, {p3}");

    let miners: Vec<QuicAxonInfo> = [(hk1, p1), (hk2, p2), (hk3, p3)]
        .into_iter()
        .map(|(hotkey, port)| QuicAxonInfo {
            hotkey,
            ip: "127.0.0.1".into(),
            port,
            protocol: 4,
        })
        .collect();

    let mut client = LightningClient::new(validator_hotkey);
    client.set_signer(Box::new(Sr25519Signer::from_seed(VALIDATOR_SEED)));
    client.initialize_connections(miners.clone()).await?;

    let client = Arc::new(client);
    let mut tasks = JoinSet::new();
    for miner in &miners {
        let mut data = HashMap::new();
        data.insert(
            "from".to_string(),
            rmpv::Value::String(miner.hotkey[..8].into()),
        );
        let req = QuicRequest {
            synapse_type: "echo".to_string(),
            data,
        };
        let client = Arc::clone(&client);
        let miner = miner.clone();
        tasks.spawn(async move {
            let result = client.query_axon(miner.clone(), req).await;
            (miner.hotkey[..8].to_string(), result)
        });
    }

    while let Some(res) = tasks.join_next().await {
        match res {
            Ok((hotkey_prefix, Ok(resp))) => {
                println!("miner {hotkey_prefix}: success={}", resp.success)
            }
            Ok((hotkey_prefix, Err(e))) => println!("miner {hotkey_prefix}: error={e}"),
            Err(join_err) => eprintln!("task panicked: {join_err}"),
        }
    }

    client.close_all_connections().await?;
    for srv in [srv1, srv2, srv3] {
        let _ = srv.stop().await;
    }
    Ok(())
}
