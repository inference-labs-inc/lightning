use btlightning::{
    LightningClient, LightningError, LightningServer, QuicAxonInfo, QuicRequest, Result,
    Sr25519Signer, StreamingSynapseHandler,
};
use sp_core::{crypto::Ss58Codec, sr25519, Pair};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;

const MINER_SEED: [u8; 32] = [1u8; 32];
const VALIDATOR_SEED: [u8; 32] = [2u8; 32];

struct CountdownHandler;

#[async_trait::async_trait]
impl StreamingSynapseHandler for CountdownHandler {
    async fn handle(
        &self,
        _synapse_type: &str,
        _data: HashMap<String, rmpv::Value>,
        sender: mpsc::Sender<Vec<u8>>,
    ) -> Result<()> {
        for i in (1..=5).rev() {
            sender
                .send(format!("{i}...").into_bytes())
                .await
                .map_err(|_| LightningError::Stream("send failed".to_string()))?;
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        sender
            .send(b"liftoff!".to_vec())
            .await
            .map_err(|_| LightningError::Stream("send failed".to_string()))?;
        Ok(())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let miner_hotkey = sr25519::Pair::from_seed(&MINER_SEED)
        .public()
        .to_ss58check();
    let validator_hotkey = sr25519::Pair::from_seed(&VALIDATOR_SEED)
        .public()
        .to_ss58check();

    let mut server = LightningServer::new(miner_hotkey.clone(), "127.0.0.1".into(), 0)?;
    server.set_miner_keypair(MINER_SEED);
    server
        .register_streaming_handler("countdown".to_string(), Arc::new(CountdownHandler))
        .await?;
    server.start().await?;
    let port = server.local_addr()?.port();
    println!("server listening on 127.0.0.1:{port}");

    let server = Arc::new(server);
    let s = server.clone();
    tokio::spawn(async move { s.serve_forever().await });

    let mut client = LightningClient::new(validator_hotkey);
    client.set_signer(Box::new(Sr25519Signer::from_seed(VALIDATOR_SEED)));
    let axon = QuicAxonInfo {
        hotkey: miner_hotkey,
        ip: "127.0.0.1".into(),
        port,
        protocol: 4,
    };
    client.initialize_connections(vec![axon.clone()]).await?;

    let request = QuicRequest {
        synapse_type: "countdown".to_string(),
        data: HashMap::new(),
    };
    let mut stream = client.query_axon_stream(axon, request).await?;

    while let Some(chunk) = stream.next_chunk().await? {
        print!("{}", String::from_utf8_lossy(&chunk));
    }
    println!();

    client.close_all_connections().await?;
    server.stop().await?;
    Ok(())
}
