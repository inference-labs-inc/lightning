use btlightning::{
    CallbackSigner, LightningClient, LightningServer, QuicAxonInfo, QuicRequest, Result, Signer,
    Sr25519Signer, SynapseHandler,
};
use sp_core::{crypto::Ss58Codec, sr25519, Pair};
use std::collections::HashMap;
use std::sync::Arc;

const MINER_SEED: [u8; 32] = [1u8; 32];
const VALIDATOR_SEED: [u8; 32] = [2u8; 32];

struct LoggingSigner {
    inner: Sr25519Signer,
    label: String,
}

impl Signer for LoggingSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        println!("[{}] signing {} bytes", self.label, message.len());
        self.inner.sign(message)
    }
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let miner_hotkey = sr25519::Pair::from_seed(&MINER_SEED)
        .public()
        .to_ss58check();
    let validator_hotkey = sr25519::Pair::from_seed(&VALIDATOR_SEED)
        .public()
        .to_ss58check();

    let mut server = LightningServer::new(miner_hotkey.clone(), "127.0.0.1".into(), 0)?;
    server.set_miner_signer(Box::new(LoggingSigner {
        inner: Sr25519Signer::from_seed(MINER_SEED),
        label: "miner".to_string(),
    }));
    server
        .register_synapse_handler("echo".to_string(), Arc::new(EchoHandler))
        .await?;
    server.start().await?;
    let port = server.local_addr()?.port();
    println!("server with LoggingSigner on 127.0.0.1:{port}");

    let server = Arc::new(server);
    let s = server.clone();
    tokio::spawn(async move { s.serve_forever().await });

    let callback_signer = CallbackSigner::new({
        let inner = Sr25519Signer::from_seed(VALIDATOR_SEED);
        move |msg: &[u8]| {
            println!("[callback] signing {} bytes", msg.len());
            inner.sign(msg)
        }
    });

    let mut client = LightningClient::new(validator_hotkey);
    client.set_signer(Box::new(callback_signer));
    let axon = QuicAxonInfo {
        hotkey: miner_hotkey,
        ip: "127.0.0.1".into(),
        port,
        protocol: 4,
    };
    client.initialize_connections(vec![axon.clone()]).await?;

    let request = QuicRequest {
        synapse_type: "echo".to_string(),
        data: HashMap::new(),
    };
    let response = client.query_axon(axon, request).await?;
    println!("response success={}", response.success);

    client.close_all_connections().await?;
    server.stop().await?;
    Ok(())
}
