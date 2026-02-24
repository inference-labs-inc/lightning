use btlightning::{
    typed_async_handler, LightningClient, LightningServer, QuicAxonInfo, QuicRequest, Sr25519Signer,
};
use serde::{Deserialize, Serialize};
use sp_core::{crypto::Ss58Codec, sr25519, Pair};
use std::sync::Arc;

const MINER_SEED: [u8; 32] = [1u8; 32];
const VALIDATOR_SEED: [u8; 32] = [2u8; 32];

#[derive(Serialize, Deserialize)]
struct SumRequest {
    a: i32,
    b: i32,
}

#[derive(Serialize, Deserialize)]
struct SumResponse {
    result: i32,
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
        .register_async_synapse_handler(
            "sum".to_string(),
            typed_async_handler(|req: SumRequest| async move {
                Ok::<_, String>(SumResponse {
                    result: req.a + req.b,
                })
            }),
        )
        .await?;
    server.start().await?;
    let port = server.local_addr()?.port();
    println!("server listening on 127.0.0.1:{port}");

    let server = Arc::new(server);
    let s = server.clone();
    let serve_handle = tokio::spawn(async move { s.serve_forever().await });

    let mut client = LightningClient::new(validator_hotkey);
    client.set_signer(Box::new(Sr25519Signer::from_seed(VALIDATOR_SEED)));
    let axon = QuicAxonInfo {
        hotkey: miner_hotkey,
        ip: "127.0.0.1".into(),
        port,
        protocol: 4,
    };
    client.initialize_connections(vec![axon.clone()]).await?;

    let request = QuicRequest::from_typed("sum", &SumRequest { a: 17, b: 25 })?;
    let response = client.query_axon(axon, request).await?;
    let result: SumResponse = response.deserialize_data()?;
    println!("17 + 25 = {}", result.result);

    client.close_all_connections().await?;
    server.stop().await?;
    serve_handle.await??;
    Ok(())
}
