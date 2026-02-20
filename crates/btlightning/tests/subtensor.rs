#![cfg(feature = "subtensor-tests")]

use btlightning::{
    LightningError, LightningServer, LightningServerConfig, Result, ValidatorPermitResolver,
};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use subxt::{dynamic::Value, OnlineClient, SubstrateConfig};

const TESTNET_ENDPOINT: &str = "wss://test.finney.opentensor.ai:443";

struct SubtensorPermitResolver {
    rpc_url: String,
    netuid: u16,
}

impl SubtensorPermitResolver {
    fn new(rpc_url: String, netuid: u16) -> Self {
        Self { rpc_url, netuid }
    }

    async fn resolve_async(&self) -> Result<HashSet<String>> {
        let api = OnlineClient::<SubstrateConfig>::from_url(&self.rpc_url)
            .await
            .map_err(|e| LightningError::Handler(format!("subtensor connection: {}", e)))?;

        let storage = api
            .storage()
            .at_latest()
            .await
            .map_err(|e| LightningError::Handler(e.to_string()))?;

        let permits_query = subxt::dynamic::storage(
            "SubtensorModule",
            "ValidatorPermit",
            vec![Value::u128(self.netuid as u128)],
        );

        let permits: Vec<bool> = match storage
            .fetch(&permits_query)
            .await
            .map_err(|e| LightningError::Handler(e.to_string()))?
        {
            Some(val) => val
                .as_type()
                .map_err(|e| LightningError::Handler(format!("decode ValidatorPermit: {}", e)))?,
            None => return Ok(HashSet::new()),
        };

        let mut validators = HashSet::new();
        for (uid, has_permit) in permits.iter().enumerate() {
            if !*has_permit {
                continue;
            }

            let keys_query = subxt::dynamic::storage(
                "SubtensorModule",
                "Keys",
                vec![Value::u128(self.netuid as u128), Value::u128(uid as u128)],
            );

            if let Some(val) = storage
                .fetch(&keys_query)
                .await
                .map_err(|e| LightningError::Handler(e.to_string()))?
            {
                let account: subxt::utils::AccountId32 = val
                    .as_type()
                    .map_err(|e| LightningError::Handler(format!("decode Keys: {}", e)))?;
                validators.insert(account.to_string());
            }
        }

        Ok(validators)
    }
}

impl ValidatorPermitResolver for SubtensorPermitResolver {
    fn resolve_permitted_validators(&self) -> Result<HashSet<String>> {
        let handle = tokio::runtime::Handle::current();
        handle.block_on(self.resolve_async())
    }
}

#[tokio::test]
#[ignore]
async fn subtensor_resolver_fetches_permits() {
    let resolver = SubtensorPermitResolver::new(TESTNET_ENDPOINT.to_string(), 1);
    let validators = resolver.resolve_async().await.unwrap();
    assert!(
        !validators.is_empty(),
        "netuid 1 should have validators with permits"
    );
    for hotkey in &validators {
        assert!(
            hotkey.starts_with('5'),
            "SS58 addresses should start with '5', got: {}",
            hotkey
        );
        assert!(hotkey.len() >= 47, "SS58 address too short: {}", hotkey);
    }
}

#[tokio::test]
#[ignore]
async fn subtensor_resolver_integrates_with_server() {
    let resolver = SubtensorPermitResolver::new(TESTNET_ENDPOINT.to_string(), 1);

    let config = LightningServerConfig {
        require_validator_permit: true,
        validator_permit_refresh_secs: 3600,
        ..Default::default()
    };
    let mut server = LightningServer::with_config(
        "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY".into(),
        "127.0.0.1".into(),
        0,
        config,
    )
    .unwrap();
    server.set_miner_keypair([1u8; 32]);
    server.set_validator_permit_resolver(Box::new(resolver));
    server.start().await.unwrap();

    let server = Arc::new(server);
    let s = server.clone();
    let handle = tokio::spawn(async move { s.serve_forever().await });

    let srv = server.clone();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if srv.get_permitted_validator_count().await > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("subtensor resolver should populate permits within 30s");

    assert!(server.get_permitted_validator_count().await > 0);

    let _ = server.stop().await;
    let _ = handle.await;
}

#[tokio::test]
#[ignore]
async fn subtensor_resolver_handles_invalid_netuid() {
    let resolver = SubtensorPermitResolver::new(TESTNET_ENDPOINT.to_string(), 65535);
    let result = resolver.resolve_async().await;
    match result {
        Ok(set) => assert!(set.is_empty(), "invalid netuid should return empty set"),
        Err(_) => {}
    }
}

#[tokio::test]
#[ignore]
async fn subtensor_resolver_handles_connection_failure() {
    let resolver = SubtensorPermitResolver::new("wss://localhost:1".to_string(), 1);
    let result = resolver.resolve_async().await;
    assert!(result.is_err(), "unreachable endpoint should return Err");
}
