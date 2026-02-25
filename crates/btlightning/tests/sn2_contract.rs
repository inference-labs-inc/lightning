use btlightning::{
    typed_async_handler, LightningClient, LightningServer, LightningServerConfig, QuicAxonInfo,
    QuicRequest, Sr25519Signer,
};
use sp_core::{crypto::Ss58Codec, sr25519, Pair};
use std::collections::HashMap;
use std::sync::Arc;

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
    server_handle: tokio::task::JoinHandle<btlightning::Result<()>>,
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

async fn connect_client(port: u16) -> (LightningClient, QuicAxonInfo) {
    let mut client = LightningClient::new(validator_hotkey());
    client.set_signer(Box::new(Sr25519Signer::from_seed(VALIDATOR_SEED)));
    client.create_endpoint().await.unwrap();
    let axon = QuicAxonInfo {
        hotkey: miner_hotkey(),
        ip: "127.0.0.1".into(),
        port,
        protocol: 4,
    };
    client
        .initialize_connections(vec![axon.clone()])
        .await
        .unwrap();
    (client, axon)
}

async fn setup_typed_env<Req, Resp, E, F, Fut>(synapse_type: &str, handler_fn: F) -> TestEnv
where
    Req: serde::de::DeserializeOwned + Send + 'static,
    Resp: serde::Serialize + Send + 'static,
    E: std::fmt::Display + 'static,
    F: Fn(Req) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<Resp, E>> + Send + 'static,
{
    let mut config = LightningServerConfig::default();
    config.require_validator_permit = false;
    let mut server =
        LightningServer::with_config(miner_hotkey(), "127.0.0.1".into(), 0, config).unwrap();
    server.set_miner_keypair(MINER_SEED);
    server
        .register_async_synapse_handler(synapse_type.to_string(), typed_async_handler(handler_fn))
        .await
        .unwrap();
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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct QueryZkProof {
    #[serde(skip_serializing_if = "Option::is_none")]
    model_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    query_input: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    query_output: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct DSliceProofGenerationDataModel {
    #[serde(skip_serializing_if = "Option::is_none")]
    circuit: Option<String>,
    proof_system: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    inputs: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    outputs: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    slice_num: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    run_uid: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct Competition {
    id: i32,
    hash: String,
    file_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    commitment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[tokio::test]
async fn query_zk_proof_full_roundtrip() {
    let env = setup_typed_env("query-zk-proof", |req: QueryZkProof| async move {
        Ok::<_, String>(QueryZkProof {
            model_id: req.model_id,
            query_input: req.query_input,
            query_output: Some("proof_abc123".to_string()),
        })
    })
    .await;

    let mut data = HashMap::new();
    data.insert(
        "model_id".to_string(),
        serde_json::Value::String("model-v1".to_string()),
    );
    data.insert(
        "query_input".to_string(),
        serde_json::json!({"layer": 0, "tensor": [1.0, 2.0, 3.0]}),
    );

    let req = QuicRequest::from_typed("query-zk-proof", &data).unwrap();
    let resp = env
        .client
        .query_axon(env.axon_info.clone(), req)
        .await
        .unwrap();
    assert!(resp.success);
    let result: serde_json::Value = resp.deserialize_data().unwrap();
    assert_eq!(result["model_id"], "model-v1");
    assert_eq!(result["query_output"], "proof_abc123");
    assert!(result["query_input"]["layer"].is_number());

    env.shutdown().await;
}

#[tokio::test]
async fn query_zk_proof_all_fields_none() {
    let env = setup_typed_env("query-zk-proof", |req: QueryZkProof| async move {
        assert!(req.model_id.is_none());
        assert!(req.query_input.is_none());
        assert!(req.query_output.is_none());
        Ok::<_, String>(QueryZkProof {
            model_id: None,
            query_input: None,
            query_output: None,
        })
    })
    .await;

    let data: HashMap<String, serde_json::Value> = HashMap::new();
    let req = QuicRequest::from_typed("query-zk-proof", &data).unwrap();
    let resp = env
        .client
        .query_axon(env.axon_info.clone(), req)
        .await
        .unwrap();
    assert!(resp.success);
    let result: serde_json::Value = resp.deserialize_data().unwrap();
    assert!(
        result.get("model_id").is_none(),
        "model_id must be absent when None with skip_serializing_if"
    );
    assert!(
        result.get("query_input").is_none(),
        "query_input must be absent when None with skip_serializing_if"
    );
    assert!(
        result.get("query_output").is_none(),
        "query_output must be absent when None with skip_serializing_if"
    );

    env.shutdown().await;
}

#[tokio::test]
async fn query_zk_proof_partial_fields() {
    let env = setup_typed_env("query-zk-proof", |req: QueryZkProof| async move {
        assert!(req.model_id.is_some());
        assert!(req.query_input.is_none());
        assert!(req.query_output.is_none());
        Ok::<_, String>(req)
    })
    .await;

    let mut data = HashMap::new();
    data.insert(
        "model_id".to_string(),
        serde_json::Value::String("only-this-field".to_string()),
    );

    let req = QuicRequest::from_typed("query-zk-proof", &data).unwrap();
    let resp = env
        .client
        .query_axon(env.axon_info.clone(), req)
        .await
        .unwrap();
    assert!(resp.success);
    let result: serde_json::Value = resp.deserialize_data().unwrap();
    assert_eq!(result["model_id"], "only-this-field");

    env.shutdown().await;
}

#[tokio::test]
async fn dslice_proof_generation_full_roundtrip() {
    let env = setup_typed_env(
        "dsperse-proof-generation",
        |req: DSliceProofGenerationDataModel| async move {
            Ok::<_, String>(DSliceProofGenerationDataModel {
                circuit: req.circuit,
                proof_system: req.proof_system,
                inputs: req.inputs,
                outputs: Some(serde_json::json!({"proof": "generated"})),
                slice_num: req.slice_num,
                run_uid: req.run_uid,
            })
        },
    )
    .await;

    let mut data = HashMap::new();
    data.insert(
        "circuit".to_string(),
        serde_json::Value::String("keccak256".to_string()),
    );
    data.insert(
        "proof_system".to_string(),
        serde_json::Value::String("JSTPROVE".to_string()),
    );
    data.insert(
        "inputs".to_string(),
        serde_json::json!({"witness": [0, 1, 2]}),
    );
    data.insert(
        "slice_num".to_string(),
        serde_json::Value::String("3".to_string()),
    );
    data.insert(
        "run_uid".to_string(),
        serde_json::Value::String("abc-def-123".to_string()),
    );

    let req = QuicRequest::from_typed("dsperse-proof-generation", &data).unwrap();
    let resp = env
        .client
        .query_axon(env.axon_info.clone(), req)
        .await
        .unwrap();
    assert!(resp.success);
    let result: serde_json::Value = resp.deserialize_data().unwrap();
    assert_eq!(result["circuit"], "keccak256");
    assert_eq!(result["proof_system"], "JSTPROVE");
    assert_eq!(result["slice_num"], "3");
    assert_eq!(result["run_uid"], "abc-def-123");
    assert_eq!(result["outputs"]["proof"], "generated");

    env.shutdown().await;
}

#[tokio::test]
async fn dslice_proof_generation_minimal_fields() {
    let env = setup_typed_env(
        "dsperse-proof-generation",
        |req: DSliceProofGenerationDataModel| async move {
            assert_eq!(req.proof_system, "JSTPROVE");
            assert!(req.circuit.is_none());
            assert!(req.inputs.is_none());
            assert!(req.outputs.is_none());
            assert!(req.slice_num.is_none());
            assert!(req.run_uid.is_none());
            Ok::<_, String>(req)
        },
    )
    .await;

    let mut data = HashMap::new();
    data.insert(
        "proof_system".to_string(),
        serde_json::Value::String("JSTPROVE".to_string()),
    );

    let req = QuicRequest::from_typed("dsperse-proof-generation", &data).unwrap();
    let resp = env
        .client
        .query_axon(env.axon_info.clone(), req)
        .await
        .unwrap();
    assert!(resp.success);
    let result: serde_json::Value = resp.deserialize_data().unwrap();
    assert_eq!(result["proof_system"], "JSTPROVE");

    env.shutdown().await;
}

#[tokio::test]
async fn competition_full_roundtrip() {
    let env = setup_typed_env("competition", |req: Competition| async move {
        Ok::<_, String>(Competition {
            id: req.id,
            hash: req.hash,
            file_name: req.file_name,
            file_content: Some("circuit_bytes_here".to_string()),
            commitment: req.commitment,
            error: None,
        })
    })
    .await;

    let mut data = HashMap::new();
    data.insert("id".to_string(), serde_json::json!(42));
    data.insert(
        "hash".to_string(),
        serde_json::Value::String("sha256:deadbeef".to_string()),
    );
    data.insert(
        "file_name".to_string(),
        serde_json::Value::String("circuit.bin".to_string()),
    );
    data.insert(
        "commitment".to_string(),
        serde_json::Value::String("0xabc".to_string()),
    );

    let req = QuicRequest::from_typed("competition", &data).unwrap();
    let resp = env
        .client
        .query_axon(env.axon_info.clone(), req)
        .await
        .unwrap();
    assert!(resp.success);
    let result: serde_json::Value = resp.deserialize_data().unwrap();
    assert_eq!(result["id"], 42);
    assert_eq!(result["hash"], "sha256:deadbeef");
    assert_eq!(result["file_name"], "circuit.bin");
    assert_eq!(result["file_content"], "circuit_bytes_here");
    assert_eq!(result["commitment"], "0xabc");
    assert!(
        result.get("error").is_none(),
        "error must be absent when None with skip_serializing_if"
    );

    env.shutdown().await;
}

#[tokio::test]
async fn competition_required_fields_only() {
    let env = setup_typed_env("competition", |req: Competition| async move {
        assert!(req.file_content.is_none());
        assert!(req.commitment.is_none());
        assert!(req.error.is_none());
        Ok::<_, String>(req)
    })
    .await;

    let mut data = HashMap::new();
    data.insert("id".to_string(), serde_json::json!(1));
    data.insert(
        "hash".to_string(),
        serde_json::Value::String("abc".to_string()),
    );
    data.insert(
        "file_name".to_string(),
        serde_json::Value::String("test.bin".to_string()),
    );

    let req = QuicRequest::from_typed("competition", &data).unwrap();
    let resp = env
        .client
        .query_axon(env.axon_info.clone(), req)
        .await
        .unwrap();
    assert!(resp.success);
    let result: serde_json::Value = resp.deserialize_data().unwrap();
    assert_eq!(result["id"], 1);
    assert_eq!(result["hash"], "abc");
    assert_eq!(result["file_name"], "test.bin");

    env.shutdown().await;
}

#[tokio::test]
async fn competition_error_field_roundtrip() {
    let env = setup_typed_env("competition", |_req: Competition| async move {
        Ok::<_, String>(Competition {
            id: 0,
            hash: String::new(),
            file_name: String::new(),
            file_content: None,
            commitment: None,
            error: Some("proof generation failed".to_string()),
        })
    })
    .await;

    let mut data = HashMap::new();
    data.insert("id".to_string(), serde_json::json!(0));
    data.insert("hash".to_string(), serde_json::Value::String(String::new()));
    data.insert(
        "file_name".to_string(),
        serde_json::Value::String(String::new()),
    );

    let req = QuicRequest::from_typed("competition", &data).unwrap();
    let resp = env
        .client
        .query_axon(env.axon_info.clone(), req)
        .await
        .unwrap();
    assert!(resp.success);
    let result: serde_json::Value = resp.deserialize_data().unwrap();
    assert_eq!(result["error"], "proof generation failed");

    env.shutdown().await;
}

#[tokio::test]
async fn skip_serializing_if_none_omits_fields() {
    let proof = QueryZkProof {
        model_id: Some("present".to_string()),
        query_input: None,
        query_output: None,
    };

    let req = QuicRequest::from_typed("query-zk-proof", &proof).unwrap();
    assert!(req.data.contains_key("model_id"));
    assert!(
        !req.data.contains_key("query_input"),
        "None field with skip_serializing_if should be absent from serialized map"
    );
    assert!(
        !req.data.contains_key("query_output"),
        "None field with skip_serializing_if should be absent from serialized map"
    );
}

#[tokio::test]
async fn skip_serializing_if_none_deserializes_back_to_none() {
    let env = setup_typed_env("query-zk-proof", |req: QueryZkProof| async move {
        assert_eq!(req.model_id.as_deref(), Some("test"));
        assert!(req.query_input.is_none());
        assert!(req.query_output.is_none());
        Ok::<_, String>(req)
    })
    .await;

    let proof = QueryZkProof {
        model_id: Some("test".to_string()),
        query_input: None,
        query_output: None,
    };
    let req = QuicRequest::from_typed("query-zk-proof", &proof).unwrap();
    let resp = env
        .client
        .query_axon(env.axon_info.clone(), req)
        .await
        .unwrap();
    assert!(resp.success);
    let roundtripped: QueryZkProof = resp.deserialize_data().unwrap();
    assert_eq!(roundtripped.model_id.as_deref(), Some("test"));
    assert!(roundtripped.query_input.is_none());
    assert!(roundtripped.query_output.is_none());

    env.shutdown().await;
}

#[tokio::test]
async fn hashmap_client_to_struct_server_nested_json() {
    let env = setup_typed_env("query-zk-proof", |req: QueryZkProof| async move {
        let input = req.query_input.as_ref().unwrap();
        assert!(input.is_object());
        assert!(input.get("nested").is_some());
        Ok::<_, String>(req)
    })
    .await;

    let mut data = HashMap::new();
    data.insert(
        "model_id".to_string(),
        serde_json::Value::String("m1".to_string()),
    );
    data.insert(
        "query_input".to_string(),
        serde_json::json!({
            "nested": {
                "deeply": {
                    "value": 42
                }
            },
            "array": [1, 2, 3]
        }),
    );

    let req = QuicRequest::from_typed("query-zk-proof", &data).unwrap();
    let resp = env
        .client
        .query_axon(env.axon_info.clone(), req)
        .await
        .unwrap();
    assert!(resp.success);
    let result: serde_json::Value = resp.deserialize_data().unwrap();
    assert_eq!(result["query_input"]["nested"]["deeply"]["value"], 42);
    assert_eq!(result["query_input"]["array"][0], 1);

    env.shutdown().await;
}

#[tokio::test]
async fn dslice_with_complex_inputs_and_outputs() {
    let env = setup_typed_env(
        "dsperse-proof-generation",
        |req: DSliceProofGenerationDataModel| async move {
            assert!(req.inputs.is_some());
            assert!(req.outputs.is_some());
            Ok::<_, String>(req)
        },
    )
    .await;

    let mut data = HashMap::new();
    data.insert(
        "proof_system".to_string(),
        serde_json::Value::String("JSTPROVE".to_string()),
    );
    data.insert(
        "inputs".to_string(),
        serde_json::json!({
            "layer_0": {"weights": [0.1, 0.2], "bias": [0.01]},
            "layer_1": {"weights": [0.3, 0.4], "bias": [0.02]}
        }),
    );
    data.insert(
        "outputs".to_string(),
        serde_json::json!({
            "predictions": [0.95, 0.05],
            "logits": [-1.2, 3.4]
        }),
    );

    let req = QuicRequest::from_typed("dsperse-proof-generation", &data).unwrap();
    let resp = env
        .client
        .query_axon(env.axon_info.clone(), req)
        .await
        .unwrap();
    assert!(resp.success);
    let result: serde_json::Value = resp.deserialize_data().unwrap();
    assert!(result["inputs"]["layer_0"]["weights"].is_array());
    assert!(result["outputs"]["predictions"].is_array());

    env.shutdown().await;
}

#[tokio::test]
async fn multiple_handlers_registered_simultaneously() {
    let mut config = LightningServerConfig::default();
    config.require_validator_permit = false;
    let mut server =
        LightningServer::with_config(miner_hotkey(), "127.0.0.1".into(), 0, config).unwrap();
    server.set_miner_keypair(MINER_SEED);

    server
        .register_async_synapse_handler(
            "query-zk-proof".to_string(),
            typed_async_handler(|req: QueryZkProof| async move {
                Ok::<_, String>(QueryZkProof {
                    model_id: req.model_id,
                    query_input: None,
                    query_output: Some("zk-response".to_string()),
                })
            }),
        )
        .await
        .unwrap();

    server
        .register_async_synapse_handler(
            "dsperse-proof-generation".to_string(),
            typed_async_handler(|req: DSliceProofGenerationDataModel| async move {
                Ok::<_, String>(DSliceProofGenerationDataModel {
                    circuit: req.circuit,
                    proof_system: req.proof_system,
                    inputs: None,
                    outputs: Some(serde_json::json!({"status": "complete"})),
                    slice_num: req.slice_num,
                    run_uid: req.run_uid,
                })
            }),
        )
        .await
        .unwrap();

    server
        .register_async_synapse_handler(
            "competition".to_string(),
            typed_async_handler(|req: Competition| async move {
                Ok::<_, String>(Competition {
                    id: req.id,
                    hash: req.hash,
                    file_name: req.file_name,
                    file_content: Some("content".to_string()),
                    commitment: None,
                    error: None,
                })
            }),
        )
        .await
        .unwrap();

    server.start().await.unwrap();
    let port = server.local_addr().unwrap().port();
    let server = Arc::new(server);
    let s = server.clone();
    let server_handle = tokio::spawn(async move { s.serve_forever().await });
    let (client, axon) = connect_client(port).await;

    let mut zk_data = HashMap::new();
    zk_data.insert(
        "model_id".to_string(),
        serde_json::Value::String("m1".to_string()),
    );
    let req = QuicRequest::from_typed("query-zk-proof", &zk_data).unwrap();
    let resp = client.query_axon(axon.clone(), req).await.unwrap();
    assert!(resp.success);
    let result: serde_json::Value = resp.deserialize_data().unwrap();
    assert_eq!(result["query_output"], "zk-response");

    let mut dslice_data = HashMap::new();
    dslice_data.insert(
        "proof_system".to_string(),
        serde_json::Value::String("JSTPROVE".to_string()),
    );
    dslice_data.insert(
        "circuit".to_string(),
        serde_json::Value::String("poseidon".to_string()),
    );
    let req = QuicRequest::from_typed("dsperse-proof-generation", &dslice_data).unwrap();
    let resp = client.query_axon(axon.clone(), req).await.unwrap();
    assert!(resp.success);
    let result: serde_json::Value = resp.deserialize_data().unwrap();
    assert_eq!(result["outputs"]["status"], "complete");
    assert_eq!(result["circuit"], "poseidon");

    let mut comp_data = HashMap::new();
    comp_data.insert("id".to_string(), serde_json::json!(7));
    comp_data.insert(
        "hash".to_string(),
        serde_json::Value::String("h".to_string()),
    );
    comp_data.insert(
        "file_name".to_string(),
        serde_json::Value::String("f.bin".to_string()),
    );
    let req = QuicRequest::from_typed("competition", &comp_data).unwrap();
    let resp = client.query_axon(axon.clone(), req).await.unwrap();
    assert!(resp.success);
    let result: serde_json::Value = resp.deserialize_data().unwrap();
    assert_eq!(result["id"], 7);
    assert_eq!(result["file_content"], "content");

    let _ = client.close_all_connections().await;
    let _ = server.stop().await;
    let _ = server_handle.await;
}
