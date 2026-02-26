def test_echo_roundtrip(client_and_axon):
    client, axon = client_and_axon
    resp = client.query_axon(axon, {"synapse_type": "echo", "data": {"msg": "hello"}})
    assert resp["success"] is True
    assert resp["error"] is None
    assert resp["data"]["msg"] == "hello"
    assert resp["latency_ms"] >= 0


def test_large_payload(client_and_axon):
    client, axon = client_and_axon
    payload = b"\x42" * 100_000
    resp = client.query_axon(axon, {"synapse_type": "echo", "data": {"payload": payload}})
    assert resp["success"] is True
    assert resp["data"]["payload"] == payload


def test_query_with_timeout(client_and_axon):
    client, axon = client_and_axon
    resp = client.query_axon(
        axon,
        {"synapse_type": "echo", "data": {"val": 42}},
        timeout_secs=5.0,
    )
    assert resp["success"] is True
    assert resp["data"]["val"] == 42


def test_multiple_sequential_queries(client_and_axon):
    client, axon = client_and_axon
    for i in range(10):
        resp = client.query_axon(axon, {"synapse_type": "echo", "data": {"i": i}})
        assert resp["success"] is True
        assert resp["data"]["i"] == i
