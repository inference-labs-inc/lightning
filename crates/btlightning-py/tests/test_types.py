import pytest


@pytest.mark.parametrize(
    "value",
    [
        pytest.param(None, id="none"),
        pytest.param(True, id="bool-true"),
        pytest.param(False, id="bool-false"),
        pytest.param(0, id="int-zero"),
        pytest.param(42, id="int-positive"),
        pytest.param(-7, id="int-negative"),
        pytest.param(3.14, id="float"),
        pytest.param("hello", id="str"),
        pytest.param("", id="str-empty"),
        pytest.param(b"\xde\xad\xbe\xef", id="bytes"),
        pytest.param([1, 2, 3], id="list"),
        pytest.param({"nested": {"key": "val"}}, id="nested-dict"),
    ],
)
def test_data_type_roundtrip(client_and_axon, value):
    client, axon = client_and_axon
    resp = client.query_axon(axon, {"synapse_type": "echo", "data": {"v": value}})
    assert resp["success"] is True
    assert resp["data"]["v"] == value
