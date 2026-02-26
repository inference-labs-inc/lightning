from btlightning import Lightning

from conftest import VALIDATOR_HOTKEY, VALIDATOR_SEED


def test_constructor_defaults():
    client = Lightning(wallet_hotkey=VALIDATOR_HOTKEY)
    assert client.wallet_hotkey == VALIDATOR_HOTKEY
    client.close()


def test_constructor_custom_config():
    client = Lightning(
        wallet_hotkey=VALIDATOR_HOTKEY,
        connect_timeout_secs=5,
        idle_timeout_secs=30,
        keep_alive_interval_secs=10,
        reconnect_initial_backoff_secs=1,
        reconnect_max_backoff_secs=60,
        reconnect_max_retries=3,
        max_frame_payload_bytes=2097152,
        max_stream_payload_bytes=10485760,
    )
    assert client.wallet_hotkey == VALIDATOR_HOTKEY
    client.close()


def test_set_validator_keypair():
    client = Lightning(wallet_hotkey=VALIDATOR_HOTKEY)
    client.set_validator_keypair(VALIDATOR_SEED)
    client.close()


def test_set_python_signer():
    client = Lightning(wallet_hotkey=VALIDATOR_HOTKEY)
    client.set_python_signer(lambda msg: b"\x00" * 64)
    client.close()


def test_get_connection_stats_empty():
    client = Lightning(wallet_hotkey=VALIDATOR_HOTKEY)
    stats = client.get_connection_stats()
    assert "total_connections" in stats
    assert "active_miners" in stats
    client.close()
