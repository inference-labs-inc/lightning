import socket
import threading
import time

from btlightning import LightningServer

from conftest import MINER_HOTKEY, MINER_SEED


def test_constructor_defaults():
    server = LightningServer(miner_hotkey=MINER_HOTKEY, host="127.0.0.1", port=0)
    server.stop()


def test_constructor_custom_config():
    server = LightningServer(
        miner_hotkey=MINER_HOTKEY,
        host="127.0.0.1",
        port=0,
        max_signature_age_secs=60,
        idle_timeout_secs=120,
        keep_alive_interval_secs=10,
        nonce_cleanup_interval_secs=300,
        max_nonce_entries=5000,
        max_frame_payload_bytes=2097152,
    )
    server.stop()


def test_start_stop_lifecycle():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    server = LightningServer(miner_hotkey=MINER_HOTKEY, host="127.0.0.1", port=port)
    server.set_miner_keypair(MINER_SEED)
    server.register_synapse_handler("echo", lambda data: data)
    server.start()
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    time.sleep(0.05)

    stats = server.get_connection_stats()
    assert "total_connections" in stats
    assert "verified_connections" in stats

    server.stop()


def test_get_connection_stats():
    server = LightningServer(miner_hotkey=MINER_HOTKEY, host="127.0.0.1", port=0)
    server.set_miner_keypair(MINER_SEED)
    server.register_synapse_handler("echo", lambda data: data)
    server.start()
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    time.sleep(0.05)

    stats = server.get_connection_stats()
    assert stats["total_connections"] == "0"
    assert stats["verified_connections"] == "0"

    server.stop()
