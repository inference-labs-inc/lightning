import socket
import threading
import time

from btlightning import Lightning, LightningServer

from conftest import MINER_HOTKEY, MINER_SEED, VALIDATOR_HOTKEY, VALIDATOR_SEED


def test_streaming_handler():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    chunks = [b"chunk-1", b"chunk-2", b"chunk-3"]

    def stream_handler(data):
        return iter(chunks)

    server = LightningServer(miner_hotkey=MINER_HOTKEY, host="127.0.0.1", port=port)
    server.set_miner_keypair(MINER_SEED)
    server.register_streaming_handler("stream", stream_handler)
    server.start()
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    time.sleep(0.05)

    client = Lightning(wallet_hotkey=VALIDATOR_HOTKEY)
    client.set_validator_keypair(VALIDATOR_SEED)
    axon = {"hotkey": MINER_HOTKEY, "ip": "127.0.0.1", "port": port}
    client.initialize_connections([axon])

    try:
        stream = client.query_axon_stream(axon, {"synapse_type": "stream", "data": {}})
        received = list(stream)
        assert received == chunks
    finally:
        client.close()
        server.stop()
        t.join(timeout=5)
