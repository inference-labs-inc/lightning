import socket
import threading
import time

from btlightning import Lightning, LightningServer

from conftest import MINER_HOTKEY, MINER_SEED, VALIDATOR_HOTKEY, VALIDATOR_SEED


def test_two_handlers_on_same_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    def upper_handler(data):
        return {"result": data["text"].upper()}

    server = LightningServer(miner_hotkey=MINER_HOTKEY, host="127.0.0.1", port=port)
    server.set_miner_keypair(MINER_SEED)
    server.register_synapse_handler("echo", lambda data: data)
    server.register_synapse_handler("upper", upper_handler)
    server.start()
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    time.sleep(0.05)

    client = Lightning(wallet_hotkey=VALIDATOR_HOTKEY)
    client.set_validator_keypair(VALIDATOR_SEED)
    axon = {"hotkey": MINER_HOTKEY, "ip": "127.0.0.1", "port": port}
    client.initialize_connections([axon])

    try:
        echo_resp = client.query_axon(axon, {"synapse_type": "echo", "data": {"msg": "hi"}})
        assert echo_resp["success"] is True
        assert echo_resp["data"]["msg"] == "hi"

        upper_resp = client.query_axon(axon, {"synapse_type": "upper", "data": {"text": "hello"}})
        assert upper_resp["success"] is True
        assert upper_resp["data"]["result"] == "HELLO"
    finally:
        client.close()
        server.stop()
        t.join(timeout=5)
