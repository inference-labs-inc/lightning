import socket
import threading
import time

import pytest

from btlightning import Lightning, LightningServer

MINER_SEED = bytes([1] * 32)
VALIDATOR_SEED = bytes([2] * 32)
MINER_HOTKEY = "5CcyqxXnJucaCnQQvvUg5EPzj1uoNAxACZvzArHw5aVDvgNH"
VALIDATOR_HOTKEY = "5CfCr47V5Dte6bwxNBE8K9oNnQd9fiay6aDEEkgYtFv7w4Fq"


@pytest.fixture()
def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture()
def echo_server(free_port):
    server = LightningServer(miner_hotkey=MINER_HOTKEY, host="127.0.0.1", port=free_port)
    server.set_miner_keypair(MINER_SEED)
    server.register_synapse_handler("echo", lambda data: data)
    server.start()
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    time.sleep(0.05)
    yield server, free_port
    server.stop()
    t.join(timeout=5)


@pytest.fixture()
def client_and_axon(echo_server):
    _, port = echo_server
    client = Lightning(wallet_hotkey=VALIDATOR_HOTKEY)
    client.set_validator_keypair(VALIDATOR_SEED)
    axon = {"hotkey": MINER_HOTKEY, "ip": "127.0.0.1", "port": port}
    client.initialize_connections([axon])
    yield client, axon
    client.close()
