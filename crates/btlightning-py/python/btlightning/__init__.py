from typing import Callable, Dict, Any, List, Optional, Iterator

from btlightning._native import (
    RustLightning,
    RustLightningServer,
    PyStreamingResponse,
    QuicAxonInfo,
)

LIGHTNING_AVAILABLE = True


class Lightning:
    def __init__(
        self,
        wallet_hotkey: str,
        connect_timeout_secs: Optional[int] = None,
        idle_timeout_secs: Optional[int] = None,
        keep_alive_interval_secs: Optional[int] = None,
        reconnect_initial_backoff_secs: Optional[int] = None,
        reconnect_max_backoff_secs: Optional[int] = None,
        reconnect_max_retries: Optional[int] = None,
    ):
        self._rust_client = RustLightning(
            wallet_hotkey,
            connect_timeout_secs=connect_timeout_secs,
            idle_timeout_secs=idle_timeout_secs,
            keep_alive_interval_secs=keep_alive_interval_secs,
            reconnect_initial_backoff_secs=reconnect_initial_backoff_secs,
            reconnect_max_backoff_secs=reconnect_max_backoff_secs,
            reconnect_max_retries=reconnect_max_retries,
        )
        self.wallet_hotkey = wallet_hotkey

    def set_validator_keypair(self, keypair_seed: bytes) -> None:
        return self._rust_client.set_validator_keypair(list(keypair_seed))

    def set_python_signer(self, signer_callback) -> None:
        return self._rust_client.set_python_signer(signer_callback)

    def initialize_connections(self, miners: List[Dict[str, Any]]) -> None:
        return self._rust_client.initialize_connections(miners)

    def query_axon(
        self, axon_info: Dict[str, Any], request: Dict[str, Any]
    ) -> Dict[str, Any]:
        return self._rust_client.query_axon(axon_info, request)

    def query_axon_stream(
        self, axon_info: Dict[str, Any], request: Dict[str, Any]
    ) -> Iterator[bytes]:
        return self._rust_client.query_axon_stream(axon_info, request)

    def update_miner_registry(self, miners: List[Dict[str, Any]]) -> None:
        return self._rust_client.update_miner_registry(miners)

    def get_connection_stats(self) -> Dict[str, str]:
        return self._rust_client.get_connection_stats()

    def close(self) -> None:
        return self._rust_client.close_all_connections()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


class LightningServer:
    def __init__(self, miner_hotkey: str, host: str = "0.0.0.0", port: int = 8443):
        self._rust_server = RustLightningServer(miner_hotkey, host, port)

    def register_synapse_handler(
        self, synapse_type: str, handler: Callable[[Dict[str, Any]], Dict[str, Any]]
    ) -> None:
        return self._rust_server.register_synapse_handler(synapse_type, handler)

    def register_streaming_handler(
        self, synapse_type: str, handler: Callable[[Dict[str, Any]], Iterator[bytes]]
    ) -> None:
        return self._rust_server.register_streaming_handler(synapse_type, handler)

    def start(self) -> None:
        return self._rust_server.start()

    def serve_forever(self) -> None:
        return self._rust_server.serve_forever()

    def get_connection_stats(self) -> Dict[str, str]:
        return self._rust_server.get_connection_stats()

    def cleanup_stale_connections(self, max_idle_seconds: int = 300) -> None:
        return self._rust_server.cleanup_stale_connections(max_idle_seconds)

    def stop(self) -> None:
        return self._rust_server.stop()


__all__ = [
    "Lightning",
    "LightningServer",
    "RustLightning",
    "RustLightningServer",
    "PyStreamingResponse",
    "QuicAxonInfo",
    "LIGHTNING_AVAILABLE",
]
