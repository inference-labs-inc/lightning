import sys
import traceback
from typing import Callable, Dict, Any, List, Optional, Iterator, TypedDict

from btlightning._native import (
    RustLightning,
    RustLightningServer,
    PyStreamingResponse,
    QuicAxonInfo,
)

LIGHTNING_AVAILABLE = True


class AxonInfo(TypedDict):
    hotkey: str
    ip: str
    port: int
    protocol: int  # IP protocol version (4 = IPv4, 6 = IPv6)
    placeholder1: int  # Reserved for future use (Bittensor metagraph field)
    placeholder2: int  # Reserved for future use (Bittensor metagraph field)


class SynapseRequest(TypedDict):
    synapse_type: str
    data: Dict[str, Any]


class SynapseResponse(TypedDict):
    success: bool
    data: Dict[str, Any]
    latency_ms: float
    error: Optional[str]


class ClientConnectionStats(TypedDict):
    total_connections: str
    active_miners: str


class ServerConnectionStats(TypedDict):
    total_connections: str
    verified_connections: str


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

    def set_python_signer(self, signer_callback: Callable[[bytes], bytes]) -> None:
        return self._rust_client.set_python_signer(signer_callback)

    def set_wallet(
        self,
        wallet_name: str = "default",
        wallet_path: str = "~/.bittensor/wallets",
        hotkey_name: str = "default",
    ) -> None:
        return self._rust_client.set_wallet(wallet_name, wallet_path, hotkey_name)

    def initialize_connections(self, miners: List[AxonInfo]) -> None:
        return self._rust_client.initialize_connections(miners)

    def query_axon(
        self,
        axon_info: AxonInfo,
        request: SynapseRequest,
        timeout_secs: Optional[float] = None,
    ) -> SynapseResponse:
        return self._rust_client.query_axon(axon_info, request, timeout_secs=timeout_secs)

    def query_axon_stream(
        self, axon_info: AxonInfo, request: SynapseRequest
    ) -> Iterator[bytes]:
        return self._rust_client.query_axon_stream(axon_info, request)

    def update_miner_registry(self, miners: List[AxonInfo]) -> None:
        return self._rust_client.update_miner_registry(miners)

    def get_connection_stats(self) -> ClientConnectionStats:
        return self._rust_client.get_connection_stats()

    def close(self) -> None:
        return self._rust_client.close_all_connections()

    def __del__(self):
        try:
            self.close()
        except Exception:
            sys.stderr.write(f"Lightning.__del__: {traceback.format_exc()}")


class LightningServer:
    def __init__(
        self,
        miner_hotkey: str,
        host: str = "0.0.0.0",
        port: int = 8443,
        max_signature_age_secs: Optional[int] = None,
        idle_timeout_secs: Optional[int] = None,
        keep_alive_interval_secs: Optional[int] = None,
        nonce_cleanup_interval_secs: Optional[int] = None,
        max_nonce_entries: Optional[int] = None,
    ):
        self._rust_server = RustLightningServer(
            miner_hotkey,
            host,
            port,
            max_signature_age_secs=max_signature_age_secs,
            idle_timeout_secs=idle_timeout_secs,
            keep_alive_interval_secs=keep_alive_interval_secs,
            nonce_cleanup_interval_secs=nonce_cleanup_interval_secs,
            max_nonce_entries=max_nonce_entries,
        )

    def set_miner_keypair(self, keypair_seed: bytes) -> None:
        return self._rust_server.set_miner_keypair(list(keypair_seed))

    def set_miner_wallet(
        self,
        wallet_name: str = "default",
        wallet_path: str = "~/.bittensor/wallets",
        hotkey_name: str = "default",
    ) -> None:
        return self._rust_server.set_miner_wallet(wallet_name, wallet_path, hotkey_name)

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

    def get_connection_stats(self) -> ServerConnectionStats:
        return self._rust_server.get_connection_stats()

    def cleanup_stale_connections(self, max_idle_seconds: int = 300) -> None:
        return self._rust_server.cleanup_stale_connections(max_idle_seconds)

    def stop(self) -> None:
        return self._rust_server.stop()

    def __del__(self):
        try:
            self.stop()
        except Exception:
            sys.stderr.write(f"LightningServer.__del__: {traceback.format_exc()}")


__all__ = [
    "AxonInfo",
    "ClientConnectionStats",
    "Lightning",
    "LightningServer",
    "LIGHTNING_AVAILABLE",
    "PyStreamingResponse",
    "QuicAxonInfo",
    "RustLightning",
    "RustLightningServer",
    "ServerConnectionStats",
    "SynapseRequest",
    "SynapseResponse",
]
