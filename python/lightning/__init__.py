"""
Rust Lightning QUIC Client - Python bindings for ultra-fast miner communication
"""

from typing import Dict, Any, List, Optional

try:

    lightning_rust = None

    try:
        from lightning import lightning as lightning_rust
    except ImportError:
        pass

    if lightning_rust is None:
        try:
            from . import lightning as lightning_rust
        except ImportError:
            pass

    if lightning_rust is None:
        try:
            from lightning.python.lightning import lightning as lightning_rust
        except ImportError:
            pass

    if lightning_rust is not None:
        LIGHTNING_AVAILABLE = True
    else:
        raise ImportError("Could not import lightning module from any path")

except ImportError as e:
    print(
        f"Warning: Rust Lightning module not found: {e}. Using fallback implementation."
    )
    lightning_rust = None
    LIGHTNING_AVAILABLE = False


class Lightning:
    """
    Lightning-fast QUIC-based client for communicating with bittensor axons.
    Drop-in replacement for the Python aioquic implementation.
    """

    def __init__(self, wallet_hotkey: str):
        """Initialize Lightning client with wallet hotkey"""
        if lightning_rust is None:
            raise ImportError("Rust Lightning module not available")
        self._rust_client = lightning_rust.RustLightning(wallet_hotkey)
        self.wallet_hotkey = wallet_hotkey

    def initialize_connections(self, miners: List[Dict[str, Any]]) -> None:
        """Initialize connections to miners"""
        return self._rust_client.initialize_connections(miners)

    async def query_axon(
        self, axon_info: Dict[str, Any], request: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Query axon using QUIC while preserving bittensor authentication.
        """
        return await self._rust_client.query_axon(axon_info, request)

    def close(self) -> None:
        """Close all connections"""
        return self._rust_client.close_all_connections()

    def close_connection(self, uid: int) -> None:
        """Close persistent connection for specific miner UID"""
        self._rust_client.close_connection(uid)

    def close(self) -> None:
        """Close all connections and cleanup"""
        self._rust_client.close()

    def __del__(self):
        """Cleanup on deletion"""
        try:
            self.close()
        except Exception:
            pass


async def query_axon_quic(lightning_client: Lightning, request) -> Optional[object]:
    """
    Drop-in replacement for query_single_axon using QUIC transport.
    Maintains full backward compatibility with existing code.
    """
    try:

        request_dict = {
            "uid": request.uid,
            "axon": {
                "ip": request.axon.ip,
                "port": request.axon.port,
                "hotkey": request.axon.hotkey,
                "protocol": 4,
            },
            "synapse": request.synapse.__dict__,
            "circuit_timeout": request.circuit.timeout,
            "dendrite_headers": getattr(request, "dendrite_headers", {}),
            "request_type": str(request.request_type),
            "request_hash": request.request_hash,
            "save": request.save,
        }

        response = await lightning_client.query_axon(request_dict)

        if not response["success"]:
            return None

        class BittensorResult:
            def __init__(self):
                self.dendrite = BittensorDendrite()

            def deserialize(self):
                return response["deserialized"]

        class BittensorDendrite:
            def __init__(self):
                self.process_time = response["response_time"]
                self.status_code = response["status_code"]
                self.status_message = (
                    "Success"
                    if response["success"]
                    else response.get("error_message", "Error")
                )

                for key, value in response["headers"].items():
                    setattr(self, key.replace("-", "_"), value)

        request.result = BittensorResult()
        request.response_time = response["response_time"]
        request.deserialized = response["deserialized"]

        return request

    except Exception as e:
        print(f"QUIC query failed: {e}")
        return None


__all__ = ["Lightning", "query_axon_quic", "LIGHTNING_AVAILABLE"]


if LIGHTNING_AVAILABLE and lightning_rust:
    RustLightning = lightning_rust.RustLightning
    RustLightningServer = lightning_rust.RustLightningServer
    QuicAxonInfo = lightning_rust.QuicAxonInfo
    __all__.extend(["RustLightning", "RustLightningServer", "QuicAxonInfo"])
