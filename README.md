<div align="center">
    <h2>Ligh𝞽ning</h2>
    <p><strong>Rust QUIC transport layer for Bittensor</strong></p>
    <p>Persistent QUIC connections with sr25519 handshake authentication for validator-miner communication.</p>
</div>

## Python

```bash
pip install btlightning
```

```python
from btlightning import Lightning

client = Lightning(wallet_hotkey="5GrwvaEF...")
client.set_python_signer(my_signer_callback)
client.initialize_connections([
    {"hotkey": "5FHneW46...", "ip": "192.168.1.1", "port": 8443}
])
response = client.query_axon(
    {"hotkey": "5FHneW46...", "ip": "192.168.1.1", "port": 8443},
    {"synapse_type": "MyQuery", "data": {"key": "value"}}
)
```

## Rust

```toml
[dependencies]
btlightning = "0.1"
```

```rust
use btlightning::{LightningClient, Sr25519Signer, QuicAxonInfo, QuicRequest};

let mut client = LightningClient::new("5GrwvaEF...".into());
client.set_signer(Box::new(Sr25519Signer::from_seed(seed)));
client.initialize_connections(vec![
    QuicAxonInfo::new("5FHneW46...".into(), "192.168.1.1".into(), 8443, 4, 0, 0)
]).await?;
```

## Build from source

```bash
cargo build -p btlightning
maturin develop --manifest-path crates/btlightning-py/Cargo.toml
```
