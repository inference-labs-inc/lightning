use pyo3::prelude::*;

mod client;
mod error;
mod extraction;
mod handler;
mod server;
mod signer;
mod types;

use client::{PyStreamingResponse, RustLightning};
use server::RustLightningServer;
use types::PyQuicAxonInfo;

macro_rules! set_opt {
    ($config:expr, $field:ident, $opt:expr) => {
        if let Some(v) = $opt {
            $config.$field = v;
        }
    };
    ($config:expr, $field:ident, $opt:expr, secs) => {
        if let Some(v) = $opt {
            $config.$field = Duration::from_secs(v);
        }
    };
}
pub(crate) use set_opt;

#[pymodule]
fn _native(m: &Bound<'_, pyo3::types::PyModule>) -> PyResult<()> {
    m.add_class::<RustLightning>()?;
    m.add_class::<RustLightningServer>()?;
    m.add_class::<PyStreamingResponse>()?;
    m.add_class::<PyQuicAxonInfo>()?;
    Ok(())
}
