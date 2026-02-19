use btlightning::types::QuicAxonInfo as CoreQuicAxonInfo;
use pyo3::prelude::*;

#[pyclass(name = "QuicAxonInfo")]
#[derive(Debug, Clone)]
pub struct PyQuicAxonInfo {
    #[pyo3(get, set)]
    pub hotkey: String,
    #[pyo3(get, set)]
    pub ip: String,
    #[pyo3(get, set)]
    pub port: u16,
    #[pyo3(get, set)]
    pub protocol: u8,
    #[pyo3(get, set)]
    pub placeholder1: u8,
    #[pyo3(get, set)]
    pub placeholder2: u8,
}

#[pymethods]
impl PyQuicAxonInfo {
    #[new]
    pub fn new(
        hotkey: String,
        ip: String,
        port: u16,
        protocol: u8,
        placeholder1: u8,
        placeholder2: u8,
    ) -> Self {
        Self {
            hotkey,
            ip,
            port,
            protocol,
            placeholder1,
            placeholder2,
        }
    }
}

impl From<PyQuicAxonInfo> for CoreQuicAxonInfo {
    fn from(py: PyQuicAxonInfo) -> Self {
        CoreQuicAxonInfo::new(
            py.hotkey,
            py.ip,
            py.port,
            py.protocol,
            py.placeholder1,
            py.placeholder2,
        )
    }
}

impl From<CoreQuicAxonInfo> for PyQuicAxonInfo {
    fn from(core: CoreQuicAxonInfo) -> Self {
        Self {
            hotkey: core.hotkey,
            ip: core.ip,
            port: core.port,
            protocol: core.protocol,
            placeholder1: core.placeholder1,
            placeholder2: core.placeholder2,
        }
    }
}
