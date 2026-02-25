use pyo3::PyErr;

pub(crate) fn to_pyerr(err: btlightning::LightningError) -> PyErr {
    match err {
        btlightning::LightningError::Connection(msg) => {
            PyErr::new::<pyo3::exceptions::PyConnectionError, _>(format!(
                "connection error: {}",
                msg
            ))
        }
        btlightning::LightningError::Handshake(msg) => {
            PyErr::new::<pyo3::exceptions::PyConnectionError, _>(format!(
                "handshake error: {}",
                msg
            ))
        }
        btlightning::LightningError::Config(msg) => {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("config error: {}", msg))
        }
        btlightning::LightningError::Serialization(msg) => {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("serialization error: {}", msg))
        }
        btlightning::LightningError::Transport(msg) => {
            PyErr::new::<pyo3::exceptions::PyConnectionError, _>(format!(
                "transport error: {}",
                msg
            ))
        }
        btlightning::LightningError::Signing(msg) => {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("signing error: {}", msg))
        }
        btlightning::LightningError::Handler(msg) => {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("handler error: {}", msg))
        }
        btlightning::LightningError::Stream(msg) => {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("stream error: {}", msg))
        }
    }
}
