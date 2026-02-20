use std::fmt;

#[derive(Debug)]
pub enum LightningError {
    Connection(String),
    Handshake(String),
    Signing(String),
    Serialization(String),
    Transport(String),
    Handler(String),
    Config(String),
    Stream(String),
}

impl fmt::Display for LightningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LightningError::Connection(msg) => write!(f, "connection error: {}", msg),
            LightningError::Handshake(msg) => write!(f, "handshake error: {}", msg),
            LightningError::Signing(msg) => write!(f, "signing error: {}", msg),
            LightningError::Serialization(msg) => write!(f, "serialization error: {}", msg),
            LightningError::Transport(msg) => write!(f, "transport error: {}", msg),
            LightningError::Handler(msg) => write!(f, "handler error: {}", msg),
            LightningError::Config(msg) => write!(f, "config error: {}", msg),
            LightningError::Stream(msg) => write!(f, "stream error: {}", msg),
        }
    }
}

impl std::error::Error for LightningError {}

impl LightningError {
    pub fn handler(e: impl std::fmt::Display) -> Self {
        LightningError::Handler(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, LightningError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_formats_all_variants() {
        let cases: Vec<(LightningError, &str)> = vec![
            (
                LightningError::Connection("x".into()),
                "connection error: x",
            ),
            (LightningError::Handshake("x".into()), "handshake error: x"),
            (LightningError::Signing("x".into()), "signing error: x"),
            (
                LightningError::Serialization("x".into()),
                "serialization error: x",
            ),
            (LightningError::Transport("x".into()), "transport error: x"),
            (LightningError::Handler("x".into()), "handler error: x"),
            (LightningError::Config("x".into()), "config error: x"),
            (LightningError::Stream("x".into()), "stream error: x"),
        ];
        for (err, expected) in cases {
            assert_eq!(format!("{}", err), expected);
        }
    }

    #[test]
    fn handler_constructor() {
        let err = LightningError::handler("something failed");
        assert_eq!(format!("{}", err), "handler error: something failed");
        assert!(matches!(err, LightningError::Handler(_)));
    }
}
