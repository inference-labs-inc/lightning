use crate::error::{LightningError, Result};
use crate::types::DEFAULT_MAX_FRAME_PAYLOAD;

#[derive(Debug, Copy, Clone)]
#[non_exhaustive]
pub struct LightningServerConfig {
    pub max_signature_age_secs: u64,
    pub idle_timeout_secs: u64,
    pub keep_alive_interval_secs: u64,
    pub nonce_cleanup_interval_secs: u64,
    pub max_connections: usize,
    pub max_nonce_entries: usize,
    pub handshake_timeout_secs: u64,
    pub max_handshake_attempts_per_minute: u32,
    pub max_concurrent_bidi_streams: u32,
    pub require_validator_permit: bool,
    pub validator_permit_refresh_secs: u64,
    pub max_tracked_rate_ips: usize,
    pub handler_timeout_secs: u64,
    pub max_frame_payload_bytes: usize,
    pub streaming_channel_buffer: usize,
}

impl Default for LightningServerConfig {
    fn default() -> Self {
        Self {
            max_signature_age_secs: 300,
            idle_timeout_secs: 150,
            keep_alive_interval_secs: 30,
            nonce_cleanup_interval_secs: 60,
            max_connections: 128,
            max_nonce_entries: 100_000,
            handshake_timeout_secs: 10,
            max_handshake_attempts_per_minute: 30,
            max_concurrent_bidi_streams: 128,
            require_validator_permit: false,
            validator_permit_refresh_secs: 1800,
            max_tracked_rate_ips: 10_000,
            handler_timeout_secs: 30,
            max_frame_payload_bytes: DEFAULT_MAX_FRAME_PAYLOAD,
            streaming_channel_buffer: 32,
        }
    }
}

macro_rules! require_nonzero {
    ($config:expr, $field:ident) => {
        if $config.$field == 0 {
            return Err(LightningError::Config(format!(
                "{} must be non-zero",
                stringify!($field)
            )));
        }
    };
}

macro_rules! require_less_than {
    ($config:expr, $field:ident < $ceiling:ident) => {
        if $config.$field >= $config.$ceiling {
            return Err(LightningError::Config(format!(
                "{} ({}) must be less than {} ({})",
                stringify!($field),
                $config.$field,
                stringify!($ceiling),
                $config.$ceiling
            )));
        }
    };
}

impl LightningServerConfig {
    pub(super) fn validate(&self) -> Result<()> {
        require_nonzero!(self, max_signature_age_secs);
        if self.max_signature_age_secs > 3600 {
            return Err(LightningError::Config(
                "max_signature_age_secs must not exceed 3600 (1 hour)".to_string(),
            ));
        }
        require_nonzero!(self, nonce_cleanup_interval_secs);
        require_nonzero!(self, idle_timeout_secs);
        require_nonzero!(self, keep_alive_interval_secs);
        require_less_than!(self, keep_alive_interval_secs < idle_timeout_secs);
        require_nonzero!(self, max_connections);
        require_nonzero!(self, max_nonce_entries);
        require_nonzero!(self, handshake_timeout_secs);
        require_less_than!(self, handshake_timeout_secs < idle_timeout_secs);
        require_nonzero!(self, max_handshake_attempts_per_minute);
        require_nonzero!(self, max_concurrent_bidi_streams);
        require_nonzero!(self, validator_permit_refresh_secs);
        require_nonzero!(self, max_tracked_rate_ips);
        require_nonzero!(self, handler_timeout_secs);
        require_less_than!(self, handler_timeout_secs < idle_timeout_secs);
        require_nonzero!(self, streaming_channel_buffer);
        if self.max_frame_payload_bytes < 1_048_576 {
            return Err(LightningError::Config(format!(
                "max_frame_payload_bytes ({}) must be at least 1048576 (1 MB)",
                self.max_frame_payload_bytes
            )));
        }
        if self.max_frame_payload_bytes > u32::MAX as usize {
            return Err(LightningError::Config(format!(
                "max_frame_payload_bytes ({}) must not exceed {} (u32::MAX)",
                self.max_frame_payload_bytes,
                u32::MAX
            )));
        }
        Ok(())
    }
}
