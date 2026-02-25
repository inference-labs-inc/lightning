use crate::error::{LightningError, Result};
use crate::types::DEFAULT_MAX_FRAME_PAYLOAD;

/// Configuration for [`LightningServer`](super::LightningServer).
///
/// All fields have sensible defaults via [`Default`]. The server validates constraints
/// (e.g. `keep_alive_interval_secs < idle_timeout_secs`) at construction time.
#[derive(Debug, Copy, Clone)]
#[non_exhaustive]
pub struct LightningServerConfig {
    /// Maximum age of a handshake signature before rejection. Default: 300s. Max: 3600s.
    pub max_signature_age_secs: u64,
    /// QUIC idle timeout. Default: 150s.
    pub idle_timeout_secs: u64,
    /// QUIC keep-alive interval. Must be less than `idle_timeout_secs`. Default: 30s.
    pub keep_alive_interval_secs: u64,
    /// Interval for automatic nonce eviction. Default: 60s.
    pub nonce_cleanup_interval_secs: u64,
    /// Maximum concurrent validator connections. Default: 128.
    pub max_connections: usize,
    /// Hard cap on stored nonces (oldest evicted first). Default: 100,000.
    pub max_nonce_entries: usize,
    /// Per-stream handshake timeout. Must be less than `idle_timeout_secs`. Default: 10s.
    pub handshake_timeout_secs: u64,
    /// Per-IP handshake rate limit (attempts per 60-second window). Default: 30.
    pub max_handshake_attempts_per_minute: u32,
    /// Maximum concurrent bidirectional QUIC streams per connection. Default: 128.
    pub max_concurrent_bidi_streams: u32,
    /// When true, only validators returned by [`ValidatorPermitResolver`](super::ValidatorPermitResolver) can connect. Default: false.
    pub require_validator_permit: bool,
    /// Interval for refreshing the validator permit cache. Default: 1800s.
    pub validator_permit_refresh_secs: u64,
    /// Maximum number of distinct IPs tracked for handshake rate limiting. Default: 10,000.
    pub max_tracked_rate_ips: usize,
    /// Per-request handler timeout. Must be less than `idle_timeout_secs`. Default: 30s.
    pub handler_timeout_secs: u64,
    /// Maximum single-frame payload size in bytes. Default: 64 MiB. Minimum: 1 MiB.
    pub max_frame_payload_bytes: usize,
    /// Capacity of the `mpsc` channel between streaming handlers and the frame writer. Default: 32.
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
    pub fn builder() -> LightningServerConfigBuilder {
        LightningServerConfigBuilder {
            config: Self::default(),
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
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

pub struct LightningServerConfigBuilder {
    config: LightningServerConfig,
}

impl LightningServerConfigBuilder {
    pub fn max_signature_age_secs(mut self, val: u64) -> Self {
        self.config.max_signature_age_secs = val;
        self
    }
    pub fn idle_timeout_secs(mut self, val: u64) -> Self {
        self.config.idle_timeout_secs = val;
        self
    }
    pub fn keep_alive_interval_secs(mut self, val: u64) -> Self {
        self.config.keep_alive_interval_secs = val;
        self
    }
    pub fn nonce_cleanup_interval_secs(mut self, val: u64) -> Self {
        self.config.nonce_cleanup_interval_secs = val;
        self
    }
    pub fn max_connections(mut self, val: usize) -> Self {
        self.config.max_connections = val;
        self
    }
    pub fn max_nonce_entries(mut self, val: usize) -> Self {
        self.config.max_nonce_entries = val;
        self
    }
    pub fn handshake_timeout_secs(mut self, val: u64) -> Self {
        self.config.handshake_timeout_secs = val;
        self
    }
    pub fn max_handshake_attempts_per_minute(mut self, val: u32) -> Self {
        self.config.max_handshake_attempts_per_minute = val;
        self
    }
    pub fn max_concurrent_bidi_streams(mut self, val: u32) -> Self {
        self.config.max_concurrent_bidi_streams = val;
        self
    }
    pub fn require_validator_permit(mut self, val: bool) -> Self {
        self.config.require_validator_permit = val;
        self
    }
    pub fn validator_permit_refresh_secs(mut self, val: u64) -> Self {
        self.config.validator_permit_refresh_secs = val;
        self
    }
    pub fn max_tracked_rate_ips(mut self, val: usize) -> Self {
        self.config.max_tracked_rate_ips = val;
        self
    }
    pub fn handler_timeout_secs(mut self, val: u64) -> Self {
        self.config.handler_timeout_secs = val;
        self
    }
    pub fn max_frame_payload_bytes(mut self, val: usize) -> Self {
        self.config.max_frame_payload_bytes = val;
        self
    }
    pub fn streaming_channel_buffer(mut self, val: usize) -> Self {
        self.config.streaming_channel_buffer = val;
        self
    }
    pub fn build(self) -> Result<LightningServerConfig> {
        self.config.validate()?;
        Ok(self.config)
    }
}
