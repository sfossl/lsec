/// max locked memory per buffer (16 mib)
pub const DEFAULT_MAX_LOCKED_MEMORY_BYTES: usize = 16 * 1024 * 1024;

/// argon2id memory (64 mib)
pub const DEFAULT_ARGON2_MEMORY_KIB: u32 = 64 * 1024;

/// minimum argon2id memory (1 mib)
pub const MIN_ARGON2_MEMORY_KIB: u32 = 1024;

/// maximum argon2id memory (1 gib)
pub const MAX_ARGON2_MEMORY_KIB: u32 = 1024 * 1024;

/// argon2id iterations
pub const DEFAULT_ARGON2_ITERATIONS: u32 = 3;

/// minimum argon2id iterations
pub const MIN_ARGON2_ITERATIONS: u32 = 1;

/// maximum argon2id iterations
pub const MAX_ARGON2_ITERATIONS: u32 = 64;

/// argon2id parallelism lanes
pub const DEFAULT_ARGON2_PARALLELISM: u32 = 4;

/// minimum argon2id lanes
pub const MIN_ARGON2_PARALLELISM: u32 = 1;

/// maximum argon2id lanes
pub const MAX_ARGON2_PARALLELISM: u32 = 16;

/// symmetric key length (256 bits)
pub const DEFAULT_KEY_LEN_BYTES: usize = 32;

/// cryptographic salt length (128 bits)
pub const DEFAULT_SALT_LEN_BYTES: usize = 16;

/// aead nonce length (96 bits)
pub const DEFAULT_NONCE_LEN_BYTES: usize = 12;

/// aead tag length (128 bits)
pub const DEFAULT_TAG_LEN_BYTES: usize = 16;

/// vault file permissions (0600)
pub const POSIX_FILE_PERMISSIONS: u32 = 0o600;

/// vault directory permissions (0700)
pub const POSIX_DIR_PERMISSIONS: u32 = 0o700;

/// vault container magic header
pub const VAULT_MAGIC_HEADER: [u8; 6] = [b'L', b'S', b'E', b'C', 0x01, 0x00];

/// totp interval in seconds
pub const DEFAULT_TOTP_STEP_SECONDS: u64 = 30;

/// default totp digits
pub const DEFAULT_TOTP_DIGITS: u32 = 6;

/// minimum totp digits
pub const MIN_TOTP_DIGITS: u32 = 6;

/// maximum totp digits
pub const MAX_TOTP_DIGITS: u32 = 8;

/// allowed totp window drift in steps
pub const DEFAULT_TOTP_DRIFT_STEPS: u8 = 1;

/// clipboard clear delay in seconds
pub const DEFAULT_CLIPBOARD_TIMEOUT_SECONDS: u64 = 15;

/// runtime security parameters
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityConfig {
    /// max locked ram per buffer
    pub max_locked_memory: usize,
    /// argon2id memory in kib
    pub argon2_memory_kib: u32,
    /// argon2id iteration count
    pub argon2_iterations: u32,
    /// argon2id thread lanes
    pub argon2_parallelism: u32,
    /// totp step duration in seconds
    pub totp_step_seconds: u64,
    /// totp code digits
    pub totp_digits: u32,
    /// allowed totp drift steps
    pub totp_drift_steps: u8,
    /// clipboard auto-wipe timeout
    pub clipboard_timeout_seconds: u64,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            max_locked_memory: DEFAULT_MAX_LOCKED_MEMORY_BYTES,
            argon2_memory_kib: DEFAULT_ARGON2_MEMORY_KIB,
            argon2_iterations: DEFAULT_ARGON2_ITERATIONS,
            argon2_parallelism: DEFAULT_ARGON2_PARALLELISM,
            totp_step_seconds: DEFAULT_TOTP_STEP_SECONDS,
            totp_digits: DEFAULT_TOTP_DIGITS,
            totp_drift_steps: DEFAULT_TOTP_DRIFT_STEPS,
            clipboard_timeout_seconds: DEFAULT_CLIPBOARD_TIMEOUT_SECONDS,
        }
    }
}

impl SecurityConfig {
    /// default security config builder
    #[must_use]
    pub fn builder() -> SecurityConfigBuilder {
        SecurityConfigBuilder::default()
    }
}

/// config builder
#[derive(Debug, Default)]
pub struct SecurityConfigBuilder {
    config: SecurityConfig,
}

impl SecurityConfigBuilder {
    /// set max locked buffer size in bytes
    #[must_use]
    pub fn max_locked_memory(mut self, bytes: usize) -> Self {
        self.config.max_locked_memory = bytes;
        self
    }

    /// set argon2id memory in kib
    #[must_use]
    pub fn argon2_memory_kib(mut self, kib: u32) -> Self {
        self.config.argon2_memory_kib = kib;
        self
    }

    /// set argon2id iterations
    #[must_use]
    pub fn argon2_iterations(mut self, iterations: u32) -> Self {
        self.config.argon2_iterations = iterations;
        self
    }

    /// set argon2id thread lanes
    #[must_use]
    pub fn argon2_parallelism(mut self, lanes: u32) -> Self {
        self.config.argon2_parallelism = lanes;
        self
    }

    /// set totp step interval in seconds
    #[must_use]
    pub fn totp_step_seconds(mut self, seconds: u64) -> Self {
        self.config.totp_step_seconds = seconds;
        self
    }

    /// set totp code digits
    #[must_use]
    pub fn totp_digits(mut self, digits: u32) -> Self {
        self.config.totp_digits = digits;
        self
    }

    /// set allowed totp drift steps
    #[must_use]
    pub fn totp_drift_steps(mut self, steps: u8) -> Self {
        self.config.totp_drift_steps = steps;
        self
    }

    /// set clipboard clear delay in seconds
    #[must_use]
    pub fn clipboard_timeout_seconds(mut self, seconds: u64) -> Self {
        self.config.clipboard_timeout_seconds = seconds;
        self
    }

    /// build configuration
    #[must_use]
    pub fn build(self) -> SecurityConfig {
        self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_matches_constants() {
        let cfg = SecurityConfig::default();
        assert_eq!(cfg.max_locked_memory, DEFAULT_MAX_LOCKED_MEMORY_BYTES);
        assert_eq!(cfg.argon2_memory_kib, DEFAULT_ARGON2_MEMORY_KIB);
        assert_eq!(cfg.argon2_iterations, DEFAULT_ARGON2_ITERATIONS);
        assert_eq!(cfg.totp_step_seconds, DEFAULT_TOTP_STEP_SECONDS);
        assert_eq!(cfg.totp_digits, DEFAULT_TOTP_DIGITS);
    }

    #[test]
    fn test_builder_overrides_correctly() {
        let cfg = SecurityConfig::builder()
            .argon2_memory_kib(32768)
            .argon2_iterations(5)
            .totp_step_seconds(60)
            .totp_digits(8)
            .build();

        assert_eq!(cfg.argon2_memory_kib, 32768);
        assert_eq!(cfg.argon2_iterations, 5);
        assert_eq!(cfg.totp_step_seconds, 60);
        assert_eq!(cfg.totp_digits, 8);
        assert_eq!(cfg.max_locked_memory, DEFAULT_MAX_LOCKED_MEMORY_BYTES);
    }
}
