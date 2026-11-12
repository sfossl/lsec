pub mod envelope;
pub mod error;
pub mod format;
pub mod io;
pub mod multi_slot;

pub use envelope::{seal, seal_default, unseal};
pub use error::VaultError;
pub use format::{CipherSuite, KdfAlgorithm, VaultHeader, HEADER_SIZE};
pub use io::{seal_to_file, seal_to_file_default, unseal_from_file};
pub use multi_slot::{MultiSlotVault, MAX_SLOTS, MULTI_HEADER_SIZE, MULTI_VAULT_MAGIC};
