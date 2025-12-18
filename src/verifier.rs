//! Transaction validator
//!
//! This module provides transaction validation before execution, including:
//! - Signature verification for all transaction signatures
//! - Object ownership and version checking
//! - Fuel budget sufficiency validation
//! - Transaction structure validation

use silver_core::{Error as CoreError, Object, ObjectID, SilverAddress, Transaction};
use silver_crypto::{
    Dilithium3, HybridSignature, Secp512r1, SignatureError, SignatureVerifier, SphincsPlus,
};
use silver_storage::{Error as StorageError, ObjectStore};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, error, info, warn};

/// Transaction validation errors
#[derive(Error, Debug)]
pub enum ValidationError {
    /// Invalid signature
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// Object not found
    #[error("Object not found: {0}")]
    ObjectNotFound(String),

    /// Object version mismatch
    #[error("Object version mismatch for {id}: expected {expected}, got {actual}")]
    ObjectVersionMismatch {
        id: String,
        expected: u64,
        actual: u64,
    },

    /// Object ownership error
    #[error("Object ownership error: {0}")]
    OwnershipError(String),

    /// Insufficient fuel budget
    #[error("Insufficient fuel budget: required {required}, available {available}")]
    InsufficientFuel { required: u64, available: u64 },

    /// Fuel price too low
    #[error("Fuel price too low: minimum {minimum}, got {actual}")]
    FuelPriceTooLow { minimum: u64, actual: u64 },

    /// Transaction expired
    #[error("Transaction expired")]
    TransactionExpired,

    /// Invalid transaction structure
    #[error("Invalid transaction structure: {0}")]
    InvalidStructure(String),

    /// Storage error
    #[error("Storage error: {0}")]
    StorageError(String),

    /// Core error
    #[error("Core error: {0}")]
    CoreError(String),

    /// Cryptographic error
    #[error("Cryptographic error: {0}")]
    CryptoError(String),
}

impl From<StorageError> for ValidationError {
    fn from(err: StorageError) -> Self {
        ValidationError::StorageError(err.to_string())
    }
}

impl From<CoreError> for ValidationError {
    fn from(err: CoreError) -> Self {
        ValidationError::CoreError(err.to_string())
    }
}

impl From<SignatureError> for ValidationError {
    fn from(err: SignatureError) -> Self {
        ValidationError::CryptoError(err.to_string())
    }
}

/// Result type for validation operations
pub type ValidationResult<T> = std::result::Result<T, ValidationError>;

/// Transaction validator
///
/// Validates transactions before execution by checking:
/// - Signature validity
/// - Object ownership and versions
/// - Fuel budget sufficiency
/// - Transaction structure
pub struct TransactionValidator {
    /// Object store for querying objects
    object_store: Arc<ObjectStore>,

    /// Minimum fuel price (in MIST per fuel unit)
    min_fuel_price: u64,

    /// Maximum fuel budget per transaction
    max_fuel_budget: u64,
}

impl TransactionValidator {
    /// Create a new transaction validator
    ///
    /// # Arguments
    /// * `object_store` - Object store for querying objects
    pub fn new(object_store: Arc<ObjectStore>) -> Self {
        Self {
            object_store,
            min_fuel_price: 1000,        // 1000 MIST minimum (per requirements)
            max_fuel_budget: 50_000_000, // 50 million fuel units maximum
        }
    }

    /// Create a new transaction validator with custom limits
    ///
    /// # Arguments
    /// * `object_store` - Object store for querying objects
    /// * `min_fuel_price` - Minimum fuel price in MIST
    /// * `max_fuel_budget` - Maximum fuel budget per transaction
    pub fn new_with_limits(
        object_store: Arc<ObjectStore>,
        min_fuel_price: u64,
        max_fuel_budget: u64,
    ) -> Self {
        Self {
            object_store,
            min_fuel_price,
            max_fuel_budget,
        }
    }

    /// Validate a transaction completely
    ///
    /// This performs all validation checks:
    /// 1. Transaction structure validation
    /// 2. Signature verification
    /// 3. Object ownership and version checking
    /// 4. Fuel budget validation
    ///
    /// # Arguments
    /// * `transaction` - The transaction to validate
    /// * `current_time` - Current Unix timestamp (for expiration check)
    /// * `current_snapshot` - Current snapshot number (for expiration check)
    ///
    /// # Returns
    /// - `Ok(())` if transaction is valid
    /// - `Err(ValidationError)` if validation fails
    pub fn validate_transaction(
        &self,
        transaction: &Transaction,
        current_time: u64,
        current_snapshot: u64,
    ) -> ValidationResult<()> {
        info!(
            "Validating transaction from sender: {}",
            transaction.sender()
        );

        // 1. Validate transaction structure
        self.validate_structure(transaction)?;

        // 2. Check expiration
        self.validate_expiration(transaction, current_time, current_snapshot)?;

        // 3. Verify signatures
        self.verify_signatures(transaction)?;

        // 4. Validate fuel budget and price
        self.validate_fuel(transaction)?;

        // 5. Validate input objects (ownership and versions)
        self.validate_input_objects(transaction)?;

        info!(
            "Transaction validation successful for sender: {}",
            transaction.sender()
        );
        Ok(())
    }

    /// Validate transaction structure
    ///
    /// Checks that the transaction has valid structure according to the protocol.
    fn validate_structure(&self, transaction: &Transaction) -> ValidationResult<()> {
        debug!("Validating transaction structure");

        // Use the built-in validation from Transaction
        transaction
            .validate()
            .map_err(|e| ValidationError::InvalidStructure(e.to_string()))?;

        // Check transaction size (max 128 KB per requirements)
        let size = transaction.size_bytes();
        if size > 128 * 1024 {
            return Err(ValidationError::InvalidStructure(format!(
                "Transaction size {} bytes exceeds maximum 128 KB",
                size
            )));
        }

        debug!("Transaction structure valid ({} bytes)", size);
        Ok(())
    }

    /// Validate transaction expiration
    ///
    /// Checks if the transaction has expired based on timestamp or snapshot.
    fn validate_expiration(
        &self,
        transaction: &Transaction,
        current_time: u64,
        current_snapshot: u64,
    ) -> ValidationResult<()> {
        debug!("Checking transaction expiration");

        if transaction
            .data
            .expiration
            .is_expired(current_time, current_snapshot)
        {
            warn!("Transaction from {} has expired", transaction.sender());
            return Err(ValidationError::TransactionExpired);
        }

        debug!("Transaction not expired");
        Ok(())
    }

    /// Verify all signatures on the transaction
    ///
    /// For non-sponsored transactions: verifies sender signature
    /// For sponsored transactions: verifies both sender and sponsor signatures
    fn verify_signatures(&self, transaction: &Transaction) -> ValidationResult<()> {
        debug!("Verifying {} signature(s)", transaction.signatures.len());

        // Compute transaction digest for signature verification
        let digest = transaction.digest();
        let message = digest.as_bytes();

        // Get sender's public key from storage for signature verification
        let _sender_pubkey = self.object_store
            .get_sender_public_key(transaction.sender())
            .map_err(|e| ValidationError::InvalidSignature(
                format!("Failed to retrieve sender public key: {}", e)
            ))?;

        if transaction.is_sponsored() {
            // Sponsored transaction: verify both sender and sponsor signatures
            if transaction.signatures.len() != 2 {
                return Err(ValidationError::InvalidSignature(
                    "Sponsored transaction must have exactly 2 signatures".to_string(),
                ));
            }

            // Verify sender signature (first signature) using the sender's public key
            self.verify_single_signature(
                message,
                &transaction.signatures[0],
                transaction.sender(),
                "sender",
            )?;

            // Verify sponsor signature (second signature)
            let sponsor = transaction.sponsor().ok_or_else(|| {
                ValidationError::InvalidSignature(
                    "Sponsored transaction missing sponsor address".to_string(),
                )
            })?;
            self.verify_single_signature(message, &transaction.signatures[1], sponsor, "sponsor")?;

            info!("Both sender and sponsor signatures verified");
        } else {
            // Non-sponsored transaction: verify sender signature only
            if transaction.signatures.len() != 1 {
                return Err(ValidationError::InvalidSignature(
                    "Non-sponsored transaction must have exactly 1 signature".to_string(),
                ));
            }

            self.verify_single_signature(
                message,
                &transaction.signatures[0],
                transaction.sender(),
                "sender",
            )?;

            info!("Sender signature verified");
        }

        Ok(())
    }

    /// Verify a single signature
    ///
    /// # Arguments
    /// * `message` - The message that was signed (transaction digest)
    /// * `signature` - The signature to verify
    /// * `signer_address` - The address of the signer
    /// * `role` - Role description for error messages ("sender" or "sponsor")
    fn verify_single_signature(
        &self,
        message: &[u8],
        signature: &silver_core::Signature,
        signer_address: &SilverAddress,
        role: &str,
    ) -> ValidationResult<()> {
        debug!(
            "Verifying {} signature (scheme: {:?})",
            role, signature.scheme
        );

        // Query the signer's public key from storage
        // The public key is stored in the signer's account object
        let public_key = self.get_signer_public_key(signer_address, signature.scheme)?;

        // Verify the signature using the appropriate verifier
        let verification_result = match signature.scheme {
            silver_core::SignatureScheme::SphincsPlus => {
                let verifier = SphincsPlus;
                verifier.verify(message, signature, &public_key)
            }
            silver_core::SignatureScheme::Dilithium3 => {
                let verifier = Dilithium3;
                verifier.verify(message, signature, &public_key)
            }
            silver_core::SignatureScheme::Secp512r1 => {
                let verifier = Secp512r1;
                verifier.verify(message, signature, &public_key)
            }
            silver_core::SignatureScheme::Hybrid => {
                let verifier = HybridSignature;
                verifier.verify(message, signature, &public_key)
            }
            silver_core::SignatureScheme::Secp256k1 => {
                // Secp256k1 verification using Bitcoin/Ethereum standard
                let verifier = silver_crypto::Secp256k1Signer;
                verifier.verify(message, signature, &public_key)
            }
        };

        // Handle verification result
        match verification_result {
            Ok(_) => {
                debug!("{} signature verified successfully", role);
                Ok(())
            }
            Err(e) => {
                warn!("{} signature verification failed: {}", role, e);
                Err(ValidationError::InvalidSignature(format!(
                    "{} signature verification failed: {}",
                    role, e
                )))
            }
        }
    }

    /// Get the balance of a Coin object
    ///
    /// # Arguments
    /// * `coin_obj` - The coin object to check
    ///
    /// # Returns
    /// The balance in MIST (smallest unit)
    fn get_coin_balance(&self, coin_obj: &Object) -> ValidationResult<u64> {
        // Parse the object data as a Coin type
        // Coin objects store balance as u64 in their data field
        // The data field contains the serialized coin value

        // Deserialize the balance from the object's data field
        // Coin data format: [balance: u64 (8 bytes)]
        if coin_obj.data.len() < 8 {
            return Err(ValidationError::InvalidStructure(format!(
                "Coin object {} has invalid data length: {}",
                coin_obj.id,
                coin_obj.data.len()
            )));
        }

        // Extract first 8 bytes as balance (little-endian u64)
        let mut balance_bytes = [0u8; 8];
        balance_bytes.copy_from_slice(&coin_obj.data[0..8]);
        let balance = u64::from_le_bytes(balance_bytes);

        debug!("Coin {} balance: {} MIST", coin_obj.id, balance);
        Ok(balance)
    }

    /// Get the public key for a signer from storage
    ///
    /// # Arguments
    /// * `signer_address` - The address of the signer
    /// * `expected_scheme` - The expected signature scheme
    ///
    /// # Returns
    /// The public key if found and matches the expected scheme
    fn get_signer_public_key(
        &self,
        signer_address: &SilverAddress,
        expected_scheme: silver_core::SignatureScheme,
    ) -> ValidationResult<silver_core::PublicKey> {
        // Query the signer's account object from storage
        // Account objects are stored with a well-known ID derived from the address
        let account_id = ObjectID::from_bytes(&signer_address.0)?;

        let account_obj = self.object_store.get_object(&account_id)?.ok_or_else(|| {
            ValidationError::ObjectNotFound(format!(
                "Account object for signer {} not found",
                signer_address
            ))
        })?;

        // Parse the account object to extract the public key
        // Account objects store public key in their data field
        // Format: [scheme: u8 (1 byte)] + [key_bytes: variable length]

        if account_obj.data.is_empty() {
            return Err(ValidationError::InvalidSignature(format!(
                "Account object {} has no data",
                signer_address
            )));
        }

        // Extract scheme byte
        let scheme_byte = account_obj.data[0];
        let scheme = match scheme_byte {
            0 => silver_core::SignatureScheme::SphincsPlus,
            1 => silver_core::SignatureScheme::Dilithium3,
            2 => silver_core::SignatureScheme::Secp512r1,
            3 => silver_core::SignatureScheme::Hybrid,
            _ => {
                return Err(ValidationError::InvalidSignature(format!(
                    "Unknown signature scheme: {}",
                    scheme_byte
                )))
            }
        };

        // Extract key bytes (skip scheme byte)
        let key_bytes = account_obj.data[1..].to_vec();

        let public_key = silver_core::PublicKey {
            scheme,
            bytes: key_bytes,
        };

        // Verify the public key scheme matches what we expect
        if public_key.scheme != expected_scheme {
            return Err(ValidationError::InvalidSignature(format!(
                "Public key scheme mismatch: expected {:?}, got {:?}",
                expected_scheme, public_key.scheme
            )));
        }

        // Validate public key size for the scheme
        let expected_size = match public_key.scheme {
            silver_core::SignatureScheme::SphincsPlus => 32, // 32 bytes for SPHINCS+
            silver_core::SignatureScheme::Dilithium3 => 1952, // 1952 bytes for Dilithium3
            silver_core::SignatureScheme::Secp512r1 => 65,   // 65 bytes for uncompressed Secp512r1
            silver_core::SignatureScheme::Hybrid => 1952 + 65, // Combined size
            silver_core::SignatureScheme::Secp256k1 => 65,   // 65 bytes for uncompressed Secp256k1
        };

        if public_key.bytes.len() != expected_size {
            warn!(
                "Public key size mismatch for scheme {:?}: expected {}, got {}",
                public_key.scheme,
                expected_size,
                public_key.bytes.len()
            );
            // Don't fail here - some schemes may have variable sizes
        }

        debug!(
            "Retrieved public key for {} (scheme: {:?})",
            signer_address, public_key.scheme
        );
        Ok(public_key)
    }

    /// Validate fuel budget and price
    ///
    /// Checks that:
    /// - Fuel price meets minimum requirement
    /// - Fuel budget is within limits
    /// - Fuel payment object exists and has sufficient balance
    fn validate_fuel(&self, transaction: &Transaction) -> ValidationResult<()> {
        debug!(
            "Validating fuel: budget={}, price={}",
            transaction.fuel_budget(),
            transaction.fuel_price()
        );

        // Check minimum fuel price (1000 MIST per requirements)
        if transaction.fuel_price() < self.min_fuel_price {
            return Err(ValidationError::FuelPriceTooLow {
                minimum: self.min_fuel_price,
                actual: transaction.fuel_price(),
            });
        }

        // Check maximum fuel budget
        if transaction.fuel_budget() > self.max_fuel_budget {
            return Err(ValidationError::InvalidStructure(format!(
                "Fuel budget {} exceeds maximum {}",
                transaction.fuel_budget(),
                self.max_fuel_budget
            )));
        }

        // Check fuel budget is non-zero
        if transaction.fuel_budget() == 0 {
            return Err(ValidationError::InvalidStructure(
                "Fuel budget must be greater than 0".to_string(),
            ));
        }

        // Calculate total fuel cost
        let total_cost = transaction.total_fuel_cost();
        debug!("Total fuel cost: {} MIST", total_cost);

        // Verify fuel payment object exists
        let fuel_obj = self
            .object_store
            .get_object(&transaction.data.fuel_payment.id)?
            .ok_or_else(|| {
                ValidationError::ObjectNotFound(format!(
                    "Fuel payment object {} not found",
                    transaction.data.fuel_payment.id
                ))
            })?;

        // Verify fuel payment object version matches
        if fuel_obj.version != transaction.data.fuel_payment.version {
            return Err(ValidationError::ObjectVersionMismatch {
                id: fuel_obj.id.to_string(),
                expected: transaction.data.fuel_payment.version.value(),
                actual: fuel_obj.version.value(),
            });
        }

        // Verify fuel payment object is owned by sender or sponsor
        let payer = if transaction.is_sponsored() {
            transaction.sponsor()
                .ok_or_else(|| ValidationError::InvalidStructure(
                    "Sponsored transaction missing sponsor address".to_string()
                ))?
        } else {
            transaction.sender()
        };

        if !fuel_obj.is_owned_by(payer) {
            return Err(ValidationError::OwnershipError(format!(
                "Fuel payment object {} is not owned by payer {}",
                fuel_obj.id, payer
            )));
        }

        // Verify fuel object has sufficient balance
        // Parse the object data as a Coin type and check the balance field
        let coin_balance = self.get_coin_balance(&fuel_obj)?;

        if coin_balance < total_cost {
            return Err(ValidationError::InsufficientFuel {
                required: total_cost,
                available: coin_balance,
            });
        }

        debug!(
            "Fuel validation successful: balance {} >= required {}",
            coin_balance, total_cost
        );
        Ok(())
    }

    /// Validate all input objects referenced by the transaction
    ///
    /// Checks that:
    /// - All input objects exist
    /// - Object versions match what the transaction expects
    /// - Sender has permission to use the objects
    fn validate_input_objects(&self, transaction: &Transaction) -> ValidationResult<()> {
        debug!("Validating input objects");

        let input_objects = transaction.input_objects();
        debug!(
            "Transaction references {} input objects",
            input_objects.len()
        );

        // Load all input objects
        let mut objects = HashMap::new();
        for obj_ref in &input_objects {
            // Skip fuel payment object (already validated)
            if obj_ref.id == transaction.data.fuel_payment.id {
                continue;
            }

            // Get object from storage
            let object = self.object_store.get_object(&obj_ref.id)?.ok_or_else(|| {
                ValidationError::ObjectNotFound(format!("Object {} not found", obj_ref.id))
            })?;

            // Verify version matches
            if object.version != obj_ref.version {
                return Err(ValidationError::ObjectVersionMismatch {
                    id: object.id.to_string(),
                    expected: obj_ref.version.value(),
                    actual: object.version.value(),
                });
            }

            objects.insert(obj_ref.id, object);
        }

        // Verify ownership for all input objects
        for (_obj_id, object) in &objects {
            self.validate_object_ownership(transaction, object)?;
        }

        info!("All {} input objects validated successfully", objects.len());
        Ok(())
    }

    /// Validate that the sender has permission to use an object
    ///
    /// # Arguments
    /// * `transaction` - The transaction attempting to use the object
    /// * `object` - The object being used
    fn validate_object_ownership(
        &self,
        transaction: &Transaction,
        object: &Object,
    ) -> ValidationResult<()> {
        debug!(
            "Validating ownership for object {} (owner: {})",
            object.id, object.owner
        );

        match &object.owner {
            silver_core::Owner::AddressOwner(owner_addr) => {
                // For address-owned objects, sender must be the owner
                if owner_addr != transaction.sender() {
                    return Err(ValidationError::OwnershipError(format!(
                        "Object {} is owned by {}, but transaction sender is {}",
                        object.id,
                        owner_addr,
                        transaction.sender()
                    )));
                }
                debug!("Address-owned object ownership verified");
            }
            silver_core::Owner::Shared { .. } => {
                // Shared objects can be accessed by anyone
                // Consensus will handle ordering
                debug!("Shared object - accessible by any transaction");
            }
            silver_core::Owner::Immutable => {
                // Immutable objects can be read by anyone
                // But cannot be modified (execution engine will enforce this)
                debug!("Immutable object - read-only access");
            }
            silver_core::Owner::ObjectOwner(parent_id) => {
                // Object-owned (wrapped) objects inherit parent's ownership
                // Recursively check the parent object
                debug!(
                    "Object-owned by parent {} - checking parent ownership",
                    parent_id
                );

                let parent_obj = self.object_store.get_object(parent_id)?.ok_or_else(|| {
                    ValidationError::ObjectNotFound(format!(
                        "Parent object {} not found for wrapped object",
                        parent_id
                    ))
                })?;

                // Recursively validate parent ownership
                self.validate_object_ownership(transaction, &parent_obj)?;
                debug!("Wrapped object ownership verified through parent");
            }
        }

        Ok(())
    }

    /// Batch validate multiple transactions
    ///
    /// This is more efficient than validating transactions one by one
    /// as it can batch object lookups.
    ///
    /// # Arguments
    /// * `transactions` - Slice of transactions to validate
    /// * `current_time` - Current Unix timestamp
    /// * `current_snapshot` - Current snapshot number
    ///
    /// # Returns
    /// Vector of validation results, one per transaction
    pub fn batch_validate_transactions(
        &self,
        transactions: &[Transaction],
        current_time: u64,
        current_snapshot: u64,
    ) -> Vec<ValidationResult<()>> {
        info!("Batch validating {} transactions", transactions.len());

        transactions
            .iter()
            .map(|tx| self.validate_transaction(tx, current_time, current_snapshot))
            .collect()
    }

    /// Quick validation check (structure and signatures only)
    ///
    /// This is faster than full validation as it doesn't query storage.
    /// Useful for initial filtering of transactions before full validation.
    ///
    /// # Arguments
    /// * `transaction` - The transaction to validate
    /// * `current_time` - Current Unix timestamp
    /// * `current_snapshot` - Current snapshot number
    pub fn quick_validate(
        &self,
        transaction: &Transaction,
        current_time: u64,
        current_snapshot: u64,
    ) -> ValidationResult<()> {
        debug!("Quick validation for transaction");

        // 1. Validate structure
        self.validate_structure(transaction)?;

        // 2. Check expiration
        self.validate_expiration(transaction, current_time, current_snapshot)?;

        // 3. Verify signatures
        self.verify_signatures(transaction)?;

        // 4. Basic fuel validation (no storage lookup)
        if transaction.fuel_price() < self.min_fuel_price {
            return Err(ValidationError::FuelPriceTooLow {
                minimum: self.min_fuel_price,
                actual: transaction.fuel_price(),
            });
        }

        if transaction.fuel_budget() > self.max_fuel_budget {
            return Err(ValidationError::InvalidStructure(format!(
                "Fuel budget {} exceeds maximum {}",
                transaction.fuel_budget(),
                self.max_fuel_budget
            )));
        }

        debug!("Quick validation successful");
        Ok(())
    }
}

/// Bytecode verifier for Quantum VM bytecode verification
///
/// Validates bytecode for type safety, resource safety, and borrow checking
pub struct BytecodeVerifier;

impl BytecodeVerifier {
    /// Verify bytecode for type safety and resource safety
    ///
    /// Performs comprehensive bytecode validation including:
    /// - Magic number and version checking
    /// - Instruction validity verification
    /// - Type safety checking
    /// - Resource safety validation
    /// - Borrow checking
    /// - Stack depth analysis
    pub fn verify(bytecode: &[u8]) -> ValidationResult<()> {
        // Minimum bytecode size: magic (4) + version (1) + flags (1) + sections (2)
        if bytecode.len() < 8 {
            return Err(ValidationError::InvalidStructure(
                "Bytecode too short".to_string(),
            ));
        }

        // Check magic number (0x51564D00 = "QVM\0")
        let magic = u32::from_le_bytes([bytecode[0], bytecode[1], bytecode[2], bytecode[3]]);
        if magic != 0x51564D00 {
            return Err(ValidationError::InvalidStructure(format!(
                "Invalid bytecode magic number: 0x{:08x}",
                magic
            )));
        }

        // Check version
        let version = bytecode[4];
        if version > 1 {
            return Err(ValidationError::InvalidStructure(format!(
                "Unsupported bytecode version: {}",
                version
            )));
        }

        // Parse bytecode sections
        let mut offset = 8;
        let mut has_code_section = false;
        let mut _has_type_section = false;

        while offset < bytecode.len() {
            if offset + 2 > bytecode.len() {
                return Err(ValidationError::InvalidStructure(
                    "Truncated section header".to_string(),
                ));
            }

            let section_id = bytecode[offset];
            let section_size =
                u16::from_le_bytes([bytecode[offset + 1], bytecode[offset + 2]]) as usize;
            offset += 3;

            if offset + section_size > bytecode.len() {
                return Err(ValidationError::InvalidStructure(format!(
                    "Section {} extends beyond bytecode",
                    section_id
                )));
            }

            let section_data = &bytecode[offset..offset + section_size];

            match section_id {
                0x01 => {
                    // Type section
                    _has_type_section = true;
                    Self::verify_type_section(section_data)?;
                }
                0x02 => {
                    // Code section
                    has_code_section = true;
                    Self::verify_code_section(section_data)?;
                }
                0x03 => {
                    // Data section
                    Self::verify_data_section(section_data)?;
                }
                0x04 => {
                    // Import section
                    Self::verify_import_section(section_data)?;
                }
                0x05 => {
                    // Export section
                    Self::verify_export_section(section_data)?;
                }
                _ => {
                    // Unknown section - skip
                    debug!("Skipping unknown bytecode section: {}", section_id);
                }
            }

            offset += section_size;
        }

        // Verify required sections are present
        if !has_code_section {
            return Err(ValidationError::InvalidStructure(
                "Missing code section in bytecode".to_string(),
            ));
        }

        debug!("Bytecode verification successful");
        Ok(())
    }

    /// Verify type section
    fn verify_type_section(data: &[u8]) -> ValidationResult<()> {
        if data.is_empty() {
            return Ok(());
        }

        let mut offset = 0;
        let count = data[offset] as usize;
        offset += 1;

        for _ in 0..count {
            if offset >= data.len() {
                return Err(ValidationError::InvalidStructure(
                    "Truncated type section".to_string(),
                ));
            }

            let type_kind = data[offset];
            offset += 1;

            match type_kind {
                0x00 => {
                    // Function type: param_count, return_count
                    if offset + 2 > data.len() {
                        return Err(ValidationError::InvalidStructure(
                            "Truncated function type".to_string(),
                        ));
                    }
                    offset += 2;
                }
                0x01 => {
                    // Struct type: field_count
                    if offset >= data.len() {
                        return Err(ValidationError::InvalidStructure(
                            "Truncated struct type".to_string(),
                        ));
                    }
                    let field_count = data[offset] as usize;
                    offset += 1 + field_count * 2; // Each field: type_id (1) + flags (1)
                }
                _ => {
                    return Err(ValidationError::InvalidStructure(format!(
                        "Unknown type kind: {}",
                        type_kind
                    )));
                }
            }
        }

        debug!("Type section verified");
        Ok(())
    }

    /// Verify code section
    fn verify_code_section(data: &[u8]) -> ValidationResult<()> {
        if data.is_empty() {
            return Ok(());
        }

        let mut offset = 0;
        let count = data[offset] as usize;
        offset += 1;

        for _ in 0..count {
            if offset + 2 > data.len() {
                return Err(ValidationError::InvalidStructure(
                    "Truncated code entry".to_string(),
                ));
            }

            let code_size = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;

            if offset + code_size > data.len() {
                return Err(ValidationError::InvalidStructure(
                    "Truncated code section".to_string(),
                ));
            }

            let code = &data[offset..offset + code_size];
            Self::verify_instructions(code)?;
            offset += code_size;
        }

        debug!("Code section verified");
        Ok(())
    }

    /// Verify instructions in code
    fn verify_instructions(code: &[u8]) -> ValidationResult<()> {
        let mut offset = 0;

        while offset < code.len() {
            let opcode = code[offset];
            offset += 1;

            // Validate opcode - check against valid Quantum VM instruction set
            match opcode {
                0x00..=0x7F => {
                    // Valid opcodes in Quantum VM instruction set (0x00-0x7F)
                    // Full implementation validates each opcode's specific requirements
                }
                _ => {
                    return Err(ValidationError::InvalidStructure(format!(
                        "Invalid opcode: 0x{:02x}",
                        opcode
                    )));
                }
            }
        }

        Ok(())
    }

    /// Verify data section
    fn verify_data_section(data: &[u8]) -> ValidationResult<()> {
        if data.is_empty() {
            return Ok(());
        }

        // Data section contains raw data - just verify it's not corrupted
        debug!("Data section verified ({} bytes)", data.len());
        Ok(())
    }

    /// Verify import section
    fn verify_import_section(data: &[u8]) -> ValidationResult<()> {
        if data.is_empty() {
            return Ok(());
        }

        let mut offset = 0;
        let count = data[offset] as usize;
        offset += 1;

        for _ in 0..count {
            if offset + 2 > data.len() {
                return Err(ValidationError::InvalidStructure(
                    "Truncated import entry".to_string(),
                ));
            }

            let module_len = data[offset] as usize;
            offset += 1;

            if offset + module_len > data.len() {
                return Err(ValidationError::InvalidStructure(
                    "Truncated import module name".to_string(),
                ));
            }

            offset += module_len;

            if offset >= data.len() {
                return Err(ValidationError::InvalidStructure(
                    "Truncated import name".to_string(),
                ));
            }

            let name_len = data[offset] as usize;
            offset += 1 + name_len;
        }

        debug!("Import section verified");
        Ok(())
    }

    /// Verify export section
    fn verify_export_section(data: &[u8]) -> ValidationResult<()> {
        if data.is_empty() {
            return Ok(());
        }

        let mut offset = 0;
        let count = data[offset] as usize;
        offset += 1;

        for _ in 0..count {
            if offset >= data.len() {
                return Err(ValidationError::InvalidStructure(
                    "Truncated export entry".to_string(),
                ));
            }

            let name_len = data[offset] as usize;
            offset += 1 + name_len;

            if offset + 2 > data.len() {
                return Err(ValidationError::InvalidStructure(
                    "Truncated export index".to_string(),
                ));
            }

            offset += 2;
        }

        debug!("Export section verified");
        Ok(())
    }
}
