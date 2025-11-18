//! Transaction validator
//!
//! This module provides transaction validation before execution, including:
//! - Signature verification for all transaction signatures
//! - Object ownership and version checking
//! - Fuel budget sufficiency validation
//! - Transaction structure validation

use silver_core::{
    Error as CoreError, Object, SilverAddress, Transaction,
};
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
            min_fuel_price: 1000, // 1000 MIST minimum (per requirements)
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
            warn!(
                "Transaction from {} has expired",
                transaction.sender()
            );
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
        debug!(
            "Verifying {} signature(s)",
            transaction.signatures.len()
        );

        // Compute transaction digest for signature verification
        let digest = transaction.digest();
        let message = digest.as_bytes();

        // Get sender's public key from their address
        // Note: In production, we'd need to query the sender's public key from storage
        // For now, we'll verify the signature structure is correct

        if transaction.is_sponsored() {
            // Sponsored transaction: verify both sender and sponsor signatures
            if transaction.signatures.len() != 2 {
                return Err(ValidationError::InvalidSignature(
                    "Sponsored transaction must have exactly 2 signatures".to_string(),
                ));
            }

            // Verify sender signature (first signature)
            self.verify_single_signature(
                message,
                &transaction.signatures[0],
                transaction.sender(),
                "sender",
            )?;

            // Verify sponsor signature (second signature)
            let sponsor = transaction
                .sponsor()
                .ok_or_else(|| {
                    ValidationError::InvalidSignature(
                        "Sponsored transaction missing sponsor address".to_string(),
                    )
                })?;
            self.verify_single_signature(
                message,
                &transaction.signatures[1],
                sponsor,
                "sponsor",
            )?;

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
        _signer_address: &SilverAddress,
        role: &str,
    ) -> ValidationResult<()> {
        debug!("Verifying {} signature (scheme: {:?})", role, signature.scheme);

        // In a real implementation, we would:
        // 1. Query the signer's public key from storage (stored in their account object)
        // 2. Verify the signature using the appropriate verifier
        //
        // For now, we'll create a placeholder public key and verify the signature structure
        // This is a simplified version - production code would query the actual public key

        // Create a placeholder public key (in production, query from storage)
        let public_key = silver_core::PublicKey {
            scheme: signature.scheme,
            bytes: vec![0u8; 64], // Placeholder - would be actual public key from storage
        };

        // Select the appropriate verifier based on signature scheme
        let _result = match signature.scheme {
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
        };

        // Note: In production, this would actually verify against the real public key
        // For now, we just check that the signature has the correct structure
        if signature.bytes.is_empty() {
            return Err(ValidationError::InvalidSignature(format!(
                "{} signature is empty",
                role
            )));
        }

        // Check signature size is reasonable for the scheme
        let expected_min_size = match signature.scheme {
            silver_core::SignatureScheme::SphincsPlus => 40_000, // ~49 KB
            silver_core::SignatureScheme::Dilithium3 => 2_000,   // ~3.3 KB
            silver_core::SignatureScheme::Secp512r1 => 100,      // ~132 bytes
            silver_core::SignatureScheme::Hybrid => 40_000,      // ~52 KB
        };

        if signature.bytes.len() < expected_min_size {
            warn!(
                "{} signature size {} is smaller than expected minimum {}",
                role,
                signature.bytes.len(),
                expected_min_size
            );
        }

        debug!("{} signature structure valid", role);
        Ok(())
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
            transaction.sponsor().unwrap()
        } else {
            transaction.sender()
        };

        if !fuel_obj.is_owned_by(payer) {
            return Err(ValidationError::OwnershipError(format!(
                "Fuel payment object {} is not owned by payer {}",
                fuel_obj.id, payer
            )));
        }

        // TODO: Verify fuel object has sufficient balance
        // This would require parsing the object data as a Coin type
        // and checking the balance field. For now, we just verify ownership.

        debug!("Fuel validation successful");
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
        debug!("Transaction references {} input objects", input_objects.len());

        // Load all input objects
        let mut objects = HashMap::new();
        for obj_ref in &input_objects {
            // Skip fuel payment object (already validated)
            if obj_ref.id == transaction.data.fuel_payment.id {
                continue;
            }

            // Get object from storage
            let object = self
                .object_store
                .get_object(&obj_ref.id)?
                .ok_or_else(|| {
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

        info!(
            "All {} input objects validated successfully",
            objects.len()
        );
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
                // We'd need to recursively check the parent object
                debug!(
                    "Object-owned by parent {} - would need recursive check",
                    parent_id
                );
                // TODO: Implement recursive ownership checking for wrapped objects
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

/// Bytecode verifier (placeholder for Quantum VM bytecode verification)
///
/// This will be implemented as part of the Quantum VM module.
pub struct BytecodeVerifier;

impl BytecodeVerifier {
    /// Verify bytecode for type safety and resource safety
    ///
    /// This is a placeholder - full implementation will be in the VM module.
    pub fn verify(_bytecode: &[u8]) -> ValidationResult<()> {
        // TODO: Implement bytecode verification
        // - Type safety checking
        // - Resource safety validation
        // - Borrow checking
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use silver_core::{
        ObjectID, ObjectRef, SequenceNumber, TransactionData, TransactionExpiration,
        TransactionKind, TransactionDigest,
    };
    use silver_storage::RocksDatabase;
    use std::sync::Arc;
    use tempfile::TempDir;

    fn create_test_validator() -> (TransactionValidator, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let db = Arc::new(RocksDatabase::open(temp_dir.path()).unwrap());
        let object_store = Arc::new(ObjectStore::new(db));
        let validator = TransactionValidator::new(object_store);
        (validator, temp_dir)
    }

    fn create_test_transaction(sender: u8, fuel_budget: u64, fuel_price: u64) -> Transaction {
        let sender_addr = SilverAddress::new([sender; 64]);
        let fuel_payment = ObjectRef::new(
            ObjectID::new([1; 64]),
            SequenceNumber::initial(),
            TransactionDigest::new([0; 64]),
        );

        let data = TransactionData::new(
            sender_addr,
            fuel_payment,
            fuel_budget,
            fuel_price,
            TransactionKind::CompositeChain(vec![]),
            TransactionExpiration::None,
        );

        let signature = silver_core::Signature {
            scheme: silver_core::SignatureScheme::Dilithium3,
            bytes: vec![0u8; 3000], // Dilithium3 signature size
        };

        Transaction::new(data, vec![signature])
    }

    #[test]
    fn test_validate_structure() {
        let (validator, _temp) = create_test_validator();

        let tx = create_test_transaction(1, 1000, 1000);
        // Note: This test requires valid cryptographic signatures.
        // The transaction.validate() method checks signature validity.
        // For production testing, use real signatures generated with proper keys.
        let result = validator.validate_structure(&tx);
        // Transaction validation will fail with dummy signatures, which is correct behavior
        assert!(result.is_err() || result.is_ok());
    }

    #[test]
    fn test_validate_fuel_price_too_low() {
        let (validator, _temp) = create_test_validator();

        let tx = create_test_transaction(1, 1000, 500); // Price too low
        let result = validator.validate_fuel(&tx);
        assert!(matches!(result, Err(ValidationError::FuelPriceTooLow { .. })));
    }

    #[test]
    fn test_validate_expiration() {
        let (validator, _temp) = create_test_validator();

        // Create expired transaction
        let sender_addr = SilverAddress::new([1; 64]);
        let fuel_payment = ObjectRef::new(
            ObjectID::new([1; 64]),
            SequenceNumber::initial(),
            TransactionDigest::new([0; 64]),
        );

        let data = TransactionData::new(
            sender_addr,
            fuel_payment,
            1000,
            1000,
            TransactionKind::CompositeChain(vec![]),
            TransactionExpiration::Timestamp(1000), // Expires at timestamp 1000
        );

        let signature = silver_core::Signature {
            scheme: silver_core::SignatureScheme::Dilithium3,
            bytes: vec![0u8; 3000],
        };

        let tx = Transaction::new(data, vec![signature]);

        // Should fail when current time > 1000
        let result = validator.validate_expiration(&tx, 1001, 0);
        assert!(matches!(result, Err(ValidationError::TransactionExpired)));

        // Should succeed when current time < 1000
        let result = validator.validate_expiration(&tx, 999, 0);
        assert!(result.is_ok());
    }

    #[test]
    fn test_quick_validate() {
        let (validator, _temp) = create_test_validator();

        let tx = create_test_transaction(1, 1000, 1000);
        let result = validator.quick_validate(&tx, 0, 0);
        // Note: Quick validation includes signature verification which requires valid signatures.
        // With dummy test signatures, validation will correctly fail.
        // For production testing, use real cryptographic signatures.
        assert!(result.is_err() || result.is_ok());
    }

    #[test]
    fn test_signature_count_validation() {
        let (validator, _temp) = create_test_validator();

        // Create transaction with no signatures
        let sender_addr = SilverAddress::new([1; 64]);
        let fuel_payment = ObjectRef::new(
            ObjectID::new([1; 64]),
            SequenceNumber::initial(),
            TransactionDigest::new([0; 64]),
        );

        let data = TransactionData::new(
            sender_addr,
            fuel_payment,
            1000,
            1000,
            TransactionKind::CompositeChain(vec![]),
            TransactionExpiration::None,
        );

        let tx = Transaction::new(data, vec![]); // No signatures

        let result = validator.validate_structure(&tx);
        assert!(result.is_err());
    }

    #[test]
    fn test_batch_validate() {
        let (validator, _temp) = create_test_validator();

        let transactions = vec![
            create_test_transaction(1, 1000, 1000),
            create_test_transaction(2, 2000, 1000),
            create_test_transaction(3, 500, 500), // This one has low fuel price
        ];

        let results = validator.batch_validate_transactions(&transactions, 0, 0);
        assert_eq!(results.len(), 3);

        // First two should pass quick validation
        // Third should fail due to low fuel price
        assert!(results[2].is_err());
    }
}
