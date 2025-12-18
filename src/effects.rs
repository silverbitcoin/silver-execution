//! Transaction effects and execution results
//!
//! This module defines the effects of transaction execution:
//! - Object mutations (created, modified, deleted)
//! - Fuel usage breakdown
//! - Emitted events
//! - Execution status

use serde::{Deserialize, Serialize};
use silver_core::{Object, ObjectID, SilverAddress};
use tracing::error;

/// Execution status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionStatus {
    /// Transaction executed successfully
    Success,

    /// Transaction execution failed
    Failed,
}

/// Transaction execution result
///
/// Contains all effects of executing a transaction, including:
/// - Execution status (success/failure)
/// - Fuel usage and refund
/// - Object mutations
/// - Emitted events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    /// Execution status
    pub status: ExecutionStatus,

    /// Fuel consumed during execution
    pub fuel_used: u64,

    /// Fuel refunded (unused portion of budget)
    pub fuel_refund: u64,

    /// Objects that were modified
    pub modified_objects: Vec<Object>,

    /// Objects that were created
    pub created_objects: Vec<Object>,

    /// Object IDs that were deleted
    pub deleted_objects: Vec<ObjectID>,

    /// Events emitted during execution
    pub events: Vec<Event>,

    /// Error message if execution failed
    pub error_message: Option<String>,
}

impl ExecutionResult {
    /// Check if execution was successful
    pub fn is_success(&self) -> bool {
        self.status == ExecutionStatus::Success
    }

    /// Check if execution failed
    pub fn is_failure(&self) -> bool {
        self.status == ExecutionStatus::Failed
    }

    /// Get total fuel cost (used fuel * price)
    pub fn total_fuel_cost(&self, fuel_price: u64) -> u64 {
        self.fuel_used.saturating_mul(fuel_price)
    }

    /// Get refund amount (refunded fuel * price)
    pub fn refund_amount(&self, fuel_price: u64) -> u64 {
        self.fuel_refund.saturating_mul(fuel_price)
    }

    /// Get all affected object IDs
    pub fn affected_objects(&self) -> Vec<ObjectID> {
        let mut objects = Vec::new();

        // Add modified objects
        objects.extend(self.modified_objects.iter().map(|o| o.id));

        // Add created objects
        objects.extend(self.created_objects.iter().map(|o| o.id));

        // Add deleted objects
        objects.extend(self.deleted_objects.iter().copied());

        objects
    }

    /// Get the number of state changes
    pub fn state_change_count(&self) -> usize {
        self.modified_objects.len() + self.created_objects.len() + self.deleted_objects.len()
    }
}

/// Event emitted during transaction execution
///
/// Events provide a way for smart contracts to emit structured data
/// that can be observed by external systems.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Event type identifier
    pub event_type: String,

    /// Address that emitted the event (transaction sender)
    pub sender: SilverAddress,

    /// Event data (serialized)
    pub data: Vec<u8>,
}

impl Event {
    /// Create a new event
    pub fn new(event_type: String, sender: SilverAddress, data: Vec<u8>) -> Self {
        Self {
            event_type,
            sender,
            data,
        }
    }

    /// Get the event type
    pub fn event_type(&self) -> &str {
        &self.event_type
    }

    /// Get the sender address
    pub fn sender(&self) -> &SilverAddress {
        &self.sender
    }

    /// Get the event data
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get the size of the event in bytes
    pub fn size_bytes(&self) -> usize {
        self.event_type.len() + std::mem::size_of::<SilverAddress>() + self.data.len()
    }
}

/// Transaction effects (detailed breakdown)
///
/// This provides a more detailed view of transaction effects,
/// including per-command effects and fuel breakdown.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionEffects {
    /// Transaction digest
    pub transaction_digest: silver_core::TransactionDigest,

    /// Execution result
    pub result: ExecutionResult,

    /// Per-command effects
    pub command_effects: Vec<CommandEffect>,

    /// Fuel usage breakdown
    pub fuel_breakdown: FuelBreakdown,

    /// Cryptographic signature of effects (for verification)
    pub signature: Option<Vec<u8>>,

    /// Timestamp when effects were generated
    pub timestamp: u64,
}

impl TransactionEffects {
    /// Create new transaction effects
    pub fn new(
        transaction_digest: silver_core::TransactionDigest,
        result: ExecutionResult,
        command_effects: Vec<CommandEffect>,
        fuel_breakdown: FuelBreakdown,
    ) -> Self {
        Self {
            transaction_digest,
            result,
            command_effects,
            fuel_breakdown,
            signature: None,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or_else(|e| {
                    error!("Failed to get system time: {}", e);
                    0
                }),
        }
    }

    /// Create new transaction effects with signature
    pub fn new_with_signature(
        transaction_digest: silver_core::TransactionDigest,
        result: ExecutionResult,
        command_effects: Vec<CommandEffect>,
        fuel_breakdown: FuelBreakdown,
        signature: Vec<u8>,
    ) -> Self {
        Self {
            transaction_digest,
            result,
            command_effects,
            fuel_breakdown,
            signature: Some(signature),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or_else(|e| {
                    error!("Failed to get system time: {}", e);
                    0
                }),
        }
    }

    /// Get the transaction digest
    pub fn digest(&self) -> &silver_core::TransactionDigest {
        &self.transaction_digest
    }

    /// Check if transaction was successful
    pub fn is_success(&self) -> bool {
        self.result.is_success()
    }

    /// Get total fuel used
    pub fn fuel_used(&self) -> u64 {
        self.result.fuel_used
    }

    /// Sign the effects with a validator key
    ///
    /// This creates a cryptographic signature over the effects data
    /// to enable independent verification.
    pub fn sign(&mut self, signature: Vec<u8>) {
        self.signature = Some(signature);
    }

    /// Verify the effects signature
    ///
    /// Returns true if the signature is valid, false otherwise.
    pub fn verify_signature(&self, public_key: &[u8]) -> bool {
        // Verify the effects signature using the provided public key
        if let Some(sig) = &self.signature {
            // Compute the effects digest
            let digest = self.compute_effects_digest();

            // Verify signature using Dilithium3 (default scheme for effects)
            use silver_crypto::SignatureVerifier;
            let verifier = silver_crypto::Dilithium3;

            let public_key_obj = silver_core::PublicKey {
                scheme: silver_core::SignatureScheme::Dilithium3,
                bytes: public_key.to_vec(),
            };

            let signature_obj = silver_core::Signature {
                scheme: silver_core::SignatureScheme::Dilithium3,
                bytes: sig.clone(),
            };

            match verifier.verify(&digest, &signature_obj, &public_key_obj) {
                Ok(_) => true,
                Err(e) => {
                    tracing::warn!("Effects signature verification failed: {}", e);
                    false
                }
            }
        } else {
            false
        }
    }

    /// Compute a digest of the effects for signing
    ///
    /// This creates a canonical representation of the effects
    /// that can be signed by validators.
    pub fn compute_effects_digest(&self) -> [u8; 64] {
        let mut hasher = blake3::Hasher::new();

        // Hash transaction digest
        hasher.update(self.transaction_digest.as_bytes());

        // Hash execution status
        let status_byte = match self.result.status {
            ExecutionStatus::Success => 1u8,
            ExecutionStatus::Failed => 0u8,
        };
        hasher.update(&[status_byte]);

        // Hash fuel usage
        hasher.update(&self.result.fuel_used.to_le_bytes());
        hasher.update(&self.result.fuel_refund.to_le_bytes());

        // Hash object mutations
        hasher.update(&(self.result.modified_objects.len() as u64).to_le_bytes());
        for obj in &self.result.modified_objects {
            hasher.update(obj.id.as_bytes());
            hasher.update(&obj.version.value().to_le_bytes());
        }

        hasher.update(&(self.result.created_objects.len() as u64).to_le_bytes());
        for obj in &self.result.created_objects {
            hasher.update(obj.id.as_bytes());
        }

        hasher.update(&(self.result.deleted_objects.len() as u64).to_le_bytes());
        for obj_id in &self.result.deleted_objects {
            hasher.update(obj_id.as_bytes());
        }

        // Hash events
        hasher.update(&(self.result.events.len() as u64).to_le_bytes());
        for event in &self.result.events {
            hasher.update(event.event_type.as_bytes());
            hasher.update(event.sender.as_bytes());
            hasher.update(&event.data);
        }

        // Finalize hash
        let mut output = [0u8; 64];
        hasher.finalize_xof().fill(&mut output);
        output
    }

    /// Get a summary of the effects
    pub fn summary(&self) -> EffectsSummary {
        EffectsSummary {
            transaction_digest: self.transaction_digest,
            status: self.result.status,
            fuel_used: self.result.fuel_used,
            fuel_refund: self.result.fuel_refund,
            objects_modified: self.result.modified_objects.len(),
            objects_created: self.result.created_objects.len(),
            objects_deleted: self.result.deleted_objects.len(),
            events_emitted: self.result.events.len(),
            timestamp: self.timestamp,
        }
    }
}

/// Summary of transaction effects
///
/// A compact representation of effects for quick queries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffectsSummary {
    /// Transaction digest
    pub transaction_digest: silver_core::TransactionDigest,

    /// Execution status
    pub status: ExecutionStatus,

    /// Fuel used
    pub fuel_used: u64,

    /// Fuel refunded
    pub fuel_refund: u64,

    /// Number of objects modified
    pub objects_modified: usize,

    /// Number of objects created
    pub objects_created: usize,

    /// Number of objects deleted
    pub objects_deleted: usize,

    /// Number of events emitted
    pub events_emitted: usize,

    /// Timestamp
    pub timestamp: u64,
}

/// Effect of executing a single command
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandEffect {
    /// Command index in the transaction
    pub command_index: usize,

    /// Objects read by this command
    pub objects_read: Vec<ObjectID>,

    /// Objects modified by this command
    pub objects_modified: Vec<ObjectID>,

    /// Objects created by this command
    pub objects_created: Vec<ObjectID>,

    /// Objects deleted by this command
    pub objects_deleted: Vec<ObjectID>,

    /// Fuel consumed by this command
    pub fuel_used: u64,
}

impl CommandEffect {
    /// Create a new command effect
    pub fn new(command_index: usize) -> Self {
        Self {
            command_index,
            objects_read: Vec::new(),
            objects_modified: Vec::new(),
            objects_created: Vec::new(),
            objects_deleted: Vec::new(),
            fuel_used: 0,
        }
    }

    /// Add a read object
    pub fn add_read(&mut self, object_id: ObjectID) {
        self.objects_read.push(object_id);
    }

    /// Add a modified object
    pub fn add_modified(&mut self, object_id: ObjectID) {
        self.objects_modified.push(object_id);
    }

    /// Add a created object
    pub fn add_created(&mut self, object_id: ObjectID) {
        self.objects_created.push(object_id);
    }

    /// Add a deleted object
    pub fn add_deleted(&mut self, object_id: ObjectID) {
        self.objects_deleted.push(object_id);
    }

    /// Set fuel used
    pub fn set_fuel_used(&mut self, fuel: u64) {
        self.fuel_used = fuel;
    }
}

/// Fuel usage breakdown
///
/// Provides detailed breakdown of fuel consumption by category.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuelBreakdown {
    /// Fuel used for computation (VM execution)
    pub computation: u64,

    /// Fuel used for storage operations
    pub storage: u64,

    /// Fuel used for network operations
    pub network: u64,

    /// Fuel used for cryptographic operations
    pub crypto: u64,

    /// Base transaction fee
    pub base_fee: u64,
}

impl FuelBreakdown {
    /// Create a new fuel breakdown
    pub fn new() -> Self {
        Self {
            computation: 0,
            storage: 0,
            network: 0,
            crypto: 0,
            base_fee: 0,
        }
    }

    /// Get total fuel used
    pub fn total(&self) -> u64 {
        self.computation + self.storage + self.network + self.crypto + self.base_fee
    }

    /// Add computation fuel
    pub fn add_computation(&mut self, fuel: u64) {
        self.computation = self.computation.saturating_add(fuel);
    }

    /// Add storage fuel
    pub fn add_storage(&mut self, fuel: u64) {
        self.storage = self.storage.saturating_add(fuel);
    }

    /// Add network fuel
    pub fn add_network(&mut self, fuel: u64) {
        self.network = self.network.saturating_add(fuel);
    }

    /// Add crypto fuel
    pub fn add_crypto(&mut self, fuel: u64) {
        self.crypto = self.crypto.saturating_add(fuel);
    }

    /// Set base fee
    pub fn set_base_fee(&mut self, fuel: u64) {
        self.base_fee = fuel;
    }
}

impl Default for FuelBreakdown {
    fn default() -> Self {
        Self::new()
    }
}
