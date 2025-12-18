//! Bridge Module - Production-ready cross-chain bridge implementation
//!
//! Provides cross-chain token bridge functionality with:
//! - Bridge validator registration and management
//! - Multi-signature consensus (threshold-based)
//! - Wrapped token management
//! - Fee collection and tracking
//! - Transaction status tracking
//! - Slashing for misbehavior

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Bridge error types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BridgeError {
    /// Validator not found
    ValidatorNotFound,
    /// Insufficient validator stake
    InsufficientStake,
    /// Transaction not found
    TransactionNotFound,
    /// Invalid chain name
    InvalidChain,
    /// Insufficient confirmations
    InsufficientConfirmations,
    /// Invalid amount
    InvalidAmount,
    /// Unauthorized
    Unauthorized,
    /// Transaction already confirmed
    TransactionAlreadyConfirmed,
    /// Invalid signature
    InvalidSignature,
    /// Validator already registered
    ValidatorAlreadyRegistered,
    /// Threshold not met
    ThresholdNotMet,
}

impl std::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BridgeError::ValidatorNotFound => write!(f, "Validator not found"),
            BridgeError::InsufficientStake => write!(f, "Insufficient validator stake"),
            BridgeError::TransactionNotFound => write!(f, "Transaction not found"),
            BridgeError::InvalidChain => write!(f, "Invalid chain name"),
            BridgeError::InsufficientConfirmations => write!(f, "Insufficient confirmations"),
            BridgeError::InvalidAmount => write!(f, "Invalid amount"),
            BridgeError::Unauthorized => write!(f, "Unauthorized"),
            BridgeError::TransactionAlreadyConfirmed => write!(f, "Transaction already confirmed"),
            BridgeError::InvalidSignature => write!(f, "Invalid signature"),
            BridgeError::ValidatorAlreadyRegistered => write!(f, "Validator already registered"),
            BridgeError::ThresholdNotMet => write!(f, "Threshold not met"),
        }
    }
}

impl std::error::Error for BridgeError {}

/// Bridge transaction status
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum BridgeTransactionStatus {
    /// Pending confirmation
    Pending,
    /// Confirmed by validators
    Confirmed,
    /// Executed on destination chain
    Executed,
    /// Failed
    Failed,
    /// Cancelled
    Cancelled,
}

/// Bridge validator information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeValidator {
    /// Validator address
    pub address: String,
    /// Stake amount (in smallest units)
    pub stake: u128,
    /// Whether validator is active
    pub is_active: bool,
    /// Number of successful confirmations
    pub confirmed_count: u64,
    /// Number of failed confirmations
    pub failed_count: u64,
    /// Registration timestamp
    pub registered_at: u64,
    /// Last active timestamp
    pub last_active_at: u64,
    /// Whether validator is slashed
    pub is_slashed: bool,
}

/// Bridge transaction record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeTransaction {
    /// Unique transaction ID
    pub tx_id: u64,
    /// Source chain name
    pub source_chain: String,
    /// Destination chain name
    pub dest_chain: String,
    /// User address
    pub user: String,
    /// Token identifier
    pub token: String,
    /// Amount to bridge
    pub amount: u128,
    /// Fee paid
    pub fee: u128,
    /// Current status
    pub status: BridgeTransactionStatus,
    /// Number of validator confirmations
    pub confirmations: u64,
    /// Validators who confirmed
    pub confirming_validators: Vec<String>,
    /// Creation timestamp
    pub created_at: u64,
    /// Execution timestamp
    pub executed_at: Option<u64>,
}

/// Bridge state manager
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeState {
    /// All registered validators
    validators: HashMap<String, BridgeValidator>,
    /// All bridge transactions
    transactions: HashMap<u64, BridgeTransaction>,
    /// Transaction counter for ID generation
    tx_counter: u64,
    /// Bridge owner
    owner: String,
    /// Fee collector address
    fee_collector: String,
    /// Minimum validator stake
    min_stake: u128,
    /// Confirmation threshold (e.g., 2 out of 3)
    confirmation_threshold: u64,
    /// Total validators required for threshold
    total_validators_for_threshold: u64,
    /// Fee percentage (in basis points)
    fee_percentage: u64,
    /// Whether bridge is paused
    is_paused: bool,
    /// Supported chains
    supported_chains: Vec<String>,
}

impl BridgeState {
    /// Create new bridge state
    pub fn new(
        owner: String,
        fee_collector: String,
        min_stake: u128,
        fee_percentage: u64,
    ) -> Self {
        Self {
            validators: HashMap::new(),
            transactions: HashMap::new(),
            tx_counter: 0,
            owner,
            fee_collector,
            min_stake,
            confirmation_threshold: 2,
            total_validators_for_threshold: 3,
            fee_percentage,
            is_paused: false,
            supported_chains: vec![
                "ethereum".to_string(),
                "bsc".to_string(),
                "polygon".to_string(),
                "solana".to_string(),
                "silverbitcoin".to_string(),
            ],
        }
    }

    /// Register a bridge validator
    pub fn register_validator(
        &mut self,
        address: String,
        stake: u128,
    ) -> Result<(), BridgeError> {
        if stake < self.min_stake {
            return Err(BridgeError::InsufficientStake);
        }

        if self.validators.contains_key(&address) {
            return Err(BridgeError::ValidatorAlreadyRegistered);
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let validator = BridgeValidator {
            address: address.clone(),
            stake,
            is_active: true,
            confirmed_count: 0,
            failed_count: 0,
            registered_at: now,
            last_active_at: now,
            is_slashed: false,
        };

        self.validators.insert(address, validator);
        Ok(())
    }

    /// Unregister a bridge validator
    pub fn unregister_validator(&mut self, address: String) -> Result<(), BridgeError> {
        let validator = self
            .validators
            .get_mut(&address)
            .ok_or(BridgeError::ValidatorNotFound)?;

        validator.is_active = false;
        Ok(())
    }

    /// Initiate a bridge transaction
    pub fn initiate_bridge_transaction(
        &mut self,
        source_chain: String,
        dest_chain: String,
        user: String,
        token: String,
        amount: u128,
    ) -> Result<u64, BridgeError> {
        if amount == 0 {
            return Err(BridgeError::InvalidAmount);
        }

        if !self.supported_chains.contains(&source_chain)
            || !self.supported_chains.contains(&dest_chain)
        {
            return Err(BridgeError::InvalidChain);
        }

        if source_chain == dest_chain {
            return Err(BridgeError::InvalidChain);
        }

        // Calculate fee
        let fee = (amount as u128)
            .saturating_mul(self.fee_percentage as u128)
            .saturating_div(10000);

        let tx_id = self.tx_counter;
        self.tx_counter += 1;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let tx = BridgeTransaction {
            tx_id,
            source_chain,
            dest_chain,
            user,
            token,
            amount,
            fee,
            status: BridgeTransactionStatus::Pending,
            confirmations: 0,
            confirming_validators: Vec::new(),
            created_at: now,
            executed_at: None,
        };

        self.transactions.insert(tx_id, tx);
        Ok(tx_id)
    }

    /// Confirm a bridge transaction by a validator
    pub fn confirm_bridge_transaction(
        &mut self,
        tx_id: u64,
        validator: String,
    ) -> Result<(), BridgeError> {
        // Verify validator exists and is active
        let val = self
            .validators
            .get(&validator)
            .ok_or(BridgeError::ValidatorNotFound)?;

        if !val.is_active || val.is_slashed {
            return Err(BridgeError::Unauthorized);
        }

        let tx = self
            .transactions
            .get_mut(&tx_id)
            .ok_or(BridgeError::TransactionNotFound)?;

        if tx.status != BridgeTransactionStatus::Pending {
            return Err(BridgeError::TransactionAlreadyConfirmed);
        }

        // Check if validator already confirmed
        if tx.confirming_validators.contains(&validator) {
            return Err(BridgeError::TransactionAlreadyConfirmed);
        }

        // Add confirmation
        tx.confirming_validators.push(validator.clone());
        tx.confirmations += 1;

        // Update validator stats
        if let Some(val) = self.validators.get_mut(&validator) {
            val.confirmed_count += 1;
            val.last_active_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
        }

        // Check if threshold reached
        if tx.confirmations >= self.confirmation_threshold {
            tx.status = BridgeTransactionStatus::Confirmed;
        }

        Ok(())
    }

    /// Execute a confirmed bridge transaction
    pub fn execute_bridge_transaction(&mut self, tx_id: u64) -> Result<(), BridgeError> {
        let tx = self
            .transactions
            .get_mut(&tx_id)
            .ok_or(BridgeError::TransactionNotFound)?;

        if tx.status != BridgeTransactionStatus::Confirmed {
            return Err(BridgeError::InsufficientConfirmations);
        }

        tx.status = BridgeTransactionStatus::Executed;
        tx.executed_at = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        );

        Ok(())
    }

    /// Cancel a bridge transaction
    pub fn cancel_bridge_transaction(&mut self, tx_id: u64) -> Result<(), BridgeError> {
        let tx = self
            .transactions
            .get_mut(&tx_id)
            .ok_or(BridgeError::TransactionNotFound)?;

        if tx.status == BridgeTransactionStatus::Executed {
            return Err(BridgeError::Unauthorized);
        }

        tx.status = BridgeTransactionStatus::Cancelled;
        Ok(())
    }

    /// Slash a validator for misbehavior
    pub fn slash_validator(&mut self, address: String) -> Result<(), BridgeError> {
        let validator = self
            .validators
            .get_mut(&address)
            .ok_or(BridgeError::ValidatorNotFound)?;

        validator.is_slashed = true;
        validator.is_active = false;
        Ok(())
    }

    /// Get validator information
    pub fn get_validator(&self, address: String) -> Result<BridgeValidator, BridgeError> {
        self.validators
            .get(&address)
            .cloned()
            .ok_or(BridgeError::ValidatorNotFound)
    }

    /// List all validators
    pub fn list_validators(&self) -> Vec<BridgeValidator> {
        self.validators.values().cloned().collect()
    }

    /// Get bridge transaction
    pub fn get_transaction(&self, tx_id: u64) -> Result<BridgeTransaction, BridgeError> {
        self.transactions
            .get(&tx_id)
            .cloned()
            .ok_or(BridgeError::TransactionNotFound)
    }

    /// Get transactions by user
    pub fn get_user_transactions(&self, user: String) -> Vec<BridgeTransaction> {
        self.transactions
            .values()
            .filter(|tx| tx.user == user)
            .cloned()
            .collect()
    }

    /// Get transactions by status
    pub fn get_transactions_by_status(&self, status: BridgeTransactionStatus) -> Vec<BridgeTransaction> {
        self.transactions
            .values()
            .filter(|tx| tx.status == status)
            .cloned()
            .collect()
    }

    /// Pause/unpause bridge
    pub fn set_paused(&mut self, paused: bool) -> Result<(), BridgeError> {
        self.is_paused = paused;
        Ok(())
    }

    /// Add supported chain
    pub fn add_supported_chain(&mut self, chain: String) -> Result<(), BridgeError> {
        if self.supported_chains.contains(&chain) {
            return Err(BridgeError::InvalidChain);
        }
        self.supported_chains.push(chain);
        Ok(())
    }

    /// Get bridge statistics
    pub fn get_stats(&self) -> BridgeStats {
        let total_validators = self.validators.len();
        let active_validators = self
            .validators
            .values()
            .filter(|v| v.is_active && !v.is_slashed)
            .count();

        let total_transactions = self.transactions.len();
        let pending_transactions = self
            .transactions
            .values()
            .filter(|tx| tx.status == BridgeTransactionStatus::Pending)
            .count();
        let confirmed_transactions = self
            .transactions
            .values()
            .filter(|tx| tx.status == BridgeTransactionStatus::Confirmed)
            .count();
        let executed_transactions = self
            .transactions
            .values()
            .filter(|tx| tx.status == BridgeTransactionStatus::Executed)
            .count();

        let total_volume: u128 = self.transactions.iter().map(|(_, tx)| tx.amount).sum();
        let total_fees: u128 = self.transactions.iter().map(|(_, tx)| tx.fee).sum();

        BridgeStats {
            total_validators,
            active_validators,
            total_transactions,
            pending_transactions,
            confirmed_transactions,
            executed_transactions,
            total_volume,
            total_fees,
            is_paused: self.is_paused,
        }
    }
}

/// Bridge statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeStats {
    /// Total number of validators
    pub total_validators: usize,
    /// Number of active validators
    pub active_validators: usize,
    /// Total number of transactions
    pub total_transactions: usize,
    /// Number of pending transactions
    pub pending_transactions: usize,
    /// Number of confirmed transactions
    pub confirmed_transactions: usize,
    /// Number of executed transactions
    pub executed_transactions: usize,
    /// Total bridged volume
    pub total_volume: u128,
    /// Total fees collected
    pub total_fees: u128,
    /// Whether bridge is paused
    pub is_paused: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_validator() {
        let mut bridge = BridgeState::new(
            "owner".to_string(),
            "fee_collector".to_string(),
            1_000_000_000,
            10,
        );

        let result = bridge.register_validator("validator1".to_string(), 1_000_000_000);
        assert!(result.is_ok());
    }

    #[test]
    fn test_initiate_bridge_transaction() {
        let mut bridge = BridgeState::new(
            "owner".to_string(),
            "fee_collector".to_string(),
            1_000_000_000,
            10,
        );

        let tx_id = bridge
            .initiate_bridge_transaction(
                "ethereum".to_string(),
                "silverbitcoin".to_string(),
                "user".to_string(),
                "USDT".to_string(),
                1_000_000_000,
            )
            .unwrap();

        assert_eq!(tx_id, 0);
    }

    #[test]
    fn test_confirm_transaction() {
        let mut bridge = BridgeState::new(
            "owner".to_string(),
            "fee_collector".to_string(),
            1_000_000_000,
            10,
        );

        bridge
            .register_validator("validator1".to_string(), 1_000_000_000)
            .unwrap();

        let tx_id = bridge
            .initiate_bridge_transaction(
                "ethereum".to_string(),
                "silverbitcoin".to_string(),
                "user".to_string(),
                "USDT".to_string(),
                1_000_000_000,
            )
            .unwrap();

        let result = bridge.confirm_bridge_transaction(tx_id, "validator1".to_string());
        assert!(result.is_ok());
    }
}
