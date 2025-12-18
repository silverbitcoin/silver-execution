//! Fuel metering and economics
//!
//! This module provides fuel metering for transaction execution:
//! - Fuel consumption tracking
//! - Fuel price schedule for operations
//! - Fuel budget enforcement

use thiserror::Error;

/// Fuel metering errors
#[derive(Error, Debug)]
pub enum FuelError {
    /// Insufficient fuel
    #[error("Insufficient fuel: required {required}, available {available}")]
    InsufficientFuel { required: u64, available: u64 },

    /// Fuel budget exceeded
    #[error("Fuel budget exceeded")]
    BudgetExceeded,
}

/// Result type for fuel operations
pub type FuelResult<T> = std::result::Result<T, FuelError>;

/// Minimum fuel price in MIST per fuel unit (Requirement 9.5)
pub const MIN_FUEL_PRICE: u64 = 1000;

/// Number of MIST per SBTC (1 SBTC = 1,000,000,000 MIST)
pub const MIST_PER_SBTC: u64 = 1_000_000_000;

/// Target maximum fee for simple transfers (0.001 SBTC = 1,000,000 MIST)
/// This is the target maximum fee to meet Requirement 31.1
pub const TARGET_MAX_SIMPLE_TRANSFER_FEE_MIST: u64 = 1_000_000;

/// Fuel payment information
///
/// Tracks fuel payment, deduction, and refund for a transaction.
#[derive(Debug, Clone)]
pub struct FuelPayment {
    /// Total fuel budget (in fuel units)
    pub budget: u64,

    /// Fuel price (in MIST per fuel unit)
    pub price: u64,

    /// Fuel consumed during execution
    pub consumed: u64,

    /// Fuel refunded after execution
    pub refunded: u64,

    /// Total cost deducted (budget * price in MIST)
    pub total_deducted: u64,

    /// Total refund amount (refunded * price in MIST)
    pub total_refund: u64,
}

impl FuelPayment {
    /// Create a new fuel payment
    ///
    /// # Arguments
    /// * `budget` - Total fuel budget in fuel units
    /// * `price` - Fuel price in MIST per fuel unit
    ///
    /// # Returns
    /// - `Ok(FuelPayment)` if price meets minimum
    /// - `Err(FuelError)` if price is below minimum
    pub fn new(budget: u64, price: u64) -> FuelResult<Self> {
        if price < MIN_FUEL_PRICE {
            return Err(FuelError::InsufficientFuel {
                required: MIN_FUEL_PRICE,
                available: price,
            });
        }

        let total_deducted = budget.saturating_mul(price);

        Ok(Self {
            budget,
            price,
            consumed: 0,
            refunded: 0,
            total_deducted,
            total_refund: 0,
        })
    }

    /// Record fuel consumption
    ///
    /// # Arguments
    /// * `consumed` - Amount of fuel consumed
    pub fn record_consumption(&mut self, consumed: u64) {
        self.consumed = consumed;
        self.refunded = self.budget.saturating_sub(consumed);
        self.total_refund = self.refunded.saturating_mul(self.price);
    }

    /// Get the net cost (deducted - refunded)
    pub fn net_cost(&self) -> u64 {
        self.total_deducted.saturating_sub(self.total_refund)
    }

    /// Get fuel utilization rate (0.0 to 1.0)
    pub fn utilization_rate(&self) -> f64 {
        if self.budget == 0 {
            return 0.0;
        }
        self.consumed as f64 / self.budget as f64
    }
}

/// Fuel economics manager
///
/// Handles fuel deduction, tracking, and refund for transactions.
pub struct FuelEconomics {
    /// Fuel schedule for pricing
    schedule: FuelSchedule,
}

impl FuelEconomics {
    /// Create a new fuel economics manager
    pub fn new(schedule: FuelSchedule) -> Self {
        Self { schedule }
    }

    /// Create with default schedule
    pub fn default() -> Self {
        Self::new(FuelSchedule::default())
    }

    /// Validate and prepare fuel payment for a transaction
    ///
    /// This should be called before transaction execution to:
    /// 1. Validate fuel price meets minimum
    /// 2. Calculate total deduction amount
    /// 3. Prepare fuel payment tracking
    ///
    /// # Arguments
    /// * `budget` - Fuel budget in fuel units
    /// * `price` - Fuel price in MIST per fuel unit
    ///
    /// # Returns
    /// - `Ok(FuelPayment)` if valid
    /// - `Err(FuelError)` if price below minimum
    pub fn prepare_payment(&self, budget: u64, price: u64) -> FuelResult<FuelPayment> {
        FuelPayment::new(budget, price)
    }

    /// Calculate refund after transaction execution
    ///
    /// # Arguments
    /// * `payment` - Fuel payment to update
    /// * `consumed` - Actual fuel consumed
    pub fn calculate_refund(&self, payment: &mut FuelPayment, consumed: u64) {
        payment.record_consumption(consumed);
    }

    /// Get the fuel schedule
    pub fn schedule(&self) -> &FuelSchedule {
        &self.schedule
    }
}

/// Fuel meter for tracking consumption during execution
///
/// Tracks fuel consumption and enforces budget limits.
#[derive(Debug, Clone)]
pub struct FuelMeter {
    /// Total fuel budget for this execution
    budget: u64,

    /// Fuel consumed so far
    consumed: u64,

    /// Fuel schedule for pricing operations
    schedule: FuelSchedule,
}

impl FuelMeter {
    /// Create a new fuel meter
    ///
    /// # Arguments
    /// * `budget` - Total fuel budget
    /// * `schedule` - Fuel price schedule
    pub fn new(budget: u64, schedule: FuelSchedule) -> Self {
        Self {
            budget,
            consumed: 0,
            schedule,
        }
    }

    /// Consume fuel for an operation
    ///
    /// # Arguments
    /// * `amount` - Amount of fuel to consume
    ///
    /// # Returns
    /// - `Ok(())` if fuel was consumed successfully
    /// - `Err(FuelError)` if insufficient fuel
    pub fn consume(&mut self, amount: u64) -> FuelResult<()> {
        let new_consumed = self.consumed.saturating_add(amount);

        if new_consumed > self.budget {
            return Err(FuelError::InsufficientFuel {
                required: amount,
                available: self.remaining(),
            });
        }

        self.consumed = new_consumed;
        Ok(())
    }

    /// Get remaining fuel
    pub fn remaining(&self) -> u64 {
        self.budget.saturating_sub(self.consumed)
    }

    /// Get consumed fuel
    pub fn consumed(&self) -> u64 {
        self.consumed
    }

    /// Get total budget
    pub fn budget(&self) -> u64 {
        self.budget
    }

    /// Check if there's enough fuel for an operation
    pub fn has_fuel(&self, amount: u64) -> bool {
        self.remaining() >= amount
    }

    /// Get the fuel schedule
    pub fn schedule(&self) -> &FuelSchedule {
        &self.schedule
    }
}

/// Fuel price schedule for operations
///
/// Defines the fuel cost for various blockchain operations.
/// Costs are based on computational complexity, storage usage, and network bandwidth.
#[derive(Debug, Clone)]
pub struct FuelSchedule {
    // Base costs
    /// Base cost for any transaction
    pub base_transaction: u64,

    /// Cost per byte of transaction data
    pub per_byte: u64,

    // Command costs
    /// Cost for TransferObjects command
    pub transfer: u64,

    /// Cost for SplitCoins command
    pub split: u64,

    /// Cost for MergeCoins command
    pub merge: u64,

    /// Cost per byte for Publish command
    pub publish_per_byte: u64,

    /// Base cost for Call command
    pub call_base: u64,

    /// Cost per argument for Call command
    pub call_per_arg: u64,

    /// Cost per element for MakeMoveVec command
    pub vector_per_element: u64,

    /// Cost for DeleteObject command
    pub delete: u64,

    /// Cost for ShareObject command
    pub share: u64,

    /// Cost for FreezeObject command
    pub freeze: u64,

    // VM costs
    /// Cost per bytecode instruction
    pub instruction: u64,

    /// Cost for memory allocation (per byte)
    pub memory_per_byte: u64,

    /// Cost for storage read (per byte)
    pub storage_read_per_byte: u64,

    /// Cost for storage write (per byte)
    pub storage_write_per_byte: u64,

    // Cryptographic operation costs
    /// Cost for signature verification (Ed25519/Secp256k1)
    pub signature_verify: u64,

    /// Cost for post-quantum signature verification (SPHINCS+)
    pub signature_verify_sphincs: u64,

    /// Cost for post-quantum signature verification (Dilithium3)
    pub signature_verify_dilithium: u64,

    /// Cost for hash computation (per byte)
    pub hash_per_byte: u64,

    /// Cost for Blake3-512 hash computation (per byte)
    pub blake3_per_byte: u64,

    /// Cost for public key derivation
    pub pubkey_derive: u64,

    /// Cost for address derivation
    pub address_derive: u64,

    // Bytecode instruction costs (detailed)
    /// Cost for arithmetic operations (add, sub, mul, div, mod)
    pub arithmetic_op: u64,

    /// Cost for comparison operations (eq, ne, lt, gt, le, ge)
    pub comparison_op: u64,

    /// Cost for logical operations (and, or, xor, not)
    pub logical_op: u64,

    /// Cost for bitwise operations (shl, shr, rotl, rotr)
    pub bitwise_op: u64,

    /// Cost for stack operations (push, pop, dup, swap)
    pub stack_op: u64,

    /// Cost for local variable access (load, store)
    pub local_access: u64,

    /// Cost for global variable access (load, store)
    pub global_access: u64,

    /// Cost for function call
    pub function_call: u64,

    /// Cost for function return
    pub function_return: u64,

    /// Cost for branch/jump operations
    pub branch_op: u64,

    /// Cost for object field access
    pub field_access: u64,

    /// Cost for vector operations (per element)
    pub vector_op_per_element: u64,
}

impl Default for FuelSchedule {
    fn default() -> Self {
        Self::optimized()
    }
}

impl FuelSchedule {
    /// Create an optimized fuel schedule for low transaction fees
    ///
    /// This schedule is designed to meet Requirement 31.1:
    /// Average transaction fees below 0.001 SBTC for simple transfers.
    ///
    /// Calculation for simple transfer at minimum fuel price (1000 MIST/fuel):
    /// - Base transaction: 200 fuel = 200,000 MIST
    /// - Signature verification (Dilithium3): 300 fuel = 300,000 MIST
    /// - Transfer command: 50 fuel = 50,000 MIST
    /// - Transaction size (500 bytes): 0 fuel = 0 MIST (included in base)
    /// - Storage write (200 bytes): 400 fuel = 400,000 MIST
    /// **Total: ~950 fuel = 950,000 MIST = 0.00095 SBTC** ✓
    ///
    /// This is well below the 0.001 SBTC (1,000,000 MIST) target.
    pub fn optimized() -> Self {
        Self {
            // Base costs - OPTIMIZED for low fees
            base_transaction: 200, // Reduced from 1000 to 200
            per_byte: 0,           // Reduced from 1 to 0 (size included in base)

            // Command costs - OPTIMIZED for common operations
            transfer: 50,          // Reduced from 100 to 50
            split: 80,             // Reduced from 200 to 80
            merge: 60,             // Reduced from 150 to 60
            publish_per_byte: 5,   // Reduced from 10 to 5
            call_base: 200,        // Reduced from 500 to 200
            call_per_arg: 20,      // Reduced from 50 to 20
            vector_per_element: 5, // Reduced from 10 to 5
            delete: 40,            // Reduced from 100 to 40
            share: 80,             // Reduced from 200 to 80
            freeze: 80,            // Reduced from 200 to 80

            // VM costs - OPTIMIZED for efficient execution
            instruction: 1,
            memory_per_byte: 0,        // Reduced from 1 to 0 (minimal cost)
            storage_read_per_byte: 1,  // Reduced from 10 to 1 (ParityDB is fast)
            storage_write_per_byte: 2, // Reduced from 100 to 2 (with compression)

            // Cryptographic costs - OPTIMIZED with GPU acceleration in mind
            signature_verify: 400, // Reduced from 1000 to 400 (GPU accelerated)
            signature_verify_sphincs: 1200, // Reduced from 3000 to 1200 (GPU accelerated)
            signature_verify_dilithium: 300, // Reduced from 1500 to 300 (GPU accelerated, preferred)
            hash_per_byte: 0,                // Reduced from 1 to 0 (Blake3 is extremely fast)
            blake3_per_byte: 0,              // Blake3 is extremely fast, minimal cost
            pubkey_derive: 100,              // Reduced from 500 to 100
            address_derive: 50,              // Reduced from 200 to 50

            // Bytecode instruction costs - OPTIMIZED for VM efficiency
            arithmetic_op: 1,
            comparison_op: 1,
            logical_op: 1,
            bitwise_op: 1,
            stack_op: 1,
            local_access: 1,          // Reduced from 2 to 1
            global_access: 3,         // Reduced from 5 to 3
            function_call: 5,         // Reduced from 10 to 5
            function_return: 2,       // Reduced from 5 to 2
            branch_op: 1,             // Reduced from 2 to 1
            field_access: 2,          // Reduced from 3 to 2
            vector_op_per_element: 1, // Reduced from 2 to 1
        }
    }

    /// Create a legacy fuel schedule (pre-optimization)
    ///
    /// This schedule represents the original costs before optimization.
    /// Kept for compatibility and testing purposes.
    pub fn legacy() -> Self {
        Self {
            // Base costs
            base_transaction: 1000,
            per_byte: 1,

            // Command costs
            transfer: 100,
            split: 200,
            merge: 150,
            publish_per_byte: 10,
            call_base: 500,
            call_per_arg: 50,
            vector_per_element: 10,
            delete: 100,
            share: 200,
            freeze: 200,

            // VM costs
            instruction: 1,
            memory_per_byte: 1,
            storage_read_per_byte: 10,
            storage_write_per_byte: 100,

            // Cryptographic costs (based on computational complexity)
            signature_verify: 1000, // Classical signatures (Ed25519/Secp256k1)
            signature_verify_sphincs: 3000, // SPHINCS+ is slower
            signature_verify_dilithium: 1500, // Dilithium3 is faster than SPHINCS+
            hash_per_byte: 1,
            blake3_per_byte: 1, // Blake3 is very fast
            pubkey_derive: 500,
            address_derive: 200,

            // Bytecode instruction costs (1 fuel per simple operation)
            arithmetic_op: 1,
            comparison_op: 1,
            logical_op: 1,
            bitwise_op: 1,
            stack_op: 1,
            local_access: 2,
            global_access: 5,
            function_call: 10,
            function_return: 5,
            branch_op: 2,
            field_access: 3,
            vector_op_per_element: 2,
        }
    }
}

impl FuelSchedule {
    /// Create a new fuel schedule with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Get base transaction cost
    pub fn base_transaction_cost(&self) -> u64 {
        self.base_transaction
    }

    /// Get cost for a transaction based on size
    pub fn transaction_cost(&self, size_bytes: usize) -> u64 {
        self.base_transaction + (self.per_byte * size_bytes as u64)
    }

    /// Get cost for a command
    pub fn command_cost(&self) -> u64 {
        100 // Base command cost
    }

    /// Get cost for TransferObjects
    pub fn transfer_cost(&self) -> u64 {
        self.transfer
    }

    /// Get cost for SplitCoins
    pub fn split_cost(&self) -> u64 {
        self.split
    }

    /// Get cost for MergeCoins
    pub fn merge_cost(&self) -> u64 {
        self.merge
    }

    /// Get cost for Publish based on module size
    pub fn publish_cost(&self, size_bytes: u64) -> u64 {
        self.publish_per_byte * size_bytes
    }

    /// Get cost for Call command
    pub fn call_cost(&self) -> u64 {
        self.call_base
    }

    /// Get cost for Call with arguments
    pub fn call_cost_with_args(&self, num_args: usize) -> u64 {
        self.call_base + (self.call_per_arg * num_args as u64)
    }

    /// Get cost for MakeMoveVec
    pub fn vector_cost(&self, num_elements: u64) -> u64 {
        self.vector_per_element * num_elements
    }

    /// Get cost for DeleteObject
    pub fn delete_cost(&self) -> u64 {
        self.delete
    }

    /// Get cost for ShareObject
    pub fn share_cost(&self) -> u64 {
        self.share
    }

    /// Get cost for FreezeObject
    pub fn freeze_cost(&self) -> u64 {
        self.freeze
    }

    /// Get cost for bytecode instruction execution
    pub fn instruction_cost(&self) -> u64 {
        self.instruction
    }

    /// Get cost for memory allocation
    pub fn memory_cost(&self, bytes: u64) -> u64 {
        self.memory_per_byte * bytes
    }

    /// Get cost for storage read
    pub fn storage_read_cost(&self, bytes: u64) -> u64 {
        self.storage_read_per_byte * bytes
    }

    /// Get cost for storage write
    pub fn storage_write_cost(&self, bytes: u64) -> u64 {
        self.storage_write_per_byte * bytes
    }

    /// Get cost for signature verification
    pub fn signature_verify_cost(&self) -> u64 {
        self.signature_verify
    }

    /// Get cost for hash computation
    pub fn hash_cost(&self, bytes: u64) -> u64 {
        self.hash_per_byte * bytes
    }

    /// Calculate total fuel cost for a transaction
    ///
    /// This estimates the fuel cost based on transaction size and complexity.
    pub fn estimate_transaction_cost(&self, tx_size_bytes: usize, num_commands: usize) -> u64 {
        let base = self.transaction_cost(tx_size_bytes);
        let commands = self.command_cost() * num_commands as u64;
        base + commands
    }

    /// Get cost for SPHINCS+ signature verification
    pub fn signature_verify_sphincs_cost(&self) -> u64 {
        self.signature_verify_sphincs
    }

    /// Get cost for Dilithium3 signature verification
    pub fn signature_verify_dilithium_cost(&self) -> u64 {
        self.signature_verify_dilithium
    }

    /// Get cost for Blake3-512 hash computation
    pub fn blake3_cost(&self, bytes: u64) -> u64 {
        self.blake3_per_byte * bytes
    }

    /// Get cost for public key derivation
    pub fn pubkey_derive_cost(&self) -> u64 {
        self.pubkey_derive
    }

    /// Get cost for address derivation
    pub fn address_derive_cost(&self) -> u64 {
        self.address_derive
    }

    /// Get cost for arithmetic operation
    pub fn arithmetic_cost(&self) -> u64 {
        self.arithmetic_op
    }

    /// Get cost for comparison operation
    pub fn comparison_cost(&self) -> u64 {
        self.comparison_op
    }

    /// Get cost for logical operation
    pub fn logical_cost(&self) -> u64 {
        self.logical_op
    }

    /// Get cost for bitwise operation
    pub fn bitwise_cost(&self) -> u64 {
        self.bitwise_op
    }

    /// Get cost for stack operation
    pub fn stack_cost(&self) -> u64 {
        self.stack_op
    }

    /// Get cost for local variable access
    pub fn local_access_cost(&self) -> u64 {
        self.local_access
    }

    /// Get cost for global variable access
    pub fn global_access_cost(&self) -> u64 {
        self.global_access
    }

    /// Get cost for function call
    pub fn function_call_cost(&self) -> u64 {
        self.function_call
    }

    /// Get cost for function return
    pub fn function_return_cost(&self) -> u64 {
        self.function_return
    }

    /// Get cost for branch operation
    pub fn branch_cost(&self) -> u64 {
        self.branch_op
    }

    /// Get cost for field access
    pub fn field_access_cost(&self) -> u64 {
        self.field_access
    }

    /// Get cost for vector operation
    pub fn vector_op_cost(&self, num_elements: u64) -> u64 {
        self.vector_op_per_element * num_elements
    }

    /// Calculate the fuel cost for a simple transfer transaction
    ///
    /// A simple transfer includes:
    /// - Base transaction cost
    /// - Signature verification (Dilithium3 preferred for speed)
    /// - Transfer command
    /// - Transaction size overhead (typical ~500 bytes)
    /// - Storage write for balance update (~200 bytes)
    ///
    /// # Returns
    /// Total fuel units required for a simple transfer
    pub fn simple_transfer_fuel_cost(&self) -> u64 {
        let base = self.base_transaction;
        let signature = self.signature_verify_dilithium; // Use Dilithium3 (fastest PQ signature)
        let transfer = self.transfer;
        let tx_size = 500; // Typical transaction size in bytes
        let size_cost = self.per_byte * tx_size;
        let storage = self.storage_write_per_byte * 200; // ~200 bytes for balance update

        base + signature + transfer + size_cost + storage
    }

    /// Calculate the MIST cost for a simple transfer at minimum fuel price
    ///
    /// # Returns
    /// Total cost in MIST for a simple transfer at minimum fuel price
    pub fn simple_transfer_mist_cost(&self) -> u64 {
        self.simple_transfer_fuel_cost() * MIN_FUEL_PRICE
    }

    /// Calculate the SBTC cost for a simple transfer at minimum fuel price
    ///
    /// # Returns
    /// Total cost in SBTC (as f64) for a simple transfer at minimum fuel price
    pub fn simple_transfer_sbtc_cost(&self) -> f64 {
        self.simple_transfer_mist_cost() as f64 / MIST_PER_SBTC as f64
    }

    /// Verify that simple transfer costs meet the accessibility requirement
    ///
    /// Requirement 31.1: Average transaction fees below 0.001 SBTC
    ///
    /// # Returns
    /// `true` if the simple transfer cost is below 0.001 SBTC, `false` otherwise
    pub fn meets_accessibility_requirement(&self) -> bool {
        self.simple_transfer_mist_cost() < TARGET_MAX_SIMPLE_TRANSFER_FEE_MIST
    }

    /// Get a detailed breakdown of simple transfer costs
    ///
    /// # Returns
    /// A tuple of (fuel_units, mist_cost, sbtc_cost, meets_requirement)
    pub fn simple_transfer_cost_breakdown(&self) -> (u64, u64, f64, bool) {
        let fuel = self.simple_transfer_fuel_cost();
        let mist = self.simple_transfer_mist_cost();
        let sbtc = self.simple_transfer_sbtc_cost();
        let meets_req = self.meets_accessibility_requirement();

        (fuel, mist, sbtc, meets_req)
    }
}
