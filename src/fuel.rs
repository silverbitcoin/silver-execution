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
            base_transaction: 200,  // Reduced from 1000 to 200
            per_byte: 0,            // Reduced from 1 to 0 (size included in base)

            // Command costs - OPTIMIZED for common operations
            transfer: 50,           // Reduced from 100 to 50
            split: 80,              // Reduced from 200 to 80
            merge: 60,              // Reduced from 150 to 60
            publish_per_byte: 5,    // Reduced from 10 to 5
            call_base: 200,         // Reduced from 500 to 200
            call_per_arg: 20,       // Reduced from 50 to 20
            vector_per_element: 5,  // Reduced from 10 to 5
            delete: 40,             // Reduced from 100 to 40
            share: 80,              // Reduced from 200 to 80
            freeze: 80,             // Reduced from 200 to 80

            // VM costs - OPTIMIZED for efficient execution
            instruction: 1,
            memory_per_byte: 0,     // Reduced from 1 to 0 (minimal cost)
            storage_read_per_byte: 1,   // Reduced from 10 to 1 (RocksDB is fast)
            storage_write_per_byte: 2,  // Reduced from 100 to 2 (with compression)

            // Cryptographic costs - OPTIMIZED with GPU acceleration in mind
            signature_verify: 400,           // Reduced from 1000 to 400 (GPU accelerated)
            signature_verify_sphincs: 1200,  // Reduced from 3000 to 1200 (GPU accelerated)
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
            local_access: 1,        // Reduced from 2 to 1
            global_access: 3,       // Reduced from 5 to 3
            function_call: 5,       // Reduced from 10 to 5
            function_return: 2,     // Reduced from 5 to 2
            branch_op: 1,           // Reduced from 2 to 1
            field_access: 2,        // Reduced from 3 to 2
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
            signature_verify: 1000,           // Classical signatures (Ed25519/Secp256k1)
            signature_verify_sphincs: 3000,   // SPHINCS+ is slower
            signature_verify_dilithium: 1500, // Dilithium3 is faster than SPHINCS+
            hash_per_byte: 1,
            blake3_per_byte: 1,               // Blake3 is very fast
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fuel_meter_creation() {
        let schedule = FuelSchedule::default();
        let meter = FuelMeter::new(1000, schedule);

        assert_eq!(meter.budget(), 1000);
        assert_eq!(meter.consumed(), 0);
        assert_eq!(meter.remaining(), 1000);
    }

    #[test]
    fn test_fuel_consumption() {
        let schedule = FuelSchedule::default();
        let mut meter = FuelMeter::new(1000, schedule);

        assert!(meter.consume(100).is_ok());
        assert_eq!(meter.consumed(), 100);
        assert_eq!(meter.remaining(), 900);

        assert!(meter.consume(200).is_ok());
        assert_eq!(meter.consumed(), 300);
        assert_eq!(meter.remaining(), 700);
    }

    #[test]
    fn test_insufficient_fuel() {
        let schedule = FuelSchedule::default();
        let mut meter = FuelMeter::new(100, schedule);

        assert!(meter.consume(50).is_ok());
        assert_eq!(meter.consumed(), 50);

        // Try to consume more than remaining
        let result = meter.consume(100);
        assert!(matches!(result, Err(FuelError::InsufficientFuel { .. })));

        // Consumed amount should not change
        assert_eq!(meter.consumed(), 50);
    }

    #[test]
    fn test_has_fuel() {
        let schedule = FuelSchedule::default();
        let mut meter = FuelMeter::new(1000, schedule);

        assert!(meter.has_fuel(500));
        assert!(meter.has_fuel(1000));
        assert!(!meter.has_fuel(1001));

        meter.consume(600).unwrap();
        assert!(meter.has_fuel(400));
        assert!(!meter.has_fuel(401));
    }

    #[test]
    fn test_fuel_schedule_defaults() {
        let schedule = FuelSchedule::default();

        // Default is now optimized
        assert_eq!(schedule.base_transaction, 200);
        assert_eq!(schedule.transfer, 50);
        assert_eq!(schedule.instruction, 1);
        assert_eq!(schedule.signature_verify, 400);
        assert_eq!(schedule.signature_verify_sphincs, 1200);
        assert_eq!(schedule.signature_verify_dilithium, 300);
    }

    #[test]
    fn test_fuel_schedule_costs() {
        let schedule = FuelSchedule::default();

        // Test transaction cost calculation (per_byte is now 0)
        let tx_cost = schedule.transaction_cost(1000);
        assert_eq!(tx_cost, schedule.base_transaction); // No per-byte cost

        // Test publish cost
        let publish_cost = schedule.publish_cost(5000);
        assert_eq!(publish_cost, schedule.publish_per_byte * 5000);

        // Test call cost with args
        let call_cost = schedule.call_cost_with_args(5);
        assert_eq!(call_cost, schedule.call_base + (schedule.call_per_arg * 5));
    }

    #[test]
    fn test_estimate_transaction_cost() {
        let schedule = FuelSchedule::default();

        let estimated = schedule.estimate_transaction_cost(1000, 5);
        let expected = schedule.transaction_cost(1000) + (schedule.command_cost() * 5);

        assert_eq!(estimated, expected);
    }

    #[test]
    fn test_fuel_meter_saturation() {
        let schedule = FuelSchedule::default();
        let mut meter = FuelMeter::new(100, schedule);

        // Consume all fuel
        meter.consume(100).unwrap();
        assert_eq!(meter.remaining(), 0);

        // Try to consume more - should fail
        assert!(meter.consume(1).is_err());
    }

    #[test]
    fn test_cryptographic_operation_costs() {
        let schedule = FuelSchedule::default();

        // Test signature verification costs (optimized with GPU)
        assert_eq!(schedule.signature_verify_cost(), 400);
        assert_eq!(schedule.signature_verify_sphincs_cost(), 1200);
        assert_eq!(schedule.signature_verify_dilithium_cost(), 300);

        // Test hash costs (Blake3 is nearly free)
        assert_eq!(schedule.blake3_cost(1000), 0);
        assert_eq!(schedule.hash_cost(500), 0);

        // Test key derivation costs (optimized)
        assert_eq!(schedule.pubkey_derive_cost(), 100);
        assert_eq!(schedule.address_derive_cost(), 50);
    }

    #[test]
    fn test_bytecode_instruction_costs() {
        let schedule = FuelSchedule::default();

        // Test basic instruction costs
        assert_eq!(schedule.arithmetic_cost(), 1);
        assert_eq!(schedule.comparison_cost(), 1);
        assert_eq!(schedule.logical_cost(), 1);
        assert_eq!(schedule.bitwise_cost(), 1);
        assert_eq!(schedule.stack_cost(), 1);

        // Test memory access costs (optimized)
        assert_eq!(schedule.local_access_cost(), 1);
        assert_eq!(schedule.global_access_cost(), 3);

        // Test control flow costs (optimized)
        assert_eq!(schedule.function_call_cost(), 5);
        assert_eq!(schedule.function_return_cost(), 2);
        assert_eq!(schedule.branch_cost(), 1);

        // Test object access costs (optimized)
        assert_eq!(schedule.field_access_cost(), 2);
        assert_eq!(schedule.vector_op_cost(10), 10);
    }

    #[test]
    fn test_storage_operation_costs() {
        let schedule = FuelSchedule::default();

        // Test storage costs (optimized)
        assert_eq!(schedule.storage_read_cost(1000), 1000);
        assert_eq!(schedule.storage_write_cost(1000), 2000);
        assert_eq!(schedule.memory_cost(1000), 0);
    }

    #[test]
    fn test_fuel_payment_creation() {
        // Valid fuel payment
        let payment = FuelPayment::new(10000, 1000).unwrap();
        assert_eq!(payment.budget, 10000);
        assert_eq!(payment.price, 1000);
        assert_eq!(payment.total_deducted, 10_000_000);
        assert_eq!(payment.consumed, 0);
        assert_eq!(payment.refunded, 0);

        // Invalid fuel payment (price below minimum)
        let result = FuelPayment::new(10000, 500);
        assert!(result.is_err());
    }

    #[test]
    fn test_fuel_payment_consumption() {
        let mut payment = FuelPayment::new(10000, 1000).unwrap();

        // Record consumption
        payment.record_consumption(7000);

        assert_eq!(payment.consumed, 7000);
        assert_eq!(payment.refunded, 3000);
        assert_eq!(payment.total_refund, 3_000_000);
        assert_eq!(payment.net_cost(), 7_000_000);
    }

    #[test]
    fn test_fuel_payment_full_consumption() {
        let mut payment = FuelPayment::new(10000, 1000).unwrap();

        // Consume all fuel
        payment.record_consumption(10000);

        assert_eq!(payment.consumed, 10000);
        assert_eq!(payment.refunded, 0);
        assert_eq!(payment.total_refund, 0);
        assert_eq!(payment.net_cost(), 10_000_000);
    }

    #[test]
    fn test_fuel_payment_utilization_rate() {
        let mut payment = FuelPayment::new(10000, 1000).unwrap();

        payment.record_consumption(7500);
        assert!((payment.utilization_rate() - 0.75).abs() < 0.01);

        payment.record_consumption(10000);
        assert!((payment.utilization_rate() - 1.0).abs() < 0.01);

        payment.record_consumption(0);
        assert!((payment.utilization_rate() - 0.0).abs() < 0.01);
    }

    #[test]
    fn test_fuel_economics_prepare_payment() {
        let economics = FuelEconomics::default();

        // Valid payment
        let payment = economics.prepare_payment(10000, 1000).unwrap();
        assert_eq!(payment.budget, 10000);
        assert_eq!(payment.price, 1000);

        // Invalid payment (below minimum price)
        let result = economics.prepare_payment(10000, 500);
        assert!(result.is_err());
    }

    #[test]
    fn test_fuel_economics_calculate_refund() {
        let economics = FuelEconomics::default();
        let mut payment = economics.prepare_payment(10000, 1000).unwrap();

        // Calculate refund
        economics.calculate_refund(&mut payment, 6000);

        assert_eq!(payment.consumed, 6000);
        assert_eq!(payment.refunded, 4000);
        assert_eq!(payment.total_refund, 4_000_000);
    }

    #[test]
    fn test_minimum_fuel_price_constant() {
        assert_eq!(MIN_FUEL_PRICE, 1000);
    }

    #[test]
    fn test_mist_per_sbtc_constant() {
        assert_eq!(MIST_PER_SBTC, 1_000_000_000);
    }

    #[test]
    fn test_target_max_simple_transfer_fee() {
        assert_eq!(TARGET_MAX_SIMPLE_TRANSFER_FEE_MIST, 1_000_000);
        // Verify it equals 0.001 SBTC
        assert_eq!(TARGET_MAX_SIMPLE_TRANSFER_FEE_MIST, MIST_PER_SBTC / 1000);
    }

    #[test]
    fn test_optimized_schedule_simple_transfer_cost() {
        let schedule = FuelSchedule::optimized();

        // Calculate simple transfer cost
        let fuel_cost = schedule.simple_transfer_fuel_cost();
        let mist_cost = schedule.simple_transfer_mist_cost();
        let sbtc_cost = schedule.simple_transfer_sbtc_cost();

        println!("Simple transfer cost:");
        println!("  Fuel units: {}", fuel_cost);
        println!("  MIST: {}", mist_cost);
        println!("  SBTC: {:.6}", sbtc_cost);

        // Verify it meets the requirement (< 0.001 SBTC)
        assert!(
            mist_cost < TARGET_MAX_SIMPLE_TRANSFER_FEE_MIST,
            "Simple transfer cost {} MIST exceeds target {} MIST",
            mist_cost,
            TARGET_MAX_SIMPLE_TRANSFER_FEE_MIST
        );

        assert!(
            sbtc_cost < 0.001,
            "Simple transfer cost {:.6} SBTC exceeds target 0.001 SBTC",
            sbtc_cost
        );
    }

    #[test]
    fn test_optimized_schedule_meets_accessibility_requirement() {
        let schedule = FuelSchedule::optimized();

        assert!(
            schedule.meets_accessibility_requirement(),
            "Optimized schedule does not meet accessibility requirement (Requirement 31.1)"
        );
    }

    #[test]
    fn test_simple_transfer_cost_breakdown() {
        let schedule = FuelSchedule::optimized();

        let (fuel, mist, sbtc, meets_req) = schedule.simple_transfer_cost_breakdown();

        println!("Simple transfer breakdown:");
        println!("  Fuel: {} units", fuel);
        println!("  MIST: {}", mist);
        println!("  SBTC: {:.6}", sbtc);
        println!("  Meets requirement: {}", meets_req);

        assert!(meets_req, "Simple transfer does not meet accessibility requirement");
        assert!(fuel > 0, "Fuel cost should be positive");
        assert!(mist > 0, "MIST cost should be positive");
        assert!(sbtc > 0.0, "SBTC cost should be positive");
    }

    #[test]
    fn test_optimized_vs_legacy_schedule() {
        let optimized = FuelSchedule::optimized();
        let legacy = FuelSchedule::legacy();

        // Optimized should have lower costs
        assert!(
            optimized.base_transaction < legacy.base_transaction,
            "Optimized base transaction cost should be lower"
        );
        assert!(
            optimized.transfer < legacy.transfer,
            "Optimized transfer cost should be lower"
        );
        assert!(
            optimized.signature_verify_dilithium < legacy.signature_verify_dilithium,
            "Optimized signature verification cost should be lower"
        );

        // Verify optimized meets requirement but legacy might not
        assert!(
            optimized.meets_accessibility_requirement(),
            "Optimized schedule should meet accessibility requirement"
        );

        println!("Optimized simple transfer: {:.6} SBTC", optimized.simple_transfer_sbtc_cost());
        println!("Legacy simple transfer: {:.6} SBTC", legacy.simple_transfer_sbtc_cost());
    }

    #[test]
    fn test_detailed_simple_transfer_breakdown() {
        let schedule = FuelSchedule::optimized();

        // Break down each component
        let base = schedule.base_transaction;
        let signature = schedule.signature_verify_dilithium;
        let transfer = schedule.transfer;
        let size_cost = schedule.per_byte * 500;
        let storage = schedule.storage_write_per_byte * 200;

        let total_fuel = base + signature + transfer + size_cost + storage;
        let total_mist = total_fuel * MIN_FUEL_PRICE;
        let total_sbtc = total_mist as f64 / MIST_PER_SBTC as f64;

        println!("Detailed breakdown:");
        println!("  Base transaction: {} fuel = {} MIST", base, base * MIN_FUEL_PRICE);
        println!("  Signature (Dilithium3): {} fuel = {} MIST", signature, signature * MIN_FUEL_PRICE);
        println!("  Transfer command: {} fuel = {} MIST", transfer, transfer * MIN_FUEL_PRICE);
        println!("  Size overhead (500 bytes): {} fuel = {} MIST", size_cost, size_cost * MIN_FUEL_PRICE);
        println!("  Storage write (200 bytes): {} fuel = {} MIST", storage, storage * MIN_FUEL_PRICE);
        println!("  ---");
        println!("  Total: {} fuel = {} MIST = {:.6} SBTC", total_fuel, total_mist, total_sbtc);

        assert_eq!(total_fuel, schedule.simple_transfer_fuel_cost());
        assert_eq!(total_mist, schedule.simple_transfer_mist_cost());
        assert!((total_sbtc - schedule.simple_transfer_sbtc_cost()).abs() < 0.000001);
    }

    #[test]
    fn test_common_operations_are_affordable() {
        let schedule = FuelSchedule::optimized();

        // Test various common operations at minimum fuel price
        let operations = vec![
            ("Simple transfer", schedule.simple_transfer_fuel_cost()),
            ("Split coins", schedule.base_transaction + schedule.split + schedule.signature_verify_dilithium),
            ("Merge coins", schedule.base_transaction + schedule.merge + schedule.signature_verify_dilithium),
            ("Delete object", schedule.base_transaction + schedule.delete + schedule.signature_verify_dilithium),
        ];

        println!("Common operation costs:");
        for (name, fuel) in operations {
            let mist = fuel * MIN_FUEL_PRICE;
            let sbtc = mist as f64 / MIST_PER_SBTC as f64;
            println!("  {}: {} fuel = {} MIST = {:.6} SBTC", name, fuel, mist, sbtc);

            // All common operations should be well below 0.01 SBTC
            assert!(
                sbtc < 0.01,
                "{} cost {:.6} SBTC exceeds 0.01 SBTC threshold",
                name,
                sbtc
            );
        }
    }

    #[test]
    fn test_gpu_accelerated_signature_costs() {
        let schedule = FuelSchedule::optimized();

        // GPU acceleration should make signature verification cheaper
        assert!(
            schedule.signature_verify_dilithium < 500,
            "Dilithium3 verification should be < 500 fuel with GPU acceleration"
        );
        assert!(
            schedule.signature_verify_sphincs < 1500,
            "SPHINCS+ verification should be < 1500 fuel with GPU acceleration"
        );
        assert!(
            schedule.signature_verify < 500,
            "Classical signature verification should be < 500 fuel with GPU acceleration"
        );
    }

    #[test]
    fn test_storage_costs_are_reasonable() {
        let schedule = FuelSchedule::optimized();

        // Storage costs should be reasonable for typical operations
        let read_1kb = schedule.storage_read_cost(1024);
        let write_1kb = schedule.storage_write_cost(1024);

        let read_mist = read_1kb * MIN_FUEL_PRICE;
        let write_mist = write_1kb * MIN_FUEL_PRICE;

        println!("Storage costs (1KB):");
        println!("  Read: {} fuel = {} MIST", read_1kb, read_mist);
        println!("  Write: {} fuel = {} MIST", write_1kb, write_mist);

        // 1KB storage operations should be affordable (optimized costs)
        assert!(
            read_mist < 2_000_000,
            "1KB read cost {} MIST is too high",
            read_mist
        );
        assert!(
            write_mist < 3_000_000,
            "1KB write cost {} MIST is too high",
            write_mist
        );
    }

    #[test]
    fn test_vm_instruction_costs_are_minimal() {
        let schedule = FuelSchedule::optimized();

        // VM instructions should have minimal cost
        assert_eq!(schedule.arithmetic_cost(), 1);
        assert_eq!(schedule.comparison_cost(), 1);
        assert_eq!(schedule.logical_cost(), 1);
        assert_eq!(schedule.stack_cost(), 1);

        // Even complex operations should be cheap
        assert!(schedule.function_call_cost() <= 5);
        assert!(schedule.global_access_cost() <= 3);
    }

    #[test]
    fn test_hash_operations_are_nearly_free() {
        let schedule = FuelSchedule::optimized();

        // Blake3 is extremely fast, should have minimal cost
        let hash_1kb = schedule.blake3_cost(1024);
        assert_eq!(hash_1kb, 0, "Blake3 hashing should be nearly free");

        let hash_cost = schedule.hash_cost(1024);
        assert_eq!(hash_cost, 0, "Generic hashing should be nearly free");
    }

    #[test]
    fn test_fuel_schedule_consistency() {
        let schedule = FuelSchedule::optimized();

        // Verify internal consistency
        assert!(
            schedule.split >= schedule.transfer,
            "Split should cost at least as much as transfer"
        );
        assert!(
            schedule.merge >= schedule.transfer,
            "Merge should cost at least as much as transfer"
        );
        assert!(
            schedule.storage_write_per_byte >= schedule.storage_read_per_byte,
            "Write should cost at least as much as read"
        );
        assert!(
            schedule.signature_verify_sphincs >= schedule.signature_verify_dilithium,
            "SPHINCS+ should cost at least as much as Dilithium3"
        );
    }
}

