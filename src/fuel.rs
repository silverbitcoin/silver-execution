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

        assert_eq!(schedule.base_transaction, 1000);
        assert_eq!(schedule.transfer, 100);
        assert_eq!(schedule.instruction, 1);
        assert_eq!(schedule.signature_verify, 1000);
        assert_eq!(schedule.signature_verify_sphincs, 3000);
        assert_eq!(schedule.signature_verify_dilithium, 1500);
    }

    #[test]
    fn test_fuel_schedule_costs() {
        let schedule = FuelSchedule::default();

        // Test transaction cost calculation
        let tx_cost = schedule.transaction_cost(1000);
        assert_eq!(tx_cost, schedule.base_transaction + 1000);

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

        // Test signature verification costs
        assert_eq!(schedule.signature_verify_cost(), 1000);
        assert_eq!(schedule.signature_verify_sphincs_cost(), 3000);
        assert_eq!(schedule.signature_verify_dilithium_cost(), 1500);

        // Test hash costs
        assert_eq!(schedule.blake3_cost(1000), 1000);
        assert_eq!(schedule.hash_cost(500), 500);

        // Test key derivation costs
        assert_eq!(schedule.pubkey_derive_cost(), 500);
        assert_eq!(schedule.address_derive_cost(), 200);
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

        // Test memory access costs
        assert_eq!(schedule.local_access_cost(), 2);
        assert_eq!(schedule.global_access_cost(), 5);

        // Test control flow costs
        assert_eq!(schedule.function_call_cost(), 10);
        assert_eq!(schedule.function_return_cost(), 5);
        assert_eq!(schedule.branch_cost(), 2);

        // Test object access costs
        assert_eq!(schedule.field_access_cost(), 3);
        assert_eq!(schedule.vector_op_cost(10), 20);
    }

    #[test]
    fn test_storage_operation_costs() {
        let schedule = FuelSchedule::default();

        // Test storage costs
        assert_eq!(schedule.storage_read_cost(1000), 10_000);
        assert_eq!(schedule.storage_write_cost(1000), 100_000);
        assert_eq!(schedule.memory_cost(1000), 1000);
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
}

