//! # SilverBitcoin Execution Engine
//!
//! Quantum VM execution engine with parallel transaction processing.
//!
//! This crate provides:
//! - Quantum VM bytecode interpreter
//! - Bytecode verifier (type safety, resource safety)
//! - Parallel transaction executor
//! - Fuel metering system
//! - Transaction effects generation

#![warn(missing_docs, rust_2018_idioms)]
#![allow(unsafe_code)] // NUMA affinity requires unsafe code
#![allow(missing_docs)] // Internal implementation details

pub mod bridge;
pub mod dex;
pub mod effects;
pub mod event_emitter;
pub mod executor;
pub mod fuel;
pub mod parallel_optimized;
pub mod sbtc20_token;
pub mod token_factory;
pub mod verifier;
pub mod vm; // OPTIMIZATION: Work-stealing executor (Task 35.2)

pub use bridge::{BridgeError, BridgeState, BridgeStats, BridgeTransaction, BridgeTransactionStatus, BridgeValidator};
pub use dex::{DexError, DEXState, DexStats, LiquidityPool, LiquidityPosition, SwapRecord};
pub use effects::{ExecutionResult, TransactionEffects};
pub use event_emitter::{EventEmitter, EventStats};
pub use executor::{ParallelExecutor, TransactionExecutor};
pub use fuel::{FuelMeter, FuelSchedule};
pub use parallel_optimized::{hot_path, WorkStealingExecutor};
pub use sbtc20_token::{SBTC20Token, TokenError, TokenMetadata};
pub use token_factory::{TokenFactory, FactoryError, TokenRegistryEntry};
pub use verifier::BytecodeVerifier;
pub use vm::{Bytecode, Instruction, QuantumVM}; // OPTIMIZATION exports
