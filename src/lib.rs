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
#![forbid(unsafe_code)]

pub mod vm;
pub mod verifier;
pub mod executor;
pub mod fuel;
pub mod effects;
pub mod event_emitter;

pub use vm::{QuantumVM, Bytecode, Instruction};
pub use verifier::BytecodeVerifier;
pub use executor::{TransactionExecutor, ParallelExecutor};
pub use fuel::{FuelMeter, FuelSchedule};
pub use effects::{TransactionEffects, ExecutionResult};
pub use event_emitter::{EventEmitter, EventStats};
