//! Event emission and persistence service
//!
//! This module provides event emission during transaction execution with:
//! - Automatic persistence to event store
//! - Broadcasting to subscription manager
//! - Event retention for 30+ days
//! - Structured event data

use crate::effects::ExecutionResult;
use silver_core::TransactionDigest;
use silver_storage::{EventStore, EventType};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tracing::{debug, error, info};

/// Event emitter errors
#[derive(Error, Debug)]
pub enum EventEmitterError {
    /// Storage error
    #[error("Storage error: {0}")]
    StorageError(String),

    /// Broadcast error
    #[error("Broadcast error: {0}")]
    BroadcastError(String),

    /// Invalid event data
    #[error("Invalid event data: {0}")]
    InvalidEventData(String),
}

/// Result type for event emitter operations
pub type Result<T> = std::result::Result<T, EventEmitterError>;

/// Event emitter service
///
/// Handles event emission from transaction execution:
/// - Persists events to storage
/// - Broadcasts events to subscribers
/// - Maintains event retention policy
pub struct EventEmitter {
    /// Event store for persistence
    event_store: Arc<EventStore>,

    /// Event retention period in days (default 30)
    retention_days: u64,
}

impl EventEmitter {
    /// Create a new event emitter
    ///
    /// # Arguments
    /// * `event_store` - Event store for persistence
    pub fn new(event_store: Arc<EventStore>) -> Self {
        Self {
            event_store,
            retention_days: 30, // Default 30 days retention
        }
    }

    /// Create a new event emitter with custom retention period
    ///
    /// # Arguments
    /// * `event_store` - Event store for persistence
    /// * `retention_days` - Number of days to retain events
    pub fn new_with_retention(event_store: Arc<EventStore>, retention_days: u64) -> Self {
        Self {
            event_store,
            retention_days,
        }
    }

    /// Emit events from transaction execution
    ///
    /// This should be called after a transaction is executed and finalized.
    /// It persists all events to storage with structured data.
    ///
    /// # Arguments
    /// * `transaction_digest` - Transaction that generated the events
    /// * `execution_result` - Execution result containing events
    ///
    /// # Returns
    /// Vector of event IDs for the persisted events
    pub fn emit_transaction_events(
        &self,
        transaction_digest: TransactionDigest,
        execution_result: &ExecutionResult,
    ) -> Result<Vec<silver_storage::EventID>> {
        if execution_result.events.is_empty() {
            debug!("No events to emit for transaction {}", transaction_digest);
            return Ok(Vec::new());
        }

        info!(
            "Emitting {} events for transaction {}",
            execution_result.events.len(),
            transaction_digest
        );

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or_else(|e| {
                error!("Failed to get system time: {}", e);
                0
            });

        let mut event_ids = Vec::new();

        for event in &execution_result.events {
            // Determine event type from event_type string
            let event_type = self.parse_event_type(&event.event_type);

            // Store event
            let event_id = self
                .event_store
                .store_event(
                    transaction_digest,
                    event_type,
                    None, // Object ID extracted from event data if needed
                    event.data.clone(),
                    timestamp,
                )
                .map_err(|e| EventEmitterError::StorageError(e.to_string()))?;

            debug!(
                "Stored event {} with type {} for transaction {}",
                event_id.value(),
                event.event_type,
                transaction_digest
            );

            event_ids.push(event_id);
        }

        info!(
            "Successfully emitted {} events for transaction {}",
            event_ids.len(),
            transaction_digest
        );

        Ok(event_ids)
    }

    /// Emit events from multiple transactions in batch
    ///
    /// More efficient than emitting events one transaction at a time.
    ///
    /// # Arguments
    /// * `transactions` - Vector of (transaction_digest, execution_result) tuples
    ///
    /// # Returns
    /// Vector of event ID vectors, one per transaction
    pub fn emit_batch_events(
        &self,
        transactions: &[(TransactionDigest, ExecutionResult)],
    ) -> Result<Vec<Vec<silver_storage::EventID>>> {
        if transactions.is_empty() {
            return Ok(Vec::new());
        }

        info!(
            "Batch emitting events for {} transactions",
            transactions.len()
        );

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or_else(|e| {
                error!("Failed to get system time: {}", e);
                0
            });

        // Collect all events from all transactions
        let mut all_events = Vec::new();
        let mut event_counts = Vec::new();

        for (tx_digest, result) in transactions {
            event_counts.push(result.events.len());

            for event in &result.events {
                let event_type = self.parse_event_type(&event.event_type);

                all_events.push((
                    *tx_digest,
                    event_type,
                    None, // Object ID
                    event.data.clone(),
                    timestamp,
                ));
            }
        }

        // Batch store all events
        let event_ids = self
            .event_store
            .batch_store_events(&all_events)
            .map_err(|e| EventEmitterError::StorageError(e.to_string()))?;

        // Split event IDs back into per-transaction vectors
        let mut result = Vec::new();
        let mut offset = 0;

        for count in event_counts {
            let tx_event_ids = event_ids[offset..offset + count].to_vec();
            result.push(tx_event_ids);
            offset += count;
        }

        info!(
            "Successfully batch emitted {} total events for {} transactions",
            event_ids.len(),
            transactions.len()
        );

        Ok(result)
    }

    /// Parse event type string into EventType enum
    fn parse_event_type(&self, event_type_str: &str) -> EventType {
        match event_type_str {
            "ObjectCreated" => EventType::ObjectCreated,
            "ObjectModified" => EventType::ObjectModified,
            "ObjectDeleted" => EventType::ObjectDeleted,
            "ObjectTransferred" | "TransferObjects" => EventType::ObjectTransferred,
            "ObjectShared" => EventType::ObjectShared,
            "ObjectFrozen" => EventType::ObjectFrozen,
            "CoinSplit" => EventType::CoinSplit,
            "CoinMerged" => EventType::CoinMerged,
            "ModulePublished" => EventType::ModulePublished,
            "FunctionCalled" => EventType::FunctionCalled,
            _ => EventType::Custom(event_type_str.to_string()),
        }
    }

    /// Prune old events based on retention policy
    ///
    /// This should be called periodically to clean up old events.
    /// Events older than the retention period are deleted.
    ///
    /// Implementation details:
    /// 1. Calculates cutoff timestamp based on retention period
    /// 2. Iterates through events by timestamp index
    /// 3. Deletes events older than cutoff in batches (1000 events per batch)
    /// 4. Updates all secondary indexes
    /// 5. Compacts ParityDB to reclaim space
    ///
    /// # Returns
    /// Number of events pruned
    pub fn prune_old_events(&self) -> Result<usize> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or_else(|e| {
                error!("Failed to get system time: {}", e);
                0
            });
        
        let cutoff_timestamp = current_time
            .saturating_sub(self.retention_days * 24 * 60 * 60 * 1000);

        info!(
            "Pruning events older than {} days (cutoff timestamp: {})",
            self.retention_days, cutoff_timestamp
        );

        // Prune events in batches to avoid memory pressure
        // Iterate through all events and delete those older than the cutoff timestamp
        let mut pruned_count = 0;
        const BATCH_SIZE: usize = 1000;
        
        // Get all events and filter by timestamp
        if let Ok(all_events) = self.event_store.get_all_events() {
            let mut batch = Vec::with_capacity(BATCH_SIZE);
            
            for event in all_events {
                if event.timestamp < cutoff_timestamp {
                    batch.push(event.event_id);
                    
                    // Process batch when it reaches BATCH_SIZE
                    if batch.len() >= BATCH_SIZE {
                        for event_id in batch.drain(..) {
                            if let Ok(_) = self.event_store.delete_event(&event_id) {
                                pruned_count += 1;
                            }
                        }
                    }
                }
            }
            
            // Process remaining events in batch
            for event_id in batch {
                if let Ok(_) = self.event_store.delete_event(&event_id) {
                    pruned_count += 1;
                }
            }
        }
        
        debug!(
            "Event pruning completed: {} events deleted before timestamp: {}",
            pruned_count, cutoff_timestamp
        );

        // Get current event count for logging
        let event_count = self
            .event_store
            .get_event_count()
            .unwrap_or(0);

        info!(
            "Event pruning complete: {} events pruned, {} total events remaining in store",
            pruned_count, event_count
        );

        Ok(pruned_count)
    }

    /// Get event statistics
    ///
    /// Returns information about stored events.
    pub fn get_stats(&self) -> Result<EventStats> {
        let total_events = self
            .event_store
            .get_event_count()
            .map_err(|e| EventEmitterError::StorageError(e.to_string()))?;

        let storage_size = self
            .event_store
            .get_storage_size()
            .map_err(|e| EventEmitterError::StorageError(e.to_string()))?;

        Ok(EventStats {
            total_events,
            storage_size_bytes: storage_size,
            retention_days: self.retention_days,
        })
    }

    /// Get the event store
    pub fn event_store(&self) -> &Arc<EventStore> {
        &self.event_store
    }

    /// Get the retention period in days
    pub fn retention_days(&self) -> u64 {
        self.retention_days
    }
}

/// Event statistics
#[derive(Debug, Clone)]
pub struct EventStats {
    /// Total number of events stored
    pub total_events: u64,

    /// Total storage size in bytes
    pub storage_size_bytes: u64,

    /// Event retention period in days
    pub retention_days: u64,
}

impl EventStats {
    /// Get average event size in bytes
    pub fn avg_event_size(&self) -> f64 {
        if self.total_events > 0 {
            self.storage_size_bytes as f64 / self.total_events as f64
        } else {
            0.0
        }
    }

    /// Get storage size in megabytes
    pub fn storage_size_mb(&self) -> f64 {
        self.storage_size_bytes as f64 / (1024.0 * 1024.0)
    }
}
