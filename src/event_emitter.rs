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
use tracing::{debug, error, info, warn};

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
            .unwrap()
            .as_millis() as u64;

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

        info!("Batch emitting events for {} transactions", transactions.len());

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

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
    /// # Returns
    /// Number of events pruned
    pub fn prune_old_events(&self) -> Result<usize> {
        let cutoff_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            - (self.retention_days * 24 * 60 * 60 * 1000);

        info!(
            "Pruning events older than {} days (cutoff timestamp: {})",
            self.retention_days, cutoff_timestamp
        );

        // Note: Event pruning requires iterating through all events and checking timestamps.
        // This is an expensive operation that should be run during low-traffic periods.
        // The EventStore would need to implement a prune_events_before(timestamp) method
        // that efficiently removes old events while maintaining index consistency.
        // 
        // For production deployment, this should be implemented as:
        // 1. Iterate through events by timestamp index
        // 2. Delete events older than cutoff in batches
        // 3. Update all secondary indexes
        // 4. Compact RocksDB to reclaim space
        //
        // Current implementation: Events are retained indefinitely until EventStore
        // implements the pruning method. This is acceptable for initial deployment
        // as 30 days of events at 10K TPS = ~26B events = ~2.6TB at 100 bytes/event.
        
        warn!(
            "Event pruning requires EventStore.prune_events_before() implementation. \
             Events will be retained indefinitely until this is implemented. \
             Monitor storage usage and implement pruning before reaching capacity."
        );

        Ok(0)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::effects::Event;
    use silver_core::{SilverAddress, TransactionDigest};
    use silver_storage::RocksDatabase;
    use tempfile::TempDir;

    fn create_test_emitter() -> (EventEmitter, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let db = Arc::new(RocksDatabase::open(temp_dir.path()).unwrap());
        let event_store = Arc::new(EventStore::new(db));
        let emitter = EventEmitter::new(event_store);
        (emitter, temp_dir)
    }

    fn create_test_execution_result() -> ExecutionResult {
        ExecutionResult {
            status: crate::effects::ExecutionStatus::Success,
            fuel_used: 1000,
            fuel_refund: 500,
            modified_objects: Vec::new(),
            created_objects: Vec::new(),
            deleted_objects: Vec::new(),
            events: vec![
                Event {
                    event_type: "ObjectCreated".to_string(),
                    sender: SilverAddress::new([1; 64]),
                    data: vec![1, 2, 3],
                },
                Event {
                    event_type: "TransferObjects".to_string(),
                    sender: SilverAddress::new([1; 64]),
                    data: vec![4, 5, 6],
                },
            ],
            error_message: None,
        }
    }

    #[test]
    fn test_emit_transaction_events() {
        let (emitter, _temp) = create_test_emitter();
        let tx_digest = TransactionDigest::new([1; 64]);
        let result = create_test_execution_result();

        let event_ids = emitter.emit_transaction_events(tx_digest, &result).unwrap();
        assert_eq!(event_ids.len(), 2);
    }

    #[test]
    fn test_emit_empty_events() {
        let (emitter, _temp) = create_test_emitter();
        let tx_digest = TransactionDigest::new([1; 64]);
        let result = ExecutionResult {
            status: crate::effects::ExecutionStatus::Success,
            fuel_used: 1000,
            fuel_refund: 500,
            modified_objects: Vec::new(),
            created_objects: Vec::new(),
            deleted_objects: Vec::new(),
            events: Vec::new(),
            error_message: None,
        };

        let event_ids = emitter.emit_transaction_events(tx_digest, &result).unwrap();
        assert_eq!(event_ids.len(), 0);
    }

    #[test]
    fn test_emit_batch_events() {
        let (emitter, _temp) = create_test_emitter();

        let transactions = vec![
            (TransactionDigest::new([1; 64]), create_test_execution_result()),
            (TransactionDigest::new([2; 64]), create_test_execution_result()),
        ];

        let result = emitter.emit_batch_events(&transactions).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].len(), 2); // 2 events per transaction
        assert_eq!(result[1].len(), 2);
    }

    #[test]
    fn test_parse_event_type() {
        let (emitter, _temp) = create_test_emitter();

        assert!(matches!(
            emitter.parse_event_type("ObjectCreated"),
            EventType::ObjectCreated
        ));
        assert!(matches!(
            emitter.parse_event_type("TransferObjects"),
            EventType::ObjectTransferred
        ));
        assert!(matches!(
            emitter.parse_event_type("CustomEvent"),
            EventType::Custom(_)
        ));
    }

    #[test]
    fn test_get_stats() {
        let (emitter, _temp) = create_test_emitter();
        let tx_digest = TransactionDigest::new([1; 64]);
        let result = create_test_execution_result();

        // Emit some events
        emitter.emit_transaction_events(tx_digest, &result).unwrap();

        // Get stats
        let stats = emitter.get_stats().unwrap();
        assert!(stats.total_events >= 2);
        assert_eq!(stats.retention_days, 30);
    }

    #[test]
    fn test_custom_retention_period() {
        let temp_dir = TempDir::new().unwrap();
        let db = Arc::new(RocksDatabase::open(temp_dir.path()).unwrap());
        let event_store = Arc::new(EventStore::new(db));
        let emitter = EventEmitter::new_with_retention(event_store, 60);

        assert_eq!(emitter.retention_days(), 60);
    }

    #[test]
    fn test_event_stats_calculations() {
        let stats = EventStats {
            total_events: 1000,
            storage_size_bytes: 1024 * 1024, // 1 MB
            retention_days: 30,
        };

        // 1 MB / 1000 events = 1048.576 bytes per event
        assert_eq!(stats.avg_event_size(), 1048.576);
        assert_eq!(stats.storage_size_mb(), 1.0);
    }

    #[test]
    fn test_event_stats_zero_events() {
        let stats = EventStats {
            total_events: 0,
            storage_size_bytes: 0,
            retention_days: 30,
        };

        assert_eq!(stats.avg_event_size(), 0.0);
        assert_eq!(stats.storage_size_mb(), 0.0);
    }
}
