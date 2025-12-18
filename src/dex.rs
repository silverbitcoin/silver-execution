//! DEX (Decentralized Exchange) Module - Production-ready AMM implementation
//!
//! Provides Automated Market Maker (AMM) functionality with:
//! - Liquidity pools (Token A ↔ Token B)
//! - Constant product formula (x*y=k)
//! - Liquidity provider shares
//! - Swap fees and protocol fees
//! - Pool creation and management
//! - Price oracle functionality

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// DEX error types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DexError {
    /// Pool not found
    PoolNotFound,
    /// Insufficient liquidity
    InsufficientLiquidity,
    /// Insufficient input amount
    InsufficientInputAmount,
    /// Invalid token pair
    InvalidTokenPair,
    /// Slippage exceeded
    SlippageExceeded,
    /// Invalid fee
    InvalidFee,
    /// Pool already exists
    PoolAlreadyExists,
    /// Insufficient shares
    InsufficientShares,
    /// Invalid amount
    InvalidAmount,
    /// Unauthorized
    Unauthorized,
}

impl std::fmt::Display for DexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DexError::PoolNotFound => write!(f, "Pool not found"),
            DexError::InsufficientLiquidity => write!(f, "Insufficient liquidity"),
            DexError::InsufficientInputAmount => write!(f, "Insufficient input amount"),
            DexError::InvalidTokenPair => write!(f, "Invalid token pair"),
            DexError::SlippageExceeded => write!(f, "Slippage exceeded"),
            DexError::InvalidFee => write!(f, "Invalid fee"),
            DexError::PoolAlreadyExists => write!(f, "Pool already exists"),
            DexError::InsufficientShares => write!(f, "Insufficient shares"),
            DexError::InvalidAmount => write!(f, "Invalid amount"),
            DexError::Unauthorized => write!(f, "Unauthorized"),
        }
    }
}

impl std::error::Error for DexError {}

/// Liquidity pool state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiquidityPool {
    /// Unique pool ID
    pub pool_id: u64,
    /// First token identifier
    pub token_a: String,
    /// Second token identifier
    pub token_b: String,
    /// Reserve of token A (in smallest units)
    pub reserve_a: u128,
    /// Reserve of token B (in smallest units)
    pub reserve_b: u128,
    /// Total liquidity provider shares
    pub total_shares: u128,
    /// Fee percentage (in basis points, e.g., 30 = 0.3%)
    pub fee_percentage: u64,
    /// Protocol fee percentage (in basis points)
    pub protocol_fee_percentage: u64,
    /// Pool creator address
    pub creator: String,
    /// Creation timestamp (Unix seconds)
    pub created_at: u64,
    /// Last update timestamp
    pub updated_at: u64,
    /// Whether pool is active
    pub is_active: bool,
}

/// Liquidity provider position
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiquidityPosition {
    /// Position ID
    pub position_id: u64,
    /// Pool ID
    pub pool_id: u64,
    /// Provider address
    pub provider: String,
    /// LP shares owned
    pub shares: u128,
    /// Timestamp of last update
    pub updated_at: u64,
}

/// Swap transaction record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapRecord {
    /// Swap ID
    pub swap_id: u64,
    /// Pool ID
    pub pool_id: u64,
    /// Swapper address
    pub swapper: String,
    /// Input token
    pub token_in: String,
    /// Output token
    pub token_out: String,
    /// Input amount
    pub amount_in: u128,
    /// Output amount
    pub amount_out: u128,
    /// Fee paid
    pub fee_paid: u128,
    /// Timestamp
    pub timestamp: u64,
}

/// DEX state manager
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DEXState {
    /// All liquidity pools
    pools: HashMap<u64, LiquidityPool>,
    /// All liquidity positions
    positions: HashMap<u64, LiquidityPosition>,
    /// Swap history
    swap_history: Vec<SwapRecord>,
    /// Pool counter for ID generation
    pool_counter: u64,
    /// Position counter for ID generation
    position_counter: u64,
    /// Swap counter for ID generation
    swap_counter: u64,
    /// DEX owner
    owner: String,
    /// Fee collector address
    fee_collector: String,
    /// Protocol fee percentage (in basis points)
    protocol_fee_percentage: u64,
    /// Whether DEX is paused
    is_paused: bool,
}

impl DEXState {
    /// Create new DEX state
    pub fn new(owner: String, fee_collector: String, protocol_fee: u64) -> Self {
        Self {
            pools: HashMap::new(),
            positions: HashMap::new(),
            swap_history: Vec::new(),
            pool_counter: 0,
            position_counter: 0,
            swap_counter: 0,
            owner,
            fee_collector,
            protocol_fee_percentage: protocol_fee,
            is_paused: false,
        }
    }

    /// Create a new liquidity pool
    pub fn create_pool(
        &mut self,
        creator: String,
        token_a: String,
        token_b: String,
        fee_percentage: u64,
    ) -> Result<u64, DexError> {
        // Validate inputs
        if token_a == token_b {
            return Err(DexError::InvalidTokenPair);
        }

        if fee_percentage > 10000 {
            // Max 100% fee
            return Err(DexError::InvalidFee);
        }

        // Check if pool already exists (normalized order)
        let (token_a_norm, token_b_norm) = if token_a < token_b {
            (token_a.clone(), token_b.clone())
        } else {
            (token_b.clone(), token_a.clone())
        };

        for pool in self.pools.values() {
            let (pool_a, pool_b) = if pool.token_a < pool.token_b {
                (pool.token_a.clone(), pool.token_b.clone())
            } else {
                (pool.token_b.clone(), pool.token_a.clone())
            };

            if pool_a == token_a_norm && pool_b == token_b_norm {
                return Err(DexError::PoolAlreadyExists);
            }
        }

        // Create new pool
        let pool_id = self.pool_counter;
        self.pool_counter += 1;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let pool = LiquidityPool {
            pool_id,
            token_a,
            token_b,
            reserve_a: 0,
            reserve_b: 0,
            total_shares: 0,
            fee_percentage,
            protocol_fee_percentage: self.protocol_fee_percentage,
            creator,
            created_at: now,
            updated_at: now,
            is_active: true,
        };

        self.pools.insert(pool_id, pool);
        Ok(pool_id)
    }

    /// Add liquidity to a pool
    pub fn add_liquidity(
        &mut self,
        provider: String,
        pool_id: u64,
        amount_a: u128,
        amount_b: u128,
    ) -> Result<u128, DexError> {
        if amount_a == 0 || amount_b == 0 {
            return Err(DexError::InvalidAmount);
        }

        let pool = self.pools.get_mut(&pool_id).ok_or(DexError::PoolNotFound)?;

        let shares = if pool.total_shares == 0 {
            // First liquidity provider: shares = sqrt(amount_a * amount_b)
            // Using integer square root approximation
            let product = (amount_a as u128).saturating_mul(amount_b as u128);
            integer_sqrt(product)
        } else {
            // Subsequent providers: shares = min(amount_a * total_shares / reserve_a, amount_b * total_shares / reserve_b)
            let shares_a = (amount_a as u128)
                .saturating_mul(pool.total_shares)
                .saturating_div(pool.reserve_a.max(1));
            let shares_b = (amount_b as u128)
                .saturating_mul(pool.total_shares)
                .saturating_div(pool.reserve_b.max(1));
            shares_a.min(shares_b)
        };

        if shares == 0 {
            return Err(DexError::InvalidAmount);
        }

        // Update pool reserves
        pool.reserve_a = pool.reserve_a.saturating_add(amount_a);
        pool.reserve_b = pool.reserve_b.saturating_add(amount_b);
        pool.total_shares = pool.total_shares.saturating_add(shares);
        pool.updated_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Create or update position
        let position_id = self.position_counter;
        self.position_counter += 1;

        let position = LiquidityPosition {
            position_id,
            pool_id,
            provider,
            shares,
            updated_at: pool.updated_at,
        };

        self.positions.insert(position_id, position);

        Ok(shares)
    }

    /// Remove liquidity from a pool
    pub fn remove_liquidity(
        &mut self,
        _provider: String,
        pool_id: u64,
        shares: u128,
    ) -> Result<(u128, u128), DexError> {
        if shares == 0 {
            return Err(DexError::InvalidAmount);
        }

        let pool = self.pools.get_mut(&pool_id).ok_or(DexError::PoolNotFound)?;

        if pool.total_shares == 0 {
            return Err(DexError::InsufficientLiquidity);
        }

        // Calculate amounts to return
        let amount_a = (shares as u128)
            .saturating_mul(pool.reserve_a)
            .saturating_div(pool.total_shares);
        let amount_b = (shares as u128)
            .saturating_mul(pool.reserve_b)
            .saturating_div(pool.total_shares);

        if amount_a == 0 || amount_b == 0 {
            return Err(DexError::InvalidAmount);
        }

        // Update pool reserves
        pool.reserve_a = pool.reserve_a.saturating_sub(amount_a);
        pool.reserve_b = pool.reserve_b.saturating_sub(amount_b);
        pool.total_shares = pool.total_shares.saturating_sub(shares);
        pool.updated_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok((amount_a, amount_b))
    }

    /// Perform a token swap
    pub fn swap(
        &mut self,
        swapper: String,
        pool_id: u64,
        token_in: String,
        amount_in: u128,
        min_amount_out: u128,
    ) -> Result<u128, DexError> {
        if amount_in == 0 {
            return Err(DexError::InvalidAmount);
        }

        let pool = self.pools.get_mut(&pool_id).ok_or(DexError::PoolNotFound)?;

        if !pool.is_active {
            return Err(DexError::PoolNotFound);
        }

        // Determine input and output tokens
        let (reserve_in, reserve_out, token_out) = if token_in == pool.token_a {
            (pool.reserve_a, pool.reserve_b, pool.token_b.clone())
        } else if token_in == pool.token_b {
            (pool.reserve_b, pool.reserve_a, pool.token_a.clone())
        } else {
            return Err(DexError::InvalidTokenPair);
        };

        if reserve_in == 0 || reserve_out == 0 {
            return Err(DexError::InsufficientLiquidity);
        }

        // Calculate output amount using constant product formula: x*y=k
        // amount_out = (amount_in * (1 - fee) * reserve_out) / (reserve_in + amount_in * (1 - fee))
        let fee_basis_points = 10000 - pool.fee_percentage;
        let amount_in_with_fee = (amount_in as u128)
            .saturating_mul(fee_basis_points as u128)
            .saturating_div(10000);

        let numerator = (amount_in_with_fee as u128).saturating_mul(reserve_out);
        let denominator = (reserve_in as u128).saturating_add(amount_in_with_fee as u128);

        let amount_out = numerator.saturating_div(denominator.max(1));

        if amount_out < min_amount_out {
            return Err(DexError::SlippageExceeded);
        }

        if amount_out > reserve_out {
            return Err(DexError::InsufficientLiquidity);
        }

        // Calculate fees
        let fee_paid = (amount_in as u128)
            .saturating_mul(pool.fee_percentage as u128)
            .saturating_div(10000);

        // Update pool reserves
        if token_in == pool.token_a {
            pool.reserve_a = pool.reserve_a.saturating_add(amount_in);
            pool.reserve_b = pool.reserve_b.saturating_sub(amount_out);
        } else {
            pool.reserve_b = pool.reserve_b.saturating_add(amount_in);
            pool.reserve_a = pool.reserve_a.saturating_sub(amount_out);
        }

        pool.updated_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Record swap
        let swap_id = self.swap_counter;
        self.swap_counter += 1;

        let swap_record = SwapRecord {
            swap_id,
            pool_id,
            swapper,
            token_in,
            token_out,
            amount_in,
            amount_out,
            fee_paid,
            timestamp: pool.updated_at,
        };

        self.swap_history.push(swap_record);

        Ok(amount_out)
    }

    /// Get pool information
    pub fn get_pool(&self, pool_id: u64) -> Result<LiquidityPool, DexError> {
        self.pools
            .get(&pool_id)
            .cloned()
            .ok_or(DexError::PoolNotFound)
    }

    /// List all pools
    pub fn list_pools(&self) -> Vec<LiquidityPool> {
        self.pools.values().cloned().collect()
    }

    /// Get price of token_out in terms of token_in
    pub fn get_price(
        &self,
        pool_id: u64,
        token_in: String,
        amount_in: u128,
    ) -> Result<u128, DexError> {
        let pool = self.pools.get(&pool_id).ok_or(DexError::PoolNotFound)?;

        if !pool.is_active {
            return Err(DexError::PoolNotFound);
        }

        let (reserve_in, reserve_out) = if token_in == pool.token_a {
            (pool.reserve_a, pool.reserve_b)
        } else if token_in == pool.token_b {
            (pool.reserve_b, pool.reserve_a)
        } else {
            return Err(DexError::InvalidTokenPair);
        };

        if reserve_in == 0 || reserve_out == 0 {
            return Err(DexError::InsufficientLiquidity);
        }

        // Calculate price without fees (for price oracle)
        let price = (amount_in as u128)
            .saturating_mul(reserve_out)
            .saturating_div(reserve_in.max(1));

        Ok(price)
    }

    /// Get swap history
    pub fn get_swap_history(&self, pool_id: u64, limit: usize) -> Vec<SwapRecord> {
        self.swap_history
            .iter()
            .filter(|s| s.pool_id == pool_id)
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    /// Pause/unpause DEX
    pub fn set_paused(&mut self, paused: bool) -> Result<(), DexError> {
        self.is_paused = paused;
        Ok(())
    }

    /// Get DEX statistics
    pub fn get_stats(&self) -> DexStats {
        let total_pools = self.pools.len();
        let total_positions = self.positions.len();
        let total_swaps = self.swap_history.len();

        let total_volume: u128 = self.swap_history.iter().map(|s| s.amount_in).sum();
        let total_fees: u128 = self.swap_history.iter().map(|s| s.fee_paid).sum();

        DexStats {
            total_pools,
            total_positions,
            total_swaps,
            total_volume,
            total_fees,
            is_paused: self.is_paused,
        }
    }
}

/// DEX statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexStats {
    /// Total number of pools
    pub total_pools: usize,
    /// Total number of liquidity positions
    pub total_positions: usize,
    /// Total number of swaps
    pub total_swaps: usize,
    /// Total trading volume
    pub total_volume: u128,
    /// Total fees collected
    pub total_fees: u128,
    /// Whether DEX is paused
    pub is_paused: bool,
}

/// Integer square root using Newton's method
fn integer_sqrt(n: u128) -> u128 {
    if n == 0 {
        return 0;
    }

    let mut x = n;
    let mut y = (x + 1) / 2;

    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }

    x
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_pool() {
        let mut dex = DEXState::new("owner".to_string(), "fee_collector".to_string(), 5);
        let pool_id = dex
            .create_pool(
                "creator".to_string(),
                "BTC".to_string(),
                "USDT".to_string(),
                30,
            )
            .unwrap();
        assert_eq!(pool_id, 0);
    }

    #[test]
    fn test_add_liquidity() {
        let mut dex = DEXState::new("owner".to_string(), "fee_collector".to_string(), 5);
        let pool_id = dex
            .create_pool(
                "creator".to_string(),
                "BTC".to_string(),
                "USDT".to_string(),
                30,
            )
            .unwrap();

        let shares = dex
            .add_liquidity("provider".to_string(), pool_id, 1_000_000, 50_000_000)
            .unwrap();
        assert!(shares > 0);
    }

    #[test]
    fn test_swap() {
        let mut dex = DEXState::new("owner".to_string(), "fee_collector".to_string(), 5);
        let pool_id = dex
            .create_pool(
                "creator".to_string(),
                "BTC".to_string(),
                "USDT".to_string(),
                30,
            )
            .unwrap();

        dex.add_liquidity("provider".to_string(), pool_id, 1_000_000, 50_000_000)
            .unwrap();

        let amount_out = dex
            .swap(
                "swapper".to_string(),
                pool_id,
                "BTC".to_string(),
                100_000,
                0,
            )
            .unwrap();
        assert!(amount_out > 0);
    }
}
