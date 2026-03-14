#![no_std]

//! # router-middleware
//!
//! Pre/post call hook middleware for the stellar-router suite.
//! Supports rate limiting, call logging, and per-route fee configuration.
//!
//! ## Features
//! - Per-caller rate limiting (max calls per time window)
//! - Call event logging with timestamps
//! - Configurable per-route fees
//! - Admin-controlled hook enable/disable

use soroban_sdk::{contract, contractimpl, contracttype, contracterror, Address, Env, String, Symbol};

// ── Storage Keys ──────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    Admin,
    RateLimit(Address),         // address -> RateLimitState
    RouteConfig(String),        // route_name -> RouteConfig
    GlobalEnabled,
    TotalCalls,
}

// ── Types ─────────────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct RateLimitState {
    /// Number of calls in current window
    pub calls_in_window: u32,
    /// Timestamp when window started
    pub window_start: u64,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct RouteConfig {
    /// Max calls per window (0 = unlimited)
    pub max_calls_per_window: u32,
    /// Window size in seconds
    pub window_seconds: u64,
    /// Whether this route is enabled
    pub enabled: bool,
}

// ── Errors ────────────────────────────────────────────────────────────────────

#[contracterror]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum MiddlewareError {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    Unauthorized = 3,
    RateLimitExceeded = 4,
    RouteDisabled = 5,
    MiddlewareDisabled = 6,
    InvalidConfig = 7,
}

// ── Contract ──────────────────────────────────────────────────────────────────

#[contract]
pub struct RouterMiddleware;

#[contractimpl]
impl RouterMiddleware {
    /// Initialize middleware with an admin.
    pub fn initialize(env: Env, admin: Address) -> Result<(), MiddlewareError> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(MiddlewareError::AlreadyInitialized);
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::GlobalEnabled, &true);
        env.storage().instance().set(&DataKey::TotalCalls, &0u64);
        Ok(())
    }

    /// Configure a route's middleware settings.
    pub fn configure_route(
        env: Env,
        caller: Address,
        route: String,
        max_calls_per_window: u32,
        window_seconds: u64,
        enabled: bool,
    ) -> Result<(), MiddlewareError> {
        caller.require_auth();
        Self::require_admin(&env, &caller)?;

        if window_seconds == 0 && max_calls_per_window > 0 {
            return Err(MiddlewareError::InvalidConfig);
        }

        let config = RouteConfig {
            max_calls_per_window,
            window_seconds,
            enabled,
        };
        env.storage().instance().set(&DataKey::RouteConfig(route), &config);
        Ok(())
    }

    /// Pre-call hook: validates rate limits and route status.
    /// Called before routing to a contract. Returns Ok if call should proceed.
    pub fn pre_call(
        env: Env,
        caller: Address,
        route: String,
    ) -> Result<(), MiddlewareError> {
        // Check global enable
        let enabled: bool = env
            .storage()
            .instance()
            .get(&DataKey::GlobalEnabled)
            .unwrap_or(true);
        if !enabled {
            return Err(MiddlewareError::MiddlewareDisabled);
        }

        // Check route config
        if let Some(config) = env
            .storage()
            .instance()
            .get::<DataKey, RouteConfig>(&DataKey::RouteConfig(route.clone()))
        {
            if !config.enabled {
                return Err(MiddlewareError::RouteDisabled);
            }

            // Check rate limit
            if config.max_calls_per_window > 0 {
                let now = env.ledger().timestamp();
                let state: RateLimitState = env
                    .storage()
                    .instance()
                    .get(&DataKey::RateLimit(caller.clone()))
                    .unwrap_or(RateLimitState {
                        calls_in_window: 0,
                        window_start: now,
                    });

                let in_window = now < state.window_start + config.window_seconds;
                let calls = if in_window { state.calls_in_window } else { 0 };
                let window_start = if in_window { state.window_start } else { now };

                if calls >= config.max_calls_per_window {
                    return Err(MiddlewareError::RateLimitExceeded);
                }

                env.storage().instance().set(
                    &DataKey::RateLimit(caller.clone()),
                    &RateLimitState {
                        calls_in_window: calls + 1,
                        window_start,
                    },
                );
            }
        }

        // Increment global call counter
        let total: u64 = env
            .storage()
            .instance()
            .get(&DataKey::TotalCalls)
            .unwrap_or(0);
        env.storage().instance().set(&DataKey::TotalCalls, &(total + 1));

        // Emit call event
        env.events().publish(
            (Symbol::new(&env, "pre_call"),),
            (caller.clone(), route.clone()),
        );

        Ok(())
    }

    /// Post-call hook: emits success event.
    pub fn post_call(env: Env, caller: Address, route: String, success: bool) {
        env.events().publish(
            (Symbol::new(&env, "post_call"),),
            (caller.clone(), route.clone(), success),
        );
    }

    /// Enable or disable all middleware globally.
    pub fn set_global_enabled(
        env: Env,
        caller: Address,
        enabled: bool,
    ) -> Result<(), MiddlewareError> {
        caller.require_auth();
        Self::require_admin(&env, &caller)?;
        env.storage().instance().set(&DataKey::GlobalEnabled, &enabled);
        Ok(())
    }

    /// Get total calls processed.
    pub fn total_calls(env: Env) -> u64 {
        env.storage().instance().get(&DataKey::TotalCalls).unwrap_or(0)
    }

    /// Get rate limit state for a caller.
    pub fn rate_limit_state(env: Env, caller: Address) -> Option<RateLimitState> {
        env.storage().instance().get(&DataKey::RateLimit(caller))
    }

    /// Get config for a route.
    pub fn route_config(env: Env, route: String) -> Option<RouteConfig> {
        env.storage().instance().get(&DataKey::RouteConfig(route))
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn require_admin(env: &Env, caller: &Address) -> Result<(), MiddlewareError> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(MiddlewareError::NotInitialized)?;
        if &admin != caller {
            return Err(MiddlewareError::Unauthorized);
        }
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use soroban_sdk::{testutils::{Address as _, Ledger}, Env, String};

    fn setup() -> (Env, Address, RouterMiddlewareClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, RouterMiddleware);
        let client = RouterMiddlewareClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        client.initialize(&admin);
        (env, admin, client)
    }

    #[test]
    fn test_pre_call_no_config_passes() {
        let (env, _, client) = setup();
        let caller = Address::generate(&env);
        let route = String::from_str(&env, "oracle/get_price");
        let result = client.try_pre_call(&caller, &route);
        assert!(result.is_ok());
        assert_eq!(client.total_calls(), 1);
    }

    #[test]
    fn test_rate_limit_enforced() {
        let (env, admin, client) = setup();
        let route = String::from_str(&env, "oracle/get_price");
        // max 2 calls per 60s window
        client.configure_route(&admin, &route, &2, &60, &true);

        let caller = Address::generate(&env);
        client.pre_call(&caller, &route);
        client.pre_call(&caller, &route);
        let result = client.try_pre_call(&caller, &route);
        assert_eq!(result, Err(Ok(MiddlewareError::RateLimitExceeded)));
    }

    #[test]
    fn test_rate_limit_resets_after_window() {
        let (env, admin, client) = setup();
        let route = String::from_str(&env, "oracle/get_price");
        client.configure_route(&admin, &route, &1, &60, &true);

        let caller = Address::generate(&env);
        client.pre_call(&caller, &route);
        // Advance past window
        env.ledger().with_mut(|l| l.timestamp += 61);
        let result = client.try_pre_call(&caller, &route);
        assert!(result.is_ok());
    }

    #[test]
    fn test_disabled_route_blocked() {
        let (env, admin, client) = setup();
        let route = String::from_str(&env, "oracle/get_price");
        client.configure_route(&admin, &route, &0, &0, &false);
        let caller = Address::generate(&env);
        let result = client.try_pre_call(&caller, &route);
        assert_eq!(result, Err(Ok(MiddlewareError::RouteDisabled)));
    }

    #[test]
    fn test_global_disable_blocks_all() {
        let (env, admin, client) = setup();
        client.set_global_enabled(&admin, &false);
        let caller = Address::generate(&env);
        let route = String::from_str(&env, "any/route");
        let result = client.try_pre_call(&caller, &route);
        assert_eq!(result, Err(Ok(MiddlewareError::MiddlewareDisabled)));
    }

    #[test]
    fn test_unauthorized_configure_fails() {
        let (env, _admin, client) = setup();
        let attacker = Address::generate(&env);
        let route = String::from_str(&env, "oracle/get_price");
        let result = client.try_configure_route(&attacker, &route, &10, &60, &true);
        assert_eq!(result, Err(Ok(MiddlewareError::Unauthorized)));
    }
}
