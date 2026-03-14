#![no_std]

//! # router-core
//!
//! Central dispatcher for the stellar-router suite.
//! Routes calls to registered contracts by name, enforces access control,
//! and delegates to the registry for address resolution.
//!
//! ## Features
//! - Route calls to contracts by name (resolved via registry)
//! - Admin-controlled route registration and removal
//! - Pause/unpause individual routes or all routing
//! - Event emission on every route operation

use soroban_sdk::{
    contract, contractimpl, contracttype, contracterror,
    Address, Env, String, Symbol,
};

// ── Storage Keys ──────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    Admin,
    Route(String),    // name -> RouteEntry
    Paused,
    TotalRouted,
}

// ── Types ─────────────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct RouteEntry {
    /// Resolved contract address for this route
    pub address: Address,
    /// Human-readable route name
    pub name: String,
    /// Whether this specific route is paused
    pub paused: bool,
    /// Who last updated this route
    pub updated_by: Address,
}

// ── Errors ────────────────────────────────────────────────────────────────────

#[contracterror]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum RouterError {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    Unauthorized = 3,
    RouteNotFound = 4,
    RoutePaused = 5,
    RouterPaused = 6,
    RouteAlreadyExists = 7,
}

// ── Contract ──────────────────────────────────────────────────────────────────

#[contract]
pub struct RouterCore;

#[contractimpl]
impl RouterCore {
    /// Initialize the router with an admin address.
    pub fn initialize(env: Env, admin: Address) -> Result<(), RouterError> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(RouterError::AlreadyInitialized);
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Paused, &false);
        env.storage().instance().set(&DataKey::TotalRouted, &0u64);
        Ok(())
    }

    /// Register a new route by name pointing to a contract address.
    pub fn register_route(
        env: Env,
        caller: Address,
        name: String,
        address: Address,
    ) -> Result<(), RouterError> {
        caller.require_auth();
        Self::require_admin(&env, &caller)?;

        if env.storage().instance().has(&DataKey::Route(name.clone())) {
            return Err(RouterError::RouteAlreadyExists);
        }

        let entry = RouteEntry {
            address,
            name: name.clone(),
            paused: false,
            updated_by: caller,
        };
        env.storage().instance().set(&DataKey::Route(name.clone()), &entry);

        env.events().publish(
            (Symbol::new(&env, "route_registered"),),
            name.clone(),
        );

        Ok(())
    }

    /// Update an existing route to point to a new address.
    pub fn update_route(
        env: Env,
        caller: Address,
        name: String,
        new_address: Address,
    ) -> Result<(), RouterError> {
        caller.require_auth();
        Self::require_admin(&env, &caller)?;

        let mut entry: RouteEntry = env
            .storage()
            .instance()
            .get(&DataKey::Route(name.clone()))
            .ok_or(RouterError::RouteNotFound)?;

        entry.address = new_address;
        entry.updated_by = caller;
        env.storage().instance().set(&DataKey::Route(name.clone()), &entry);

        env.events().publish(
            (Symbol::new(&env, "route_updated"),),
            name.clone(),
        );

        Ok(())
    }

    /// Remove a route entirely.
    pub fn remove_route(env: Env, caller: Address, name: String) -> Result<(), RouterError> {
        caller.require_auth();
        Self::require_admin(&env, &caller)?;

        if !env.storage().instance().has(&DataKey::Route(name.clone())) {
            return Err(RouterError::RouteNotFound);
        }

        env.storage().instance().remove(&DataKey::Route(name.clone()));

        env.events().publish(
            (Symbol::new(&env, "route_removed"),),
            name.clone(),
        );

        Ok(())
    }

    /// Resolve a route name to its contract address.
    /// Also validates the router and route are not paused.
    pub fn resolve(env: Env, name: String) -> Result<Address, RouterError> {
        let paused: bool = env
            .storage()
            .instance()
            .get(&DataKey::Paused)
            .unwrap_or(false);
        if paused {
            return Err(RouterError::RouterPaused);
        }

        let entry: RouteEntry = env
            .storage()
            .instance()
            .get(&DataKey::Route(name.clone()))
            .ok_or(RouterError::RouteNotFound)?;

        if entry.paused {
            return Err(RouterError::RoutePaused);
        }

        // Increment total routed counter
        let total: u64 = env
            .storage()
            .instance()
            .get(&DataKey::TotalRouted)
            .unwrap_or(0);
        env.storage().instance().set(&DataKey::TotalRouted, &(total + 1));

        env.events().publish(
            (Symbol::new(&env, "routed"),),
            (name.clone(), entry.address.clone()),
        );

        Ok(entry.address)
    }

    /// Pause or unpause a specific route.
    pub fn set_route_paused(
        env: Env,
        caller: Address,
        name: String,
        paused: bool,
    ) -> Result<(), RouterError> {
        caller.require_auth();
        Self::require_admin(&env, &caller)?;

        let mut entry: RouteEntry = env
            .storage()
            .instance()
            .get(&DataKey::Route(name.clone()))
            .ok_or(RouterError::RouteNotFound)?;

        entry.paused = paused;
        env.storage().instance().set(&DataKey::Route(name), &entry);
        Ok(())
    }

    /// Pause or unpause the entire router.
    pub fn set_paused(env: Env, caller: Address, paused: bool) -> Result<(), RouterError> {
        caller.require_auth();
        Self::require_admin(&env, &caller)?;
        env.storage().instance().set(&DataKey::Paused, &paused);
        Ok(())
    }

    /// Get a route entry by name.
    pub fn get_route(env: Env, name: String) -> Option<RouteEntry> {
        env.storage().instance().get(&DataKey::Route(name))
    }

    /// Get the total number of resolved calls.
    pub fn total_routed(env: Env) -> u64 {
        env.storage().instance().get(&DataKey::TotalRouted).unwrap_or(0)
    }

    /// Get current admin.
    pub fn admin(env: Env) -> Result<Address, RouterError> {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(RouterError::NotInitialized)
    }

    /// Transfer admin to a new address.
    pub fn transfer_admin(env: Env, current: Address, new_admin: Address) -> Result<(), RouterError> {
        current.require_auth();
        Self::require_admin(&env, &current)?;
        env.storage().instance().set(&DataKey::Admin, &new_admin);
        Ok(())
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn require_admin(env: &Env, caller: &Address) -> Result<(), RouterError> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(RouterError::NotInitialized)?;
        if &admin != caller {
            return Err(RouterError::Unauthorized);
        }
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use soroban_sdk::{testutils::Address as _, Env, String};

    fn setup() -> (Env, Address, RouterCoreClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, RouterCore);
        let client = RouterCoreClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        client.initialize(&admin);
        (env, admin, client)
    }

    #[test]
    fn test_register_and_resolve() {
        let (env, admin, client) = setup();
        let name = String::from_str(&env, "oracle");
        let addr = Address::generate(&env);
        client.register_route(&admin, &name, &addr);
        let resolved = client.resolve(&name);
        assert_eq!(resolved, addr);
        assert_eq!(client.total_routed(), 1);
    }

    #[test]
    fn test_update_route() {
        let (env, admin, client) = setup();
        let name = String::from_str(&env, "oracle");
        let addr1 = Address::generate(&env);
        let addr2 = Address::generate(&env);
        client.register_route(&admin, &name, &addr1);
        client.update_route(&admin, &name, &addr2);
        assert_eq!(client.resolve(&name), addr2);
    }

    #[test]
    fn test_remove_route() {
        let (env, admin, client) = setup();
        let name = String::from_str(&env, "oracle");
        let addr = Address::generate(&env);
        client.register_route(&admin, &name, &addr);
        client.remove_route(&admin, &name);
        let result = client.try_resolve(&name);
        assert_eq!(result, Err(Ok(RouterError::RouteNotFound)));
    }

    #[test]
    fn test_duplicate_route_fails() {
        let (env, admin, client) = setup();
        let name = String::from_str(&env, "oracle");
        let addr = Address::generate(&env);
        client.register_route(&admin, &name, &addr);
        let result = client.try_register_route(&admin, &name, &addr);
        assert_eq!(result, Err(Ok(RouterError::RouteAlreadyExists)));
    }

    #[test]
    fn test_pause_route() {
        let (env, admin, client) = setup();
        let name = String::from_str(&env, "oracle");
        let addr = Address::generate(&env);
        client.register_route(&admin, &name, &addr);
        client.set_route_paused(&admin, &name, &true);
        let result = client.try_resolve(&name);
        assert_eq!(result, Err(Ok(RouterError::RoutePaused)));
    }

    #[test]
    fn test_pause_router() {
        let (env, admin, client) = setup();
        let name = String::from_str(&env, "oracle");
        let addr = Address::generate(&env);
        client.register_route(&admin, &name, &addr);
        client.set_paused(&admin, &true);
        let result = client.try_resolve(&name);
        assert_eq!(result, Err(Ok(RouterError::RouterPaused)));
    }

    #[test]
    fn test_unauthorized_register_fails() {
        let (env, _admin, client) = setup();
        let attacker = Address::generate(&env);
        let name = String::from_str(&env, "oracle");
        let addr = Address::generate(&env);
        let result = client.try_register_route(&attacker, &name, &addr);
        assert_eq!(result, Err(Ok(RouterError::Unauthorized)));
    }

    #[test]
    fn test_transfer_admin() {
        let (env, admin, client) = setup();
        let new_admin = Address::generate(&env);
        client.transfer_admin(&admin, &new_admin);
        assert_eq!(client.admin(), new_admin);
    }
}
