#![no_std]

//! # router-registry
//!
//! Central registry for the stellar-router suite.
//! Stores contract addresses keyed by name + version, supports deprecation and lookup.
//!
//! ## Features
//! - Register contracts by name and semantic version
//! - Lookup latest or specific version of a contract
//! - Deprecate old versions
//! - Admin-controlled with ownership transfer

use soroban_sdk::{contract, contractimpl, contracttype, contracterror, Address, Env, String, Vec};

// ── Storage Keys ──────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    Admin,
    Entry(String, u32),   // (name, version) -> ContractEntry
    Versions(String),     // name -> Vec<u32>
}

// ── Types ─────────────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct ContractEntry {
    /// Registered contract address
    pub address: Address,
    /// Human-readable name
    pub name: String,
    /// Version number (monotonically increasing)
    pub version: u32,
    /// Whether this entry has been deprecated
    pub deprecated: bool,
    /// Who registered it
    pub registered_by: Address,
}

// ── Errors ────────────────────────────────────────────────────────────────────

#[contracterror]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum RegistryError {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    Unauthorized = 3,
    NotFound = 4,
    AlreadyRegistered = 5,
    AlreadyDeprecated = 6,
    InvalidVersion = 7,
}

// ── Contract ──────────────────────────────────────────────────────────────────

#[contract]
pub struct RouterRegistry;

#[contractimpl]
impl RouterRegistry {
    /// Initialize the registry with an admin address.
    pub fn initialize(env: Env, admin: Address) -> Result<(), RegistryError> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(RegistryError::AlreadyInitialized);
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        Ok(())
    }

    /// Register a new contract entry.
    /// Version must be greater than any existing version for this name.
    pub fn register(
        env: Env,
        caller: Address,
        name: String,
        address: Address,
        version: u32,
    ) -> Result<(), RegistryError> {
        caller.require_auth();
        Self::require_admin(&env, &caller)?;

        if version == 0 {
            return Err(RegistryError::InvalidVersion);
        }

        if env.storage().instance().has(&DataKey::Entry(name.clone(), version)) {
            return Err(RegistryError::AlreadyRegistered);
        }

        // Validate version is greater than all existing versions
        let versions = Self::get_versions_list(&env, &name);
        for v in versions.iter() {
            if version <= v {
                return Err(RegistryError::InvalidVersion);
            }
        }

        let entry = ContractEntry {
            address,
            name: name.clone(),
            version,
            deprecated: false,
            registered_by: caller,
        };

        env.storage().instance().set(&DataKey::Entry(name.clone(), version), &entry);

        // Update version list
        let mut versions = Self::get_versions_list(&env, &name);
        versions.push_back(version);
        env.storage().instance().set(&DataKey::Versions(name), &versions);

        Ok(())
    }

    /// Look up a contract by name and specific version.
    pub fn get(env: Env, name: String, version: u32) -> Result<ContractEntry, RegistryError> {
        env.storage()
            .instance()
            .get(&DataKey::Entry(name, version))
            .ok_or(RegistryError::NotFound)
    }

    /// Get the latest (highest version) non-deprecated entry for a name.
    pub fn get_latest(env: Env, name: String) -> Result<ContractEntry, RegistryError> {
        let versions = Self::get_versions_list(&env, &name);
        // Iterate in reverse to find latest non-deprecated
        let len = versions.len();
        let mut i = len;
        while i > 0 {
            i -= 1;
            let v = versions.get(i).unwrap();
            let entry: ContractEntry = env
                .storage()
                .instance()
                .get(&DataKey::Entry(name.clone(), v))
                .ok_or(RegistryError::NotFound)?;
            if !entry.deprecated {
                return Ok(entry);
            }
        }
        Err(RegistryError::NotFound)
    }

    /// Deprecate a specific version of a contract.
    pub fn deprecate(
        env: Env,
        caller: Address,
        name: String,
        version: u32,
    ) -> Result<(), RegistryError> {
        caller.require_auth();
        Self::require_admin(&env, &caller)?;

        let mut entry: ContractEntry = env
            .storage()
            .instance()
            .get(&DataKey::Entry(name.clone(), version))
            .ok_or(RegistryError::NotFound)?;

        if entry.deprecated {
            return Err(RegistryError::AlreadyDeprecated);
        }

        entry.deprecated = true;
        env.storage().instance().set(&DataKey::Entry(name, version), &entry);
        Ok(())
    }

    /// Transfer admin to a new address.
    pub fn transfer_admin(env: Env, current: Address, new_admin: Address) -> Result<(), RegistryError> {
        current.require_auth();
        Self::require_admin(&env, &current)?;
        env.storage().instance().set(&DataKey::Admin, &new_admin);
        Ok(())
    }

    /// Get the current admin.
    pub fn admin(env: Env) -> Result<Address, RegistryError> {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(RegistryError::NotInitialized)
    }

    /// Get all registered versions for a name.
    pub fn versions(env: Env, name: String) -> Vec<u32> {
        Self::get_versions_list(&env, &name)
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn require_admin(env: &Env, caller: &Address) -> Result<(), RegistryError> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(RegistryError::NotInitialized)?;
        if &admin != caller {
            return Err(RegistryError::Unauthorized);
        }
        Ok(())
    }

    fn get_versions_list(env: &Env, name: &String) -> Vec<u32> {
        env.storage()
            .instance()
            .get(&DataKey::Versions(name.clone()))
            .unwrap_or(Vec::new(env))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use soroban_sdk::{testutils::Address as _, Env, String};

    fn setup() -> (Env, Address, RouterRegistryClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, RouterRegistry);
        let client = RouterRegistryClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        client.initialize(&admin);
        (env, admin, client)
    }

    #[test]
    fn test_initialize() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, RouterRegistry);
        let client = RouterRegistryClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        let result = client.try_initialize(&admin);
        assert!(result.is_ok());
    }

    #[test]
    fn test_double_initialize_fails() {
        let (_, admin, client) = setup();
        let result = client.try_initialize(&admin);
        assert_eq!(result, Err(Ok(RegistryError::AlreadyInitialized)));
    }

    #[test]
    fn test_register_and_get() {
        let (env, admin, client) = setup();
        let name = String::from_str(&env, "oracle");
        let addr = Address::generate(&env);
        client.register(&admin, &name, &addr, &1);
        let entry = client.get(&name, &1);
        assert_eq!(entry.address, addr);
        assert_eq!(entry.version, 1);
        assert!(!entry.deprecated);
    }

    #[test]
    fn test_get_latest() {
        let (env, admin, client) = setup();
        let name = String::from_str(&env, "oracle");
        let addr1 = Address::generate(&env);
        let addr2 = Address::generate(&env);
        client.register(&admin, &name, &addr1, &1);
        client.register(&admin, &name, &addr2, &2);
        let latest = client.get_latest(&name);
        assert_eq!(latest.address, addr2);
        assert_eq!(latest.version, 2);
    }

    #[test]
    fn test_deprecate() {
        let (env, admin, client) = setup();
        let name = String::from_str(&env, "oracle");
        let addr1 = Address::generate(&env);
        let addr2 = Address::generate(&env);
        client.register(&admin, &name, &addr1, &1);
        client.register(&admin, &name, &addr2, &2);
        client.deprecate(&admin, &name, &2);
        // latest should now return v1
        let latest = client.get_latest(&name);
        assert_eq!(latest.version, 1);
    }

    #[test]
    fn test_duplicate_version_fails() {
        let (env, admin, client) = setup();
        let name = String::from_str(&env, "oracle");
        let addr = Address::generate(&env);
        client.register(&admin, &name, &addr, &1);
        let result = client.try_register(&admin, &name, &addr, &1);
        assert_eq!(result, Err(Ok(RegistryError::AlreadyRegistered)));
    }

    #[test]
    fn test_version_must_increase() {
        let (env, admin, client) = setup();
        let name = String::from_str(&env, "oracle");
        let addr = Address::generate(&env);
        client.register(&admin, &name, &addr, &5);
        let result = client.try_register(&admin, &name, &addr, &3);
        assert_eq!(result, Err(Ok(RegistryError::InvalidVersion)));
    }

    #[test]
    fn test_unauthorized_register_fails() {
        let (env, _admin, client) = setup();
        let name = String::from_str(&env, "oracle");
        let addr = Address::generate(&env);
        let attacker = Address::generate(&env);
        let result = client.try_register(&attacker, &name, &addr, &1);
        assert_eq!(result, Err(Ok(RegistryError::Unauthorized)));
    }

    #[test]
    fn test_transfer_admin() {
        let (env, admin, client) = setup();
        let new_admin = Address::generate(&env);
        client.transfer_admin(&admin, &new_admin);
        assert_eq!(client.admin(), new_admin);
    }
}
