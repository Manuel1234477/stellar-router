#![no_std]

use soroban_sdk::{Address, Env, Symbol};

/// Macro to require admin with custom error types.
///
/// This eliminates the repetitive `require_admin` / `require_super_admin` boilerplate
/// across all router contracts while allowing each contract to use its own error enum.
#[macro_export]
macro_rules! require_admin {
    ($env:expr, $caller:expr, $data_key:expr, $not_init_err:expr, $unauth_err:expr) => {{
        let admin: soroban_sdk::Address = $env
            .storage()
            .instance()
            .get($data_key)
            .ok_or($not_init_err)?;

        if &admin != $caller {
            return Err($unauth_err);
        }
        Ok(())
    }};
}

/// Convenience version when using DataKey::Admin and standard error variants
#[macro_export]
macro_rules! require_admin_simple {
    ($env:expr, $caller:expr, $data_key:expr, $error_type:ty) => {
        $crate::require_admin!(
            $env,
            $caller,
            $data_key,
            <$error_type>::NotInitialized,
            <$error_type>::Unauthorized
        )
    };
}