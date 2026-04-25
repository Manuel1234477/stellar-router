//! # router-common
//!
//! Shared macros and utilities for the stellar-router suite.
//!
//! ## Macros
//! - [`require_admin!`] — inline admin check used across router contracts

/// Checks that `caller` matches the admin address stored under `key`.
///
/// Expands to an expression that returns `Err($not_init_err)` if the key is
/// absent, or `Err($unauth_err)` if the caller does not match.
///
/// # Arguments
/// * `$env`          — `&Env` reference
/// * `$caller`       — `&Address` to validate
/// * `$key`          — storage key whose value is the admin `Address`
/// * `$not_init_err` — error variant returned when the key is missing
/// * `$unauth_err`   — error variant returned when the caller is not the admin
///
/// # Example
///
/// ```ignore
/// // Inside a #[contractimpl] block:
/// require_admin!(&env, &caller, &DataKey::Admin, MyError::NotInitialized, MyError::Unauthorized)?;
/// ```
#[macro_export]
macro_rules! require_admin {
    ($env:expr, $caller:expr, $key:expr, $not_init_err:expr, $unauth_err:expr) => {{
        let admin: soroban_sdk::Address = $env
            .storage()
            .instance()
            .get($key)
            .ok_or($not_init_err)?;
        if &admin != $caller {
            return Err($unauth_err);
        }
        Ok::<(), _>(())
    }};
}

/// Returns `true` if `s` is empty or consists entirely of ASCII whitespace
/// (space 0x20, tab 0x09, newline 0x0A, vertical tab 0x0B, form feed 0x0C,
/// carriage return 0x0D).
///
/// # Example
///
/// ```
/// use router_common::is_whitespace_only;
/// assert!(is_whitespace_only(""));
/// assert!(is_whitespace_only("   "));
/// assert!(is_whitespace_only("\t\n\r"));
/// assert!(!is_whitespace_only("oracle"));
/// assert!(!is_whitespace_only(" oracle "));
/// ```
pub fn is_whitespace_only(s: &str) -> bool {
    s.is_empty() || s.bytes().all(|b| matches!(b, 9 | 10 | 11 | 12 | 13 | 32))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_string_is_whitespace_only() {
        assert!(is_whitespace_only(""));
    }

    #[test]
    fn test_spaces_are_whitespace_only() {
        assert!(is_whitespace_only("   "));
    }

    #[test]
    fn test_tab_is_whitespace_only() {
        assert!(is_whitespace_only("\t"));
    }

    #[test]
    fn test_newline_is_whitespace_only() {
        assert!(is_whitespace_only("\n"));
    }

    #[test]
    fn test_carriage_return_is_whitespace_only() {
        assert!(is_whitespace_only("\r"));
    }

    #[test]
    fn test_mixed_whitespace_is_whitespace_only() {
        assert!(is_whitespace_only(" \t\n\r\x0b\x0c"));
    }

    #[test]
    fn test_normal_name_is_not_whitespace_only() {
        assert!(!is_whitespace_only("oracle"));
    }

    #[test]
    fn test_name_with_surrounding_spaces_is_not_whitespace_only() {
        assert!(!is_whitespace_only(" oracle "));
    }
}
