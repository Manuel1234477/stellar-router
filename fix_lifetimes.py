#!/usr/bin/env python3
# Run from inside ~/stellar-router
# Usage: python3 fix_lifetimes.py

import os

fixes = [
    ("contracts/router-core/src/lib.rs", "RouterCoreClient"),
    ("contracts/router-middleware/src/lib.rs", "RouterMiddlewareClient"),
    ("contracts/router-multicall/src/lib.rs", "RouterMulticallClient"),
    ("contracts/router-timelock/src/lib.rs", "RouterTimelockClient"),
    ("contracts/router-registry/src/lib.rs", "RouterRegistryClient"),
    ("contracts/router-access/src/lib.rs", "RouterAccessClient"),
]

for path, client in fixes:
    if not os.path.exists(path):
        print(f"SKIP (not found): {path}")
        continue
    with open(path, 'r') as f:
        content = f.read()
    changed = False
    for old in [
        f"fn setup() -> (Env, Address, {client})",
        f"fn setup() -> (Env, Address, {client}<'_>)",
    ]:
        new = f"fn setup() -> (Env, Address, {client}<'static>)"
        if old in content:
            content = content.replace(old, new)
            changed = True

    if changed:
        with open(path, 'w') as f:
            f.write(content)
        print(f"FIXED: {client}")
    elif f"{client}<'static>" in content:
        print(f"OK (already fixed): {client}")
    else:
        print(f"NOT FOUND: {client} in {path}")

print("\nDone. Now run: cargo test")
