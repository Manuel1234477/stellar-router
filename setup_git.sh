#!/bin/bash
# Run from inside ~/stellar-router
# Usage: bash setup_git.sh

set -e

git init
git add .
git commit -m "feat: initial stellar-router infrastructure suite

6 contracts:
- router-core: central dispatcher with route registration and pause controls
- router-registry: versioned contract address registry with deprecation
- router-access: role-based ACL with blacklisting and role admins
- router-middleware: rate limiting, call logging, route enable/disable
- router-timelock: delayed execution queue for sensitive changes
- router-multicall: batch cross-contract calls in one transaction

42 tests across all contracts."

git branch -M main
git remote add origin git@github.com:Maki-Zeninn/stellar-router.git
git push -u origin main

echo ""
echo "Done! Visit: https://github.com/Maki-Zeninn/stellar-router"
