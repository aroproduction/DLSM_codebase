#!/usr/bin/env bash
set -euo pipefail

print_check() {
  local name="$1"
  local command="$2"

  printf "%-18s" "$name"
  if output=$(eval "$command" 2>&1); then
    first_line=$(printf "%s" "$output" | head -n 1)
    printf "OK      %s\n" "$first_line"
  else
    first_line=$(printf "%s" "$output" | head -n 1)
    printf "MISSING %s\n" "$first_line"
  fi
}

echo "DLSM Fabric prerequisite check"
echo

print_check "Docker CLI" "docker --version"
print_check "Docker daemon" "docker info --format '{{.ServerVersion}}'"
print_check "Docker Compose" "docker compose version"
print_check "Git" "git --version"
print_check "curl" "curl --version"
print_check "Node.js" "node --version"
print_check "npm" "npm --version"

echo
echo "Notes:"
echo "- Docker daemon must be running before Fabric test network commands work."
echo "- Go is optional for this project because the prototype chaincode will use TypeScript."

