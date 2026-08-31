#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FABRIC_WORKDIR="${FABRIC_WORKDIR:-${PROJECT_ROOT}/fabric-samples/test-network}"
FABRIC_SAMPLES_DIR="$(dirname "$FABRIC_WORKDIR")"

export PATH="${FABRIC_SAMPLES_DIR}/bin:${PATH}"
export FABRIC_CFG_PATH="${FABRIC_SAMPLES_DIR}/config"
export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_LOCALMSPID=Org1MSP
export CORE_PEER_MSPCONFIGPATH="${FABRIC_WORKDIR}/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp"
export CORE_PEER_ADDRESS=localhost:7051
export CORE_PEER_TLS_ROOTCERT_FILE="${FABRIC_WORKDIR}/organizations/peerOrganizations/org1.example.com/tlsca/tlsca.org1.example.com-cert.pem"

peer channel list

