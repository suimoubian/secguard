#!/bin/bash
set -eu
cd "$(dirname "$0")"

export SECGUARD_DB_USER=secguard
export SECGUARD_DB_PASS='Sg_dev_2026!'
export SECGUARD_DB_NAME=secguard
export SECGUARD_JWT_SECRET='dev-only-secret-change-me-0123456789'
export SECGUARD_LOG_LEVEL=info

exec ./build/secguard
