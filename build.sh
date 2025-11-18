#!/usr/bin/env bash
# Exit on error
set -o errexit

# Install dependencies
pip install -r requirements.txt

# Ensure admin user exists with correct password (safe for existing databases)
python -c "from app import app, ensure_admin_user; ensure_admin_user()"
