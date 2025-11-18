#!/usr/bin/env bash
# Exit on error
set -o errexit

# Install dependencies
pip install -r requirements.txt

# Run database initialization with sample data (including admin user)
python -c "from app import app, init_db; init_db(); print('Database initialized successfully with admin user!')"
