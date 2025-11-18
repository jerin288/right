#!/usr/bin/env bash
# Exit on error
set -o errexit

# Install dependencies
pip install -r requirements.txt

# Run database initialization
python -c "from app import app, db; app.app_context().push(); db.create_all(); print('Database tables created successfully!')"
