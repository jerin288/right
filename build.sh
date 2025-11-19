#!/usr/bin/env bash
# Exit on error
set -o errexit

# Install dependencies
pip install -r requirements.txt

# Create upload directories if they don't exist
mkdir -p static/uploads/products

# Initialize database tables and admin user
python -c "from app import app, db, init_db, ensure_admin_user; 
with app.app_context(): 
    db.create_all(); 
    print('Database tables created'); 
    ensure_admin_user(); 
    print('Admin user ensured')"
