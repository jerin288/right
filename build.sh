#!/usr/bin/env bash
# Exit on error
set -o errexit

# Install dependencies
pip install -r requirements.txt

# Create upload directories if they don't exist
mkdir -p static/uploads/products

# Initialize database tables and admin user
echo "==================================================="
echo "Initializing database..."
echo "==================================================="
python -c "from app import app, db, ensure_admin_user; 
from sqlalchemy import text, inspect

with app.app_context(): 
    # Create all tables first
    print('Running db.create_all()...')
    db.create_all()
    print('✓ db.create_all() completed')
    
    # Check what tables exist
    inspector = inspect(db.engine)
    existing_tables = inspector.get_table_names()
    print(f'Existing tables: {existing_tables}')
    
    # Force create product_feature table if missing
    if 'product_feature' not in existing_tables:
        print('⚠️ product_feature table MISSING - creating now...')
        db.session.execute(text('''CREATE TABLE product_feature (
            id SERIAL PRIMARY KEY,
            product_id INTEGER NOT NULL REFERENCES product(id) ON DELETE CASCADE,
            feature_text VARCHAR(200) NOT NULL,
            is_enabled BOOLEAN DEFAULT TRUE,
            display_order INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )'''))
        db.session.commit()
        print('✅ product_feature table CREATED successfully!')
    else:
        print('✓ product_feature table already exists')
    
    # Ensure admin user
    ensure_admin_user()
    print('✓ Admin user ensured')

print('====================================================')
print('Database initialization complete!')
print('====================================================')"
