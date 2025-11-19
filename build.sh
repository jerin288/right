#!/usr/bin/env bash
# Exit on error
set -o errexit

# Install dependencies
pip install -r requirements.txt

# Create upload directories if they don't exist
mkdir -p static/uploads/products

# Initialize database tables and admin user
echo "Initializing database..."
python -c "from app import app, db, init_db, ensure_admin_user; 
with app.app_context(): 
    # Create all tables
    db.create_all(); 
    print('✓ Database tables created'); 
    
    # Ensure ProductFeature table exists (fallback)
    from sqlalchemy import text
    try:
        db.session.execute(text('SELECT 1 FROM product_feature LIMIT 1'))
        print('✓ product_feature table exists')
    except Exception:
        print('⚠ Creating product_feature table...')
        db.session.execute(text('''CREATE TABLE IF NOT EXISTS product_feature (
            id SERIAL PRIMARY KEY,
            product_id INTEGER NOT NULL REFERENCES product(id),
            feature_text VARCHAR(200) NOT NULL,
            is_enabled BOOLEAN DEFAULT TRUE,
            display_order INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )'''))
        db.session.commit()
        print('✓ product_feature table created')
    
    ensure_admin_user(); 
    print('✓ Admin user ensured')"
