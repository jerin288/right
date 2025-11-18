"""
Utility Functions for Right Fit E-commerce
Common administrative and maintenance tasks
"""

import secrets
from app import app, db, User, Product, Order, Category
from datetime import datetime, timedelta

def generate_secret_key():
    """Generate a secure secret key for Flask"""
    key = secrets.token_hex(32)
    print('=' * 60)
    print('Generated Secret Key for Flask:')
    print('=' * 60)
    print(key)
    print('=' * 60)
    print('\nAdd this to your .env file:')
    print(f'SECRET_KEY={key}')
    print('\nNEVER share this key or commit it to version control!')
    return key

def create_admin_user(username, email, password):
    """Create a new admin user"""
    with app.app_context():
        # Check if user already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            print(f'❌ Username "{username}" already exists!')
            return False
        
        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            print(f'❌ Email "{email}" already registered!')
            return False
        
        # Create admin user
        admin = User(username=username, email=email, is_admin=True)
        admin.set_password(password)
        
        db.session.add(admin)
        db.session.commit()
        
        print('✅ Admin user created successfully!')
        print(f'   Username: {username}')
        print(f'   Email: {email}')
        print(f'   Role: Administrator')
        return True

def reset_user_password(username, new_password):
    """Reset user password"""
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        
        if not user:
            print(f'❌ User "{username}" not found!')
            return False
        
        user.set_password(new_password)
        db.session.commit()
        
        print(f'✅ Password reset successful for user: {username}')
        return True

def get_database_stats():
    """Display database statistics"""
    with app.app_context():
        total_users = User.query.count()
        admin_users = User.query.filter_by(is_admin=True).count()
        customer_users = User.query.filter_by(is_admin=False).count()
        
        total_products = Product.query.count()
        active_products = Product.query.filter_by(is_active=True).count()
        inactive_products = Product.query.filter_by(is_active=False).count()
        
        total_categories = Category.query.count()
        
        total_orders = Order.query.count()
        pending_orders = Order.query.filter_by(status='Pending').count()
        delivered_orders = Order.query.filter_by(status='Delivered').count()
        cancelled_orders = Order.query.filter_by(status='Cancelled').count()
        
        total_revenue = db.session.query(db.func.sum(Order.total_amount)).filter(
            Order.payment_status.in_(['PAID', 'PENDING'])
        ).scalar() or 0
        
        paid_revenue = db.session.query(db.func.sum(Order.total_amount)).filter(
            Order.payment_status == 'PAID'
        ).scalar() or 0
        
        print('=' * 60)
        print('DATABASE STATISTICS - RIGHT FIT E-COMMERCE')
        print('=' * 60)
        print(f'\n👥 USERS:')
        print(f'   Total Users: {total_users}')
        print(f'   Administrators: {admin_users}')
        print(f'   Customers: {customer_users}')
        
        print(f'\n📦 PRODUCTS:')
        print(f'   Total Products: {total_products}')
        print(f'   Active Products: {active_products}')
        print(f'   Inactive Products: {inactive_products}')
        print(f'   Categories: {total_categories}')
        
        print(f'\n🛒 ORDERS:')
        print(f'   Total Orders: {total_orders}')
        print(f'   Pending: {pending_orders}')
        print(f'   Delivered: {delivered_orders}')
        print(f'   Cancelled: {cancelled_orders}')
        
        print(f'\n💰 REVENUE:')
        print(f'   Total Revenue: ₹{total_revenue:,.2f}')
        print(f'   Paid Revenue: ₹{paid_revenue:,.2f}')
        print(f'   Pending Revenue: ₹{total_revenue - paid_revenue:,.2f}')
        
        print('=' * 60)

def cleanup_old_carts(days=30):
    """Remove cart items older than specified days"""
    with app.app_context():
        from app import Cart
        
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        old_carts = Cart.query.filter(Cart.added_at < cutoff_date).all()
        
        count = len(old_carts)
        
        if count == 0:
            print(f'✅ No cart items older than {days} days found.')
            return 0
        
        for cart in old_carts:
            db.session.delete(cart)
        
        db.session.commit()
        print(f'✅ Removed {count} cart items older than {days} days')
        return count

def list_low_stock_products(threshold=10):
    """List products with stock below threshold"""
    with app.app_context():
        low_stock = Product.query.filter(
            Product.stock < threshold,
            Product.is_active == True
        ).all()
        
        if not low_stock:
            print(f'✅ No products with stock below {threshold} units.')
            return []
        
        print('=' * 60)
        print(f'⚠️  LOW STOCK ALERT (Below {threshold} units)')
        print('=' * 60)
        
        for product in low_stock:
            print(f'\n📦 {product.name}')
            print(f'   ID: {product.id}')
            print(f'   Stock: {product.stock} units')
            print(f'   Price: ₹{product.price:,.2f}')
            print(f'   Category: {product.category.name}')
        
        print('=' * 60)
        return low_stock

def export_orders_to_csv(filename='orders_export.csv'):
    """Export all orders to CSV file"""
    import csv
    
    with app.app_context():
        orders = Order.query.order_by(Order.created_at.desc()).all()
        
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            
            # Header
            writer.writerow([
                'Order ID', 'Customer', 'Email', 'Phone', 'Total Amount',
                'Status', 'Payment Method', 'Payment Status', 'Order Date'
            ])
            
            # Data
            for order in orders:
                writer.writerow([
                    order.id,
                    order.user.username,
                    order.user.email,
                    order.phone,
                    f'₹{order.total_amount:.2f}',
                    order.status,
                    order.payment_method,
                    order.payment_status,
                    order.created_at.strftime('%Y-%m-%d %H:%M:%S')
                ])
        
        print(f'✅ Exported {len(orders)} orders to: {filename}')
        return filename

# Command-line interface
if __name__ == '__main__':
    import sys
    
    print('=' * 60)
    print('RIGHT FIT E-COMMERCE - UTILITY TOOLS')
    print('=' * 60)
    print()
    
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == 'generate-key':
            generate_secret_key()
        
        elif command == 'stats':
            get_database_stats()
        
        elif command == 'low-stock':
            threshold = int(sys.argv[2]) if len(sys.argv) > 2 else 10
            list_low_stock_products(threshold)
        
        elif command == 'cleanup-carts':
            days = int(sys.argv[2]) if len(sys.argv) > 2 else 30
            cleanup_old_carts(days)
        
        elif command == 'export-orders':
            filename = sys.argv[2] if len(sys.argv) > 2 else 'orders_export.csv'
            export_orders_to_csv(filename)
        
        elif command == 'create-admin':
            if len(sys.argv) < 5:
                print('Usage: python utils.py create-admin <username> <email> <password>')
            else:
                create_admin_user(sys.argv[2], sys.argv[3], sys.argv[4])
        
        elif command == 'reset-password':
            if len(sys.argv) < 4:
                print('Usage: python utils.py reset-password <username> <new_password>')
            else:
                reset_user_password(sys.argv[2], sys.argv[3])
        
        else:
            print('Unknown command. Available commands:')
            print('  python utils.py generate-key                              - Generate SECRET_KEY')
            print('  python utils.py stats                                     - Show database statistics')
            print('  python utils.py low-stock [threshold]                     - List low stock products')
            print('  python utils.py cleanup-carts [days]                      - Remove old cart items')
            print('  python utils.py export-orders [filename]                  - Export orders to CSV')
            print('  python utils.py create-admin <user> <email> <password>    - Create admin user')
            print('  python utils.py reset-password <username> <new_password>  - Reset user password')
    
    else:
        print('Available commands:')
        print('  python utils.py generate-key                              - Generate SECRET_KEY')
        print('  python utils.py stats                                     - Show database statistics')
        print('  python utils.py low-stock [threshold]                     - List low stock products')
        print('  python utils.py cleanup-carts [days]                      - Remove old cart items')
        print('  python utils.py export-orders [filename]                  - Export orders to CSV')
        print('  python utils.py create-admin <user> <email> <password>    - Create admin user')
        print('  python utils.py reset-password <username> <new_password>  - Reset user password')
    
    print()
