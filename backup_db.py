"""
Database Backup Utility
Automatically backs up the SQLite database with timestamp
Keeps only the last 7 backups to save space
"""

import shutil
import os
from datetime import datetime

def backup_database():
    """Backup the database file"""
    source = os.path.join('instance', 'ecommerce.db')
    backup_folder = 'backups'
    
    # Check if database exists
    if not os.path.exists(source):
        print(f'❌ Database not found at: {source}')
        print('   Run the application first to create the database.')
        return False
    
    # Create backup folder if it doesn't exist
    if not os.path.exists(backup_folder):
        os.makedirs(backup_folder)
        print(f'📁 Created backup folder: {backup_folder}')
    
    # Create backup with timestamp
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    destination = os.path.join(backup_folder, f'ecommerce_backup_{timestamp}.db')
    
    try:
        shutil.copy2(source, destination)
        file_size = os.path.getsize(destination) / 1024  # KB
        print(f'✅ Database backed up successfully!')
        print(f'   Location: {destination}')
        print(f'   Size: {file_size:.2f} KB')
        
        # Clean up old backups (keep only last 7)
        backups = sorted([
            f for f in os.listdir(backup_folder) 
            if f.startswith('ecommerce_backup_') and f.endswith('.db')
        ])
        
        if len(backups) > 7:
            for old_backup in backups[:-7]:
                old_path = os.path.join(backup_folder, old_backup)
                os.remove(old_path)
                print(f'🗑️  Removed old backup: {old_backup}')
            print(f'   Keeping last 7 backups')
        
        return True
        
    except Exception as e:
        print(f'❌ Backup failed: {e}')
        return False

def restore_database(backup_file):
    """Restore database from backup file"""
    source = os.path.join('backups', backup_file)
    destination = os.path.join('instance', 'ecommerce.db')
    
    if not os.path.exists(source):
        print(f'❌ Backup file not found: {source}')
        return False
    
    try:
        # Create backup of current database before restoring
        if os.path.exists(destination):
            current_backup = os.path.join('backups', f'current_before_restore_{datetime.now().strftime("%Y%m%d_%H%M%S")}.db')
            shutil.copy2(destination, current_backup)
            print(f'💾 Current database backed up to: {current_backup}')
        
        # Restore from backup
        shutil.copy2(source, destination)
        print(f'✅ Database restored successfully from: {backup_file}')
        return True
        
    except Exception as e:
        print(f'❌ Restore failed: {e}')
        return False

def list_backups():
    """List all available backups"""
    backup_folder = 'backups'
    
    if not os.path.exists(backup_folder):
        print('📁 No backups folder found.')
        return []
    
    backups = sorted([
        f for f in os.listdir(backup_folder) 
        if f.startswith('ecommerce_backup_') and f.endswith('.db')
    ], reverse=True)
    
    if not backups:
        print('📁 No backups found.')
        return []
    
    print(f'\n📦 Available backups ({len(backups)}):')
    print('-' * 60)
    for i, backup in enumerate(backups, 1):
        filepath = os.path.join(backup_folder, backup)
        size = os.path.getsize(filepath) / 1024  # KB
        mtime = datetime.fromtimestamp(os.path.getmtime(filepath))
        print(f'{i}. {backup}')
        print(f'   Size: {size:.2f} KB | Modified: {mtime.strftime("%Y-%m-%d %H:%M:%S")}')
    print('-' * 60)
    
    return backups

if __name__ == '__main__':
    import sys
    
    print('=' * 60)
    print('Database Backup Utility - Right Fit E-commerce')
    print('=' * 60)
    print()
    
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == 'backup':
            backup_database()
        
        elif command == 'list':
            list_backups()
        
        elif command == 'restore':
            if len(sys.argv) < 3:
                print('Usage: python backup_db.py restore <backup_filename>')
                list_backups()
            else:
                restore_database(sys.argv[2])
        
        else:
            print('Unknown command. Available commands:')
            print('  python backup_db.py backup          - Create new backup')
            print('  python backup_db.py list            - List all backups')
            print('  python backup_db.py restore <file>  - Restore from backup')
    
    else:
        # Default: create backup
        backup_database()
    
    print()
