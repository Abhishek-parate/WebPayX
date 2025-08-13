"""
PostgreSQL Database Setup for SaaS Platform
==========================================

This script initializes the database using PostgreSQL instead of SQLite.
"""

import os
import sys
import traceback
from datetime import datetime, timedelta
from decimal import Decimal
import uuid

# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sqlalchemy import create_engine, text, inspect
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError, OperationalError, ProgrammingError
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

# Import models and enums
from models import (
    Base, Tenant, User, UserRoleType, KYCStatus, Wallet,
    OrganizationBankAccount, BankAccountType, AccountPurpose, BankAccountStatus,
    CommissionPlan, ServiceType, CommissionMode, NotificationTemplate,
    Permission, create_default_permissions, create_sample_tenant_data
)

class PostgreSQLDatabaseInitializer:
    """PostgreSQL database initialization handler"""
    
    def __init__(self, config=None):
        """Initialize with PostgreSQL configuration"""
        if config is None:
            config = {
                'host': 'localhost',
                'port': 5432,
                'username': 'postgres',
                'password': 'admin',  # Change this to your PostgreSQL password
                'database': 'saas_platform'
            }
        
        self.config = config
        self.admin_url = f"postgresql://{config['username']}:{config['password']}@{config['host']}:{config['port']}/postgres"
        self.database_url = f"postgresql://{config['username']}:{config['password']}@{config['host']}:{config['port']}/{config['database']}"
        
        # Test connection first
        self.test_connection()
        
        # Create database if it doesn't exist
        self.create_database_if_not_exists()
        
        # Create engine and session
        self.engine = create_engine(self.database_url, echo=False)
        self.SessionLocal = sessionmaker(bind=self.engine)
    
    def test_connection(self):
        """Test PostgreSQL connection"""
        try:
            print("🔌 Testing PostgreSQL connection...")
            conn = psycopg2.connect(
                host=self.config['host'],
                port=self.config['port'],
                user=self.config['username'],
                password=self.config['password'],
                database='postgres'
            )
            conn.close()
            print("✅ PostgreSQL connection successful")
        except psycopg2.Error as e:
            print(f"❌ PostgreSQL connection failed: {e}")
            print("\n💡 Troubleshooting tips:")
            print("   1. Make sure PostgreSQL is running")
            print("   2. Check your username/password")
            print("   3. Verify the host and port")
            print("   4. Ensure user has database creation privileges")
            sys.exit(1)
    
    def create_database_if_not_exists(self):
        """Create database if it doesn't exist"""
        try:
            print(f"🗄️  Checking if database '{self.config['database']}' exists...")
            
            # Connect to postgres database to create our database
            conn = psycopg2.connect(
                host=self.config['host'],
                port=self.config['port'],
                user=self.config['username'],
                password=self.config['password'],
                database='postgres'
            )
            conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
            cursor = conn.cursor()
            
            # Check if database exists
            cursor.execute("SELECT 1 FROM pg_catalog.pg_database WHERE datname = %s", (self.config['database'],))
            exists = cursor.fetchone()
            
            if not exists:
                print(f"📊 Creating database '{self.config['database']}'...")
                cursor.execute(f'CREATE DATABASE "{self.config["database"]}"')
                print("✅ Database created successfully")
            else:
                print("✅ Database already exists")
            
            cursor.close()
            conn.close()
            
        except psycopg2.Error as e:
            print(f"❌ Error creating database: {e}")
            sys.exit(1)
    
    def check_table_exists(self, table_name):
        """Check if a table exists in the database"""
        inspector = inspect(self.engine)
        return table_name in inspector.get_table_names()
    
    def get_table_columns(self, table_name):
        """Get existing columns in a table"""
        if not self.check_table_exists(table_name):
            return []
        
        inspector = inspect(self.engine)
        columns = inspector.get_columns(table_name)
        return [col['name'] for col in columns]
    
    def drop_all_tables(self):
        """Drop all existing tables"""
        try:
            print("🗑️  Dropping existing tables...")
            Base.metadata.drop_all(self.engine)
            print("✅ All tables dropped successfully")
        except Exception as e:
            print(f"⚠️  Warning during table drop: {e}")
    
    def create_all_tables(self):
        """Create all tables from models"""
        try:
            print("🔧 Creating database tables...")
            Base.metadata.create_all(self.engine)
            print("✅ All tables created successfully")
            
            # Verify critical tables were created
            critical_tables = ['tenants', 'users', 'wallets', 'organization_bank_accounts']
            for table in critical_tables:
                if self.check_table_exists(table):
                    columns = self.get_table_columns(table)
                    print(f"  ✓ {table}: {len(columns)} columns")
                else:
                    print(f"  ❌ {table}: Table not created!")
                    
        except Exception as e:
            print(f"❌ Error creating tables: {e}")
            raise
    
    def create_default_tenant(self):
        """Create the default tenant"""
        session = self.SessionLocal()
        try:
            print("🏢 Creating default tenant...")
            
            # Check if default tenant already exists
            existing_tenant = session.query(Tenant).filter_by(tenant_code='DEFAULT').first()
            if existing_tenant:
                print("✅ Default tenant already exists")
                return existing_tenant
            
            # Create default tenant
            tenant = Tenant(
                tenant_code='DEFAULT',
                tenant_name='Default SaaS Tenant',
                domain='localhost',
                subdomain='default',
                theme_config={
                    "primary_color": "#007bff",
                    "secondary_color": "#6c757d", 
                    "accent_color": "#28a745",
                    "logo_url": "/static/images/logo.png",
                    "favicon_url": "/static/images/favicon.ico"
                },
                is_active=True,
                api_settings={
                    "rate_limit": 1000,
                    "timeout": 30,
                    "max_requests_per_day": 10000
                },
                rate_limits={
                    "api_calls_per_minute": 100,
                    "transactions_per_hour": 500
                },
                meta_data={}
            )
            
            session.add(tenant)
            session.commit()
            session.refresh(tenant)
            
            print(f"✅ Default tenant created with ID: {tenant.id}")
            return tenant
            
        except Exception as e:
            session.rollback()
            print(f"❌ Error creating default tenant: {e}")
            raise
        finally:
            session.close()
    
    def create_super_admin(self, tenant):
        """Create super admin user"""
        session = self.SessionLocal()
        try:
            print("👤 Creating super admin user...")
            
            # Check if super admin already exists
            existing_admin = session.query(User).filter_by(
                username='superadmin',
                tenant_id=tenant.id
            ).first()
            
            if existing_admin:
                print("✅ Super admin already exists")
                return existing_admin
            
            # Create super admin
            admin = User(
                tenant_id=tenant.id,
                user_code='SA001',
                username='superadmin',
                email='admin@localhost.com',
                phone='9999999999',
                role=UserRoleType.SUPER_ADMIN,
                full_name='Super Administrator',
                business_name='Platform Administration',
                address={
                    "line1": "Platform Headquarters",
                    "city": "System City",
                    "state": "System State",
                    "pincode": "000000",
                    "country": "IN"
                },
                kyc_status=KYCStatus.APPROVED,
                is_active=True,
                is_verified=True,
                email_verified=True,
                phone_verified=True,
                tree_path='',
                level=0,
                settings={
                    "dashboard_preference": "advanced",
                    "notification_email": True,
                    "notification_sms": True
                }
            )
            
            admin.set_password('Admin@123')  # Default password
            admin.generate_api_key()
            
            session.add(admin)
            session.commit()
            session.refresh(admin)
            
            # Update tree_path after creation
            admin.tree_path = str(admin.id)
            session.commit()
            
            print(f"✅ Super admin created:")
            print(f"   Username: {admin.username}")
            print(f"   Password: Admin@123")
            print(f"   API Key: {admin.api_key}")
            
            return admin
            
        except Exception as e:
            session.rollback()
            print(f"❌ Error creating super admin: {e}")
            raise
        finally:
            session.close()
    
    def create_admin_wallet(self, admin_user):
        """Create wallet for admin user"""
        session = self.SessionLocal()
        try:
            print("💰 Creating admin wallet...")
            
            # Check if wallet already exists
            existing_wallet = session.query(Wallet).filter_by(user_id=admin_user.id).first()
            if existing_wallet:
                print("✅ Admin wallet already exists")
                return existing_wallet
            
            # Create wallet
            wallet = Wallet(
                user_id=admin_user.id,
                balance=Decimal('100000.0000'),  # Initial balance
                daily_limit=Decimal('1000000.0000'),
                monthly_limit=Decimal('10000000.0000'),
                is_active=True
            )
            
            session.add(wallet)
            session.commit()
            session.refresh(wallet)
            
            print(f"✅ Admin wallet created with balance: ₹{wallet.balance}")
            return wallet
            
        except Exception as e:
            session.rollback()
            print(f"❌ Error creating admin wallet: {e}")
            raise
        finally:
            session.close()
    
    def create_default_bank_account(self, tenant, admin_user):
        """Create default organization bank account"""
        session = self.SessionLocal()
        try:
            print("🏦 Creating default bank account...")
            
            # Check if default bank account exists
            existing_account = session.query(OrganizationBankAccount).filter_by(
                tenant_id=tenant.id,
                is_primary=True
            ).first()
            
            if existing_account:
                print("✅ Default bank account already exists")
                return existing_account
            
            # Create default bank account
            bank_account = OrganizationBankAccount(
                tenant_id=tenant.id,
                created_by=admin_user.id,
                account_code='BA001',
                account_name='Primary Collection Account',
                account_number='1234567890123456',
                ifsc_code='SBIN0123456',
                bank_name='State Bank of India',
                branch_name='Main Branch',
                branch_address='Main Street, City Center',
                account_type=BankAccountType.CURRENT,
                account_holder_name='SaaS Platform Pvt Ltd',
                pan_number='ABCDE1234F',
                gstin='12ABCDE1234F1Z5',
                status=BankAccountStatus.ACTIVE,
                purpose=[AccountPurpose.WALLET_TOPUP.value, AccountPurpose.SETTLEMENT.value],
                is_primary=True,
                is_default_topup=True,
                is_default_settlement=True,
                daily_limit=Decimal('1000000.0000'),
                monthly_limit=Decimal('50000000.0000'),
                minimum_balance=Decimal('100000.0000'),
                current_balance=Decimal('500000.0000'),
                upi_id='saasplatform@sbi',
                is_visible_to_users=True,
                display_order=1
            )
            
            session.add(bank_account)
            session.commit()
            session.refresh(bank_account)
            
            print(f"✅ Default bank account created: {bank_account.account_name}")
            return bank_account
            
        except Exception as e:
            session.rollback()
            print(f"❌ Error creating default bank account: {e}")
            raise
        finally:
            session.close()
    
    def create_default_permissions(self):
        """Create default system permissions"""
        session = self.SessionLocal()
        try:
            print("🔐 Creating default permissions...")
            
            # Check if permissions already exist
            existing_count = session.query(Permission).count()
            if existing_count > 0:
                print(f"✅ {existing_count} permissions already exist")
                return
            
            # Create default permissions
            permissions = create_default_permissions()
            for permission in permissions:
                session.add(permission)
            
            session.commit()
            print(f"✅ Created {len(permissions)} default permissions")
            
        except Exception as e:
            session.rollback()
            print(f"❌ Error creating default permissions: {e}")
            raise
        finally:
            session.close()
    
    def create_sample_data(self, tenant):
        """Create sample data for the tenant"""
        session = self.SessionLocal()
        try:
            print("📊 Creating sample data...")
            
            # Check if sample data already exists
            existing_plans = session.query(CommissionPlan).filter_by(tenant_id=tenant.id).count()
            if existing_plans > 0:
                print("✅ Sample data already exists")
                return
            
            create_sample_tenant_data(session, tenant.id)
            session.commit()
            
            print("✅ Sample data created successfully")
            
        except Exception as e:
            session.rollback()
            print(f"❌ Error creating sample data: {e}")
            # Don't raise here, sample data is optional
        finally:
            session.close()
    
    def run_full_initialization(self, force_recreate=False):
        """Run complete database initialization"""
        try:
            print("🔧 Initializing SaaS Platform Database (PostgreSQL)...")
            print("=" * 55)
            
            if force_recreate:
                self.drop_all_tables()
            
            self.create_all_tables()
            
            # Create core data
            tenant = self.create_default_tenant()
            admin = self.create_super_admin(tenant)
            wallet = self.create_admin_wallet(admin)
            bank_account = self.create_default_bank_account(tenant, admin)
            
            # Create optional data
            self.create_default_permissions()
            self.create_sample_data(tenant)
            
            print("\n" + "=" * 55)
            print("🎉 PostgreSQL Database initialization completed successfully!")
            print(f"\n📊 Database Details:")
            print(f"   🗄️  Host: {self.config['host']}:{self.config['port']}")
            print(f"   📂 Database: {self.config['database']}")
            print(f"   👤 User: {self.config['username']}")
            print("\n📋 Application Summary:")
            print(f"   🏢 Tenant: {tenant.tenant_name} ({tenant.tenant_code})")
            print(f"   👤 Admin: {admin.username}")
            print(f"   💰 Wallet Balance: ₹{wallet.balance}")
            print(f"   🏦 Bank Account: {bank_account.account_name}")
            print("\n🔑 Login Details:")
            print(f"   Username: {admin.username}")
            print(f"   Password: Admin@123")
            print(f"   API Key: {admin.api_key}")
            print("\n⚠️  Please change the default password after first login!")
            
            return True
            
        except Exception as e:
            print(f"\n❌ Database initialization failed: {e}")
            print(f"Error type: {type(e).__name__}")
            traceback.print_exc()
            return False

def get_postgresql_config():
    """Get PostgreSQL configuration from user input or environment"""
    config = {}
    
    print("🔧 PostgreSQL Configuration")
    print("=" * 30)
    
    # Get configuration from environment variables or prompt user
    config['host'] = os.getenv('DB_HOST') or input("Host [localhost]: ").strip() or 'localhost'
    config['port'] = int(os.getenv('DB_PORT') or input("Port [5432]: ").strip() or '5432')
    config['username'] = os.getenv('DB_USER') or input("Username [postgres]: ").strip() or 'postgres'
    
    # Get password securely
    import getpass
    if os.getenv('DB_PASSWORD'):
        config['password'] = os.getenv('DB_PASSWORD')
    else:
        config['password'] = getpass.getpass("Password: ")
    
    config['database'] = os.getenv('DB_NAME') or input("Database name [saas_platform]: ").strip() or 'saas_platform'
    
    return config

def main():
    """Main function to run database initialization"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Initialize SaaS Platform Database with PostgreSQL')
    parser.add_argument('--force', action='store_true', help='Force recreate all tables')
    parser.add_argument('--auto', action='store_true', help='Use default configuration without prompts')
    
    args = parser.parse_args()
    
    # Get PostgreSQL configuration
    if args.auto:
        config = {
            'host': 'localhost',
            'port': 5432,
            'username': 'postgres',
            'password': 'admin',  # Change this to your actual password
            'database': 'saas_platform'
        }
        print("🤖 Using automatic configuration (change password in script if needed)")
    else:
        config = get_postgresql_config()
    
    # Initialize database
    try:
        initializer = PostgreSQLDatabaseInitializer(config)
        success = initializer.run_full_initialization(force_recreate=args.force)
        
        if success:
            print("\n🚀 You can now start your application!")
            print("💡 Don't forget to update your app's database URL to use PostgreSQL")
            sys.exit(0)
        else:
            print("\n💥 Initialization failed. Please check the errors above.")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n\n⚠️  Setup cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Setup failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()