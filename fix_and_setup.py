"""
PostgreSQL Database Setup for SaaS Platform
==========================================

This script initializes the database using PostgreSQL instead of SQLite.
It can also populate the database with a full hierarchy of dummy data for testing.
"""

import os
import sys
import traceback
from datetime import datetime, timedelta
from decimal import Decimal
import uuid
import random

# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sqlalchemy import create_engine, text, inspect
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError, OperationalError, ProgrammingError
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

# Import all necessary models and enums
from models import (
    db, Tenant, User, UserRoleType, KYCStatus, Wallet,
    OrganizationBankAccount, BankAccountType, AccountPurpose, BankAccountStatus,
    CommissionPlan, ServiceType, CommissionMode, NotificationTemplate,
    Permission, create_default_permissions, create_sample_tenant_data,
    Transaction, TransactionStatus, WalletTransaction, WalletTransactionType,
    WalletTopupRequest, TopupMethod, TransactionMode
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
                'password': '',  # This MUST be set correctly
                'database': 'saas_platform'
            }
        
        self.config = config
        self.admin_url = f"postgresql://{config['username']}:{config['password']}@{config['host']}:{config['port']}/postgres"
        self.database_url = f"postgresql://{config['username']}:{config['password']}@{config['host']}:{config['port']}/{config['database']}"
        
        print(f"🔧 Configuration:")
        print(f"   Host: {config['host']}:{config['port']}")
        print(f"   Username: {config['username']}")
        print(f"   Database: {config['database']}")
        
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
            
            conn = psycopg2.connect(
                host=self.config['host'],
                port=self.config['port'],
                user=self.config['username'],
                password=self.config['password'],
                database='postgres'
            )
            conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
            cursor = conn.cursor()
            
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
            db.metadata.drop_all(self.engine)
            print("✅ All tables dropped successfully")
        except Exception as e:
            print(f"⚠️  Warning during table drop: {e}")
    
    def create_all_tables(self):
        """Create all tables from models"""
        try:
            print("🔧 Creating database tables...")
            db.metadata.create_all(self.engine)
            print("✅ All tables created successfully")
            
            critical_tables = ['tenants', 'users', 'wallets', 'organization_bank_accounts']
            for table in critical_tables:
                if self.check_table_exists(table):
                    columns = self.get_table_columns(table)
                    print(f"   ✓ {table}: {len(columns)} columns")
                else:
                    print(f"   ❌ {table}: Table not created!")
                    
        except Exception as e:
            print(f"❌ Error creating tables: {e}")
            raise
    
    def create_default_tenant(self):
        """Create the default tenant"""
        session = self.SessionLocal()
        try:
            print("🏢 Creating default tenant...")
            
            existing_tenant = session.query(Tenant).filter_by(tenant_code='DEFAULT').first()
            if existing_tenant:
                print("✅ Default tenant already exists")
                return existing_tenant
            
            tenant = Tenant(
                tenant_code='DEFAULT',
                tenant_name='Default SaaS Tenant',
                domain='localhost',
                subdomain='default',
                theme_config={"primary_color": "#007bff"},
                is_active=True,
                api_settings={"rate_limit": 1000},
                rate_limits={"api_calls_per_minute": 100},
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
            
            existing_admin = session.query(User).filter_by(username='superadmin', tenant_id=tenant.id).first()
            if existing_admin:
                print("✅ Super admin already exists")
                return existing_admin
            
            admin = User(
                tenant_id=tenant.id,
                user_code='SA001',
                username='superadmin',
                email='admin@localhost.com',
                phone='9999999999',
                role=UserRoleType.SUPER_ADMIN,
                full_name='Super Administrator',
                kyc_status=KYCStatus.APPROVED,
                is_active=True,
                is_verified=True,
                email_verified=True,
                phone_verified=True,
                level=0
            )
            
            admin.set_password('Admin@123')
            admin.generate_api_key()
            
            session.add(admin)
            session.commit()
            session.refresh(admin)
            
            admin.tree_path = str(admin.id)
            session.commit()
            
            print(f"✅ Super admin created:")
            print(f"   Username: {admin.username}")
            print(f"   Password: Admin@123")
            
            return admin
            
        except Exception as e:
            session.rollback()
            print(f"❌ Error creating super admin: {e}")
            raise
        finally:
            session.close()

    def create_wallet_for_user(self, user, initial_balance=10000.00):
        """Helper function to create a wallet for a given user."""
        session = self.SessionLocal()
        try:
            existing_wallet = session.query(Wallet).filter_by(user_id=user.id).first()
            if existing_wallet:
                return existing_wallet

            wallet = Wallet(
                user_id=user.id,
                balance=Decimal(str(initial_balance)),
                daily_limit=Decimal('50000.0000'),
                monthly_limit=Decimal('200000.0000'),
                is_active=True
            )
            session.add(wallet)
            session.commit()
            session.refresh(wallet)
            print(f"   - Created wallet for {user.username} with balance: ₹{wallet.balance}")
            return wallet
        except Exception as e:
            session.rollback()
            print(f"❌ Error creating wallet for {user.username}: {e}")
            raise
        finally:
            session.close()

    def create_full_dummy_hierarchy(self):
        """Creates a full hierarchy of users with wallets and transactions."""
        session = self.SessionLocal()
        try:
            print("\n" + "=" * 55)
            print("🌱 Populating database with extensive dummy data...")
            
            tenant = session.query(Tenant).filter_by(tenant_code='DEFAULT').first()
            if not tenant:
                print("❌ Default tenant not found. Run basic initialization first.")
                return

            super_admin = session.query(User).filter_by(role=UserRoleType.SUPER_ADMIN).first()
            if not super_admin:
                print("❌ Super Admin not found. Run basic initialization first.")
                return

            self.create_wallet_for_user(super_admin, initial_balance=1000000.00)

            # 1. Create Admin
            admin_user = self.create_dummy_user(session, tenant, super_admin, UserRoleType.ADMIN, 'Main Admin', 'admin01')
            self.create_wallet_for_user(admin_user, 500000.00)

            # 2. Create White Label
            wl_user = self.create_dummy_user(session, tenant, admin_user, UserRoleType.WHITE_LABEL, 'Travel Portal', 'whitelabel01')
            self.create_wallet_for_user(wl_user, 250000.00)

            # 3. Create Master Distributor
            md_user = self.create_dummy_user(session, tenant, wl_user, UserRoleType.MASTER_DISTRIBUTOR, 'North Zone MD', 'md01')
            self.create_wallet_for_user(md_user, 100000.00)

            # 4. Create multiple Distributors
            for i in range(2):
                dist_user = self.create_dummy_user(session, tenant, md_user, UserRoleType.DISTRIBUTOR, f'Distributor {i+1}', f'dist{i+1}')
                self.create_wallet_for_user(dist_user, 50000.00)
                
                # 5. Create multiple Retailers under each Distributor
                for j in range(3):
                    retailer_user = self.create_dummy_user(session, tenant, dist_user, UserRoleType.RETAILER, f'Retailer {i+1}-{j+1}', f'retailer{i+1}{j+1}')
                    self.create_wallet_for_user(retailer_user, 10000.00)
                    
                    # Create some transactions for each retailer
                    self.create_dummy_transactions_for_user(session, retailer_user, tenant.id)
                    # Create some topup requests for each retailer
                    self.create_dummy_topup_requests(session, retailer_user, dist_user)


            print("✅ Extensive dummy data hierarchy created successfully!")

        except Exception as e:
            session.rollback()
            print(f"❌ Error creating dummy data hierarchy: {e}")
            traceback.print_exc()
        finally:
            session.close()

    def create_dummy_user(self, session, tenant, parent, role, name, username_suffix):
        """Helper to create a single dummy user."""
        username = f"{role.value.lower()}_{username_suffix}"
        existing_user = session.query(User).filter_by(username=username).first()
        if existing_user:
            print(f"   - User {username} already exists. Skipping.")
            return existing_user

        user = User(
            tenant_id=tenant.id,
            parent_id=parent.id,
            user_code=f"{role.name[:2]}{random.randint(100, 999)}",
            username=username,
            email=f"{username}@example.com",
            phone=f"9{random.randint(100000000, 999999999)}",
            role=role,
            full_name=name,
            business_name=f"{name} Services",
            kyc_status=KYCStatus.APPROVED,
            is_active=True,
            is_verified=True,
            level=parent.level + 1,
        )
        user.set_password('password123')
        session.add(user)
        session.commit()
        session.refresh(user)
        
        user.tree_path = f"{parent.tree_path}/{user.id}"
        session.commit()

        print(f"   - Created {role.value}: {user.username} (Password: password123)")
        return user

    def create_dummy_transactions_for_user(self, session, user, tenant_id):
        """Helper to create sample transactions for a user."""
        print(f"   - Creating dummy transactions for {user.username}...")
        wallet = session.query(Wallet).filter_by(user_id=user.id).one()
        
        services = [ServiceType.MOBILE_RECHARGE, ServiceType.DTH_RECHARGE, ServiceType.BILL_PAYMENT, ServiceType.MONEY_TRANSFER]
        for i in range(random.randint(3, 8)):
            service = random.choice(services)
            amount = Decimal(str(random.uniform(50, 2500)))
            commission = amount * Decimal('0.02') if service != ServiceType.MONEY_TRANSFER else 0
            platform_charges = amount * Decimal('0.01') if service == ServiceType.MONEY_TRANSFER else 0
            net_amount = amount - commission + platform_charges
            
            if wallet.balance < net_amount:
                continue

            balance_before = wallet.balance
            wallet.balance -= net_amount
            balance_after = wallet.balance

            txn = Transaction(
                tenant_id=tenant_id,
                user_id=user.id,
                transaction_id=f"DUMMY-TXN-{uuid.uuid4().hex[:10].upper()}",
                service_type=service,
                amount=amount,
                commission=commission,
                platform_charges=platform_charges,
                net_amount=net_amount,
                status=random.choice([TransactionStatus.SUCCESS, TransactionStatus.FAILED, TransactionStatus.PENDING]),
                provider="DummyProvider",
                customer_details={"number": f"987654321{i}", "name": "John Doe"},
                service_details={"operator": "DummyOperator", "biller_id": "DUMMYBILLER"},
                processed_at=datetime.utcnow() - timedelta(days=i, hours=i)
            )
            session.add(txn)
            
            wallet_txn = WalletTransaction(
                wallet_id=wallet.id,
                transaction_type=WalletTransactionType.DEBIT,
                amount=net_amount,
                balance_before=balance_before,
                balance_after=balance_after,
                reference_id=txn.id,
                reference_type='Transaction',
                description=f"{service.value} of INR {amount}"
            )
            session.add(wallet_txn)
        session.commit()

    def create_dummy_topup_requests(self, session, user, approver):
        """Helper to create dummy wallet topup requests."""
        print(f"   - Creating dummy topup requests for {user.username}...")
        for i in range(random.randint(1, 3)):
            amount = Decimal(str(random.choice([500, 1000, 2000, 5000])))
            status = random.choice([TransactionStatus.SUCCESS, TransactionStatus.PENDING, TransactionStatus.FAILED])
            
            req = WalletTopupRequest(
                request_id=f"DUMMY-REQ-{uuid.uuid4().hex[:10].upper()}",
                user_id=user.id,
                requested_by=user.id,
                approved_by=approver.id if status == TransactionStatus.SUCCESS else None,
                topup_method=TopupMethod.BANK_TRANSFER,
                amount=amount,
                net_amount=amount,
                transaction_mode=TransactionMode.UPI,
                external_transaction_id=f"DUMMY-UPI-{random.randint(100000, 999999)}",
                status=status,
                request_remarks="Please approve my topup.",
                admin_remarks="Approved" if status == TransactionStatus.SUCCESS else "",
                processed_at=datetime.utcnow() - timedelta(days=i) if status == TransactionStatus.SUCCESS else None
            )
            session.add(req)
        session.commit()

    def run_full_initialization(self, force_recreate=False):
        """Run complete database initialization"""
        try:
            print("🔧 Initializing SaaS Platform Database (PostgreSQL)...")
            print("=" * 55)
            
            if force_recreate:
                self.drop_all_tables()
            
            self.create_all_tables()
            
            tenant = self.create_default_tenant()
            self.create_super_admin(tenant)
            
            print("\n" + "=" * 55)
            print("🎉 PostgreSQL Database initialization completed successfully!")
            
            return True
            
        except Exception as e:
            print(f"\n❌ Database initialization failed: {e}")
            traceback.print_exc()
            return False

def get_postgresql_config():
    """Get PostgreSQL configuration from user input or environment"""
    config = {}
    
    print("🔧 PostgreSQL Configuration")
    print("=" * 30)
    
    config['host'] = os.getenv('DB_HOST') or input("Host [localhost]: ").strip() or 'localhost'
    config['port'] = int(os.getenv('DB_PORT') or input("Port [5432]: ").strip() or '5432')
    config['username'] = os.getenv('DB_USER') or input("Username [postgres]: ").strip() or 'postgres'
    
    import getpass
    config['password'] = os.getenv('DB_PASSWORD') or getpass.getpass("Password: ")
    
    config['database'] = os.getenv('DB_NAME') or input("Database name [saas_platform]: ").strip() or 'saas_platform'
    
    return config

def main():
    """Main function to run database initialization"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Initialize SaaS Platform Database with PostgreSQL')
    parser.add_argument('--force', action='store_true', help='Force recreate all tables')
    parser.add_argument('--auto', action='store_true', help='Use default configuration without prompts')
    parser.add_argument('--dummy-data', action='store_true', help='Populate the database with a full hierarchy of dummy data')
    
    args = parser.parse_args()
    
    if args.auto:
        config = {
            'host': 'localhost',
            'port': 5432,
            'username': 'postgres',
            'password': '',  # ⚠️ SET YOUR ACTUAL POSTGRESQL PASSWORD HERE
            'database': 'saas_platform'
        }
        print("🤖 Using automatic configuration")
    else:
        config = get_postgresql_config()
    
    try:
        print("🚀 Starting database initialization...")
        initializer = PostgreSQLDatabaseInitializer(config)
        
        if args.dummy_data or args.force:
            success = initializer.run_full_initialization(force_recreate=args.force)
            if not success:
                 sys.exit(1)
        
        if args.dummy_data:
            initializer.create_full_dummy_hierarchy()

        print("\n🚀 Process finished.")
        if not args.dummy_data and not args.force:
            print("💡 No actions performed. Use --force to create/recreate tables or --dummy-data to populate.")

    except KeyboardInterrupt:
        print("\n\n⚠️  Setup cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Setup failed: {e}")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()