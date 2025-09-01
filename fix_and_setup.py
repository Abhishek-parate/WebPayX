"""
PostgreSQL Database Setup for SaaS Platform - COMPLETE VERSION
==============================================================

This script initializes the database using PostgreSQL and can populate it with
comprehensive dummy data including all features of the SaaS platform.

Features:
- Complete user hierarchy with realistic roles
- Multiple bank accounts with different purposes
- Payment gateway configurations
- Comprehensive transaction history
- Commission distribution system
- Wallet topup requests with various statuses
- API configurations and logs
- Audit trails and daily summaries
- Bank transaction reconciliation data

Usage:
    python complete_setup.py --complete-data    # Full feature demo
    python complete_setup.py --dummy-data       # Basic hierarchy only
    python complete_setup.py --setup-only       # Database setup only
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
    WalletTopupRequest, TopupMethod, TransactionMode, PaymentGateway, PaymentGatewayType,
    UserCommission, CommissionDistribution, APIConfiguration, AuditLog, DailySummary,
    PaymentWebhook, PaymentGatewayLog, BankAccountTransaction, BankStatementImport
)

class ComprehensiveDatabaseInitializer:
    """Comprehensive PostgreSQL database initialization with full dummy data"""
    
    def __init__(self, config=None):
        """Initialize with PostgreSQL configuration"""
        if config is None:
            config = {
                'host': 'localhost',
                'port': 5432,
                'username': 'postgres',
                'password': '',
                'database': 'saas_platform'
            }
        
        self.config = config
        self.admin_url = f"postgresql://{config['username']}:{config['password']}@{config['host']}:{config['port']}/postgres"
        self.database_url = f"postgresql://{config['username']}:{config['password']}@{config['host']}:{config['port']}/{config['database']}"
        
        print(f"Configuration: {config['host']}:{config['port']} -> {config['database']}")
        
        self.test_connection()
        self.create_database_if_not_exists()
        
        self.engine = create_engine(self.database_url, echo=False)
        self.SessionLocal = sessionmaker(bind=self.engine)
    
    def test_connection(self):
        """Test PostgreSQL connection"""
        try:
            print("Testing PostgreSQL connection...")
            conn = psycopg2.connect(
                host=self.config['host'],
                port=self.config['port'],
                user=self.config['username'],
                password=self.config['password'],
                database='postgres'
            )
            conn.close()
            print("✓ PostgreSQL connection successful")
        except psycopg2.Error as e:
            print(f"✗ PostgreSQL connection failed: {e}")
            print("\nTroubleshooting tips:")
            print("1. Make sure PostgreSQL is running")
            print("2. Check your username/password")
            print("3. Verify the host and port")
            print("4. Ensure user has database creation privileges")
            sys.exit(1)
    
    def create_database_if_not_exists(self):
        """Create database if it doesn't exist"""
        try:
            print(f"Checking if database '{self.config['database']}' exists...")
            
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
                print(f"Creating database '{self.config['database']}'...")
                cursor.execute(f'CREATE DATABASE "{self.config["database"]}"')
                print("✓ Database created successfully")
            else:
                print("✓ Database already exists")
            
            cursor.close()
            conn.close()
            
        except psycopg2.Error as e:
            print(f"✗ Error creating database: {e}")
            sys.exit(1)
    
    def drop_all_tables(self):
        """Drop all existing tables"""
        try:
            print("Dropping existing tables...")
            db.metadata.drop_all(self.engine)
            print("✓ All tables dropped successfully")
        except Exception as e:
            print(f"Warning during table drop: {e}")
    
    def create_all_tables(self):
        """Create all tables from models"""
        try:
            print("Creating database tables...")
            db.metadata.create_all(self.engine)
            print("✓ All tables created successfully")
        except Exception as e:
            print(f"✗ Error creating tables: {e}")
            raise
    
    def create_default_tenant(self):
        """Create the default tenant"""
        session = self.SessionLocal()
        try:
            print("Creating default tenant...")
            
            existing_tenant = session.query(Tenant).filter_by(tenant_code='DEFAULT').first()
            if existing_tenant:
                print("✓ Default tenant already exists")
                return existing_tenant
            
            tenant = Tenant(
                tenant_code='DEFAULT',
                tenant_name='SaaS Platform Demo',
                domain='demo.saasplatform.com',
                subdomain='demo',
                theme_config={"primary_color": "#007bff", "secondary_color": "#6c757d"},
                is_active=True,
                api_settings={"rate_limit": 1000, "timeout": 30},
                rate_limits={"api_calls_per_minute": 100}
            )
            
            session.add(tenant)
            session.commit()
            session.refresh(tenant)
            
            print(f"✓ Default tenant created with ID: {tenant.id}")
            return tenant
            
        except Exception as e:
            session.rollback()
            print(f"✗ Error creating default tenant: {e}")
            raise
        finally:
            session.close()
    
    def create_super_admin(self, tenant):
        """Create super admin user"""
        session = self.SessionLocal()
        try:
            print("Creating super admin user...")
            
            existing_admin = session.query(User).filter_by(username='superadmin', tenant_id=tenant.id).first()
            if existing_admin:
                print("✓ Super admin already exists")
                return existing_admin
            
            admin = User(
                tenant_id=tenant.id,
                user_code='SA001',
                username='superadmin',
                email='admin@demo.com',
                phone='9999999999',
                role=UserRoleType.SUPER_ADMIN,
                full_name='System Administrator',
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
            
            print("✓ Super admin created successfully")
            print(f"   Username: {admin.username}")
            print(f"   Password: Admin@123")
            
            return admin
            
        except Exception as e:
            session.rollback()
            print(f"✗ Error creating super admin: {e}")
            raise
        finally:
            session.close()

    def create_wallet_for_user(self, user, initial_balance=10000.00):
        """Create a wallet for a user"""
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
            print(f"   - Created wallet for {user.username}: ₹{wallet.balance}")
            return wallet
        except Exception as e:
            session.rollback()
            print(f"✗ Error creating wallet for {user.username}: {e}")
            raise
        finally:
            session.close()

    def create_dummy_user(self, session, tenant, parent, role, name, username_suffix):
        """Create a single dummy user"""
        username = f"{role.value.lower()}_{username_suffix}"
        existing_user = session.query(User).filter_by(username=username).first()
        if existing_user:
            return existing_user

        user = User(
            tenant_id=tenant.id,
            parent_id=parent.id,
            user_code=f"{role.name[:2]}{random.randint(100, 999)}",
            username=username,
            email=f"{username}@demo.com",
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

        print(f"   - Created {role.value}: {user.username}")
        return user

    def create_organization_bank_accounts(self, session, tenant, creator):
        """Create multiple bank accounts for different purposes"""
        bank_accounts = []
        
        bank_configs = [
            {
                "account_code": "HDFC_PRIMARY_001",
                "account_name": "HDFC Primary Collection",
                "account_number": "50200012345678",
                "ifsc_code": "HDFC0001234",
                "bank_name": "HDFC Bank",
                "branch_name": "Connaught Place Branch",
                "account_type": BankAccountType.CURRENT,
                "account_holder_name": "SaaS Platform Solutions Pvt Ltd",
                "purpose": [AccountPurpose.WALLET_TOPUP.value, AccountPurpose.GENERAL.value],
                "is_primary": True,
                "is_default_topup": True,
                "current_balance": Decimal('2500000.00')
            },
            {
                "account_code": "ICICI_SETTLEMENT_002",
                "account_name": "ICICI Settlement Account",
                "account_number": "602301234567890",
                "ifsc_code": "ICIC0006023",
                "bank_name": "ICICI Bank",
                "branch_name": "Corporate Branch Mumbai",
                "account_type": BankAccountType.CURRENT,
                "account_holder_name": "SaaS Platform Solutions Pvt Ltd",
                "purpose": [AccountPurpose.SETTLEMENT.value],
                "is_default_settlement": True,
                "current_balance": Decimal('5000000.00')
            },
            {
                "account_code": "SBI_REFUND_003",
                "account_name": "SBI Refund Processing",
                "account_number": "31234567890123",
                "ifsc_code": "SBIN0012345",
                "bank_name": "State Bank of India",
                "branch_name": "Parliament Street Branch",
                "account_type": BankAccountType.CURRENT,
                "account_holder_name": "SaaS Platform Solutions Pvt Ltd",
                "purpose": [AccountPurpose.REFUND.value],
                "is_default_refund": True,
                "current_balance": Decimal('750000.00')
            }
        ]
        
        for config in bank_configs:
            bank_account = OrganizationBankAccount(
                tenant_id=tenant.id,
                created_by=creator.id,
                **config
            )
            session.add(bank_account)
            session.commit()
            session.refresh(bank_account)
            bank_accounts.append(bank_account)
            print(f"   ✓ Created bank account: {bank_account.account_code}")
            
        return bank_accounts

    def create_payment_gateways(self, session, tenant, creator):
        """Create payment gateway configurations"""
        gateway_configs = [
            {
                "gateway_type": PaymentGatewayType.RAZORPAY,
                "gateway_name": "Razorpay Primary",
                "merchant_id": "rzp_test_1234567890",
                "api_key": "rzp_test_key_1234567890abcdef",
                "api_secret": "rzp_test_secret_abcdef1234567890",
                "webhook_secret": "webhook_secret_razorpay_123",
                "sandbox_mode": True,
                "is_default": True,
                "supported_methods": ["card", "netbanking", "upi", "wallet"]
            },
            {
                "gateway_type": PaymentGatewayType.PAYU,
                "gateway_name": "PayU Secondary",
                "merchant_id": "payu_merchant_123456",
                "api_key": "payu_key_abcdef123456",
                "api_secret": "payu_secret_123456abcdef",
                "sandbox_mode": True,
                "supported_methods": ["card", "netbanking", "upi"]
            }
        ]
        
        payment_gateways = []
        for config in gateway_configs:
            gateway = PaymentGateway(
                tenant_id=tenant.id,
                created_by=creator.id,
                callback_url="https://api.demo.com/payment/callback",
                webhook_url="https://api.demo.com/payment/webhook",
                **config
            )
            session.add(gateway)
            session.commit()
            session.refresh(gateway)
            payment_gateways.append(gateway)
            print(f"   ✓ Created payment gateway: {gateway.gateway_name}")
            
        return payment_gateways

    def create_commission_plans(self, session, tenant, creator):
        """Create comprehensive commission plans"""
        plan_configs = [
            {
                "plan_name": "Mobile Recharge - Premium",
                "service_type": ServiceType.MOBILE_RECHARGE,
                "commission_mode": CommissionMode.PERCENTAGE,
                "base_rate": Decimal('3.5'),
                "min_commission": Decimal('2.00'),
                "max_commission": Decimal('150.00')
            },
            {
                "plan_name": "DTH Recharge - Premium",
                "service_type": ServiceType.DTH_RECHARGE,
                "commission_mode": CommissionMode.PERCENTAGE,
                "base_rate": Decimal('4.0'),
                "min_commission": Decimal('3.00'),
                "max_commission": Decimal('200.00')
            },
            {
                "plan_name": "Money Transfer - Standard",
                "service_type": ServiceType.MONEY_TRANSFER,
                "commission_mode": CommissionMode.FLAT,
                "base_rate": Decimal('8.00'),
                "min_commission": Decimal('5.00'),
                "max_commission": Decimal('25.00')
            }
        ]
        
        commission_plans = []
        for config in plan_configs:
            plan = CommissionPlan(
                tenant_id=tenant.id,
                created_by=creator.id,
                is_active=True,
                valid_from=datetime.utcnow(),
                **config
            )
            session.add(plan)
            session.commit()
            session.refresh(plan)
            commission_plans.append(plan)
            print(f"   ✓ Created commission plan: {plan.plan_name}")
            
        return commission_plans

    def create_comprehensive_transactions(self, session, tenant, users):
        """Create realistic transaction history"""
        services_data = {
            ServiceType.MOBILE_RECHARGE: {
                "operators": ["Airtel", "Jio", "Vi", "BSNL"],
                "amounts": [50, 100, 200, 500, 1000, 1500, 2000]
            },
            ServiceType.DTH_RECHARGE: {
                "operators": ["Tata Sky", "Airtel Digital TV", "Dish TV"],
                "amounts": [200, 300, 500, 1000, 1500, 2000]
            },
            ServiceType.MONEY_TRANSFER: {
                "operators": ["IMPS", "NEFT"],
                "amounts": [1000, 2000, 5000, 10000, 25000]
            }
        }
        
        retailers = [user for user in users if user.role == UserRoleType.RETAILER]
        
        for retailer in retailers:
            wallet = session.query(Wallet).filter_by(user_id=retailer.id).first()
            if not wallet:
                continue
                
            num_transactions = random.randint(10, 30)
            
            for i in range(num_transactions):
                service = random.choice(list(services_data.keys()))
                service_info = services_data[service]
                
                amount = Decimal(str(random.choice(service_info["amounts"])))
                operator = random.choice(service_info["operators"])
                commission = amount * Decimal('0.025')
                net_amount = amount + commission
                
                if wallet.available_balance < net_amount:
                    continue
                
                status = random.choices(
                    [TransactionStatus.SUCCESS, TransactionStatus.FAILED],
                    weights=[85, 15]
                )[0]
                
                transaction = Transaction(
                    tenant_id=tenant.id,
                    user_id=retailer.id,
                    transaction_id=f"TXN{datetime.now().strftime('%Y%m%d')}{random.randint(100000, 999999)}",
                    service_type=service,
                    amount=amount,
                    commission=commission if status == TransactionStatus.SUCCESS else 0,
                    net_amount=net_amount,
                    status=status,
                    provider=f"{operator} API",
                    customer_details={
                        "number": f"9{random.randint(100000000, 999999999)}",
                        "name": f"Customer {random.randint(1, 1000)}"
                    },
                    service_details={"operator": operator},
                    created_at=datetime.utcnow() - timedelta(days=random.randint(1, 30))
                )
                
                session.add(transaction)
                
                if status == TransactionStatus.SUCCESS:
                    balance_before = wallet.balance
                    wallet.balance -= net_amount
                    balance_after = wallet.balance
                    
                    wallet_txn = WalletTransaction(
                        wallet_id=wallet.id,
                        transaction_type=WalletTransactionType.DEBIT,
                        amount=net_amount,
                        balance_before=balance_before,
                        balance_after=balance_after,
                        reference_id=transaction.id,
                        reference_type="Transaction",
                        description=f"{service.value} - {operator}"
                    )
                    session.add(wallet_txn)
        
        session.commit()
        print(f"   ✓ Created transactions for {len(retailers)} retailers")

    def create_comprehensive_topup_requests(self, session, users, bank_accounts):
        """Create wallet topup requests"""
        primary_bank = bank_accounts[0] if bank_accounts else None
        target_users = [user for user in users if user.role in [UserRoleType.RETAILER, UserRoleType.DISTRIBUTOR]]
        
        for user in target_users[:15]:  # Limit for demo
            num_requests = random.randint(2, 5)
            
            for i in range(num_requests):
                amount = Decimal(str(random.choice([1000, 2000, 5000, 10000])))
                status = random.choices(
                    [TransactionStatus.SUCCESS, TransactionStatus.PENDING, TransactionStatus.FAILED],
                    weights=[60, 25, 15]
                )[0]
                
                request = WalletTopupRequest(
                    request_id=f"TOP{datetime.now().strftime('%Y%m%d')}{random.randint(100000, 999999)}",
                    user_id=user.id,
                    requested_by=user.id,
                    approved_by=user.parent_id if status == TransactionStatus.SUCCESS else None,
                    selected_bank_account_id=primary_bank.id if primary_bank else None,
                    topup_method=TopupMethod.BANK_TRANSFER,
                    amount=amount,
                    net_amount=amount,
                    transaction_mode=TransactionMode.UPI,
                    status=status,
                    request_remarks="Please process my topup request",
                    created_at=datetime.utcnow() - timedelta(days=random.randint(1, 30))
                )
                
                session.add(request)
                
                if status == TransactionStatus.SUCCESS:
                    wallet = session.query(Wallet).filter_by(user_id=user.id).first()
                    if wallet:
                        wallet.balance += amount
        
        session.commit()
        print(f"   ✓ Created topup requests for {len(target_users[:15])} users")

    def create_basic_hierarchy(self):
        """Create basic user hierarchy with essential data"""
        session = self.SessionLocal()
        try:
            print("\n" + "=" * 50)
            print("Creating Basic User Hierarchy...")
            print("=" * 50)
            
            tenant = session.query(Tenant).filter_by(tenant_code='DEFAULT').first()
            super_admin = session.query(User).filter_by(role=UserRoleType.SUPER_ADMIN).first()
            
            if not tenant or not super_admin:
                print("✗ Basic setup not found. Run initialization first.")
                return
            
            # Create super admin wallet
            self.create_wallet_for_user(super_admin, 5000000.00)
            
            # Create Admin
            admin = self.create_dummy_user(session, tenant, super_admin, UserRoleType.ADMIN, 'Main Admin', 'mainadmin')
            self.create_wallet_for_user(admin, 1000000.00)
            
            # Create White Label
            wl = self.create_dummy_user(session, tenant, admin, UserRoleType.WHITE_LABEL, 'Demo White Label', 'demowl')
            self.create_wallet_for_user(wl, 500000.00)
            
            # Create Master Distributor
            md = self.create_dummy_user(session, tenant, wl, UserRoleType.MASTER_DISTRIBUTOR, 'North Zone MD', 'northmd')
            self.create_wallet_for_user(md, 250000.00)
            
            # Create Distributors
            distributors = []
            for i in range(2):
                dist = self.create_dummy_user(session, tenant, md, UserRoleType.DISTRIBUTOR, f'Distributor {i+1}', f'dist{i+1}')
                self.create_wallet_for_user(dist, 100000.00)
                distributors.append(dist)
            
            # Create Retailers
            retailers = []
            for i, dist in enumerate(distributors):
                for j in range(3):
                    retailer = self.create_dummy_user(session, tenant, dist, UserRoleType.RETAILER, f'Retailer {i+1}-{j+1}', f'ret{i+1}{j+1}')
                    self.create_wallet_for_user(retailer, 25000.00)
                    retailers.append(retailer)
            
            all_users = [admin, wl, md] + distributors + retailers
            
            print("\n" + "Bank Accounts & Payment Gateways...")
            bank_accounts = self.create_organization_bank_accounts(session, tenant, super_admin)
            payment_gateways = self.create_payment_gateways(session, tenant, super_admin)
            
            print("\n" + "Commission Plans...")
            commission_plans = self.create_commission_plans(session, tenant, super_admin)
            
            print("\n" + "Transaction History...")
            self.create_comprehensive_transactions(session, tenant, all_users)
            
            print("\n" + "Wallet Topup Requests...")
            self.create_comprehensive_topup_requests(session, all_users, bank_accounts)
            
            print("\n✓ Basic hierarchy created successfully!")
            print(f"   Users: {len(all_users) + 1}")
            print(f"   Bank Accounts: {len(bank_accounts)}")
            print(f"   Payment Gateways: {len(payment_gateways)}")
            print(f"   Commission Plans: {len(commission_plans)}")
            
        except Exception as e:
            session.rollback()
            print(f"✗ Error creating basic hierarchy: {e}")
            traceback.print_exc()
            raise
        finally:
            session.close()

    def run_initialization(self, force_recreate=False):
        """Run basic database initialization"""
        try:
            print("Initializing SaaS Platform Database...")
            print("=" * 50)
            
            if force_recreate:
                self.drop_all_tables()
            
            self.create_all_tables()
            tenant = self.create_default_tenant()
            self.create_super_admin(tenant)
            
            print("\n✓ Database initialization completed!")
            return True
            
        except Exception as e:
            print(f"✗ Database initialization failed: {e}")
            traceback.print_exc()
            return False

def get_postgresql_config():
    """Get PostgreSQL configuration"""
    config = {}
    
    print("PostgreSQL Configuration")
    print("=" * 25)
    
    config['host'] = input("Host [localhost]: ").strip() or 'localhost'
    config['port'] = int(input("Port [5432]: ").strip() or '5432')
    config['username'] = input("Username [postgres]: ").strip() or 'postgres'
    
    import getpass
    config['password'] = getpass.getpass("Password: ")
    config['database'] = input("Database name [saas_platform]: ").strip() or 'saas_platform'
    
    return config

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Initialize SaaS Platform Database')
    parser.add_argument('--force', action='store_true', help='Force recreate tables')
    parser.add_argument('--auto', action='store_true', help='Use default config')
    parser.add_argument('--dummy-data', action='store_true', help='Create basic dummy data')
    parser.add_argument('--setup-only', action='store_true', help='Setup only, no data')
    
    args = parser.parse_args()
    
    if args.auto:
        config = {
            'host': 'localhost',
            'port': 5432,
            'username': 'postgres', 
            'password': '',  # SET YOUR PASSWORD HERE
            'database': 'saas_platform'
        }
        print("Using automatic configuration")
    else:
        config = get_postgresql_config()
    
    try:
        print("Starting database setup...")
        initializer = ComprehensiveDatabaseInitializer(config)
        
        # Always run basic setup
        if args.force or args.dummy_data or args.setup_only:
            success = initializer.run_initialization(force_recreate=args.force)
            if not success:
                sys.exit(1)
        
        # Create dummy data if requested
        if args.dummy_data:
            initializer.create_basic_hierarchy()
        elif args.setup_only:
            print("✓ Database setup completed")
        else:
            print("Use --dummy-data to populate with sample data")

        print("\n" + "=" * 50)
        print("SETUP COMPLETED SUCCESSFULLY!")
        print("=" * 50)
        print("Super Admin Credentials:")
        print("  Username: superadmin")
        print("  Password: Admin@123")
        if args.dummy_data:
            print("\nSample User Credentials:")
            print("  All users password: password123")
            print("  Examples: admin_mainadmin, white_label_demowl, ret11")

    except KeyboardInterrupt:
        print("\nSetup cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nSetup failed: {e}")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()