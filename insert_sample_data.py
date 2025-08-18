#!/usr/bin/env python3
"""
SaaS Multi-Tenant Financial Services Platform - Sample Data Insertion Script
===========================================================================

This script creates comprehensive sample data for the multi-tenant platform
following the hierarchical structure: Super Admin → Admin → White Label → 
Master Distributor → Distributor → Retailer

Author: AI Assistant
Created: 2025
Usage: python insert_sample_data.py
"""

import os
import sys
import uuid
import secrets
import random
from datetime import datetime, timedelta, date
from decimal import Decimal
from faker import Faker
import bcrypt

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()  # Load .env file if it exists
except ImportError:
    pass  # dotenv is optional

# Import Flask and SQLAlchemy
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text

# Import all models (assuming models.py is in the same directory)
try:
    from models import *
except ImportError:
    print("❌ Error: models.py not found. Please ensure models.py is in the same directory.")
    sys.exit(1)

# Initialize Faker for realistic data
fake = Faker('en_IN')  # Indian locale for realistic Indian data
Faker.seed(42)  # For reproducible data
random.seed(42)

class DatabaseSeeder:
    """Database seeder class for inserting sample data"""
    
    def __init__(self, app, database_url=None):
        self.app = app
        self.database_url = database_url or 'postgresql://postgres:1234@localhost:5432/saas_platform'
        self.setup_database()
        
        # Data containers
        self.tenants = []
        self.users = {}  # {role: [users]}
        self.payment_gateways = []
        self.bank_accounts = []
        self.commission_plans = []
        self.permissions = []
        
    def setup_database(self):
        """Setup database connection"""
        self.app.config['SQLALCHEMY_DATABASE_URI'] = self.database_url
        self.app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        self.app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
            'pool_pre_ping': True,
            'pool_recycle': 300,
            'echo': False
        }
        
        # Initialize database
        db.init_app(self.app)
        
        with self.app.app_context():
            try:
                # Test connection - Updated for SQLAlchemy 2.0+
                with db.engine.connect() as connection:
                    connection.execute(text('SELECT 1'))
                print("✅ Database connection successful")
            except Exception as e:
                print(f"❌ Database connection failed: {e}")
                print("💡 Please check your database URL and ensure PostgreSQL is running")
                sys.exit(1)
    
    def create_tables(self):
        """Create all database tables"""
        with self.app.app_context():
            try:
                db.create_all()
                print("✅ Database tables created successfully")
            except Exception as e:
                print(f"❌ Error creating tables: {e}")
                raise
    
    def clear_all_data(self):
        """Clear all existing data (use with caution!)"""
        with self.app.app_context():
            try:
                # Get all table names
                tables = list(db.metadata.tables.keys())
                
                # Use text() for raw SQL execution in SQLAlchemy 2.0+
                with db.engine.connect() as connection:
                    # Disable foreign key checks temporarily
                    if db.engine.dialect.name == 'postgresql':
                        connection.execute(text('SET session_replication_role = replica;'))
                    elif db.engine.dialect.name == 'mysql':
                        connection.execute(text('SET FOREIGN_KEY_CHECKS = 0;'))
                    
                    # Truncate all tables
                    for table in tables:
                        connection.execute(text(f'TRUNCATE TABLE "{table}" CASCADE;'))
                    
                    # Re-enable foreign key checks
                    if db.engine.dialect.name == 'postgresql':
                        connection.execute(text('SET session_replication_role = DEFAULT;'))
                    elif db.engine.dialect.name == 'mysql':
                        connection.execute(text('SET FOREIGN_KEY_CHECKS = 1;'))
                    
                    connection.commit()
                
                print("✅ All existing data cleared")
                
            except Exception as e:
                print(f"❌ Error clearing data: {e}")
                raise
    
    def generate_user_code(self, role, index):
        """Generate user codes based on role"""
        prefixes = {
            UserRoleType.SUPER_ADMIN: 'SA',
            UserRoleType.ADMIN: 'AD',
            UserRoleType.WHITE_LABEL: 'WL',
            UserRoleType.MASTER_DISTRIBUTOR: 'MD',
            UserRoleType.DISTRIBUTOR: 'DS',
            UserRoleType.RETAILER: 'RT'
        }
        return f"{prefixes[role]}{str(index).zfill(4)}"
    
    def create_permissions(self):
        """Create system permissions"""
        print("📋 Creating permissions...")
        
        permissions_data = [
            # User Management
            ('USER_CREATE', 'Create users', 'USER_MANAGEMENT'),
            ('USER_READ', 'View users', 'USER_MANAGEMENT'),
            ('USER_UPDATE', 'Update users', 'USER_MANAGEMENT'),
            ('USER_DELETE', 'Delete users', 'USER_MANAGEMENT'),
            ('USER_IMPERSONATE', 'Impersonate users', 'USER_MANAGEMENT'),
            
            # Transaction Management
            ('TRANSACTION_READ', 'View transactions', 'TRANSACTIONS'),
            ('TRANSACTION_PROCESS', 'Process transactions', 'TRANSACTIONS'),
            ('TRANSACTION_REFUND', 'Refund transactions', 'TRANSACTIONS'),
            ('TRANSACTION_CANCEL', 'Cancel transactions', 'TRANSACTIONS'),
            
            # Wallet Management
            ('WALLET_READ', 'View wallet', 'WALLET'),
            ('WALLET_CREDIT', 'Credit wallet', 'WALLET'),
            ('WALLET_DEBIT', 'Debit wallet', 'WALLET'),
            ('WALLET_TOPUP_APPROVE', 'Approve wallet topup', 'WALLET'),
            ('WALLET_FUND_DOWNLINE', 'Fund downline wallets', 'WALLET'),
            
            # Commission Management
            ('COMMISSION_SET', 'Set commission rates', 'COMMISSION'),
            ('COMMISSION_VIEW', 'View commission details', 'COMMISSION'),
            ('COMMISSION_PLAN_CREATE', 'Create commission plans', 'COMMISSION'),
            
            # Reporting
            ('REPORT_VIEW_OWN', 'View own reports', 'REPORTING'),
            ('REPORT_VIEW_DOWNLINE', 'View downline reports', 'REPORTING'),
            ('REPORT_VIEW_GLOBAL', 'View global reports', 'REPORTING'),
            ('REPORT_EXPORT', 'Export reports', 'REPORTING'),
            
            # Service Management
            ('SERVICE_USE', 'Use platform services', 'SERVICES'),
            ('SERVICE_CONFIGURE', 'Configure services', 'SERVICES'),
            ('SERVICE_API_ACCESS', 'Access service APIs', 'SERVICES'),
            
            # System Configuration
            ('SYSTEM_CONFIG', 'System configuration', 'SYSTEM'),
            ('BANK_ACCOUNT_MANAGE', 'Manage bank accounts', 'SYSTEM'),
            ('PAYMENT_GATEWAY_MANAGE', 'Manage payment gateways', 'SYSTEM'),
            ('TENANT_MANAGE', 'Manage tenants', 'SYSTEM'),
            ('DOMAIN_MANAGE', 'Manage domains', 'SYSTEM'),
            ('BRANDING_MANAGE', 'Manage branding', 'SYSTEM'),
            
            # Audit & Compliance
            ('AUDIT_VIEW', 'View audit logs', 'AUDIT'),
            ('KYC_VERIFY', 'Verify KYC documents', 'COMPLIANCE'),
        ]
        
        with self.app.app_context():
            created_count = 0
            skipped_count = 0
            
            for name, desc, category in permissions_data:
                # Check if permission already exists
                existing_permission = Permission.query.filter_by(name=name).first()
                if existing_permission:
                    skipped_count += 1
                    continue
                
                permission = Permission(
                    name=name,
                    description=desc,
                    category=category,
                    is_system=True
                )
                db.session.add(permission)
                self.permissions.append(permission)
                created_count += 1
            
            try:
                db.session.commit()
                print(f"✅ Created {created_count} permissions, skipped {skipped_count} existing")
            except Exception as e:
                db.session.rollback()
                print(f"❌ Error creating permissions: {e}")
                raise
    
    def create_tenants(self):
        """Create sample tenants"""
        print("🏢 Creating tenants...")
        
        tenants_data = [
            {
                'tenant_code': 'DEMO001',
                'tenant_name': 'Demo Financial Services',
                'domain': 'demo.financialservices.com',
                'subdomain': 'demo',
                'subscription_plan': 'ENTERPRISE',
                'subscription_expires_at': datetime.utcnow() + timedelta(days=365)
            },
            {
                'tenant_code': 'FINTECH02',
                'tenant_name': 'FinTech Solutions India',
                'domain': 'fintech.solutions.in',
                'subdomain': 'fintech',
                'subscription_plan': 'PREMIUM',
                'subscription_expires_at': datetime.utcnow() + timedelta(days=180)
            },
            {
                'tenant_code': 'PAYMENTS03',
                'tenant_name': 'QuickPay Services',
                'domain': 'quickpay.services.com',
                'subdomain': 'quickpay',
                'subscription_plan': 'STANDARD',
                'subscription_expires_at': datetime.utcnow() + timedelta(days=90)
            }
        ]
        
        with self.app.app_context():
            created_count = 0
            skipped_count = 0
            
            for tenant_data in tenants_data:
                # Check if tenant already exists
                existing_tenant = Tenant.query.filter_by(tenant_code=tenant_data['tenant_code']).first()
                if existing_tenant:
                    self.tenants.append(existing_tenant)
                    skipped_count += 1
                    continue
                
                tenant = Tenant(
                    tenant_code=tenant_data['tenant_code'],
                    tenant_name=tenant_data['tenant_name'],
                    domain=tenant_data['domain'],
                    subdomain=tenant_data['subdomain'],
                    subscription_plan=tenant_data['subscription_plan'],
                    subscription_expires_at=tenant_data['subscription_expires_at'],
                    logo_url=f"https://cdn.example.com/logos/{tenant_data['tenant_code'].lower()}.png",
                    theme_config={
                        'primary_color': fake.color(),
                        'secondary_color': fake.color(),
                        'logo_position': 'left',
                        'theme': 'light'
                    },
                    api_settings={
                        'rate_limit': 1000,
                        'timeout': 30,
                        'retry_count': 3
                    },
                    is_active=True
                )
                db.session.add(tenant)
                self.tenants.append(tenant)
                created_count += 1
            
            try:
                db.session.commit()
                print(f"✅ Created {created_count} tenants, skipped {skipped_count} existing")
            except Exception as e:
                db.session.rollback()
                print(f"❌ Error creating tenants: {e}")
                raise
    
    def create_users(self):
        """Create hierarchical user structure"""
        print("👥 Creating users...")
        
        with self.app.app_context():
            for tenant in self.tenants:
                # Initialize user collections for this tenant
                tenant_users = {role: [] for role in UserRoleType}
                
                # 1. Create Super Admin (1 per tenant)
                super_admin = self.create_user(
                    tenant_id=tenant.id,
                    role=UserRoleType.SUPER_ADMIN,
                    parent_id=None,
                    index=1,
                    full_name="Super Administrator",
                    email=f"superadmin@{tenant.domain}",
                    business_name=f"{tenant.tenant_name} - Super Admin"
                )
                tenant_users[UserRoleType.SUPER_ADMIN].append(super_admin)
                
                # 2. Create Admins (2-3 per tenant)
                for i in range(1, 4):
                    admin = self.create_user(
                        tenant_id=tenant.id,
                        role=UserRoleType.ADMIN,
                        parent_id=super_admin.id,
                        index=i,
                        full_name=fake.name(),
                        email=f"admin{i}@{tenant.domain}",
                        business_name=f"{tenant.tenant_name} - Admin {i}"
                    )
                    tenant_users[UserRoleType.ADMIN].append(admin)
                
                # 3. Create White Label users (2-4 per admin)
                for admin in tenant_users[UserRoleType.ADMIN]:
                    for i in range(1, random.randint(2, 5)):
                        white_label = self.create_user(
                            tenant_id=tenant.id,
                            role=UserRoleType.WHITE_LABEL,
                            parent_id=admin.id,
                            index=len(tenant_users[UserRoleType.WHITE_LABEL]) + 1,
                            full_name=fake.name(),
                            email=fake.email(),
                            business_name=fake.company()
                        )
                        tenant_users[UserRoleType.WHITE_LABEL].append(white_label)
                
                # 4. Create Master Distributors (3-5 per white label)
                for white_label in tenant_users[UserRoleType.WHITE_LABEL]:
                    for i in range(1, random.randint(3, 6)):
                        master_dist = self.create_user(
                            tenant_id=tenant.id,
                            role=UserRoleType.MASTER_DISTRIBUTOR,
                            parent_id=white_label.id,
                            index=len(tenant_users[UserRoleType.MASTER_DISTRIBUTOR]) + 1,
                            full_name=fake.name(),
                            email=fake.email(),
                            business_name=fake.company()
                        )
                        tenant_users[UserRoleType.MASTER_DISTRIBUTOR].append(master_dist)
                
                # 5. Create Distributors (5-8 per master distributor)
                for master_dist in tenant_users[UserRoleType.MASTER_DISTRIBUTOR]:
                    for i in range(1, random.randint(5, 9)):
                        distributor = self.create_user(
                            tenant_id=tenant.id,
                            role=UserRoleType.DISTRIBUTOR,
                            parent_id=master_dist.id,
                            index=len(tenant_users[UserRoleType.DISTRIBUTOR]) + 1,
                            full_name=fake.name(),
                            email=fake.email(),
                            business_name=fake.company()
                        )
                        tenant_users[UserRoleType.DISTRIBUTOR].append(distributor)
                
                # 6. Create Retailers (10-15 per distributor)
                for distributor in tenant_users[UserRoleType.DISTRIBUTOR]:
                    for i in range(1, random.randint(10, 16)):
                        retailer = self.create_user(
                            tenant_id=tenant.id,
                            role=UserRoleType.RETAILER,
                            parent_id=distributor.id,
                            index=len(tenant_users[UserRoleType.RETAILER]) + 1,
                            full_name=fake.name(),
                            email=fake.email(),
                            business_name=fake.company()
                        )
                        tenant_users[UserRoleType.RETAILER].append(retailer)
                
                # Store users for this tenant
                for role, users in tenant_users.items():
                    if role not in self.users:
                        self.users[role] = []
                    self.users[role].extend(users)
            
            # Update tree paths and levels
            self.update_user_hierarchy()
            
            db.session.commit()
            
            # Print summary
            total_users = sum(len(users) for users in self.users.values())
            print(f"✅ Created {total_users} users:")
            for role, users in self.users.items():
                print(f"   • {role.value}: {len(users)}")
    
    def create_user(self, tenant_id, role, parent_id, index, full_name, email, business_name):
        """Create a single user"""
        user_code = self.generate_user_code(role, index)
        
        # Generate Indian phone number
        phone = f"+91{random.randint(7000000000, 9999999999)}"
        
        user = User(
            tenant_id=tenant_id,
            parent_id=parent_id,
            user_code=user_code,
            username=user_code.lower(),
            email=email,
            phone=phone,
            role=role,
            full_name=full_name,
            business_name=business_name,
            address={
                'street': fake.street_address(),
                'city': fake.city(),
                'state': fake.state(),
                'pincode': fake.postcode(),
                'country': 'India'
            },
            kyc_status=random.choice([KYCStatus.APPROVED, KYCStatus.PENDING, KYCStatus.NOT_SUBMITTED]),
            is_active=True,
            is_verified=random.choice([True, False]),
            email_verified=random.choice([True, False]),
            phone_verified=random.choice([True, False]),
            last_login=datetime.utcnow() - timedelta(days=random.randint(0, 30)),
            settings={
                'notifications_email': True,
                'notifications_sms': True,
                'language': 'en',
                'timezone': 'Asia/Kolkata'
            }
        )
        
        # Set password (default: password123)
        user.set_password('password123')
        
        # Generate API keys for admins and above
        if role.value in ['SUPER_ADMIN', 'ADMIN', 'WHITE_LABEL']:
            user.generate_api_key()
        
        db.session.add(user)
        db.session.flush()  # Get the ID
        
        # Create wallet for each user
        wallet = Wallet(
            user_id=user.id,
            balance=Decimal(str(random.uniform(1000, 50000))),
            daily_limit=Decimal('50000'),
            monthly_limit=Decimal('200000')
        )
        db.session.add(wallet)
        
        return user
    
    def update_user_hierarchy(self):
        """Update tree paths and levels for all users"""
        with self.app.app_context():
            def update_user_tree(user, path="", level=0):
                new_path = f"{path}/{user.id}" if path else str(user.id)
                user.tree_path = new_path
                user.level = level
                
                # Update children
                children = User.query.filter_by(parent_id=user.id).all()
                for child in children:
                    update_user_tree(child, new_path, level + 1)
            
            # Start with super admins (no parent)
            super_admins = User.query.filter_by(parent_id=None).all()
            for super_admin in super_admins:
                update_user_tree(super_admin)
    
    def create_payment_gateways(self):
        """Create payment gateway configurations"""
        print("💳 Creating payment gateways...")
        
        gateways_data = [
            {
                'gateway_type': PaymentGatewayType.RAZORPAY,
                'gateway_name': 'Razorpay Production',
                'sandbox_mode': False,
                'min_amount': Decimal('1.00'),
                'max_amount': Decimal('200000.00'),
                'processing_fee_percentage': Decimal('2.0'),
                'priority': 1
            },
            {
                'gateway_type': PaymentGatewayType.PAYU,
                'gateway_name': 'PayU Money',
                'sandbox_mode': False,
                'min_amount': Decimal('10.00'),
                'max_amount': Decimal('100000.00'),
                'processing_fee_percentage': Decimal('2.5'),
                'priority': 2
            },
            {
                'gateway_type': PaymentGatewayType.CASHFREE,
                'gateway_name': 'Cashfree Payments',
                'sandbox_mode': True,
                'min_amount': Decimal('1.00'),
                'max_amount': Decimal('500000.00'),
                'processing_fee_percentage': Decimal('1.8'),
                'priority': 3
            },
            {
                'gateway_type': PaymentGatewayType.PHONEPE,
                'gateway_name': 'PhonePe Business',
                'sandbox_mode': False,
                'min_amount': Decimal('1.00'),
                'max_amount': Decimal('100000.00'),
                'processing_fee_percentage': Decimal('1.5'),
                'priority': 4
            }
        ]
        
        with self.app.app_context():
            for tenant in self.tenants:
                for gw_data in gateways_data:
                    gateway = PaymentGateway(
                        tenant_id=tenant.id,
                        gateway_type=gw_data['gateway_type'],
                        gateway_name=gw_data['gateway_name'],
                        merchant_id=f"merchant_{fake.uuid4()[:8]}",
                        api_key=secrets.token_urlsafe(32),
                        api_secret=secrets.token_urlsafe(64),
                        webhook_secret=secrets.token_urlsafe(32),
                        callback_url=f"https://{tenant.domain}/payment/callback",
                        webhook_url=f"https://{tenant.domain}/payment/webhook",
                        sandbox_mode=gw_data['sandbox_mode'],
                        status='ACTIVE',
                        priority=gw_data['priority'],
                        min_amount=gw_data['min_amount'],
                        max_amount=gw_data['max_amount'],
                        processing_fee_percentage=gw_data['processing_fee_percentage'],
                        processing_fee_fixed=Decimal('0.00'),
                        settlement_time_hours=24,
                        supported_methods=['UPI', 'NET_BANKING', 'CARD', 'WALLET'],
                        gateway_config={
                            'webhook_events': ['payment.captured', 'payment.failed'],
                            'auto_capture': True,
                            'currency': 'INR'
                        },
                        is_default=(gw_data['priority'] == 1)
                    )
                    db.session.add(gateway)
                    self.payment_gateways.append(gateway)
            
            db.session.commit()
            print(f"✅ Created {len(gateways_data) * len(self.tenants)} payment gateways")
    
    def create_bank_accounts(self):
        """Create organization bank accounts"""
        print("🏦 Creating bank accounts...")
        
        indian_banks = [
            ('State Bank of India', 'SBIN0001234'),
            ('HDFC Bank', 'HDFC0001234'),
            ('ICICI Bank', 'ICIC0001234'),
            ('Axis Bank', 'UTIB0001234'),
            ('Bank of Baroda', 'BARB0001234'),
            ('Punjab National Bank', 'PUNB0001234'),
            ('Canara Bank', 'CNRB0001234'),
            ('Union Bank of India', 'UBIN0001234')
        ]
        
        with self.app.app_context():
            for i, tenant in enumerate(self.tenants):
                # Create 3-4 bank accounts per tenant
                for j in range(3, 5):
                    bank_name, ifsc_base = random.choice(indian_banks)
                    ifsc_code = f"{ifsc_base[:4]}{random.randint(100000, 999999)}"
                    
                    bank_account = OrganizationBankAccount(
                        tenant_id=tenant.id,
                        account_code=f"ACC{i+1}{j:02d}",
                        account_name=f"{tenant.tenant_name} - Account {j}",
                        account_number=str(random.randint(10000000000, 99999999999)),
                        ifsc_code=ifsc_code,
                        bank_name=bank_name,
                        branch_name=f"{fake.city()} Branch",
                        branch_address=fake.address(),
                        account_type=random.choice([BankAccountType.CURRENT, BankAccountType.SAVINGS]),
                        account_holder_name=tenant.tenant_name,
                        pan_number=f"ABCDE{random.randint(1000, 9999)}F",
                        gstin=f"27ABCDE{random.randint(1000, 9999)}F1Z5",
                        status=BankAccountStatus.ACTIVE,
                        purpose=[AccountPurpose.WALLET_TOPUP, AccountPurpose.SETTLEMENT],
                        is_primary=(j == 3),
                        is_default_topup=(j == 3),
                        priority=j,
                        daily_limit=Decimal('500000.00'),
                        monthly_limit=Decimal('10000000.00'),
                        minimum_balance=Decimal('10000.00'),
                        current_balance=Decimal(str(random.uniform(50000, 500000))),
                        upi_id=f"{tenant.subdomain}@{bank_name.lower().replace(' ', '')}",
                        verification_status='VERIFIED',
                        verification_date=datetime.utcnow() - timedelta(days=random.randint(1, 30)),
                        is_visible_to_users=True,
                        display_order=j
                    )
                    db.session.add(bank_account)
                    self.bank_accounts.append(bank_account)
            
            db.session.commit()
            print(f"✅ Created {len(self.bank_accounts)} bank accounts")
    
    def create_commission_plans(self):
        """Create commission plans for different services"""
        print("💰 Creating commission plans...")
        
        plans_data = [
            {
                'service_type': ServiceType.MOBILE_RECHARGE,
                'plans': [
                    {'name': 'Mobile Recharge - Basic', 'rate': 1.5, 'min_comm': 1.0, 'max_comm': 50.0},
                    {'name': 'Mobile Recharge - Premium', 'rate': 2.5, 'min_comm': 2.0, 'max_comm': 100.0},
                    {'name': 'Mobile Recharge - VIP', 'rate': 3.5, 'min_comm': 3.0, 'max_comm': 150.0}
                ]
            },
            {
                'service_type': ServiceType.DTH_RECHARGE,
                'plans': [
                    {'name': 'DTH Recharge - Basic', 'rate': 2.0, 'min_comm': 2.0, 'max_comm': 100.0},
                    {'name': 'DTH Recharge - Premium', 'rate': 3.0, 'min_comm': 3.0, 'max_comm': 200.0}
                ]
            },
            {
                'service_type': ServiceType.BILL_PAYMENT,
                'plans': [
                    {'name': 'Bill Payment - Standard', 'rate': 1.0, 'min_comm': 1.0, 'max_comm': 25.0},
                    {'name': 'Bill Payment - Premium', 'rate': 1.5, 'min_comm': 1.5, 'max_comm': 50.0}
                ]
            },
            {
                'service_type': ServiceType.MONEY_TRANSFER,
                'plans': [
                    {'name': 'Money Transfer - IMPS', 'rate': 5.0, 'min_comm': 5.0, 'max_comm': 25.0, 'mode': 'FLAT'},
                    {'name': 'Money Transfer - NEFT', 'rate': 3.0, 'min_comm': 3.0, 'max_comm': 15.0, 'mode': 'FLAT'}
                ]
            },
            {
                'service_type': ServiceType.AEPS,
                'plans': [
                    {'name': 'AEPS - Standard', 'rate': 0.4, 'min_comm': 2.0, 'max_comm': 20.0}
                ]
            }
        ]
        
        with self.app.app_context():
            for tenant in self.tenants:
                for service_data in plans_data:
                    for plan_data in service_data['plans']:
                        commission_plan = CommissionPlan(
                            tenant_id=tenant.id,
                            plan_name=plan_data['name'],
                            service_type=service_data['service_type'],
                            commission_mode=CommissionMode.FLAT if plan_data.get('mode') == 'FLAT' else CommissionMode.PERCENTAGE,
                            base_rate=Decimal(str(plan_data['rate'])),
                            min_commission=Decimal(str(plan_data['min_comm'])),
                            max_commission=Decimal(str(plan_data['max_comm'])),
                            is_active=True,
                            valid_from=datetime.utcnow(),
                            valid_until=datetime.utcnow() + timedelta(days=365)
                        )
                        db.session.add(commission_plan)
                        self.commission_plans.append(commission_plan)
            
            db.session.commit()
            print(f"✅ Created {len(self.commission_plans)} commission plans")
    
    def create_sample_transactions(self):
        """Create sample transactions"""
        print("💸 Creating sample transactions...")
        
        services = [
            ServiceType.MOBILE_RECHARGE,
            ServiceType.DTH_RECHARGE,
            ServiceType.BILL_PAYMENT,
            ServiceType.MONEY_TRANSFER
        ]
        
        operators = {
            ServiceType.MOBILE_RECHARGE: ['Airtel', 'Jio', 'Vi', 'BSNL'],
            ServiceType.DTH_RECHARGE: ['Tata Sky', 'Airtel Digital TV', 'Dish TV', 'Sun Direct'],
            ServiceType.BILL_PAYMENT: ['Electricity', 'Gas', 'Water', 'Broadband'],
            ServiceType.MONEY_TRANSFER: ['IMPS', 'NEFT', 'RTGS']
        }
        
        with self.app.app_context():
            # Create transactions for retailers only (they are the ones using services)
            retailers = self.users.get(UserRoleType.RETAILER, [])
            
            transaction_count = 0
            for retailer in retailers[:50]:  # Limit to first 50 retailers for demo
                # Create 5-15 transactions per retailer
                for _ in range(random.randint(5, 16)):
                    service_type = random.choice(services)
                    amount = Decimal(str(random.uniform(10, 5000)))
                    commission = amount * Decimal('0.02')  # 2% commission
                    
                    transaction = Transaction(
                        tenant_id=retailer.tenant_id,
                        user_id=retailer.id,
                        transaction_id=f"TXN{fake.uuid4()[:8].upper()}",
                        service_type=service_type,
                        amount=amount,
                        commission=commission,
                        platform_charges=amount * Decimal('0.005'),  # 0.5% platform charges
                        net_amount=amount - commission,
                        status=random.choice([TransactionStatus.SUCCESS, TransactionStatus.FAILED, TransactionStatus.PENDING]),
                        provider=random.choice(operators[service_type]),
                        customer_details={
                            'name': fake.name(),
                            'mobile': f"+91{random.randint(7000000000, 9999999999)}",
                            'email': fake.email()
                        },
                        service_details=self.generate_service_details(service_type, operators[service_type]),
                        operator_ref=f"OP{fake.uuid4()[:10].upper()}",
                        ip_address=fake.ipv4(),
                        processed_at=datetime.utcnow() - timedelta(minutes=random.randint(1, 1440))
                    )
                    db.session.add(transaction)
                    transaction_count += 1
            
            db.session.commit()
            print(f"✅ Created {transaction_count} sample transactions")
    
    def generate_service_details(self, service_type, operators):
        """Generate service-specific details"""
        operator = random.choice(operators)
        
        if service_type == ServiceType.MOBILE_RECHARGE:
            return {
                'operator': operator,
                'circle': random.choice(['Delhi', 'Mumbai', 'Kolkata', 'Chennai', 'Bangalore']),
                'mobile_number': f"{random.randint(7000000000, 9999999999)}",
                'plan_type': random.choice(['Talktime', 'Full Talktime', 'Data', 'SMS'])
            }
        elif service_type == ServiceType.DTH_RECHARGE:
            return {
                'operator': operator,
                'subscriber_id': f"DTH{random.randint(100000000, 999999999)}",
                'plan_name': f"{random.choice(['Gold', 'Silver', 'Platinum'])} Pack",
                'validity': random.choice(['30 days', '90 days', '180 days', '365 days'])
            }
        elif service_type == ServiceType.BILL_PAYMENT:
            return {
                'category': operator,
                'biller_name': f"{fake.company()} {operator}",
                'customer_number': f"{random.randint(1000000000, 9999999999)}",
                'bill_amount': random.uniform(100, 5000)
            }
        elif service_type == ServiceType.MONEY_TRANSFER:
            return {
                'transfer_mode': operator,
                'beneficiary_name': fake.name(),
                'account_number': f"{random.randint(10000000000, 99999999999)}",
                'ifsc_code': f"SBIN{random.randint(100000, 999999)}",
                'bank_name': random.choice(['SBI', 'HDFC', 'ICICI', 'Axis'])
            }
        
        return {}
    
    def create_wallet_topup_requests(self):
        """Create sample wallet topup requests"""
        print("💰 Creating wallet topup requests...")
        
        with self.app.app_context():
            # Create topup requests for various users
            all_users = []
            for role_users in self.users.values():
                all_users.extend(role_users)
            
            topup_count = 0
            for user in random.sample(all_users, min(100, len(all_users))):
                # Create 1-3 topup requests per selected user
                for _ in range(random.randint(1, 4)):
                    amount = Decimal(str(random.uniform(500, 50000)))
                    processing_fee = amount * Decimal('0.02')  # 2% processing fee
                    
                    topup_request = WalletTopupRequest(
                        request_id=f"TOP{fake.uuid4()[:10].upper()}",
                        user_id=user.id,
                        payment_gateway_id=random.choice(self.payment_gateways).id if self.payment_gateways else None,
                        selected_bank_account_id=random.choice(self.bank_accounts).id if self.bank_accounts else None,
                        topup_method=random.choice([TopupMethod.PAYMENT_GATEWAY, TopupMethod.BANK_TRANSFER, TopupMethod.ADMIN_CREDIT]),
                        amount=amount,
                        processing_fee=processing_fee,
                        net_amount=amount - processing_fee,
                        transaction_mode=random.choice([TransactionMode.UPI, TransactionMode.NET_BANKING, TransactionMode.IMPS]),
                        external_transaction_id=f"EXT{fake.uuid4()[:12].upper()}",
                        utr_number=f"UTR{random.randint(100000000000, 999999999999)}",
                        order_id=f"ORD{fake.uuid4()[:10].upper()}",
                        status=random.choice([TransactionStatus.SUCCESS, TransactionStatus.PENDING, TransactionStatus.FAILED]),
                        request_remarks=fake.text(max_nb_chars=100),
                        ip_address=fake.ipv4(),
                        processed_at=datetime.utcnow() - timedelta(hours=random.randint(1, 72)),
                        expires_at=datetime.utcnow() + timedelta(hours=24)
                    )
                    db.session.add(topup_request)
                    topup_count += 1
            
            db.session.commit()
            print(f"✅ Created {topup_count} wallet topup requests")
    
    def create_notification_templates(self):
        """Create notification templates"""
        print("📧 Creating notification templates...")
        
        templates_data = [
            {
                'template_code': 'WELCOME_EMAIL',
                'template_name': 'Welcome Email',
                'template_type': 'EMAIL',
                'subject': 'Welcome to {{platform_name}}',
                'body': '''Dear {{user_name}},

Welcome to {{platform_name}}! Your account has been created successfully.

Account Details:
- User ID: {{user_code}}
- Role: {{user_role}}
- Login URL: {{login_url}}

Please change your password after first login.

Best regards,
{{platform_name}} Team''',
                'variables': ['platform_name', 'user_name', 'user_code', 'user_role', 'login_url']
            },
            {
                'template_code': 'TRANSACTION_SUCCESS',
                'template_name': 'Transaction Success SMS',
                'template_type': 'SMS',
                'subject': '',
                'body': 'Transaction of Rs.{{amount}} completed successfully. Ref: {{transaction_id}}. Balance: Rs.{{wallet_balance}}. Thank you!',
                'variables': ['amount', 'transaction_id', 'wallet_balance']
            },
            {
                'template_code': 'TRANSACTION_FAILED',
                'template_name': 'Transaction Failed SMS',
                'template_type': 'SMS',
                'subject': '',
                'body': 'Transaction of Rs.{{amount}} failed. Ref: {{transaction_id}}. Reason: {{failure_reason}}. Contact support if needed.',
                'variables': ['amount', 'transaction_id', 'failure_reason']
            },
            {
                'template_code': 'LOW_WALLET_BALANCE',
                'template_name': 'Low Wallet Balance Alert',
                'template_type': 'EMAIL',
                'subject': 'Low Wallet Balance Alert - {{platform_name}}',
                'body': '''Dear {{user_name}},

Your wallet balance is running low: Rs.{{balance}}

Please recharge your wallet to continue using our services.

Current Balance: Rs.{{balance}}
Minimum Balance Threshold: Rs.{{threshold}}

Recharge URL: {{topup_url}}

Best regards,
{{platform_name}} Team''',
                'variables': ['user_name', 'balance', 'threshold', 'topup_url', 'platform_name']
            },
            {
                'template_code': 'WALLET_CREDITED',
                'template_name': 'Wallet Credit Notification',
                'template_type': 'SMS',
                'subject': '',
                'body': 'Your wallet has been credited with Rs.{{amount}}. New balance: Rs.{{new_balance}}. Ref: {{reference_id}}',
                'variables': ['amount', 'new_balance', 'reference_id']
            },
            {
                'template_code': 'KYC_APPROVED',
                'template_name': 'KYC Approval Notification',
                'template_type': 'EMAIL',
                'subject': 'KYC Verification Approved - {{platform_name}}',
                'body': '''Dear {{user_name}},

Congratulations! Your KYC verification has been approved.

You can now access all platform features without restrictions.

Best regards,
{{platform_name}} Team''',
                'variables': ['user_name', 'platform_name']
            }
        ]
        
        with self.app.app_context():
            for tenant in self.tenants:
                for template_data in templates_data:
                    template = NotificationTemplate(
                        tenant_id=tenant.id,
                        template_code=template_data['template_code'],
                        template_name=template_data['template_name'],
                        template_type=template_data['template_type'],
                        subject=template_data['subject'],
                        body=template_data['body'],
                        variables=template_data['variables'],
                        is_active=True
                    )
                    db.session.add(template)
            
            db.session.commit()
            print(f"✅ Created {len(templates_data) * len(self.tenants)} notification templates")
    
    def create_api_configurations(self):
        """Create API configurations for external services"""
        print("🔗 Creating API configurations...")
        
        api_configs = [
            {
                'service_type': ServiceType.MOBILE_RECHARGE,
                'provider': 'RechargeAPI Pro',
                'api_url': 'https://api.rechargeapi.com/v1/recharge',
                'priority': 1,
                'rate_limit': 1000
            },
            {
                'service_type': ServiceType.DTH_RECHARGE,
                'provider': 'DTH Services API',
                'api_url': 'https://api.dthservices.com/v2/recharge',
                'priority': 1,
                'rate_limit': 500
            },
            {
                'service_type': ServiceType.BILL_PAYMENT,
                'provider': 'BillPay Gateway',
                'api_url': 'https://api.billpay.com/v1/payment',
                'priority': 1,
                'rate_limit': 800
            },
            {
                'service_type': ServiceType.MONEY_TRANSFER,
                'provider': 'FastTransfer API',
                'api_url': 'https://api.fasttransfer.com/v1/transfer',
                'priority': 1,
                'rate_limit': 200
            },
            {
                'service_type': ServiceType.AEPS,
                'provider': 'AEPS Connect',
                'api_url': 'https://api.aepsconnect.com/v1/transaction',
                'priority': 1,
                'rate_limit': 300
            }
        ]
        
        with self.app.app_context():
            for tenant in self.tenants:
                for config_data in api_configs:
                    api_config = APIConfiguration(
                        tenant_id=tenant.id,
                        service_type=config_data['service_type'],
                        provider=config_data['provider'],
                        api_url=config_data['api_url'],
                        api_key=secrets.token_urlsafe(32),
                        api_secret=secrets.token_urlsafe(64),
                        headers={
                            'Content-Type': 'application/json',
                            'Accept': 'application/json',
                            'User-Agent': f"{tenant.tenant_name}/1.0"
                        },
                        parameters={
                            'timeout': 30,
                            'format': 'json',
                            'version': 'v1'
                        },
                        is_active=True,
                        priority=config_data['priority'],
                        rate_limit=config_data['rate_limit'],
                        timeout_seconds=30,
                        success_codes=[200, 201, 202],
                        retry_count=3
                    )
                    db.session.add(api_config)
            
            db.session.commit()
            print(f"✅ Created {len(api_configs) * len(self.tenants)} API configurations")
    
    def create_role_permissions(self):
        """Create role-based permission assignments"""
        print("🔐 Creating role permissions...")
        
        # Define permissions for each role
        role_permissions_map = {
            UserRoleType.SUPER_ADMIN: [
                'USER_CREATE', 'USER_READ', 'USER_UPDATE', 'USER_DELETE', 'USER_IMPERSONATE',
                'TRANSACTION_READ', 'TRANSACTION_PROCESS', 'TRANSACTION_REFUND', 'TRANSACTION_CANCEL',
                'WALLET_READ', 'WALLET_CREDIT', 'WALLET_DEBIT', 'WALLET_TOPUP_APPROVE', 'WALLET_FUND_DOWNLINE',
                'COMMISSION_SET', 'COMMISSION_VIEW', 'COMMISSION_PLAN_CREATE',
                'REPORT_VIEW_OWN', 'REPORT_VIEW_DOWNLINE', 'REPORT_VIEW_GLOBAL', 'REPORT_EXPORT',
                'SERVICE_USE', 'SERVICE_CONFIGURE', 'SERVICE_API_ACCESS',
                'SYSTEM_CONFIG', 'BANK_ACCOUNT_MANAGE', 'PAYMENT_GATEWAY_MANAGE', 'TENANT_MANAGE',
                'DOMAIN_MANAGE', 'BRANDING_MANAGE', 'AUDIT_VIEW', 'KYC_VERIFY'
            ],
            UserRoleType.ADMIN: [
                'USER_CREATE', 'USER_READ', 'USER_UPDATE', 'USER_DELETE',
                'TRANSACTION_READ', 'TRANSACTION_PROCESS', 'TRANSACTION_REFUND',
                'WALLET_READ', 'WALLET_CREDIT', 'WALLET_DEBIT', 'WALLET_TOPUP_APPROVE', 'WALLET_FUND_DOWNLINE',
                'COMMISSION_SET', 'COMMISSION_VIEW', 'COMMISSION_PLAN_CREATE',
                'REPORT_VIEW_OWN', 'REPORT_VIEW_DOWNLINE', 'REPORT_EXPORT',
                'SERVICE_CONFIGURE', 'SERVICE_API_ACCESS',
                'BANK_ACCOUNT_MANAGE', 'PAYMENT_GATEWAY_MANAGE',
                'DOMAIN_MANAGE', 'BRANDING_MANAGE', 'KYC_VERIFY'
            ],
            UserRoleType.WHITE_LABEL: [
                'USER_CREATE', 'USER_READ', 'USER_UPDATE',
                'TRANSACTION_READ', 'WALLET_READ', 'WALLET_CREDIT', 'WALLET_TOPUP_APPROVE', 'WALLET_FUND_DOWNLINE',
                'COMMISSION_SET', 'COMMISSION_VIEW',
                'REPORT_VIEW_OWN', 'REPORT_VIEW_DOWNLINE', 'REPORT_EXPORT',
                'SERVICE_API_ACCESS', 'DOMAIN_MANAGE', 'BRANDING_MANAGE'
            ],
            UserRoleType.MASTER_DISTRIBUTOR: [
                'USER_CREATE', 'USER_READ', 'USER_UPDATE',
                'TRANSACTION_READ', 'WALLET_READ', 'WALLET_FUND_DOWNLINE',
                'COMMISSION_VIEW', 'REPORT_VIEW_OWN', 'REPORT_VIEW_DOWNLINE', 'SERVICE_USE'
            ],
            UserRoleType.DISTRIBUTOR: [
                'USER_CREATE', 'USER_READ', 'USER_UPDATE',
                'TRANSACTION_READ', 'WALLET_READ', 'WALLET_FUND_DOWNLINE',
                'COMMISSION_VIEW', 'REPORT_VIEW_OWN', 'REPORT_VIEW_DOWNLINE', 'SERVICE_USE'
            ],
            UserRoleType.RETAILER: [
                'TRANSACTION_READ', 'WALLET_READ', 'COMMISSION_VIEW', 'REPORT_VIEW_OWN', 'SERVICE_USE'
            ]
        }
        
        with self.app.app_context():
            # Get all permissions
            permissions = {p.name: p for p in Permission.query.all()}
            
            for tenant in self.tenants:
                for role, permission_names in role_permissions_map.items():
                    for perm_name in permission_names:
                        if perm_name in permissions:
                            role_permission = RolePermission(
                                role=role,
                                permission_id=permissions[perm_name].id,
                                tenant_id=tenant.id,
                                is_granted=True
                            )
                            db.session.add(role_permission)
            
            db.session.commit()
            print("✅ Created role-based permissions")
    
    def create_audit_logs(self):
        """Create sample audit logs"""
        print("📝 Creating audit logs...")
        
        actions = [
            'USER_CREATED', 'USER_UPDATED', 'USER_DELETED', 'USER_LOGIN', 'USER_LOGOUT',
            'TRANSACTION_CREATED', 'TRANSACTION_UPDATED', 'WALLET_CREDITED', 'WALLET_DEBITED',
            'COMMISSION_UPDATED', 'PAYMENT_GATEWAY_CONFIGURED', 'BANK_ACCOUNT_ADDED'
        ]
        
        resource_types = ['USER', 'TRANSACTION', 'WALLET', 'COMMISSION', 'PAYMENT_GATEWAY', 'BANK_ACCOUNT']
        
        with self.app.app_context():
            audit_count = 0
            for tenant in self.tenants:
                tenant_users = [u for users in self.users.values() for u in users if u.tenant_id == tenant.id]
                
                # Create 50-100 audit logs per tenant
                for _ in range(random.randint(50, 101)):
                    user = random.choice(tenant_users)
                    
                    audit_log = AuditLog(
                        tenant_id=tenant.id,
                        user_id=user.id,
                        action=random.choice(actions),
                        resource_type=random.choice(resource_types),
                        resource_id=uuid.uuid4(),
                        old_values={'previous_value': fake.word()},
                        new_values={'new_value': fake.word()},
                        ip_address=fake.ipv4(),
                        user_agent=fake.user_agent(),
                        session_id=uuid.uuid4(),
                        severity=random.choice(['INFO', 'WARNING', 'ERROR']),
                        description=fake.sentence(),
                        created_at=datetime.utcnow() - timedelta(days=random.randint(0, 30))
                    )
                    db.session.add(audit_log)
                    audit_count += 1
            
            db.session.commit()
            print(f"✅ Created {audit_count} audit logs")
    
    def run_complete_seed(self, clear_existing=False):
        """Run the complete database seeding process"""
        print("🚀 Starting database seeding process...")
        print("=" * 60)
        
        if clear_existing:
            print("🧹 Clearing existing data...")
            self.clear_all_data()
        
        try:
            # Core data
            self.create_permissions()
            self.create_tenants()
            
            # Only create users if no existing users found
            with self.app.app_context():
                existing_users_count = User.query.count()
                if existing_users_count == 0 or clear_existing:
                    self.create_users()
                else:
                    print(f"⏭️  Skipping user creation ({existing_users_count} users already exist)")
                    # Load existing users for other operations
                    for role in UserRoleType:
                        users = User.query.filter_by(role=role).all()
                        self.users[role] = users
            
            # Financial setup
            self.create_payment_gateways()
            self.create_bank_accounts()
            self.create_commission_plans()
            
            # Operational data (only if we have users)
            if any(self.users.values()):
                self.create_sample_transactions()
                self.create_wallet_topup_requests()
            
            # System configuration
            self.create_notification_templates()
            self.create_api_configurations()
            self.create_role_permissions()
            self.create_audit_logs()
            
            print("=" * 60)
            print("✅ Database seeding completed successfully!")
            self.print_summary()
            
        except Exception as e:
            print(f"❌ Error during seeding: {e}")
            raise
    
    def print_summary(self):
        """Print a summary of created data"""
        with self.app.app_context():
            print("\n📊 SEEDING SUMMARY")
            print("=" * 40)
            
            # Count records
            print(f"🏢 Tenants: {Tenant.query.count()}")
            print(f"👥 Users: {User.query.count()}")
            for role in UserRoleType:
                count = User.query.filter_by(role=role).count()
                print(f"   • {role.value}: {count}")
            
            print(f"💳 Payment Gateways: {PaymentGateway.query.count()}")
            print(f"🏦 Bank Accounts: {OrganizationBankAccount.query.count()}")
            print(f"💰 Commission Plans: {CommissionPlan.query.count()}")
            print(f"💸 Transactions: {Transaction.query.count()}")
            print(f"💵 Wallet Topups: {WalletTopupRequest.query.count()}")
            print(f"📧 Notification Templates: {NotificationTemplate.query.count()}")
            print(f"🔗 API Configurations: {APIConfiguration.query.count()}")
            print(f"🔐 Permissions: {Permission.query.count()}")
            print(f"📝 Audit Logs: {AuditLog.query.count()}")
            
            print("\n🔑 SAMPLE LOGIN CREDENTIALS")
            print("=" * 40)
            print("Username: sa0001 | Password: password123 | Role: Super Admin")
            print("Username: ad0001 | Password: password123 | Role: Admin")
            print("Username: wl0001 | Password: password123 | Role: White Label")
            print("Username: md0001 | Password: password123 | Role: Master Distributor")
            print("Username: ds0001 | Password: password123 | Role: Distributor")
            print("Username: rt0001 | Password: password123 | Role: Retailer")
            
            print(f"\n💡 Database URL: {self.database_url}")
            print("📄 All users have default password: password123")
            print("📧 Email verification may be required based on settings")


def main():
    """Main function to run the seeder"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Seed database with sample data')
    parser.add_argument('--database-url', help='Database URL (default: PostgreSQL localhost)')
    parser.add_argument('--clear', action='store_true', help='Clear existing data before seeding')
    parser.add_argument('--create-tables', action='store_true', help='Create database tables')
    
    args = parser.parse_args()
    
    # Create Flask app
    app = Flask(__name__)
    
    # Database URL priority: CLI arg > Environment > Default
    database_url = (
        args.database_url or 
        os.getenv('DATABASE_URL') or 
        'postgresql://postgres:1234@localhost:5432/saas_platform'
    )
    
    print(f"🔗 Using database: {database_url}")
    print(f"🔍 Environment DATABASE_URL: {os.getenv('DATABASE_URL', 'Not set')}")
    
    # Initialize seeder
    seeder = DatabaseSeeder(app, database_url)
    
    with app.app_context():
        try:
            if args.create_tables:
                seeder.create_tables()
            
            # Run seeding
            seeder.run_complete_seed(clear_existing=args.clear)
            
        except Exception as e:
            print(f"💥 Seeding failed: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)


if __name__ == "__main__":
    main()