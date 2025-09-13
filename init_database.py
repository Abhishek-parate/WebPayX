# init_database.py - Database Initialization Script
import os
from flask import Flask
from models import db, User, UserSession, Tenant, create_tables, create_default_permissions

def init_database_app():
    """Initialize database with proper Flask app context"""
    app = Flask(__name__)
    
    # Use PostgreSQL configuration
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:@localhost/saas_platform'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = 'temp-key-for-init'
    
    # Initialize extensions FIRST
    db.init_app(app)
    
    # Use app context for all database operations
    with app.app_context():
        try:
            print("🔄 Initializing database...")
            
            # Create tables
            create_tables(db.engine)
            print("✅ Database tables created/verified")
            
            # NOW you can safely query models
            default_tenant = Tenant.query.filter_by(tenant_code='DEFAULT').first()
            if not default_tenant:
                default_tenant = Tenant(
                    tenant_code='DEFAULT',
                    tenant_name='Default Organization',
                    domain='localhost',
                    subdomain='default',
                    is_active=True,
                    theme_config={
                        'primary_color': '#3B82F6',
                        'secondary_color': '#6B7280',
                        'logo_url': '/static/assets/images/logo.png'
                    }
                )
                db.session.add(default_tenant)
                db.session.commit()
                print("✅ Default tenant created")
            else:
                print("✅ Default tenant already exists")
            
            # Create default permissions
            from models import Permission
            if not Permission.query.first():
                default_permissions = create_default_permissions()
                for permission in default_permissions:
                    db.session.add(permission)
                db.session.commit()
                print("✅ Default permissions created")
            else:
                print("✅ Default permissions already exist")
            
            # Create default super admin if not exists
            from models import UserRoleType
            super_admin = User.query.filter_by(
                tenant_id=default_tenant.id,
                role=UserRoleType.SUPER_ADMIN
            ).first()
            
            if not super_admin:
                from models import Wallet, KYCStatus
                
                super_admin = User(
                    tenant_id=default_tenant.id,
                    user_code='SA000001',
                    username='superadmin',
                    email='admin@example.com',
                    phone='9860303985',
                    role=UserRoleType.SUPER_ADMIN,
                    full_name='Super Administrator',
                    kyc_status=KYCStatus.APPROVED,
                    is_active=True,
                    is_verified=True,
                    email_verified=True,
                    phone_verified=True,
                    tree_path='SA000001',
                    level=0
                )
                super_admin.set_password('Admin@123')
                super_admin.generate_api_key()
                
                db.session.add(super_admin)
                db.session.flush()
                
                # Create wallet for super admin
                admin_wallet = Wallet(
                    user_id=super_admin.id,
                    balance=100000,
                    daily_limit=1000000,
                    monthly_limit=10000000
                )
                db.session.add(admin_wallet)
                db.session.commit()
                
                print("✅ Default super admin created:")
                print(f"   Username: superadmin")
                print(f"   Password: Admin@123")
                print(f"   Email: admin@example.com")
            else:
                print("✅ Super admin already exists")
            
            print("🎉 Database initialization completed successfully!")
            
        except Exception as e:
            print(f"❌ Database initialization error: {e}")
            db.session.rollback()
            raise

if __name__ == '__main__':
    init_database_app()
