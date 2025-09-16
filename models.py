"""
SaaS Multi-Tenant Financial Services Platform - SQLAlchemy Models
================================================================

This module contains all SQLAlchemy models that correspond to the database schema.
The models are designed to be compatible with both PostgreSQL (production) and SQLite (development).

Author: abhishek parate
Created: 2025
"""
# /models.py

from datetime import datetime, timedelta
from decimal import Decimal
from enum import Enum as PyEnum
import uuid
import secrets
from typing import Optional, Dict, Any

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import (
    Column, String, Integer, DateTime, Boolean, Text, DECIMAL, 
    ForeignKey, JSON, Enum, Date, BigInteger, Index, UniqueConstraint
)
from sqlalchemy.orm import relationship, backref
from sqlalchemy.sql import func
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.types import TypeDecorator, VARCHAR
from werkzeug.security import generate_password_hash, check_password_hash



# =============================================================================
# CRITICAL FIX: Create and export the db instance
# =============================================================================
db = SQLAlchemy()

# PostgreSQL-specific imports with fallbacks
try:
    from sqlalchemy.dialects.postgresql import UUID, ARRAY, INET
    HAS_POSTGRESQL = True
except ImportError:
    from sqlalchemy import String as UUID, String as ARRAY, String as INET
    HAS_POSTGRESQL = False

# =============================================================================
# CUSTOM TYPES FOR CROSS-DATABASE COMPATIBILITY
# =============================================================================

class GUID(TypeDecorator):
    """Platform-independent GUID type."""
    impl = VARCHAR
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == 'postgresql':
            return dialect.type_descriptor(UUID(as_uuid=True))
        else:
            return dialect.type_descriptor(VARCHAR(36))

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        elif dialect.name == 'postgresql':
            return str(value)
        else:
            return str(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        else:
            if not isinstance(value, uuid.UUID):
                return uuid.UUID(value)
            return value

class JSONType(TypeDecorator):
    """Platform-independent JSON type."""
    impl = Text
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == 'postgresql':
            return dialect.type_descriptor(JSON())
        else:
            return dialect.type_descriptor(Text())

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        if dialect.name == 'postgresql':
            return value
        else:
            import json
            return json.dumps(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        if dialect.name == 'postgresql':
            return value
        else:
            import json
            return json.loads(value)

class ArrayType(TypeDecorator):
    """Platform-independent Array type."""
    impl = Text
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == 'postgresql':
            return dialect.type_descriptor(ARRAY(String))
        else:
            return dialect.type_descriptor(Text())

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        if dialect.name == 'postgresql':
            return value
        else:
            import json
            return json.dumps(value if value else [])

    def process_result_value(self, value, dialect):
        if value is None:
            return []
        if dialect.name == 'postgresql':
            return value if value else []
        else:
            import json
            return json.loads(value) if value else []

class IPAddressType(TypeDecorator):
    """Platform-independent IP address type."""
    impl = VARCHAR
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == 'postgresql':
            return dialect.type_descriptor(INET())
        else:
            return dialect.type_descriptor(VARCHAR(45))  # Supports IPv6

# =============================================================================
# ENUMS - Python Enums corresponding to database custom types
# =============================================================================

class UserRoleType(PyEnum):
    """User role hierarchy for the platform"""
    SUPER_ADMIN = "SUPER_ADMIN"
    ADMIN = "ADMIN"
    WHITE_LABEL = "WHITE_LABEL"
    MASTER_DISTRIBUTOR = "MASTER_DISTRIBUTOR"
    DISTRIBUTOR = "DISTRIBUTOR"
    RETAILER = "RETAILER"

class TransactionStatus(PyEnum):
    """Transaction status types"""
    PENDING = "PENDING"
    PROCESSING = "PROCESSING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    REFUNDED = "REFUNDED"
    DISPUTED = "DISPUTED"

class ServiceType(PyEnum):
    """Available service types in the platform"""
    MOBILE_RECHARGE = "MOBILE_RECHARGE"
    DTH_RECHARGE = "DTH_RECHARGE"
    BILL_PAYMENT = "BILL_PAYMENT"
    MONEY_TRANSFER = "MONEY_TRANSFER"
    AEPS = "AEPS"
    PAYMENT_GATEWAY = "PAYMENT_GATEWAY"
    WALLET_TOPUP = "WALLET_TOPUP"
    SMS_SERVICE = "SMS_SERVICE"  # Add this line
    OTP_SERVICE = "OTP_SERVICE"  # Add this line too for OTP-specific APIs
    SMS_API = "SMS_API"  # Add this for SMS services


class TransactionMode(PyEnum):
    """Transaction mode types"""
    IMPS = "IMPS"
    NEFT = "NEFT"
    RTGS = "RTGS"
    UPI = "UPI"
    CASH = "CASH"
    WALLET = "WALLET"
    CARD = "CARD"
    NET_BANKING = "NET_BANKING"
    BANK_TRANSFER = "BANK_TRANSFER"

class KYCStatus(PyEnum):
    """KYC verification status"""
    NOT_SUBMITTED = "NOT_SUBMITTED"
    PENDING = "PENDING"
    UNDER_REVIEW = "UNDER_REVIEW"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"

class CommissionMode(PyEnum):
    """Commission calculation modes"""
    PERCENTAGE = "PERCENTAGE"
    FLAT = "FLAT"
    SLAB_BASED = "SLAB_BASED"
    VOLUME_BASED = "VOLUME_BASED"

class WalletTransactionType(PyEnum):
    """Wallet transaction types"""
    CREDIT = "CREDIT"
    DEBIT = "DEBIT"
    HOLD = "HOLD"
    RELEASE = "RELEASE"
    REFUND = "REFUND"

class PaymentGatewayType(PyEnum):
    """Supported payment gateways"""
    RAZORPAY = "RAZORPAY"
    PAYU = "PAYU"
    PAYTM = "PAYTM"
    PHONEPE = "PHONEPE"
    CASHFREE = "CASHFREE"
    INSTAMOJO = "INSTAMOJO"
    CCAVENUE = "CCAvenue"
    STRIPE = "STRIPE"
    PAYPAL = "PAYPAL"
    UPI_GATEWAY = "UPI_GATEWAY"
    BANK_TRANSFER = "BANK_TRANSFER"

class TopupMethod(PyEnum):
    """Wallet top-up methods"""
    MANUAL_REQUEST = "MANUAL_REQUEST"
    PAYMENT_GATEWAY = "PAYMENT_GATEWAY"
    ADMIN_CREDIT = "ADMIN_CREDIT"
    BANK_TRANSFER = "BANK_TRANSFER"
    CASH_DEPOSIT = "CASH_DEPOSIT"
    API_INTEGRATION = "API_INTEGRATION"

class BankAccountType(PyEnum):
    """Bank account types"""
    CURRENT = "CURRENT"
    SAVINGS = "SAVINGS"
    ESCROW = "ESCROW"
    SETTLEMENT = "SETTLEMENT"
    COLLECTION = "COLLECTION"
    OPERATING = "OPERATING"

class AccountPurpose(PyEnum):
    """Bank account usage purposes"""
    WALLET_TOPUP = "WALLET_TOPUP"
    SETTLEMENT = "SETTLEMENT"
    REFUND = "REFUND"
    COMMISSION_PAYOUT = "COMMISSION_PAYOUT"
    VENDOR_PAYMENT = "VENDOR_PAYMENT"
    GENERAL = "GENERAL"

class BankAccountStatus(PyEnum):
    """Bank account status"""
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    SUSPENDED = "SUSPENDED"
    CLOSED = "CLOSED"
    UNDER_VERIFICATION = "UNDER_VERIFICATION"

# Add these new enums to your existing enums section in models.py
class OTPType(PyEnum):
    """OTP types"""
    LOGIN = "LOGIN"
    REGISTRATION = "REGISTRATION"
    PASSWORD_RESET = "PASSWORD_RESET"
    PHONE_VERIFICATION = "PHONE_VERIFICATION"
    TRANSACTION = "TRANSACTION"

class OTPStatus(PyEnum):
    """OTP status"""
    PENDING = "PENDING"
    VERIFIED = "VERIFIED"
    EXPIRED = "EXPIRED"
    FAILED = "FAILED"


# =============================================================================
# BASE MODEL CLASS WITH COMMON FIELDS - UPDATED TO USE db.Model
# =============================================================================

class BaseModel(db.Model):
    """Base model class with common fields and methods"""
    __abstract__ = True
    
    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        """Convert model instance to dictionary"""
        result = {}
        for column in self.__table__.columns:
            value = getattr(self, column.name)
            if isinstance(value, datetime):
                result[column.name] = value.isoformat()
            elif isinstance(value, Decimal):
                result[column.name] = float(value)
            elif isinstance(value, uuid.UUID):
                result[column.name] = str(value)
            elif isinstance(value, PyEnum):
                result[column.name] = value.value
            else:
                result[column.name] = value
        return result
    
    def update_from_dict(self, data):
        """Update model instance from dictionary"""
        for key, value in data.items():
            if hasattr(self, key) and key not in ['id', 'created_at']:
                setattr(self, key, value)

# =============================================================================
# TENANT MANAGEMENT MODELS
# =============================================================================

class Tenant(BaseModel):
    """White label tenant organizations"""
    __tablename__ = 'tenants'
    
    tenant_code = Column(String(50), unique=True, nullable=False, index=True)
    tenant_name = Column(String(255), nullable=False)
    domain = Column(String(255), unique=True, index=True)
    subdomain = Column(String(100), unique=True, index=True)
    logo_url = Column(Text)
    theme_config = Column(JSONType, default={})
    is_active = Column(Boolean, default=True, index=True)
    subscription_plan = Column(String(100))
    subscription_expires_at = Column(DateTime)
    api_settings = Column(JSONType, default={})
    rate_limits = Column(JSONType, default={})
    created_by = Column(GUID(), db.ForeignKey('users.id'))
    meta_data = Column(JSONType, default={})
    
    def __repr__(self):
        return f"<Tenant(code='{self.tenant_code}', name='{self.tenant_name}')>"
    
    @property
    def is_subscription_active(self):
        """Check if subscription is still active"""
        if not self.subscription_expires_at:
            return True
        return datetime.utcnow() < self.subscription_expires_at

# =============================================================================
# USER MANAGEMENT MODELS
# =============================================================================

class User(BaseModel):
    """Hierarchical user management with role-based access"""
    __tablename__ = 'users'
    
    tenant_id = Column(GUID(), db.ForeignKey('tenants.id'), nullable=False, index=True)
    parent_id = Column(GUID(), db.ForeignKey('users.id'), index=True)
    user_code = Column(String(50), unique=True, nullable=False, index=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, index=True)
    phone = Column(String(20), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(db.Enum(UserRoleType), nullable=False, index=True)
    full_name = Column(String(255), nullable=False)
    business_name = Column(String(255))
    address = Column(JSONType, default={})
    kyc_status = Column(db.Enum(KYCStatus), default=KYCStatus.NOT_SUBMITTED, index=True)
    kyc_data = Column(JSONType, default={})
    is_active = Column(Boolean, default=True, index=True)
    is_verified = Column(Boolean, default=False)
    email_verified = Column(Boolean, default=False)
    phone_verified = Column(Boolean, default=False)
    last_login = Column(DateTime)
    login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime)
    two_factor_enabled = Column(Boolean, default=False)
    two_factor_secret = Column(String(255))
    api_key = Column(String(255), unique=True, index=True)
    api_secret = Column(String(255))
    tree_path = Column(String(500), index=True)
    level = Column(Integer, default=0)
    settings = Column(JSONType, default={})
    meta_data = Column(JSONType, default={})
    created_by = Column(GUID(), db.ForeignKey('users.id'))
    
    def __repr__(self):
        return f"<User(code='{self.user_code}', name='{self.full_name}', role='{self.role.value if self.role else None}')>"
    
    def set_password(self, password):
        """Set password hash"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check if provided password matches hash"""
        return check_password_hash(self.password_hash, password)
    
    def generate_api_key(self):
        """Generate API key and secret"""
        self.api_key = secrets.token_urlsafe(32)
        self.api_secret = secrets.token_urlsafe(64)
    
    @property
    def is_locked(self):
        """Check if user account is locked"""
        return self.locked_until and datetime.utcnow() < self.locked_until
    
    def can_access_user(self, target_user):
        """Check if this user can access target user (hierarchy check)"""
        if self.id == target_user.id:
            return True
        return target_user.tree_path and str(self.id) in target_user.tree_path

    # Flask-Login integration
    def is_authenticated(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

class UserSession(BaseModel):
    """User session management"""
    __tablename__ = 'user_sessions'
    
    user_id = Column(GUID(), db.ForeignKey('users.id'), nullable=False, index=True)
    session_token = Column(String(255), unique=True, nullable=False, index=True)
    refresh_token = Column(String(255), unique=True)
    ip_address = Column(IPAddressType)
    user_agent = Column(Text)
    device_info = Column(JSONType, default={})
    expires_at = Column(DateTime, nullable=False, index=True)
    is_active = Column(Boolean, default=True)
    last_accessed = Column(DateTime, default=datetime.utcnow)
    
    @property
    def is_expired(self):
        """Check if session is expired"""
        return datetime.utcnow() > self.expires_at

# =============================================================================
# WALLET MANAGEMENT MODELS
# =============================================================================

class Wallet(BaseModel):
    """User wallet management"""
    __tablename__ = 'wallets'
    
    user_id = Column(GUID(), db.ForeignKey('users.id'), unique=True, nullable=False)
    balance = Column(DECIMAL(15, 4), default=0, nullable=False)
    hold_balance = Column(DECIMAL(15, 4), default=0, nullable=False)
    total_credited = Column(DECIMAL(15, 4), default=0)
    total_debited = Column(DECIMAL(15, 4), default=0)
    last_transaction_at = Column(DateTime)
    is_active = Column(Boolean, default=True, index=True)
    daily_limit = Column(DECIMAL(15, 4), default=50000)
    monthly_limit = Column(DECIMAL(15, 4), default=200000)
    daily_used = Column(DECIMAL(15, 4), default=0)
    monthly_used = Column(DECIMAL(15, 4), default=0)
    last_limit_reset = Column(DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f"<Wallet(user_id='{self.user_id}', balance='{self.balance}')>"
    
    @property
    def available_balance(self):
        """Available balance (total - hold)"""
        return self.balance - self.hold_balance
    
    @property
    def daily_remaining(self):
        """Remaining daily limit"""
        return self.daily_limit - self.daily_used
    
    @property
    def monthly_remaining(self):
        """Remaining monthly limit"""
        return self.monthly_limit - self.monthly_used

class WalletTransaction(BaseModel):
    """Detailed wallet transaction ledger"""
    __tablename__ = 'wallet_transactions'
    
    wallet_id = Column(GUID(), db.ForeignKey('wallets.id'), nullable=False, index=True)
    transaction_type = Column(db.Enum(WalletTransactionType), nullable=False, index=True)
    amount = Column(DECIMAL(15, 4), nullable=False)
    balance_before = Column(DECIMAL(15, 4), nullable=False)
    balance_after = Column(DECIMAL(15, 4), nullable=False)
    reference_id = Column(GUID(), index=True)
    reference_type = Column(String(50), index=True)
    description = Column(Text)
    meta_data = Column(JSONType, default={})
    processed_by = Column(GUID(), db.ForeignKey('users.id'))

# =============================================================================
# PAYMENT GATEWAY MODELS
# =============================================================================

class PaymentGateway(BaseModel):
    """Payment gateway configurations"""
    __tablename__ = 'payment_gateways'
    
    tenant_id = Column(GUID(), db.ForeignKey('tenants.id'), nullable=False, index=True)
    gateway_type = Column(db.Enum(PaymentGatewayType), nullable=False)
    gateway_name = Column(String(255), nullable=False)
    merchant_id = Column(String(255), nullable=False)
    api_key = Column(String(500), nullable=False)
    api_secret = Column(String(500), nullable=False)
    webhook_secret = Column(String(500))
    callback_url = Column(Text)
    webhook_url = Column(Text)
    sandbox_mode = Column(Boolean, default=True)
    status = Column(String(20), default='ACTIVE')
    priority = Column(Integer, default=1)
    min_amount = Column(DECIMAL(10, 2), default=1.00)
    max_amount = Column(DECIMAL(10, 2), default=100000.00)
    processing_fee_percentage = Column(DECIMAL(5, 4), default=0)
    processing_fee_fixed = Column(DECIMAL(10, 2), default=0)
    settlement_time_hours = Column(Integer, default=24)
    supported_methods = Column(JSONType, default=[])
    gateway_config = Column(JSONType, default={})
    rate_limit_per_minute = Column(Integer, default=100)
    auto_settlement = Column(Boolean, default=True)
    is_default = Column(Boolean, default=False)
    created_by = Column(GUID(), db.ForeignKey('users.id'))

# =============================================================================
# BANK ACCOUNT MANAGEMENT MODELS
# =============================================================================

class OrganizationBankAccount(BaseModel):
    """Organization bank accounts for multi-bank support"""
    __tablename__ = 'organization_bank_accounts'
    
    tenant_id = Column(GUID(), db.ForeignKey('tenants.id'), nullable=False, index=True)
    user_id = Column(GUID(), db.ForeignKey('users.id'))
    account_code = Column(String(50), unique=True, nullable=False)
    account_name = Column(String(255), nullable=False)
    account_number = Column(String(50), nullable=False)
    ifsc_code = Column(String(11), nullable=False)
    bank_name = Column(String(255), nullable=False)
    branch_name = Column(String(255))
    branch_address = Column(Text)
    account_type = Column(db.Enum(BankAccountType), nullable=False, default=BankAccountType.CURRENT)
    account_holder_name = Column(String(255), nullable=False)
    pan_number = Column(String(10))
    gstin = Column(String(15))
    status = Column(db.Enum(BankAccountStatus), default=BankAccountStatus.ACTIVE)
    purpose = Column(ArrayType, default=[AccountPurpose.GENERAL.value])
    is_primary = Column(Boolean, default=False)
    is_default_topup = Column(Boolean, default=False)
    is_default_settlement = Column(Boolean, default=False)
    is_default_refund = Column(Boolean, default=False)
    priority = Column(Integer, default=1)
    daily_limit = Column(DECIMAL(15, 4), default=500000.00)
    monthly_limit = Column(DECIMAL(15, 4), default=10000000.00)
    daily_used = Column(DECIMAL(15, 4), default=0)
    monthly_used = Column(DECIMAL(15, 4), default=0)
    minimum_balance = Column(DECIMAL(15, 4), default=10000.00)
    current_balance = Column(DECIMAL(15, 4), default=0)
    last_statement_date = Column(Date)
    upi_id = Column(String(100))
    upi_qr_code = Column(Text)
    virtual_account_number = Column(String(50))
    razor_contact_id = Column(String(100))
    razor_fund_account_id = Column(String(100))
    bank_charges = Column(JSONType, default={})
    auto_settlement = Column(Boolean, default=False)
    settlement_schedule = Column(String(50), default='DAILY')
    webhook_url = Column(Text)
    api_integration = Column(JSONType, default={})
    verification_status = Column(String(50), default='PENDING')
    verification_date = Column(DateTime)
    verification_documents = Column(JSONType, default={})
    is_visible_to_users = Column(Boolean, default=True)
    display_order = Column(Integer, default=1)
    additional_info = Column(JSONType, default={})
    created_by = Column(GUID(), db.ForeignKey('users.id'))
    last_updated_by = Column(GUID(), db.ForeignKey('users.id'))

class UserBankPreference(BaseModel):
    """User-specific bank account preferences"""
    __tablename__ = 'user_bank_preferences'
    
    user_id = Column(GUID(), db.ForeignKey('users.id'), nullable=False)
    bank_account_id = Column(GUID(), db.ForeignKey('organization_bank_accounts.id'), nullable=False)
    is_favorite = Column(Boolean, default=False)
    usage_count = Column(Integer, default=0)
    last_used = Column(DateTime)
    notes = Column(Text)
    
    __table_args__ = (UniqueConstraint('user_id', 'bank_account_id'),)

# =============================================================================
# WALLET TOP-UP MODELS
# =============================================================================

class WalletTopupRequest(BaseModel):
    """Enhanced wallet top-up requests"""
    __tablename__ = 'wallet_topup_requests'
    
    request_id = Column(String(100), unique=True, nullable=False, index=True)
    user_id = Column(GUID(), db.ForeignKey('users.id'), nullable=False, index=True)
    requested_by = Column(GUID(), db.ForeignKey('users.id'), index=True)
    approved_by = Column(GUID(), db.ForeignKey('users.id'))
    payment_gateway_id = Column(GUID(), db.ForeignKey('payment_gateways.id'), index=True)
    selected_bank_account_id = Column(GUID(), db.ForeignKey('organization_bank_accounts.id'))
    topup_method = Column(db.Enum(TopupMethod), nullable=False, default=TopupMethod.MANUAL_REQUEST)
    amount = Column(DECIMAL(15, 4), nullable=False)
    processing_fee = Column(DECIMAL(10, 4), default=0)
    net_amount = Column(DECIMAL(15, 4), nullable=False)
    transaction_mode = Column(db.Enum(TransactionMode))
    external_transaction_id = Column(String(255), index=True)
    bank_reference = Column(String(255))
    upi_ref = Column(String(255))
    utr_number = Column(String(100))
    order_id = Column(String(255), index=True)
    status = Column(db.Enum(TransactionStatus), default=TransactionStatus.PENDING, index=True)
    gateway_status = Column(String(100))
    gateway_response = Column(JSONType, default={})
    payment_method = Column(String(100))
    payment_details = Column(JSONType, default={})
    request_remarks = Column(Text)
    admin_remarks = Column(Text)
    failure_reason = Column(Text)
    proof_document = Column(Text)
    receipt_url = Column(Text)
    refund_id = Column(String(255))
    agent_account = Column(JSONType, default={})
    self_account = Column(JSONType, default={})
    expected_deposit_info = Column(JSONType, default={})
    ip_address = Column(IPAddressType)
    device_info = Column(JSONType, default={})
    callback_received = Column(Boolean, default=False)
    webhook_received = Column(Boolean, default=False)
    auto_approved = Column(Boolean, default=False)
    retry_count = Column(Integer, default=0)
    expires_at = Column(DateTime)
    processed_at = Column(DateTime)
    settled_at = Column(DateTime)
    meta_data = Column(JSONType, default={})
    
    def __repr__(self):
        return f"<WalletTopupRequest(id='{self.request_id}', amount='{self.amount}', status='{self.status.value if self.status else None}')>"
    
    @property
    def is_expired(self):
        """Check if topup request is expired"""
        return self.expires_at and datetime.utcnow() > self.expires_at

# =============================================================================
# TRANSACTION MODELS
# =============================================================================

class Transaction(BaseModel):
    """Core transaction processing"""
    __tablename__ = 'transactions'
    
    tenant_id = Column(GUID(), db.ForeignKey('tenants.id'), nullable=False, index=True)
    user_id = Column(GUID(), db.ForeignKey('users.id'), nullable=False, index=True)
    transaction_id = Column(String(100), unique=True, nullable=False, index=True)
    service_type = Column(db.Enum(ServiceType), nullable=False, index=True)
    amount = Column(DECIMAL(15, 4), nullable=False)
    commission = Column(DECIMAL(10, 4), default=0)
    platform_charges = Column(DECIMAL(10, 4), default=0)
    net_amount = Column(DECIMAL(15, 4), nullable=False)
    status = Column(db.Enum(TransactionStatus), default=TransactionStatus.PENDING, index=True)
    provider = Column(String(100), index=True)
    provider_response = Column(JSONType, default={})
    customer_details = Column(JSONType, nullable=False)
    service_details = Column(JSONType, nullable=False)
    operator_ref = Column(String(255))
    utr_number = Column(String(100))
    failure_reason = Column(Text)
    admin_remarks = Column(Text)
    ip_address = Column(IPAddressType)
    device_info = Column(JSONType, default={})
    retry_count = Column(Integer, default=0)
    processed_at = Column(DateTime)
    callback_url = Column(Text)
    webhook_sent = Column(Boolean, default=False)
    webhook_response = Column(JSONType, default={})
    meta_data = Column(JSONType, default={})

class CommissionDistribution(BaseModel):
    """Commission distribution across user hierarchy"""
    __tablename__ = 'commission_distributions'
    
    transaction_id = Column(GUID(), db.ForeignKey('transactions.id'), nullable=False, index=True)
    user_id = Column(GUID(), db.ForeignKey('users.id'), nullable=False, index=True)
    user_level = Column(Integer, nullable=False)
    commission_rate = Column(DECIMAL(10, 4), nullable=False)
    commission_amount = Column(DECIMAL(10, 4), nullable=False)
    commission_type = Column(String(50), default='STANDARD')
    is_settled = Column(Boolean, default=False, index=True)
    settled_at = Column(DateTime)
    meta_data = Column(JSONType, default={})

# =============================================================================
# SERVICE-SPECIFIC MODELS
# =============================================================================

class RechargeTransaction(BaseModel):
    """Mobile/DTH recharge specific details"""
    __tablename__ = 'recharge_transactions'
    
    transaction_id = Column(GUID(), db.ForeignKey('transactions.id'), nullable=False)
    operator_name = Column(String(100), nullable=False, index=True)
    circle = Column(String(100))
    mobile_number = Column(String(15), nullable=False, index=True)
    plan_id = Column(String(100))
    plan_description = Column(Text)
    validity = Column(String(50))
    talktime = Column(DECIMAL(10, 2))
    operator_ref = Column(String(255))

class BillPaymentTransaction(BaseModel):
    """Bill payment specific details"""
    __tablename__ = 'bill_payment_transactions'
    
    transaction_id = Column(GUID(), db.ForeignKey('transactions.id'), nullable=False)
    category = Column(String(100), nullable=False)
    biller_name = Column(String(255), nullable=False)
    biller_id = Column(String(100), nullable=False, index=True)
    customer_name = Column(String(255))
    customer_number = Column(String(100), nullable=False, index=True)
    bill_amount = Column(DECIMAL(15, 4))
    due_date = Column(Date)
    bill_date = Column(Date)
    reference_id = Column(String(255))

class MoneyTransferTransaction(BaseModel):
    """Money transfer specific details"""
    __tablename__ = 'money_transfer_transactions'
    
    transaction_id = Column(GUID(), db.ForeignKey('transactions.id'), nullable=False)
    sender_name = Column(String(255), nullable=False)
    sender_mobile = Column(String(15), nullable=False, index=True)
    beneficiary_name = Column(String(255), nullable=False)
    beneficiary_mobile = Column(String(15))
    bank_name = Column(String(255), nullable=False)
    account_number = Column(String(50), nullable=False, index=True)
    ifsc_code = Column(String(11), nullable=False)
    transfer_mode = Column(db.Enum(TransactionMode), nullable=False)
    utr_number = Column(String(100), index=True)
    reference_number = Column(String(100))

# =============================================================================
# COMMISSION & PRICING MODELS
# =============================================================================

class CommissionPlan(BaseModel):
    """Commission plans for different services"""
    __tablename__ = 'commission_plans'
    
    tenant_id = Column(GUID(), db.ForeignKey('tenants.id'), nullable=False, index=True)
    plan_name = Column(String(255), nullable=False)
    service_type = Column(db.Enum(ServiceType), nullable=False)
    commission_mode = Column(db.Enum(CommissionMode), nullable=False)
    base_rate = Column(DECIMAL(10, 4), default=0)
    min_commission = Column(DECIMAL(10, 2), default=0)
    max_commission = Column(DECIMAL(10, 2))
    slabs = Column(JSONType, default=[])
    conditions = Column(JSONType, default={})
    is_active = Column(Boolean, default=True, index=True)
    valid_from = Column(DateTime, default=datetime.utcnow)
    valid_until = Column(DateTime)
    created_by = Column(GUID(), db.ForeignKey('users.id'))

class UserCommission(BaseModel):
    """User commission assignments"""
    __tablename__ = 'user_commissions'
    
    user_id = Column(GUID(), db.ForeignKey('users.id'), nullable=False)
    commission_plan_id = Column(GUID(), db.ForeignKey('commission_plans.id'))
    custom_rate = Column(DECIMAL(10, 4))
    is_active = Column(Boolean, default=True)
    assigned_at = Column(DateTime, default=datetime.utcnow)
    assigned_by = Column(GUID(), db.ForeignKey('users.id'))
    
    __table_args__ = (UniqueConstraint('user_id', 'commission_plan_id'),)

class ServicePricing(BaseModel):
    """Service pricing configurations"""
    __tablename__ = 'service_pricing'
    
    tenant_id = Column(GUID(), db.ForeignKey('tenants.id'), nullable=False, index=True)
    service_type = Column(db.Enum(ServiceType), nullable=False)
    provider = Column(String(100))
    base_cost = Column(DECIMAL(10, 4), nullable=False)
    markup = Column(DECIMAL(10, 4), default=0)
    min_amount = Column(DECIMAL(10, 2), default=0)
    max_amount = Column(DECIMAL(10, 2))
    is_active = Column(Boolean, default=True)
    effective_from = Column(DateTime, default=datetime.utcnow)

# =============================================================================
# PERMISSION & ACCESS CONTROL MODELS
# =============================================================================

class Permission(BaseModel):
    """System permissions"""
    __tablename__ = 'permissions'
    
    name = Column(String(100), unique=True, nullable=False)
    description = Column(Text)
    category = Column(String(50))
    is_system = Column(Boolean, default=False)

class RolePermission(BaseModel):
    """Role-based permissions"""
    __tablename__ = 'role_permissions'
    
    role = Column(db.Enum(UserRoleType), nullable=False)
    permission_id = Column(GUID(), db.ForeignKey('permissions.id'))
    tenant_id = Column(GUID(), db.ForeignKey('tenants.id'))
    is_granted = Column(Boolean, default=True)
    conditions = Column(JSONType, default={})
    
    __table_args__ = (UniqueConstraint('role', 'permission_id', 'tenant_id'),)

class UserPermission(BaseModel):
    """User-specific permission overrides"""
    __tablename__ = 'user_permissions'
    
    user_id = Column(GUID(), db.ForeignKey('users.id'), nullable=False)
    permission_id = Column(GUID(), db.ForeignKey('permissions.id'))
    is_granted = Column(Boolean, default=True)
    granted_by = Column(GUID(), db.ForeignKey('users.id'))
    expires_at = Column(DateTime)
    
    __table_args__ = (UniqueConstraint('user_id', 'permission_id'),)

# =============================================================================
# NOTIFICATION SYSTEM MODELS
# =============================================================================

class NotificationTemplate(BaseModel):
    """Notification templates"""
    __tablename__ = 'notification_templates'
    
    tenant_id = Column(GUID(), db.ForeignKey('tenants.id'))
    template_code = Column(String(100), nullable=False)
    template_name = Column(String(255), nullable=False)
    template_type = Column(String(50), nullable=False)
    subject = Column(String(500))
    body = Column(Text, nullable=False)
    variables = Column(JSONType, default=[])
    is_active = Column(Boolean, default=True)
    
    __table_args__ = (UniqueConstraint('tenant_id', 'template_code'),)

class NotificationQueue(BaseModel):
    """Notification queue for processing"""
    __tablename__ = 'notification_queue'
    
    tenant_id = Column(GUID(), db.ForeignKey('tenants.id'))
    user_id = Column(GUID(), db.ForeignKey('users.id'))
    template_id = Column(GUID(), db.ForeignKey('notification_templates.id'))
    notification_type = Column(String(50), nullable=False)
    recipient = Column(String(255), nullable=False)
    subject = Column(String(500))
    message = Column(Text, nullable=False)
    variables = Column(JSONType, default={})
    status = Column(String(50), default='PENDING')
    attempts = Column(Integer, default=0)
    max_attempts = Column(Integer, default=3)
    scheduled_at = Column(DateTime, default=datetime.utcnow)
    sent_at = Column(DateTime)
    error_message = Column(Text)

# =============================================================================
# API MANAGEMENT MODELS
# =============================================================================

class APIConfiguration(BaseModel):
    """API configurations for external services"""
    __tablename__ = 'api_configurations'
    
    tenant_id = Column(GUID(), db.ForeignKey('tenants.id'), nullable=False, index=True)
    service_type = Column(db.Enum(ServiceType), nullable=False)
    provider = Column(String(100), nullable=False)
    api_url = Column(Text, nullable=False)
    api_key = Column(String(255))
    api_secret = Column(String(255))
    headers = Column(JSONType, default={})
    parameters = Column(JSONType, default={})
    is_active = Column(Boolean, default=True)
    priority = Column(Integer, default=1)
    rate_limit = Column(Integer, default=1000)
    timeout_seconds = Column(Integer, default=30)
    success_codes = Column(ArrayType, default=[200, 201])
    retry_count = Column(Integer, default=3)

class APIRequestLog(BaseModel):
    """API request logs for debugging"""
    __tablename__ = 'api_request_logs'
    
    tenant_id = Column(GUID(), db.ForeignKey('tenants.id'))
    transaction_id = Column(GUID(), db.ForeignKey('transactions.id'))
    api_config_id = Column(GUID(), db.ForeignKey('api_configurations.id'))
    request_url = Column(Text, nullable=False)
    request_method = Column(String(10), default='POST')
    request_headers = Column(JSONType, default={})
    request_body = Column(JSONType, default={})
    response_status = Column(Integer)
    response_headers = Column(JSONType, default={})
    response_body = Column(JSONType, default={})
    response_time_ms = Column(Integer)
    error_message = Column(Text)

# =============================================================================
# AUDIT AND LOGGING MODELS
# =============================================================================

class AuditLog(BaseModel):
    """System audit logs"""
    __tablename__ = 'audit_logs'
    
    tenant_id = Column(GUID(), db.ForeignKey('tenants.id'), index=True)
    user_id = Column(GUID(), db.ForeignKey('users.id'), index=True)
    action = Column(String(100), nullable=False, index=True)
    resource_type = Column(String(100), index=True)
    resource_id = Column(GUID(), index=True)
    old_values = Column(JSONType, default={})
    new_values = Column(JSONType, default={})
    ip_address = Column(IPAddressType)
    user_agent = Column(Text)
    session_id = Column(GUID())
    severity = Column(String(20), default='INFO')
    description = Column(Text)
    meta_data = Column(JSONType, default={})

class ErrorLog(BaseModel):
    """System error logs"""
    __tablename__ = 'error_logs'
    
    tenant_id = Column(GUID(), db.ForeignKey('tenants.id'))
    user_id = Column(GUID(), db.ForeignKey('users.id'))
    error_code = Column(String(50))
    error_message = Column(Text, nullable=False)
    stack_trace = Column(Text)
    request_data = Column(JSONType, default={})
    response_data = Column(JSONType, default={})
    severity = Column(String(20), default='ERROR')
    resolved = Column(Boolean, default=False)
    resolved_by = Column(GUID(), db.ForeignKey('users.id'))
    resolved_at = Column(DateTime)

# =============================================================================
# REPORTING MODELS
# =============================================================================

class DailySummary(BaseModel):
    """Pre-computed daily summaries"""
    __tablename__ = 'daily_summaries'
    
    tenant_id = Column(GUID(), db.ForeignKey('tenants.id'), nullable=False, index=True)
    user_id = Column(GUID(), db.ForeignKey('users.id'), nullable=False, index=True)
    summary_date = Column(Date, nullable=False, index=True)
    service_type = Column(db.Enum(ServiceType))
    total_transactions = Column(Integer, default=0)
    success_transactions = Column(Integer, default=0)
    failed_transactions = Column(Integer, default=0)
    total_volume = Column(DECIMAL(15, 4), default=0)
    total_commission = Column(DECIMAL(15, 4), default=0)
    
    __table_args__ = (UniqueConstraint('tenant_id', 'user_id', 'summary_date', 'service_type'),)

# =============================================================================
# PAYMENT GATEWAY WEBHOOK MODELS
# =============================================================================

class PaymentWebhook(BaseModel):
    """Payment gateway webhook handling"""
    __tablename__ = 'payment_webhooks'
    
    webhook_id = Column(String(255), unique=True, nullable=False)
    payment_gateway_id = Column(GUID(), db.ForeignKey('payment_gateways.id'))
    topup_request_id = Column(GUID(), db.ForeignKey('wallet_topup_requests.id'))
    event_type = Column(String(100), nullable=False)
    order_id = Column(String(255), index=True)
    payment_id = Column(String(255), index=True)
    signature = Column(String(500))
    raw_payload = Column(JSONType, nullable=False)
    processed = Column(Boolean, default=False)
    processing_attempts = Column(Integer, default=0)
    processing_error = Column(Text)
    ip_address = Column(IPAddressType)
    user_agent = Column(Text)
    verified = Column(Boolean, default=False)
    verification_error = Column(Text)
    processed_at = Column(DateTime)

class PaymentGatewayLog(BaseModel):
    """Payment gateway API interaction logs"""
    __tablename__ = 'payment_gateway_logs'
    
    topup_request_id = Column(GUID(), db.ForeignKey('wallet_topup_requests.id'))
    payment_gateway_id = Column(GUID(), db.ForeignKey('payment_gateways.id'))
    log_type = Column(String(50), nullable=False)
    endpoint = Column(String(255))
    request_method = Column(String(10))
    request_headers = Column(JSONType, default={})
    request_body = Column(JSONType, default={})
    response_status = Column(Integer)
    response_headers = Column(JSONType, default={})
    response_body = Column(JSONType, default={})
    response_time_ms = Column(Integer)
    error_code = Column(String(100))
    error_message = Column(Text)
    raw_data = Column(Text)

# =============================================================================
# REFUND MANAGEMENT MODELS
# =============================================================================

class TopupRefund(BaseModel):
    """Topup refund management"""
    __tablename__ = 'topup_refunds'
    
    refund_id = Column(String(255), unique=True, nullable=False)
    topup_request_id = Column(GUID(), db.ForeignKey('wallet_topup_requests.id'), nullable=False)
    original_amount = Column(DECIMAL(15, 4), nullable=False)
    refund_amount = Column(DECIMAL(15, 4), nullable=False)
    refund_reason = Column(Text, nullable=False)
    refund_type = Column(String(50), default='FULL')
    gateway_refund_id = Column(String(255))
    gateway_response = Column(JSONType, default={})
    status = Column(db.Enum(TransactionStatus), default=TransactionStatus.PENDING)
    processed_by = Column(GUID(), db.ForeignKey('users.id'))
    processed_at = Column(DateTime)

# =============================================================================
# BANK ACCOUNT TRANSACTION MODELS
# =============================================================================

class BankAccountTransaction(BaseModel):
    """Bank account transaction log"""
    __tablename__ = 'bank_account_transactions'
    
    bank_account_id = Column(GUID(), db.ForeignKey('organization_bank_accounts.id'), nullable=False)
    topup_request_id = Column(GUID(), db.ForeignKey('wallet_topup_requests.id'))
    transaction_type = Column(String(50), nullable=False)
    amount = Column(DECIMAL(15, 4), nullable=False)
    balance_before = Column(DECIMAL(15, 4))
    balance_after = Column(DECIMAL(15, 4))
    reference_number = Column(String(255))
    utr_number = Column(String(100), index=True)
    transaction_date = Column(DateTime, default=datetime.utcnow)
    value_date = Column(Date)
    description = Column(Text)
    category = Column(String(100))
    counterparty_name = Column(String(255))
    counterparty_account = Column(String(50))
    counterparty_ifsc = Column(String(11))
    charges = Column(DECIMAL(10, 4), default=0)
    gst_amount = Column(DECIMAL(10, 4), default=0)
    net_amount = Column(DECIMAL(15, 4))
    status = Column(String(50), default='SUCCESS')
    bank_reference = Column(String(255))
    statement_reference = Column(String(255))
    reconciled = Column(Boolean, default=False)
    reconciled_at = Column(DateTime)
    reconciled_by = Column(GUID(), db.ForeignKey('users.id'))
    meta_data = Column(JSONType, default={})

class BankStatementImport(BaseModel):
    """Bank statement import tracking"""
    __tablename__ = 'bank_statement_imports'
    
    bank_account_id = Column(GUID(), db.ForeignKey('organization_bank_accounts.id'), nullable=False)
    import_batch_id = Column(String(100), unique=True, nullable=False)
    file_name = Column(String(255))
    file_type = Column(String(50))
    statement_period_from = Column(Date, nullable=False)
    statement_period_to = Column(Date, nullable=False)
    total_records = Column(Integer, default=0)
    processed_records = Column(Integer, default=0)
    matched_records = Column(Integer, default=0)
    unmatched_records = Column(Integer, default=0)
    duplicate_records = Column(Integer, default=0)
    error_records = Column(Integer, default=0)
    opening_balance = Column(DECIMAL(15, 4))
    closing_balance = Column(DECIMAL(15, 4))
    total_credits = Column(DECIMAL(15, 4), default=0)
    total_debits = Column(DECIMAL(15, 4), default=0)
    import_status = Column(String(50), default='PROCESSING')
    error_details = Column(JSONType, default={})
    processed_by = Column(GUID(), db.ForeignKey('users.id'))
    processing_started_at = Column(DateTime, default=datetime.utcnow)
    processing_completed_at = Column(DateTime)
    auto_reconcile = Column(Boolean, default=True)
    reconciliation_rules = Column(JSONType, default={})

# =============================================================================
# ROLE BANK PERMISSIONS MODEL
# =============================================================================

class RoleBankPermission(BaseModel):
    """Role-based bank access control"""
    __tablename__ = 'role_bank_permissions'
    
    tenant_id = Column(GUID(), db.ForeignKey('tenants.id'), nullable=False)
    role = Column(db.Enum(UserRoleType), nullable=False)
    bank_account_id = Column(GUID(), db.ForeignKey('organization_bank_accounts.id'))
    can_view = Column(Boolean, default=True)
    can_select_for_topup = Column(Boolean, default=True)
    can_modify = Column(Boolean, default=False)
    can_view_balance = Column(Boolean, default=False)
    can_reconcile = Column(Boolean, default=False)
    purpose_allowed = Column(ArrayType, default=[AccountPurpose.WALLET_TOPUP.value])
    amount_limit = Column(DECIMAL(15, 4))
    created_by = Column(GUID(), db.ForeignKey('users.id'))
    
    __table_args__ = (UniqueConstraint('tenant_id', 'role', 'bank_account_id'),)

# =============================================================================
# RELATIONSHIP DEFINITIONS
# =============================================================================

# Tenant relationships
Tenant.users = relationship("User", back_populates="tenant", foreign_keys="User.tenant_id")
Tenant.payment_gateways = relationship("PaymentGateway", back_populates="tenant")
Tenant.organization_bank_accounts = relationship("OrganizationBankAccount", back_populates="tenant")

# User relationships
User.tenant = relationship("Tenant", back_populates="users", foreign_keys=[User.tenant_id])
User.parent = relationship("User", remote_side=[User.id], backref="children", foreign_keys=[User.parent_id])
User.wallet = relationship("Wallet", back_populates="user", uselist=False)
User.sessions = relationship("UserSession", back_populates="user", cascade="all, delete-orphan")
User.transactions = relationship("Transaction", back_populates="user")
User.topup_requests = relationship("WalletTopupRequest", back_populates="user", foreign_keys="WalletTopupRequest.user_id")
User.bank_preferences = relationship("UserBankPreference", back_populates="user")

# UserSession relationships
UserSession.user = relationship("User", back_populates="sessions")

# Wallet relationships
Wallet.user = relationship("User", back_populates="wallet")
Wallet.transactions = relationship("WalletTransaction", back_populates="wallet")

# WalletTransaction relationships
WalletTransaction.wallet = relationship("Wallet", back_populates="transactions")

# PaymentGateway relationships
PaymentGateway.tenant = relationship("Tenant", back_populates="payment_gateways")
PaymentGateway.topup_requests = relationship("WalletTopupRequest", back_populates="payment_gateway")

# OrganizationBankAccount relationships
OrganizationBankAccount.tenant = relationship("Tenant", back_populates="organization_bank_accounts")
OrganizationBankAccount.user_preferences = relationship("UserBankPreference", back_populates="bank_account")
OrganizationBankAccount.topup_requests = relationship("WalletTopupRequest", back_populates="selected_bank_account")

# UserBankPreference relationships
UserBankPreference.user = relationship("User", back_populates="bank_preferences")
UserBankPreference.bank_account = relationship("OrganizationBankAccount", back_populates="user_preferences")

# WalletTopupRequest relationships
WalletTopupRequest.user = relationship("User", back_populates="topup_requests", foreign_keys=[WalletTopupRequest.user_id])
WalletTopupRequest.payment_gateway = relationship("PaymentGateway", back_populates="topup_requests")
WalletTopupRequest.selected_bank_account = relationship("OrganizationBankAccount", back_populates="topup_requests")

# Transaction relationships
Transaction.user = relationship("User", back_populates="transactions")
Transaction.commission_distributions = relationship("CommissionDistribution", back_populates="transaction")

# CommissionDistribution relationships
CommissionDistribution.transaction = relationship("Transaction", back_populates="commission_distributions")

# =============================================================================
# DATABASE UTILITY FUNCTIONS
# =============================================================================

def create_tables(engine):
    """Create all database tables"""
    db.metadata.create_all(engine)

def drop_tables(engine):
    """Drop all database tables (use with caution!)"""
    db.metadata.drop_all(engine)

def get_model_by_name(name: str):
    """Get model class by name"""
    for model in db.Model.registry._class_registry.values():
        if hasattr(model, '__name__') and model.__name__ == name:
            return model
    return None

def get_all_models():
    """Get all model classes"""
    models = []
    for model in db.Model.registry._class_registry.values():
        if hasattr(model, '__tablename__'):
            models.append(model)
    return models




# =============================================================================
# MODEL RELATIONSHIPS VALIDATION
# =============================================================================

def validate_model_relationships():
    """Validate that all model relationships are properly defined"""
    try:
        from sqlalchemy import MetaData
        metadata = MetaData()
        db.metadata.bind = None
        
        for table in db.metadata.sorted_tables:
            for fk in table.foreign_keys:
                target_table = fk.column.table
                if target_table not in db.metadata.tables.values():
                    raise ValueError(f"Foreign key references unknown table: {target_table.name}")
        
        return True
    except Exception as e:
        print(f"Model validation failed: {e}")
        return False

# =============================================================================
# HELPER FUNCTIONS FOR MODEL CREATION
# =============================================================================

def create_default_permissions():
    """Create default system permissions"""
    default_permissions = [
        # User Management
        ('USER_CREATE', 'Create users', 'USER_MANAGEMENT'),
        ('USER_READ', 'View users', 'USER_MANAGEMENT'),
        ('USER_UPDATE', 'Update users', 'USER_MANAGEMENT'),
        ('USER_DELETE', 'Delete users', 'USER_MANAGEMENT'),
        
        # Transaction Management
        ('TRANSACTION_READ', 'View transactions', 'TRANSACTIONS'),
        ('TRANSACTION_PROCESS', 'Process transactions', 'TRANSACTIONS'),
        ('TRANSACTION_REFUND', 'Refund transactions', 'TRANSACTIONS'),
        
        # Wallet Management
        ('WALLET_READ', 'View wallet', 'WALLET'),
        ('WALLET_CREDIT', 'Credit wallet', 'WALLET'),
        ('WALLET_DEBIT', 'Debit wallet', 'WALLET'),
        ('WALLET_TOPUP_APPROVE', 'Approve wallet topup', 'WALLET'),
        
        # Commission Management
        ('COMMISSION_SET', 'Set commission rates', 'COMMISSION'),
        ('COMMISSION_VIEW', 'View commission details', 'COMMISSION'),
        
        # Reporting
        ('REPORT_VIEW', 'View reports', 'REPORTING'),
        ('REPORT_EXPORT', 'Export reports', 'REPORTING'),
        
        # System Configuration
        ('SYSTEM_CONFIG', 'System configuration', 'SYSTEM'),
        ('BANK_ACCOUNT_MANAGE', 'Manage bank accounts', 'SYSTEM'),
        ('PAYMENT_GATEWAY_MANAGE', 'Manage payment gateways', 'SYSTEM'),
    ]
    
    return [
        Permission(name=name, description=desc, category=cat, is_system=True)
        for name, desc, cat in default_permissions
    ]

def create_sample_tenant_data(session, tenant_id: uuid.UUID):
    """Create sample data for a tenant"""
    from decimal import Decimal
    
    # Create sample commission plans
    commission_plans = [
        CommissionPlan(
            tenant_id=tenant_id,
            plan_name="Mobile Recharge - Standard",
            service_type=ServiceType.MOBILE_RECHARGE,
            commission_mode=CommissionMode.PERCENTAGE,
            base_rate=Decimal('2.5'),
            min_commission=Decimal('1.0'),
            max_commission=Decimal('100.0'),
            is_active=True
        ),
        CommissionPlan(
            tenant_id=tenant_id,
            plan_name="DTH Recharge - Standard",
            service_type=ServiceType.DTH_RECHARGE,
            commission_mode=CommissionMode.PERCENTAGE,
            base_rate=Decimal('3.0'),
            min_commission=Decimal('2.0'),
            max_commission=Decimal('200.0'),
            is_active=True
        ),
        CommissionPlan(
            tenant_id=tenant_id,
            plan_name="Money Transfer - Standard",
            service_type=ServiceType.MONEY_TRANSFER,
            commission_mode=CommissionMode.FLAT,
            base_rate=Decimal('5.0'),
            min_commission=Decimal('5.0'),
            max_commission=Decimal('25.0'),
            is_active=True
        )
    ]
    
    for plan in commission_plans:
        session.add(plan)
    
    # Create sample notification templates
    notification_templates = [
        NotificationTemplate(
            tenant_id=tenant_id,
            template_code='WELCOME_EMAIL',
            template_name='Welcome Email',
            template_type='EMAIL',
            subject='Welcome to {{platform_name}}',
            body='Dear {{user_name}}, Welcome to our platform. Your account has been created successfully.',
            variables=['platform_name', 'user_name'],
            is_active=True
        ),
        NotificationTemplate(
            tenant_id=tenant_id,
            template_code='TRANSACTION_SUCCESS',
            template_name='Transaction Success',
            template_type='SMS',
            subject='',
            body='Transaction of Rs.{{amount}} completed successfully. Ref: {{transaction_id}}',
            variables=['amount', 'transaction_id'],
            is_active=True
        ),
        NotificationTemplate(
            tenant_id=tenant_id,
            template_code='LOW_WALLET_BALANCE',
            template_name='Low Wallet Balance',
            template_type='EMAIL',
            subject='Low Wallet Balance Alert',
            body='Your wallet balance is low: Rs.{{balance}}. Please recharge to continue services.',
            variables=['balance'],
            is_active=True
        )
    ]
    
    for template in notification_templates:
        session.add(template)

# =============================================================================
# EXAMPLE USAGE AND TESTING
# =============================================================================

if __name__ == "__main__":
    """
    Example usage of the models
    """
    print("=" * 60)
    print("🚀 SaaS Platform Models Loaded Successfully!")
    print("=" * 60)
    print(f"📊 Total Models: {len([cls for cls in db.Model.registry._class_registry.values() if hasattr(cls, '__tablename__')])}")
    print(f"🔧 PostgreSQL Support: {'Yes' if HAS_POSTGRESQL else 'No (using fallbacks)'}")
    print("\n📋 Available Models:")
    
    models = get_all_models()
    for model in sorted(models, key=lambda x: x.__tablename__):
        print(f"  • {model.__tablename__} -> {model.__name__}")
    
    # Validate relationships
    print(f"\n🔍 Validating Model Relationships...")
    if validate_model_relationships():
        print("✅ All model relationships are valid!")
    else:
        print("❌ Model relationship validation failed!")
    
    print(f"\n🎯 Key Features:")
    print("  • Cross-database compatibility (PostgreSQL/SQLite)")
    print("  • Multi-tenant architecture")
    print("  • Hierarchical user management")
    print("  • Comprehensive audit logging")
    print("  • Payment gateway integration")
    print("  • Multi-bank account support")
    print("  • Commission management")
    print("  • Notification system")
    
    print(f"\n💡 Usage Tips:")
    print("  • Use create_tables(engine) to create all tables")
    print("  • Use create_default_permissions() for initial setup")
    print("  • Models support both PostgreSQL and SQLite")
    print("  • All models inherit from BaseModel with common fields")

# =============================================================================
# EXPORT ALL MODELS AND UTILITIES - INCLUDE db
# =============================================================================



#----------------------------------------------------------------------------
# SMS OTP
# ----------------------------------------------------------------------------
# Add this new model after your existing models
# Add this model after your existing models in models.py
class OTPVerification(BaseModel):
    """OTP verification management"""
    __tablename__ = 'otp_verifications'
    
    user_id = Column(GUID(), db.ForeignKey('users.id'), index=True)
    phone_number = Column(String(20), nullable=False, index=True)
    otp_code = Column(String(10), nullable=False)
    otp_type = Column(db.Enum(OTPType), nullable=False, index=True)
    status = Column(db.Enum(OTPStatus), default=OTPStatus.PENDING, index=True)
    attempts = Column(Integer, default=0)
    max_attempts = Column(Integer, default=3)
    expires_at = Column(DateTime, nullable=False, index=True)
    verified_at = Column(DateTime)
    ip_address = Column(IPAddressType)
    user_agent = Column(Text)
    session_id = Column(String(255))
    meta_data = Column(JSONType, default={})
    
    @property
    def is_expired(self):
        """Check if OTP is expired"""
        return datetime.utcnow() > self.expires_at
    
    @property
    def is_max_attempts_reached(self):
        """Check if max attempts reached"""
        return self.attempts >= self.max_attempts
    
    def increment_attempts(self):
        """Increment verification attempts"""
        self.attempts += 1
        if self.attempts >= self.max_attempts:
            self.status = OTPStatus.FAILED



__all__ = [
    # CRITICAL: Export db instance
    'db',
    
    # Custom Types
    'GUID', 'JSONType', 'ArrayType', 'IPAddressType',
    
    # Enums
    'UserRoleType', 'TransactionStatus', 'ServiceType', 'TransactionMode',
    'KYCStatus', 'CommissionMode', 'WalletTransactionType', 'PaymentGatewayType',
    'TopupMethod', 'BankAccountType', 'AccountPurpose', 'BankAccountStatus',
    
    # Core Models
    'Tenant', 'User', 'UserSession',

    # SMS OTP Model
    'OTPType', 'OTPStatus', 'OTPVerification',

    
    # Permission Models
    'Permission', 'RolePermission', 'UserPermission',
    
    # Wallet Models
    'Wallet', 'WalletTransaction', 'WalletTopupRequest',
    
    # Payment Models
    'PaymentGateway', 'PaymentWebhook', 'PaymentGatewayLog', 'TopupRefund',
    
    # Bank Models
    'OrganizationBankAccount', 'UserBankPreference', 'BankAccountTransaction',
    'BankStatementImport', 'RoleBankPermission',
    
    # Transaction Models
    'Transaction', 'CommissionDistribution', 'RechargeTransaction',
    'BillPaymentTransaction', 'MoneyTransferTransaction',
    
    # Commission Models
    'CommissionPlan', 'UserCommission', 'ServicePricing',
    
    # Notification Models
    'NotificationTemplate', 'NotificationQueue',
    
    # API Models
    'APIConfiguration', 'APIRequestLog',
    
    # Audit Models
    'AuditLog', 'ErrorLog',
    
    # Reporting Models
    'DailySummary',
    
    # Utility Functions
    'create_tables', 'drop_tables', 'validate_model_relationships',
    'get_model_by_name', 'get_all_models', 'create_default_permissions',
    'create_sample_tenant_data'
]
