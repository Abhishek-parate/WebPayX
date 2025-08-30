# Updated WalletTopupRequest model to support dual payment methods
# Add this updated class to your existing models.py file

class WalletTopupRequest(BaseModel):
    """Enhanced wallet top-up requests with dual payment method support"""
    __tablename__ = 'wallet_topup_requests'
    
    request_id = Column(String(100), unique=True, nullable=False, index=True)
    user_id = Column(GUID(), db.ForeignKey('users.id'), nullable=False, index=True)
    requested_by = Column(GUID(), db.ForeignKey('users.id'), index=True)
    approved_by = Column(GUID(), db.ForeignKey('users.id'))
    payment_gateway_id = Column(GUID(), db.ForeignKey('payment_gateways.id'), index=True)
    selected_bank_account_id = Column(GUID(), db.ForeignKey('organization_bank_accounts.id'))
    
    # Payment method information
    topup_method = Column(db.Enum(TopupMethod), nullable=False, default=TopupMethod.MANUAL_REQUEST)
    payment_type = Column(String(50))  # UPI, CARD, NET_BANKING, MANUAL_TRANSFER
    is_online_payment = Column(Boolean, default=False)
    
    # Amount details
    amount = Column(DECIMAL(15, 4), nullable=False)
    processing_fee = Column(DECIMAL(10, 4), default=0)
    net_amount = Column(DECIMAL(15, 4), nullable=False)
    
    # Transaction references
    external_transaction_id = Column(String(255), index=True)
    bank_reference = Column(String(255))
    upi_ref = Column(String(255))
    utr_number = Column(String(100))
    order_id = Column(String(255), index=True)
    gateway_transaction_id = Column(String(255))
    
    # Status and processing
    status = Column(db.Enum(TransactionStatus), default=TransactionStatus.PENDING, index=True)
    gateway_status = Column(String(100))
    gateway_response = Column(JSONType, default={})
    
    # Payment method specific details
    payment_method = Column(String(100))  # Specific method used (GPay, PhonePe, etc.)
    payment_details = Column(JSONType, default={})  # UPI details, QR code, etc.
    
    # Request information
    request_remarks = Column(Text)
    admin_remarks = Column(Text)
    failure_reason = Column(Text)
    
    # File uploads (for manual payments)
    proof_document = Column(Text)  # File path for uploaded proof
    receipt_url = Column(Text)
    
    # Payment flow data
    refund_id = Column(String(255))
    expected_deposit_info = Column(JSONType, default={})  # Expected payment details
    
    # Security and tracking
    ip_address = Column(IPAddressType)
    device_info = Column(JSONType, default={})
    
    # Processing flags
    callback_received = Column(Boolean, default=False)
    webhook_received = Column(Boolean, default=False)
    auto_approved = Column(Boolean, default=False)
    manual_verification_required = Column(Boolean, default=True)
    
    # Retry and timeout
    retry_count = Column(Integer, default=0)
    max_retries = Column(Integer, default=3)
    expires_at = Column(DateTime)  # Payment link expiry
    
    # Timestamps
    processed_at = Column(DateTime)
    settled_at = Column(DateTime)
    verified_at = Column(DateTime)
    
    # Additional metadata
    meta_data = Column(JSONType, default={})
    
    def __repr__(self):
        return f"<WalletTopupRequest(id='{self.request_id}', amount='{self.amount}', method='{self.topup_method.value if self.topup_method else None}', status='{self.status.value if self.status else None}')>"
    
    @property
    def is_expired(self):
        """Check if topup request is expired"""
        return self.expires_at and datetime.utcnow() > self.expires_at
    
    @property
    def is_manual_payment(self):
        """Check if this is a manual payment request"""
        return self.topup_method == TopupMethod.MANUAL_REQUEST
    
    @property
    def requires_proof_document(self):
        """Check if proof document is required"""
        return self.is_manual_payment and not self.proof_document
    
    @property
    def can_be_auto_approved(self):
        """Check if request can be auto-approved (online payments)"""
        return (self.topup_method == TopupMethod.PAYMENT_GATEWAY and 
                self.status == TransactionStatus.SUCCESS and 
                not self.auto_approved)
    
    def to_dict(self):
        """Convert to dictionary with payment method specific information"""
        result = super().to_dict()
        result.update({
            'is_manual_payment': self.is_manual_payment,
            'is_online_payment': self.topup_method == TopupMethod.PAYMENT_GATEWAY,
            'requires_proof_document': self.requires_proof_document,
            'can_be_auto_approved': self.can_be_auto_approved,
            'is_expired': self.is_expired,
            'payment_method_display': self.get_payment_method_display(),
            'status_display': self.get_status_display()
        })
        return result
    
    def get_payment_method_display(self):
        """Get human-readable payment method"""
        if self.topup_method == TopupMethod.MANUAL_REQUEST:
            return "Manual Bank Transfer"
        elif self.topup_method == TopupMethod.PAYMENT_GATEWAY:
            return f"Online Payment ({self.payment_type or 'UPI'})"
        else:
            return self.topup_method.value.replace('_', ' ').title()
    
    def get_status_display(self):
        """Get human-readable status"""
        status_map = {
            TransactionStatus.PENDING: "Pending Approval" if self.is_manual_payment else "Payment Pending",
            TransactionStatus.PROCESSING: "Processing Payment",
            TransactionStatus.SUCCESS: "Completed",
            TransactionStatus.FAILED: "Failed",
            TransactionStatus.CANCELLED: "Cancelled",
            TransactionStatus.REFUNDED: "Refunded"
        }
        return status_map.get(self.status, self.status.value if self.status else "Unknown")

# Updated PaymentGateway model to support UPI details
class PaymentGateway(BaseModel):
    """Payment gateway configurations with UPI support"""
    __tablename__ = 'payment_gateways'
    
    tenant_id = Column(GUID(), db.ForeignKey('tenants.id'), nullable=False, index=True)
    gateway_type = Column(db.Enum(PaymentGatewayType), nullable=False)
    gateway_name = Column(String(255), nullable=False)
    
    # API credentials
    merchant_id = Column(String(255), nullable=False)
    api_key = Column(String(500), nullable=False)
    api_secret = Column(String(500), nullable=False)
    webhook_secret = Column(String(500))
    
    # URLs
    callback_url = Column(Text)
    webhook_url = Column(Text)
    success_url = Column(Text)
    failure_url = Column(Text)
    
    # UPI specific configuration
    upi_id = Column(String(255))  # Primary UPI ID for QR code generation
    upi_merchant_name = Column(String(255))  # Merchant name for UPI
    upi_qr_template = Column(Text)  # QR code template
    
    # Configuration and limits
    sandbox_mode = Column(Boolean, default=True)
    status = Column(String(20), default='ACTIVE')
    priority = Column(Integer, default=1)
    min_amount = Column(DECIMAL(10, 2), default=1.00)
    max_amount = Column(DECIMAL(10, 2), default=100000.00)
    
    # Fee structure
    processing_fee_percentage = Column(DECIMAL(5, 4), default=0)
    processing_fee_fixed = Column(DECIMAL(10, 2), default=0)
    
    # Processing settings
    settlement_time_hours = Column(Integer, default=24)
    supported_methods = Column(JSONType, default=[])
    gateway_config = Column(JSONType, default={})
    
    # Rate limiting
    rate_limit_per_minute = Column(Integer, default=100)
    daily_transaction_limit = Column(DECIMAL(15, 4))
    monthly_transaction_limit = Column(DECIMAL(15, 4))
    
    # Flags
    auto_settlement = Column(Boolean, default=True)
    is_default = Column(Boolean, default=False)
    supports_upi = Column(Boolean, default=False)
    supports_cards = Column(Boolean, default=False)
    supports_netbanking = Column(Boolean, default=False)
    
    # Audit fields
    created_by = Column(GUID(), db.ForeignKey('users.id'))
    last_updated_by = Column(GUID(), db.ForeignKey('users.id'))
    
    def generate_upi_string(self, amount, reference_id, customer_name=None):
        """Generate UPI payment string"""
        if not self.upi_id:
            return None
        
        upi_params = [
            f"pa={self.upi_id}",  # Payee Address
            f"pn={self.upi_merchant_name or 'Merchant'}",  # Payee Name
            f"am={amount}",  # Amount
            f"tr={reference_id}",  # Transaction Reference
            f"tn=Wallet Topup",  # Transaction Note
            "cu=INR"  # Currency
        ]
        
        if customer_name:
            upi_params.append(f"mc=1234")  # Merchant Category Code (optional)
        
        return f"upi://pay?{'&'.join(upi_params)}"

# Updated OrganizationBankAccount to support UPI QR codes
class OrganizationBankAccount(BaseModel):
    """Organization bank accounts with UPI QR support"""
    __tablename__ = 'organization_bank_accounts'
    
    tenant_id = Column(GUID(), db.ForeignKey('tenants.id'), nullable=False, index=True)
    user_id = Column(GUID(), db.ForeignKey('users.id'))
    
    # Account identification
    account_code = Column(String(50), unique=True, nullable=False)
    account_name = Column(String(255), nullable=False)
    account_number = Column(String(50), nullable=False)
    ifsc_code = Column(String(11), nullable=False)
    
    # Bank details
    bank_name = Column(String(255), nullable=False)
    branch_name = Column(String(255))
    branch_address = Column(Text)
    account_type = Column(db.Enum(BankAccountType), nullable=False, default=BankAccountType.CURRENT)
    account_holder_name = Column(String(255), nullable=False)
    
    # Compliance information
    pan_number = Column(String(10))
    gstin = Column(String(15))
    
    # Status and configuration
    status = Column(db.Enum(BankAccountStatus), default=BankAccountStatus.ACTIVE)
    purpose = Column(ArrayType, default=[AccountPurpose.GENERAL.value])
    
    # Default flags
    is_primary = Column(Boolean, default=False)
    is_default_topup = Column(Boolean, default=False)
    is_default_settlement = Column(Boolean, default=False)
    is_default_refund = Column(Boolean, default=False)
    
    # Display settings
    priority = Column(Integer, default=1)
    display_order = Column(Integer, default=1)
    is_visible_to_users = Column(Boolean, default=True)
    
    # Limits and balances
    daily_limit = Column(DECIMAL(15, 4), default=500000.00)
    monthly_limit = Column(DECIMAL(15, 4), default=10000000.00)
    daily_used = Column(DECIMAL(15, 4), default=0)
    monthly_used = Column(DECIMAL(15, 4), default=0)
    minimum_balance = Column(DECIMAL(15, 4), default=10000.00)
    current_balance = Column(DECIMAL(15, 4), default=0)
    
    # Statement tracking
    last_statement_date = Column(Date)
    
    # UPI configuration
    upi_id = Column(String(100))
    upi_qr_code = Column(Text)  # Base64 encoded QR code image
    upi_qr_code_url = Column(Text)  # URL to QR code image
    supports_dynamic_qr = Column(Boolean, default=False)
    
    # Virtual account details
    virtual_account_number = Column(String(50))
    razor_contact_id = Column(String(100))
    razor_fund_account_id = Column(String(100))
    
    # Fee structure
    bank_charges = Column(JSONType, default={})
    
    # Settlement configuration
    auto_settlement = Column(Boolean, default=False)
    settlement_schedule = Column(String(50), default='DAILY')
    
    # Integration settings
    webhook_url = Column(Text)
    api_integration = Column(JSONType, default={})
    
    # Verification status
    verification_status = Column(String(50), default='PENDING')
    verification_date = Column(DateTime)
    verification_documents = Column(JSONType, default={})
    
    # Additional information
    additional_info = Column(JSONType, default={})
    
    # Audit fields
    created_by = Column(GUID(), db.ForeignKey('users.id'))
    last_updated_by = Column(GUID(), db.ForeignKey('users.id'))
    
    def generate_upi_qr_string(self, amount=None, reference_id=None):
        """Generate UPI QR string for this account"""
        if not self.upi_id:
            return None
        
        params = [
            f"pa={self.upi_id}",
            f"pn={self.account_holder_name}",
            "cu=INR"
        ]
        
        if amount:
            params.append(f"am={amount}")
        
        if reference_id:
            params.append(f"tr={reference_id}")
            params.append(f"tn=Wallet Topup - {reference_id}")
        
        return f"upi://pay?{'&'.join(params)}"
    
    def to_dict(self):
        """Convert to dictionary with UPI information"""
        result = super().to_dict()
        result.update({
            'supports_upi': bool(self.upi_id),
            'upi_available': bool(self.upi_id),
            'can_generate_qr': bool(self.upi_id and self.supports_dynamic_qr)
        })
        return result

# Database migration script for existing installations
def upgrade_database_for_dual_payments():
    """
    Add new columns to existing WalletTopupRequest table
    Run this migration script after updating the models
    """
    migration_sql = """
    -- Add new columns for dual payment method support
    ALTER TABLE wallet_topup_requests 
    ADD COLUMN IF NOT EXISTS payment_type VARCHAR(50),
    ADD COLUMN IF NOT EXISTS is_online_payment BOOLEAN DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS gateway_transaction_id VARCHAR(255),
    ADD COLUMN IF NOT EXISTS manual_verification_required BOOLEAN DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS max_retries INTEGER DEFAULT 3,
    ADD COLUMN IF NOT EXISTS verified_at TIMESTAMP;
    
    -- Add new columns to payment_gateways table
    ALTER TABLE payment_gateways 
    ADD COLUMN IF NOT EXISTS upi_id VARCHAR(255),
    ADD COLUMN IF NOT EXISTS upi_merchant_name VARCHAR(255),
    ADD COLUMN IF NOT EXISTS upi_qr_template TEXT,
    ADD COLUMN IF NOT EXISTS success_url TEXT,
    ADD COLUMN IF NOT EXISTS failure_url TEXT,
    ADD COLUMN IF NOT EXISTS daily_transaction_limit DECIMAL(15,4),
    ADD COLUMN IF NOT EXISTS monthly_transaction_limit DECIMAL(15,4),
    ADD COLUMN IF NOT EXISTS supports_upi BOOLEAN DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS supports_cards BOOLEAN DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS supports_netbanking BOOLEAN DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS last_updated_by UUID REFERENCES users(id);
    
    -- Add new columns to organization_bank_accounts table
    ALTER TABLE organization_bank_accounts 
    ADD COLUMN IF NOT EXISTS upi_qr_code_url TEXT,
    ADD COLUMN IF NOT EXISTS supports_dynamic_qr BOOLEAN DEFAULT FALSE;
    
    -- Update existing manual requests
    UPDATE wallet_topup_requests 
    SET is_online_payment = FALSE, 
        manual_verification_required = TRUE 
    WHERE topup_method = 'MANUAL_REQUEST' AND is_online_payment IS NULL;
    
    -- Update existing online requests
    UPDATE wallet_topup_requests 
    SET is_online_payment = TRUE, 
        manual_verification_required = FALSE 
    WHERE topup_method = 'PAYMENT_GATEWAY' AND is_online_payment IS NULL;
    
    -- Create indexes for better performance
    CREATE INDEX IF NOT EXISTS idx_wallet_topup_payment_type ON wallet_topup_requests(payment_type);
    CREATE INDEX IF NOT EXISTS idx_wallet_topup_is_online ON wallet_topup_requests(is_online_payment);
    CREATE INDEX IF NOT EXISTS idx_wallet_topup_verification ON wallet_topup_requests(manual_verification_required);
    CREATE INDEX IF NOT EXISTS idx_payment_gateway_upi_support ON payment_gateways(supports_upi);
    CREATE INDEX IF NOT EXISTS idx_bank_account_upi ON organization_bank_accounts(upi_id) WHERE upi_id IS NOT NULL;
    """
    
    return migration_sql

# Sample data creation for testing dual payment methods
def create_sample_dual_payment_data():
    """Create sample data for testing dual payment methods"""
    from decimal import Decimal
    
    sample_data = {
        'payment_gateway': {
            'gateway_name': 'UPI Test Gateway',
            'gateway_type': PaymentGatewayType.UPI_GATEWAY,
            'merchant_id': 'TEST_MERCHANT_001',
            'api_key': 'test_api_key_123',
            'api_secret': 'test_api_secret_456',
            'upi_id': 'testmerchant@upi',
            'upi_merchant_name': 'Test Merchant',
            'sandbox_mode': True,
            'status': 'ACTIVE',
            'is_default': True,
            'supports_upi': True,
            'min_amount': Decimal('10.00'),
            'max_amount': Decimal('100000.00')
        },
        'bank_account': {
            'account_code': 'HDFC_TOPUP_001',
            'account_name': 'Company Topup Account',
            'account_number': '50100123456789',
            'ifsc_code': 'HDFC0001234',
            'bank_name': 'HDFC Bank',
            'branch_name': 'Main Branch',
            'account_type': BankAccountType.CURRENT,
            'account_holder_name': 'Test Company Pvt Ltd',
            'status': BankAccountStatus.ACTIVE,
            'is_default_topup': True,
            'is_visible_to_users': True,
            'upi_id': 'company@hdfc',
            'supports_dynamic_qr': True,
            'purpose': [AccountPurpose.WALLET_TOPUP.value]
        }
    }
    
    return sample_data

# Export the updated classes and utilities
__all__ = [
    'WalletTopupRequest',
    'PaymentGateway', 
    'OrganizationBankAccount',
    'upgrade_database_for_dual_payments',
    'create_sample_dual_payment_data'
]