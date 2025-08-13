# utils/__init__.py
"""
Utility functions package for SaaS Platform
Contains all helper functions used across the application
"""

# utils/permissions.py
"""
Permission and access control utilities
"""

from functools import wraps
from flask import jsonify, request, current_app
from flask_login import current_user
from models import User, Permission, RolePermission, UserPermission, UserRoleType
from sqlalchemy import and_, or_
from datetime import datetime

def require_permission(permission_name):
    """Decorator to require specific permission"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return jsonify({'success': False, 'message': 'Authentication required'}), 401
            
            if not has_permission(current_user, permission_name):
                return jsonify({'success': False, 'message': f'Permission {permission_name} required'}), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def has_permission(user, permission_name):
    """Check if user has specific permission"""
    try:
        # Get permission
        permission = Permission.query.filter_by(name=permission_name).first()
        if not permission:
            return False
        
        # Check user-specific override first
        user_override = UserPermission.query.filter_by(
            user_id=user.id,
            permission_id=permission.id
        ).first()
        
        if user_override:
            # Check if not expired
            if user_override.expires_at and user_override.expires_at < datetime.utcnow():
                return False
            return user_override.is_granted
        
        # Check role-based permission
        role_permission = RolePermission.query.filter_by(
            role=user.role,
            permission_id=permission.id,
            tenant_id=user.tenant_id,
            is_granted=True
        ).first()
        
        return role_permission is not None
        
    except Exception as e:
        print(f"Error checking permission {permission_name} for user {user.id}: {e}")
        return False

def get_user_effective_permissions(user):
    """Get all effective permissions for user"""
    try:
        permissions = set()
        
        # Get role-based permissions
        role_permissions = RolePermission.query.filter_by(
            role=user.role,
            tenant_id=user.tenant_id,
            is_granted=True
        ).all()
        
        for rp in role_permissions:
            permission = Permission.query.get(rp.permission_id)
            if permission:
                permissions.add(permission.name)
        
        # Apply user-specific overrides
        user_overrides = UserPermission.query.filter_by(user_id=user.id).all()
        
        for override in user_overrides:
            permission = Permission.query.get(override.permission_id)
            if permission and (not override.expires_at or override.expires_at > datetime.utcnow()):
                if override.is_granted:
                    permissions.add(permission.name)
                elif permission.name in permissions:
                    permissions.remove(permission.name)
        
        return list(permissions)
        
    except Exception as e:
        print(f"Error getting effective permissions for user {user.id}: {e}")
        return []

def check_permission_hierarchy(current_user, permission):
    """Check if current user can grant/revoke specific permission"""
    # Super admins can manage all permissions
    if current_user.role == UserRoleType.SUPER_ADMIN:
        return True
    
    # System permissions can only be managed by super admins
    if permission.is_system and current_user.role != UserRoleType.SUPER_ADMIN:
        return False
    
    # Admins can manage most permissions except system ones
    if current_user.role == UserRoleType.ADMIN:
        return not permission.is_system
    
    return False

def validate_permission_assignment(user, permission, granter):
    """Validate if permission can be assigned to user by granter"""
    # Check if granter can assign this permission
    if not check_permission_hierarchy(granter, permission):
        return False
    
    # Check role hierarchy - can't grant permission to higher role
    role_hierarchy = {
        UserRoleType.SUPER_ADMIN: 6,
        UserRoleType.ADMIN: 5,
        UserRoleType.WHITE_LABEL: 4,
        UserRoleType.MASTER_DISTRIBUTOR: 3,
        UserRoleType.DISTRIBUTOR: 2,
        UserRoleType.RETAILER: 1
    }
    
    granter_level = role_hierarchy.get(granter.role, 0)
    user_level = role_hierarchy.get(user.role, 0)
    
    return granter_level > user_level

# utils/validators.py
"""
Input validation utilities
"""

import re
from decimal import Decimal, InvalidOperation
from models import User, OrganizationBankAccount

def validate_user_creation(data, current_user):
    """Validate user creation data"""
    try:
        # Required fields
        required_fields = ['username', 'full_name', 'phone', 'password', 'role']
        for field in required_fields:
            if not data.get(field):
                return {'valid': False, 'message': f'{field} is required'}
        
        # Username validation
        username = data['username'].strip()
        if len(username) < 3:
            return {'valid': False, 'message': 'Username must be at least 3 characters'}
        
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            return {'valid': False, 'message': 'Username can only contain letters, numbers, and underscores'}
        
        # Check username uniqueness
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return {'valid': False, 'message': 'Username already exists'}
        
        # Phone validation
        phone = data['phone'].strip()
        if not re.match(r'^\d{10}$', phone):
            return {'valid': False, 'message': 'Phone number must be 10 digits'}
        
        # Check phone uniqueness
        existing_phone = User.query.filter_by(phone=phone).first()
        if existing_phone:
            return {'valid': False, 'message': 'Phone number already exists'}
        
        # Email validation (if provided)
        email = data.get('email')
        if email:
            email = email.strip()
            if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
                return {'valid': False, 'message': 'Invalid email format'}
            
            # Check email uniqueness
            existing_email = User.query.filter_by(email=email).first()
            if existing_email:
                return {'valid': False, 'message': 'Email already exists'}
        
        # Password validation
        password = data['password']
        if len(password) < 6:
            return {'valid': False, 'message': 'Password must be at least 6 characters'}
        
        # Amount validation (if provided)
        if 'initial_balance' in data:
            try:
                amount = Decimal(str(data['initial_balance']))
                if amount < 0:
                    return {'valid': False, 'message': 'Initial balance cannot be negative'}
            except (InvalidOperation, ValueError):
                return {'valid': False, 'message': 'Invalid initial balance amount'}
        
        return {'valid': True, 'message': 'Validation passed'}
        
    except Exception as e:
        return {'valid': False, 'message': f'Validation error: {str(e)}'}

def validate_role_hierarchy(current_role, target_role):
    """Validate if current role can create target role"""
    hierarchy = {
        UserRoleType.SUPER_ADMIN: [UserRoleType.ADMIN, UserRoleType.WHITE_LABEL, UserRoleType.MASTER_DISTRIBUTOR, UserRoleType.DISTRIBUTOR, UserRoleType.RETAILER],
        UserRoleType.ADMIN: [UserRoleType.WHITE_LABEL, UserRoleType.MASTER_DISTRIBUTOR, UserRoleType.DISTRIBUTOR, UserRoleType.RETAILER],
        UserRoleType.WHITE_LABEL: [UserRoleType.MASTER_DISTRIBUTOR, UserRoleType.DISTRIBUTOR, UserRoleType.RETAILER],
        UserRoleType.MASTER_DISTRIBUTOR: [UserRoleType.DISTRIBUTOR, UserRoleType.RETAILER],
        UserRoleType.DISTRIBUTOR: [UserRoleType.RETAILER],
        UserRoleType.RETAILER: []
    }
    
    allowed_roles = hierarchy.get(current_role, [])
    return target_role in allowed_roles

def validate_topup_request(data, user):
    """Validate wallet top-up request data"""
    try:
        # Required fields
        if not data.get('amount'):
            return {'valid': False, 'message': 'Amount is required'}
        
        if not data.get('topup_method'):
            return {'valid': False, 'message': 'Top-up method is required'}
        
        # Amount validation
        try:
            amount = Decimal(str(data['amount']))
            if amount <= 0:
                return {'valid': False, 'message': 'Amount must be greater than 0'}
            
            if amount < 100:
                return {'valid': False, 'message': 'Minimum top-up amount is ₹100'}
            
            if amount > 50000:
                return {'valid': False, 'message': 'Maximum top-up amount is ₹50,000'}
                
        except (InvalidOperation, ValueError):
            return {'valid': False, 'message': 'Invalid amount format'}
        
        # Method-specific validation
        method = data['topup_method']
        if method == 'MANUAL_REQUEST':
            if not data.get('selected_bank_id'):
                return {'valid': False, 'message': 'Bank account selection is required for manual requests'}
        
        elif method == 'PAYMENT_GATEWAY':
            if not data.get('payment_gateway_id'):
                return {'valid': False, 'message': 'Payment gateway selection is required'}
        
        return {'valid': True, 'message': 'Validation passed'}
        
    except Exception as e:
        return {'valid': False, 'message': f'Validation error: {str(e)}'}

def validate_bank_account(data):
    """Validate bank account data"""
    try:
        # Required fields
        required_fields = ['account_name', 'account_number', 'ifsc_code', 'bank_name', 'account_holder_name']
        for field in required_fields:
            if not data.get(field):
                return {'valid': False, 'message': f'{field} is required'}
        
        # Account number validation
        account_number = data['account_number'].strip()
        if not re.match(r'^\d{9,18}$', account_number):
            return {'valid': False, 'message': 'Account number must be 9-18 digits'}
        
        # IFSC validation
        ifsc = data['ifsc_code'].strip().upper()
        if not re.match(r'^[A-Z]{4}0[A-Z0-9]{6}', ifsc):
            return {'valid': False, 'message': 'Invalid IFSC code format'}
        
        # PAN validation (if provided)
        pan = data.get('pan_number')
        if pan:
            pan = pan.strip().upper()
            if not re.match(r'^[A-Z]{5}[0-9]{4}[A-Z]{1}', pan):
                return {'valid': False, 'message': 'Invalid PAN number format'}
        
        # GSTIN validation (if provided)
        gstin = data.get('gstin')
        if gstin:
            gstin = gstin.strip().upper()
            if not re.match(r'^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}', gstin):
                return {'valid': False, 'message': 'Invalid GSTIN format'}
        
        return {'valid': True, 'message': 'Validation passed'}
        
    except Exception as e:
        return {'valid': False, 'message': f'Validation error: {str(e)}'}

def validate_ifsc_code(ifsc):
    """Validate IFSC code format"""
    if not ifsc or len(ifsc) != 11:
        return False
    
    return re.match(r'^[A-Z]{4}0[A-Z0-9]{6}', ifsc.upper()) is not None

def validate_bank_details(account_number, ifsc_code):
    """Validate bank account details"""
    try:
        # Account number validation
        if not re.match(r'^\d{9,18}', account_number):
            return {'valid': False, 'message': 'Invalid account number format'}
        
        # IFSC validation
        if not validate_ifsc_code(ifsc_code):
            return {'valid': False, 'message': 'Invalid IFSC code'}
        
        return {'valid': True, 'message': 'Bank details are valid'}
        
    except Exception as e:
        return {'valid': False, 'message': f'Validation error: {str(e)}'}

# utils/user_utils.py
"""
User management utilities
"""

import secrets
from models import User, UserRoleType

def generate_user_code(role, tenant_id):
    """Generate unique user code based on role"""
    # Define role prefixes
    role_prefixes = {
        UserRoleType.SUPER_ADMIN: 'SA',
        UserRoleType.ADMIN: 'AD',
        UserRoleType.WHITE_LABEL: 'WL',
        UserRoleType.MASTER_DISTRIBUTOR: 'MD',
        UserRoleType.DISTRIBUTOR: 'DT',
        UserRoleType.RETAILER: 'RT'
    }
    
    prefix = role_prefixes.get(role, 'US')
    
    # Count existing users with same role
    existing_count = User.query.filter(
        User.tenant_id == tenant_id,
        User.user_code.like(f'{prefix}%')
    ).count()
    
    # Generate code
    code_number = existing_count + 1
    return f"{prefix}{code_number:06d}"

def get_allowed_roles_for_creation(current_role):
    """Get roles that current user can create"""
    hierarchy = {
        UserRoleType.SUPER_ADMIN: [UserRoleType.ADMIN, UserRoleType.WHITE_LABEL, UserRoleType.MASTER_DISTRIBUTOR, UserRoleType.DISTRIBUTOR, UserRoleType.RETAILER],
        UserRoleType.ADMIN: [UserRoleType.WHITE_LABEL, UserRoleType.MASTER_DISTRIBUTOR, UserRoleType.DISTRIBUTOR, UserRoleType.RETAILER],
        UserRoleType.WHITE_LABEL: [UserRoleType.MASTER_DISTRIBUTOR, UserRoleType.DISTRIBUTOR, UserRoleType.RETAILER],
        UserRoleType.MASTER_DISTRIBUTOR: [UserRoleType.DISTRIBUTOR, UserRoleType.RETAILER],
        UserRoleType.DISTRIBUTOR: [UserRoleType.RETAILER],
        UserRoleType.RETAILER: []
    }
    
    return hierarchy.get(current_role, [])

# utils/notifications.py
"""
Notification utilities
"""

from models import NotificationQueue, NotificationTemplate, User
from datetime import datetime

def send_welcome_notification(user, password):
    """Send welcome notification to new user"""
    try:
        # Create welcome notification
        notification = NotificationQueue(
            tenant_id=user.tenant_id,
            user_id=user.id,
            notification_type='EMAIL',
            recipient=user.email or user.phone,
            subject='Welcome to the Platform',
            message=f'Welcome {user.full_name}! Your account has been created. Username: {user.username}, Password: {password}',
            variables={
                'user_name': user.full_name,
                'username': user.username,
                'password': password,
                'user_code': user.user_code
            }
        )
        
        from models import db
        db.session.add(notification)
        db.session.commit()
        
        return True
        
    except Exception as e:
        print(f"Failed to send welcome notification: {e}")
        return False

def send_topup_notification(topup_request, event_type):
    """Send top-up related notifications"""
    try:
        user = User.query.get(topup_request.user_id)
        if not user:
            return False
        
        # Define messages based on event type
        messages = {
            'created': f'Your wallet top-up request {topup_request.request_id} for ₹{topup_request.amount} has been created and is pending approval.',
            'approved': f'Your wallet top-up request {topup_request.request_id} for ₹{topup_request.amount} has been approved and credited to your wallet.',
            'rejected': f'Your wallet top-up request {topup_request.request_id} for ₹{topup_request.amount} has been rejected.'
        }
        
        message = messages.get(event_type, 'Top-up request status updated')
        
        notification = NotificationQueue(
            tenant_id=user.tenant_id,
            user_id=user.id,
            notification_type='SMS',
            recipient=user.phone,
            message=message,
            variables={
                'request_id': topup_request.request_id,
                'amount': float(topup_request.amount),
                'user_name': user.full_name
            }
        )
        
        from models import db
        db.session.add(notification)
        db.session.commit()
        
        return True
        
    except Exception as e:
        print(f"Failed to send topup notification: {e}")
        return False

def send_approval_notification(topup_request, action):
    """Send approval/rejection notification"""
    return send_topup_notification(topup_request, action)

# utils/bank_utils.py
"""
Bank account utilities
"""

import re
from models import WalletTopupRequest, BankAccountTransaction

def validate_utr_number(utr):
    """Validate UTR number format"""
    if not utr or len(utr) < 10:
        return False
    
    # UTR numbers are typically 12-22 characters alphanumeric
    return re.match(r'^[A-Z0-9]{10,22}', utr.upper()) is not None

def check_duplicate_utr(utr_number, exclude_request_id=None):
    """Check if UTR number already exists"""
    try:
        query = WalletTopupRequest.query.filter_by(utr_number=utr_number)
        
        if exclude_request_id:
            query = query.filter(WalletTopupRequest.id != exclude_request_id)
        
        existing_request = query.first()
        return existing_request is not None
        
    except Exception as e:
        print(f"Error checking duplicate UTR: {e}")
        return False

def verify_bank_account(bank_account):
    """Verify bank account details (mock implementation)"""
    try:
        # In real implementation, this would call bank verification APIs
        # For now, return a mock verification result
        
        # Simple IFSC validation
        if not validate_ifsc_code(bank_account.ifsc_code):
            return {'verified': False, 'message': 'Invalid IFSC code'}
        
        # Mock verification based on account number pattern
        if bank_account.account_number.startswith('9999'):
            return {'verified': False, 'message': 'Test account number - verification failed'}
        
        return {
            'verified': True,
            'message': 'Account verified successfully',
            'bank_name': bank_account.bank_name,
            'branch_name': bank_account.branch_name,
            'account_holder_name': bank_account.account_holder_name
        }
        
    except Exception as e:
        return {'verified': False, 'message': f'Verification error: {str(e)}'}

def fetch_bank_details(ifsc_code):
    """Fetch bank details from IFSC code (mock implementation)"""
    try:
        # In real implementation, this would call IFSC lookup APIs
        # Mock data based on IFSC patterns
        
        bank_mapping = {
            'SBIN': 'State Bank of India',
            'HDFC': 'HDFC Bank',
            'ICIC': 'ICICI Bank',
            'AXIS': 'Axis Bank',
            'PUNB': 'Punjab National Bank'
        }
        
        bank_code = ifsc_code[:4]
        bank_name = bank_mapping.get(bank_code, 'Unknown Bank')
        
        return {
            'success': True,
            'bank_name': bank_name,
            'branch_name': f'Branch {ifsc_code[5:]}',
            'address': 'Mock Address',
            'city': 'Mock City',
            'state': 'Mock State'
        }
        
    except Exception as e:
        return {'success': False, 'message': f'Error fetching bank details: {str(e)}'}

def parse_bank_statement(file_path, file_type):
    """Parse bank statement file (mock implementation)"""
    try:
        # In real implementation, this would parse actual bank statement files
        # For now, return mock data
        
        from datetime import date, timedelta
        from decimal import Decimal
        
        # Mock transaction data
        mock_transactions = []
        
        for i in range(10):
            transaction_date = date.today() - timedelta(days=i)
            mock_transactions.append({
                'transaction_date': transaction_date,
                'transaction_type': 'CREDIT' if i % 2 == 0 else 'DEBIT',
                'amount': float(Decimal('1000') + Decimal(str(i * 100))),
                'description': f'Mock transaction {i + 1}',
                'reference_number': f'REF{1000 + i}',
                'utr_number': f'UTR{2000 + i}' if i % 3 == 0 else None,
                'balance_after': float(Decimal('50000') - Decimal(str(i * 500))),
                'counterparty_name': f'Counterparty {i + 1}' if i % 2 == 0 else None
            })
        
        return {
            'success': True,
            'data': {
                'transactions': mock_transactions,
                'opening_balance': 55000,
                'closing_balance': 50000,
                'total_credits': sum(t['amount'] for t in mock_transactions if t['transaction_type'] == 'CREDIT'),
                'total_debits': sum(t['amount'] for t in mock_transactions if t['transaction_type'] == 'DEBIT')
            }
        }
        
    except Exception as e:
        return {'success': False, 'message': f'Error parsing statement: {str(e)}'}

def reconcile_transactions(bank_transactions, topup_requests):
    """Reconcile bank transactions with topup requests"""
    try:
        matches = []
        
        for bank_txn in bank_transactions:
            for topup_req in topup_requests:
                # Check amount match (within ₹1 tolerance)
                amount_diff = abs(float(bank_txn.amount) - float(topup_req.amount))
                if amount_diff <= 1:
                    # Check date proximity (within 2 days)
                    date_diff = abs((bank_txn.transaction_date - topup_req.created_at.date()).days)
                    if date_diff <= 2:
                        matches.append({
                            'bank_transaction_id': bank_txn.id,
                            'topup_request_id': topup_req.id,
                            'confidence': 'HIGH' if amount_diff == 0 and date_diff == 0 else 'MEDIUM',
                            'amount_diff': amount_diff,
                            'date_diff': date_diff
                        })
        
        return {'success': True, 'matches': matches}
        
    except Exception as e:
        return {'success': False, 'message': f'Error in reconciliation: {str(e)}'}

def generate_bank_report(account_id, date_from, date_to):
    """Generate comprehensive bank account report"""
    try:
        # This would generate detailed reports
        # For now, return mock report data
        
        return {
            'success': True,
            'report': {
                'account_summary': {
                    'total_transactions': 150,
                    'total_credits': 75000.00,
                    'total_debits': 25000.00,
                    'net_balance': 50000.00
                },
                'reconciliation_status': {
                    'reconciled_transactions': 140,
                    'pending_reconciliation': 10,
                    'reconciliation_rate': 93.33
                },
                'top_counterparties': [
                    {'name': 'Customer A', 'amount': 15000, 'count': 5},
                    {'name': 'Customer B', 'amount': 12000, 'count': 3}
                ]
            }
        }
        
    except Exception as e:
        return {'success': False, 'message': f'Error generating report: {str(e)}'}

# utils/payment_gateways.py
"""
Payment gateway integration utilities
"""

import secrets
from datetime import datetime
from models import PaymentGatewayLog

def create_payment_order(topup_request, payment_gateway):
    """Create payment order with gateway"""
    try:
        # Mock payment gateway integration
        # In real implementation, this would call actual gateway APIs
        
        order_data = {
            'amount': int(topup_request.amount * 100),  # Convert to paise
            'currency': 'INR',
            'receipt': topup_request.request_id,
            'notes': {
                'user_id': str(topup_request.user_id),
                'topup_request_id': topup_request.request_id
            }
        }
        
        # Mock response
        mock_response = {
            'id': f"order_{secrets.token_hex(10)}",
            'entity': 'order',
            'amount': order_data['amount'],
            'currency': order_data['currency'],
            'receipt': order_data['receipt'],
            'status': 'created',
            'created_at': int(datetime.utcnow().timestamp())
        }
        
        return {
            'success': True,
            'order_id': mock_response['id'],
            'gateway_response': mock_response,
            'payment_details': {
                'key': payment_gateway.api_key,
                'amount': order_data['amount'],
                'currency': order_data['currency'],
                'order_id': mock_response['id'],
                'name': 'Wallet Top-up',
                'description': f'Add ₹{topup_request.amount} to wallet'
            }
        }
        
    except Exception as e:
        return {'success': False, 'message': f'Gateway error: {str(e)}'}

def verify_payment_signature(payment_data, gateway_secret):
    """Verify payment signature from gateway"""
    try:
        # In real implementation, this would verify the actual signature
        # For mock, always return true for non-empty data
        return len(payment_data) > 0
        
    except Exception as e:
        print(f"Error verifying payment signature: {e}")
        return False

def process_payment_callback(callback_data, headers):
    """Process payment gateway callback"""
    try:
        # Mock callback processing
        # In real implementation, this would handle actual gateway callbacks
        
        order_id = callback_data.get('order_id')
        payment_status = callback_data.get('status', 'success')
        
        if not order_id:
            return {'success': False, 'message': 'Order ID not found'}
        
        # Find topup request
        from models import WalletTopupRequest
        topup_request = WalletTopupRequest.query.filter_by(order_id=order_id).first()
        
        if not topup_request:
            return {'success': False, 'message': 'Topup request not found'}
        
        # Update request based on status
        if payment_status == 'success':
            topup_request.callback_received = True
            topup_request.gateway_response = callback_data
            # Would trigger auto-approval here
        
        return {'success': True, 'message': 'Callback processed'}
        
    except Exception as e:
        return {'success': False, 'message': f'Callback error: {str(e)}'}

# utils/file_handlers.py
"""
File handling utilities
"""

import os
import uuid
from werkzeug.utils import secure_filename

def handle_file_upload(file, upload_type):
    """Handle file upload and return file path"""
    try:
        if not file or not file.filename:
            raise ValueError("No file provided")
        
        # Create upload directory if it doesn't exist
        upload_dir = os.path.join('uploads', upload_type)
        os.makedirs(upload_dir, exist_ok=True)
        
        # Generate unique filename
        filename = secure_filename(file.filename)
        name, ext = os.path.splitext(filename)
        unique_filename = f"{name}_{uuid.uuid4().hex[:8]}{ext}"
        
        file_path = os.path.join(upload_dir, unique_filename)
        file.save(file_path)
        
        return file_path
        
    except Exception as e:
        raise Exception(f"File upload error: {str(e)}")

def validate_statement_file(file):
    """Validate bank statement file"""
    try:
        if not file:
            return {'valid': False, 'message': 'No file provided'}
        
        filename = file.filename.lower()
        allowed_extensions = ['.csv', '.xlsx', '.xls', '.pdf']
        
        if not any(filename.endswith(ext) for ext in allowed_extensions):
            return {'valid': False, 'message': 'Invalid file type. Allowed: CSV, Excel, PDF'}
        
        # Check file size (max 10MB)
        file.seek(0, 2)  # Seek to end
        file_size = file.tell()
        file.seek(0)  # Reset to beginning
        
        if file_size > 10 * 1024 * 1024:  # 10MB
            return {'valid': False, 'message': 'File size too large (max 10MB)'}
        
        return {'valid': True, 'message': 'File is valid'}
        
    except Exception as e:
        return {'valid': False, 'message': f'Validation error: {str(e)}'}

# Export all utility functions
__all__ = [
    # Permission utilities
    'require_permission', 'has_permission', 'get_user_effective_permissions',
    'check_permission_hierarchy', 'validate_permission_assignment',
    
    # Validation utilities
    'validate_user_creation', 'validate_role_hierarchy', 'validate_topup_request',
    'validate_bank_account', 'validate_ifsc_code', 'validate_bank_details',
    
    # User utilities
    'generate_user_code', 'get_allowed_roles_for_creation',
    
    # Notification utilities
    'send_welcome_notification', 'send_topup_notification', 'send_approval_notification',
    
    # Bank utilities
    'validate_utr_number', 'check_duplicate_utr', 'verify_bank_account',
    'fetch_bank_details', 'parse_bank_statement', 'reconcile_transactions',
    'generate_bank_report',
    
    # Payment gateway utilities
    'create_payment_order', 'verify_payment_signature', 'process_payment_callback',
    
    # File handling utilities
    'handle_file_upload', 'validate_statement_file'
]