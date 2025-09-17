# utils/validation.py
"""
Form Validation Utilities
=========================

Comprehensive validation utilities for the recharge management system
including form validators, business rule validators, and data sanitizers.
"""

import re
import json
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
from typing import Dict, List, Tuple, Any, Optional, Union
from functools import wraps
from flask import request, jsonify, flash
from wtforms import validators
from wtforms.validators import ValidationError
from config.recharge_config import RechargeConfig

# =============================================================================
# CUSTOM VALIDATORS
# =============================================================================

class IndianMobileValidator:
    """Validator for Indian mobile numbers"""
    
    def __init__(self, message: str = None):
        self.message = message or "Please enter a valid 10-digit mobile number starting with 6, 7, 8, or 9"
    
    def __call__(self, form, field):
        mobile = field.data
        if not mobile:
            raise ValidationError("Mobile number is required")
        
        # Remove any spaces or special characters
        mobile = re.sub(r'[^\d]', '', mobile)
        
        # Check if it's exactly 10 digits
        if len(mobile) != 10:
            raise ValidationError("Mobile number must be exactly 10 digits")
        
        # Check if it starts with valid digits (6, 7, 8, 9)
        if not mobile.startswith(('6', '7', '8', '9')):
            raise ValidationError("Mobile number must start with 6, 7, 8, or 9")
        
        # Update field data with cleaned mobile number
        field.data = mobile

class AmountRangeValidator:
    """Validator for amount ranges based on service type"""
    
    def __init__(self, service_type: str, message: str = None):
        self.service_type = service_type
        self.message = message
        self.config = RechargeConfig()
    
    def __call__(self, form, field):
        try:
            amount = Decimal(str(field.data))
        except (InvalidOperation, ValueError, TypeError):
            raise ValidationError("Please enter a valid amount")
        
        limits = self.config.get_transaction_limits(self.service_type)
        
        if not limits:
            raise ValidationError("Invalid service type")
        
        min_amount = limits.get('min_amount', Decimal('0'))
        max_amount = limits.get('max_amount', Decimal('999999'))
        
        if amount < min_amount:
            raise ValidationError(f"Minimum amount is ₹{min_amount}")
        
        if amount > max_amount:
            raise ValidationError(f"Maximum amount is ₹{max_amount}")

class CustomerIDValidator:
    """Validator for customer IDs based on operator and service type"""
    
    def __init__(self, operator_field: str, service_type: str, message: str = None):
        self.operator_field = operator_field
        self.service_type = service_type
        self.message = message
        self.config = RechargeConfig()
    
    def __call__(self, form, field):
        customer_id = field.data
        operator_id = form[self.operator_field].data
        
        if not customer_id:
            raise ValidationError("Customer ID is required")
        
        if not operator_id:
            raise ValidationError("Please select an operator first")
        
        # Validate using config
        is_valid, message = self.config.validate_customer_id(
            customer_id, operator_id, self.service_type
        )
        
        if not is_valid:
            raise ValidationError(message)

class TransactionLimitValidator:
    """Validator for daily/monthly transaction limits"""
    
    def __init__(self, user_id_field: str, service_type: str):
        self.user_id_field = user_id_field
        self.service_type = service_type
    
    def __call__(self, form, field):
        from models import Transaction, TransactionStatus, func, db
        from datetime import date
        
        try:
            amount = Decimal(str(field.data))
        except (InvalidOperation, ValueError, TypeError):
            raise ValidationError("Please enter a valid amount")
        
        user_id = form[self.user_id_field].data if hasattr(form, self.user_id_field) else None
        
        if not user_id:
            return  # Skip validation if user_id not available
        
        # Check daily limit
        today = date.today()
        daily_total = db.session.query(
            func.coalesce(func.sum(Transaction.amount), 0)
        ).filter(
            Transaction.user_id == user_id,
            Transaction.service_type == self.service_type,
            Transaction.status == TransactionStatus.SUCCESS,
            func.date(Transaction.created_at) == today
        ).scalar()
        
        limits = RechargeConfig.get_transaction_limits(self.service_type)
        daily_limit = limits.get('daily_limit', Decimal('50000'))
        
        if (daily_total or 0) + amount > daily_limit:
            raise ValidationError(f"Daily limit of ₹{daily_limit} would be exceeded")

# =============================================================================
# BUSINESS RULE VALIDATORS
# =============================================================================

def validate_wallet_balance(user_id: str, amount: Decimal) -> Tuple[bool, str]:
    """Validate if user has sufficient wallet balance"""
    from models import Wallet
    
    wallet = Wallet.query.filter_by(user_id=user_id).first()
    
    if not wallet:
        return False, "Wallet not found"
    
    if wallet.available_balance < amount:
        return False, f"Insufficient balance. Available: ₹{wallet.available_balance}"
    
    return True, "Sufficient balance"

def validate_operator_circle_combination(operator_id: str, circle_id: str, service_type: str) -> Tuple[bool, str]:
    """Validate operator and circle combination"""
    config = RechargeConfig()
    
    operator = config.get_operator_by_id(operator_id, service_type)
    if not operator:
        return False, "Invalid operator selected"
    
    if not operator.get('active', True):
        return False, f"{operator['name']} is currently not available"
    
    if service_type == 'mobile':
        circle = config.get_circle_by_id(circle_id)
        if not circle:
            return False, "Invalid circle selected"
    
    return True, "Valid combination"

def validate_transaction_time_window() -> Tuple[bool, str]:
    """Validate if transaction is within allowed time window"""
    current_hour = datetime.now().hour
    
    # Example: Allow transactions only between 6 AM and 11 PM
    if current_hour < 6 or current_hour >= 23:
        return False, "Transactions are allowed only between 6:00 AM and 11:00 PM"
    
    return True, "Valid time window"

def validate_duplicate_transaction(user_id: str, mobile_or_customer_id: str, 
                                amount: Decimal, service_type: str, 
                                time_window_minutes: int = 5) -> Tuple[bool, str]:
    """Check for duplicate transactions within time window"""
    from models import Transaction, TransactionStatus, db
    
    time_threshold = datetime.utcnow() - timedelta(minutes=time_window_minutes)
    
    # Check for similar transaction in recent time
    duplicate_query = Transaction.query.filter(
        Transaction.user_id == user_id,
        Transaction.service_type == service_type,
        Transaction.amount == amount,
        Transaction.created_at >= time_threshold,
        Transaction.status != TransactionStatus.FAILED
    )
    
    # Check customer details based on service type
    if service_type.value == 'MOBILE_RECHARGE':
        duplicate_query = duplicate_query.filter(
            Transaction.customer_details['mobile'].astext == mobile_or_customer_id
        )
    elif service_type.value in ['DTH_RECHARGE', 'BILL_PAYMENT']:
        duplicate_query = duplicate_query.filter(
            db.or_(
                Transaction.customer_details['customer_id'].astext == mobile_or_customer_id,
                Transaction.customer_details['connection_number'].astext == mobile_or_customer_id
            )
        )
    
    duplicate = duplicate_query.first()
    
    if duplicate:
        return False, f"Similar transaction found within {time_window_minutes} minutes. Please wait before retrying."
    
    return True, "No duplicate found"

# =============================================================================
# DATA SANITIZERS
# =============================================================================

def sanitize_mobile_number(mobile: str) -> str:
    """Clean and format mobile number"""
    if not mobile:
        return ""
    
    # Remove all non-digit characters
    mobile = re.sub(r'[^\d]', '', mobile)
    
    # Remove country code if present
    if mobile.startswith('91') and len(mobile) == 12:
        mobile = mobile[2:]
    elif mobile.startswith('+91') and len(mobile) == 13:
        mobile = mobile[3:]
    
    return mobile

def sanitize_amount(amount: Union[str, float, Decimal]) -> Decimal:
    """Clean and convert amount to Decimal"""
    if isinstance(amount, Decimal):
        return amount.quantize(Decimal('0.01'))
    
    try:
        # Remove currency symbols and spaces
        if isinstance(amount, str):
            amount = re.sub(r'[₹$,\s]', '', amount)
        
        decimal_amount = Decimal(str(amount))
        return decimal_amount.quantize(Decimal('0.01'))
    
    except (InvalidOperation, ValueError, TypeError):
        raise ValueError("Invalid amount format")

def sanitize_customer_id(customer_id: str) -> str:
    """Clean customer ID"""
    if not customer_id:
        return ""
    
    # Remove spaces and special characters, keep only alphanumeric
    return re.sub(r'[^\w]', '', customer_id.strip().upper())

def sanitize_json_data(data: Any) -> Dict[str, Any]:
    """Sanitize JSON data for safe storage"""
    if isinstance(data, dict):
        return {k: sanitize_json_data(v) for k, v in data.items() if k and v is not None}
    elif isinstance(data, list):
        return [sanitize_json_data(item) for item in data if item is not None]
    elif isinstance(data, str):
        return data.strip()[:500]  # Limit string length
    elif isinstance(data, (int, float, bool)):
        return data
    else:
        return str(data)[:500] if data is not None else None

# =============================================================================
# FORM VALIDATION DECORATORS
# =============================================================================

def validate_json_request(required_fields: List[str] = None):
    """Decorator to validate JSON request data"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not request.is_json:
                return jsonify({
                    'success': False,
                    'error': 'Request must be JSON'
                }), 400
            
            data = request.get_json()
            
            if not data:
                return jsonify({
                    'success': False,
                    'error': 'No JSON data provided'
                }), 400
            
            # Check required fields
            if required_fields:
                missing_fields = [field for field in required_fields if field not in data]
                if missing_fields:
                    return jsonify({
                        'success': False,
                        'error': f'Missing required fields: {", ".join(missing_fields)}'
                    }), 400
            
            return func(*args, **kwargs)
        return wrapper
    return decorator

def validate_form_data(validators_dict: Dict[str, List[callable]]):
    """Decorator to validate form data with custom validators"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            errors = {}
            
            for field_name, field_validators in validators_dict.items():
                field_value = request.form.get(field_name) or request.json.get(field_name) if request.is_json else None
                
                for validator in field_validators:
                    try:
                        # Create a mock field object
                        class MockField:
                            def __init__(self, data):
                                self.data = data
                        
                        mock_field = MockField(field_value)
                        validator(None, mock_field)  # Pass None as form since we're not using wtforms
                        
                    except ValidationError as e:
                        errors[field_name] = str(e)
                        break
            
            if errors:
                if request.is_json:
                    return jsonify({
                        'success': False,
                        'errors': errors
                    }), 400
                else:
                    for field, error in errors.items():
                        flash(f'{field.replace("_", " ").title()}: {error}', 'error')
                    return redirect(request.url)
            
            return func(*args, **kwargs)
        return wrapper
    return decorator

# =============================================================================
# COMPREHENSIVE VALIDATION FUNCTIONS
# =============================================================================

def validate_mobile_recharge_data(data: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
    """Comprehensive validation for mobile recharge data"""
    errors = {}
    
    # Mobile number validation
    mobile = data.get('mobile', '').strip()
    mobile = sanitize_mobile_number(mobile)
    
    if not mobile:
        errors['mobile'] = "Mobile number is required"
    else:
        is_valid, message = RechargeConfig.validate_mobile_number(mobile)
        if not is_valid:
            errors['mobile'] = message
        else:
            data['mobile'] = mobile  # Update with sanitized value
    
    # Operator validation
    operator_id = data.get('operator', '').strip()
    if not operator_id:
        errors['operator'] = "Operator is required"
    else:
        operator = RechargeConfig.get_operator_by_id(operator_id, 'mobile')
        if not operator:
            errors['operator'] = "Invalid operator selected"
        elif not operator.get('active', True):
            errors['operator'] = f"{operator['name']} is currently not available"
    
    # Circle validation
    circle_id = data.get('circle', '').strip()
    if not circle_id:
        errors['circle'] = "Circle is required"
    else:
        circle = RechargeConfig.get_circle_by_id(circle_id)
        if not circle:
            errors['circle'] = "Invalid circle selected"
    
    # Amount validation
    try:
        amount = sanitize_amount(data.get('amount', '0'))
        is_valid, message = RechargeConfig.is_amount_valid('MOBILE_RECHARGE', amount)
        if not is_valid:
            errors['amount'] = message
        else:
            data['amount'] = amount  # Update with sanitized value
    except ValueError as e:
        errors['amount'] = str(e)
    
    # Business rule validations
    if not errors and 'user_id' in data:
        # Wallet balance validation
        is_valid, message = validate_wallet_balance(data['user_id'], data['amount'])
        if not is_valid:
            errors['amount'] = message
        
        # Duplicate transaction validation
        is_valid, message = validate_duplicate_transaction(
            data['user_id'], data['mobile'], data['amount'], 
            'MOBILE_RECHARGE'
        )
        if not is_valid:
            errors['duplicate'] = message
    
    return len(errors) == 0, errors

def validate_dth_recharge_data(data: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
    """Comprehensive validation for DTH recharge data"""
    errors = {}
    
    # Customer ID validation
    customer_id = sanitize_customer_id(data.get('customer_id', ''))
    if not customer_id:
        errors['customer_id'] = "Customer ID is required"
    else:
        data['customer_id'] = customer_id
    
    # Operator validation
    operator_id = data.get('operator', '').strip()
    if not operator_id:
        errors['operator'] = "DTH operator is required"
    else:
        operator = RechargeConfig.get_operator_by_id(operator_id, 'dth')
        if not operator:
            errors['operator'] = "Invalid DTH operator selected"
        elif not operator.get('active', True):
            errors['operator'] = f"{operator['name']} is currently not available"
        elif customer_id:
            # Validate customer ID format for this operator
            is_valid, message = RechargeConfig.validate_customer_id(
                customer_id, operator_id, 'dth'
            )
            if not is_valid:
                errors['customer_id'] = message
    
    # Amount validation
    try:
        amount = sanitize_amount(data.get('amount', '0'))
        is_valid, message = RechargeConfig.is_amount_valid('DTH_RECHARGE', amount)
        if not is_valid:
            errors['amount'] = message
        else:
            data['amount'] = amount
    except ValueError as e:
        errors['amount'] = str(e)
    
    return len(errors) == 0, errors

def validate_bill_payment_data(data: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
    """Comprehensive validation for bill payment data"""
    errors = {}
    
    # Connection number validation
    connection_number = sanitize_customer_id(data.get('connection_number', ''))
    if not connection_number:
        errors['connection_number'] = "Connection number is required"
    else:
        data['connection_number'] = connection_number
    
    # Operator validation
    operator_id = data.get('operator', '').strip()
    if not operator_id:
        errors['operator'] = "Bill provider is required"
    else:
        operator = RechargeConfig.get_operator_by_id(operator_id, 'bill')
        if not operator:
            errors['operator'] = "Invalid bill provider selected"
        elif not operator.get('active', True):
            errors['operator'] = f"{operator['name']} is currently not available"
        elif connection_number:
            # Validate connection number format
            is_valid, message = RechargeConfig.validate_customer_id(
                connection_number, operator_id, 'bill'
            )
            if not is_valid:
                errors['connection_number'] = message
    
    # Amount validation
    try:
        amount = sanitize_amount(data.get('amount', '0'))
        is_valid, message = RechargeConfig.is_amount_valid('BILL_PAYMENT', amount)
        if not is_valid:
            errors['amount'] = message
        else:
            data['amount'] = amount
    except ValueError as e:
        errors['amount'] = str(e)
    
    return len(errors) == 0, errors

# =============================================================================
# VALIDATION HELPER FUNCTIONS
# =============================================================================

def get_validation_errors_as_json(errors: Dict[str, str]) -> str:
    """Convert validation errors to JSON string for frontend"""
    return json.dumps(errors)

def flash_validation_errors(errors: Dict[str, str], prefix: str = "Validation Error"):
    """Flash validation errors to user"""
    for field, error in errors.items():
        field_name = field.replace('_', ' ').title()
        flash(f"{prefix} - {field_name}: {error}", 'error')

def create_validation_response(success: bool, errors: Dict[str, str] = None, 
                             data: Dict[str, Any] = None) -> Dict[str, Any]:
    """Create standardized validation response"""
    response = {
        'success': success,
        'timestamp': datetime.utcnow().isoformat()
    }
    
    if not success and errors:
        response['errors'] = errors
        response['error_count'] = len(errors)
    
    if data:
        response['data'] = data
    
    return response

# =============================================================================
# TESTING UTILITIES
# =============================================================================

def create_test_data(service_type: str) -> Dict[str, Any]:
    """Create valid test data for different service types"""
    if service_type == 'mobile':
        return {
            'mobile': '9999999999',
            'operator': '1',
            'circle': '5',
            'amount': '100'
        }
    elif service_type == 'dth':
        return {
            'customer_id': '1234567890',
            'operator': '32',
            'amount': '300'
        }
    elif service_type == 'bill':
        return {
            'connection_number': '123456789012',
            'operator': '59',
            'amount': '500'
        }
    
    return {}

# =============================================================================
# EXPORT FUNCTIONS
# =============================================================================

__all__ = [
    'IndianMobileValidator',
    'AmountRangeValidator', 
    'CustomerIDValidator',
    'TransactionLimitValidator',
    'validate_wallet_balance',
    'validate_operator_circle_combination',
    'validate_transaction_time_window',
    'validate_duplicate_transaction',
    'sanitize_mobile_number',
    'sanitize_amount',
    'sanitize_customer_id',
    'sanitize_json_data',
    'validate_json_request',
    'validate_form_data',
    'validate_mobile_recharge_data',
    'validate_dth_recharge_data',
    'validate_bill_payment_data',
    'get_validation_errors_as_json',
    'flash_validation_errors',
    'create_validation_response',
    'create_test_data'
]