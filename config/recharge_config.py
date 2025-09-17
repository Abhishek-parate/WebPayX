# config/recharge_config.py
"""
Recharge Management System Configuration
========================================

Configuration settings for the recharge management system including
API endpoints, operator configurations, and business rules.
"""

import os
from datetime import timedelta
from decimal import Decimal
from typing import Dict, List, Any

class RechargeConfig:
    """Main configuration class for recharge management system"""
    
    # =============================================================================
    # API CONFIGURATION
    # =============================================================================
    
    # MobiKwik API Configuration
    MOBIKWIK_BASE_URL = os.getenv('MOBIKWIK_BASE_URL', 'https://alpha3.mobikwik.com')
    MOBIKWIK_API_KEY = os.getenv('MOBIKWIK_API_KEY', 'abcd@123')  # Test key
    MOBIKWIK_USER_ID = os.getenv('MOBIKWIK_USER_ID', 'testalpha1@gmail.com')
    MOBIKWIK_PASSWORD = os.getenv('MOBIKWIK_PASSWORD', 'testalpha1@123')
    
    # API Timeouts and Retries
    API_TIMEOUT = 30  # seconds
    API_RETRY_COUNT = 3
    API_RETRY_DELAY = 2  # seconds between retries
    
    # Rate Limiting
    API_RATE_LIMIT_PER_MINUTE = 100
    API_RATE_LIMIT_PER_HOUR = 5000
    
    # =============================================================================
    # TRANSACTION LIMITS
    # =============================================================================
    
    TRANSACTION_LIMITS = {
        'MOBILE_RECHARGE': {
            'min_amount': Decimal('10'),
            'max_amount': Decimal('5000'),
            'daily_limit': Decimal('50000'),
            'monthly_limit': Decimal('200000')
        },
        'DTH_RECHARGE': {
            'min_amount': Decimal('100'),
            'max_amount': Decimal('10000'),
            'daily_limit': Decimal('100000'),
            'monthly_limit': Decimal('500000')
        },
        'BILL_PAYMENT': {
            'min_amount': Decimal('1'),
            'max_amount': Decimal('50000'),
            'daily_limit': Decimal('200000'),
            'monthly_limit': Decimal('1000000')
        }
    }
    
    # =============================================================================
    # OPERATOR CONFIGURATIONS
    # =============================================================================
    
    MOBILE_OPERATORS = [
        {
            'id': '1',
            'name': 'Airtel',
            'display_name': 'Bharti Airtel',
            'type': ['prepaid', 'postpaid'],
            'logo': 'airtel.png',
            'validation_regex': r'^[6-9]\d{9}$',
            'active': True,
            'commission_rate': Decimal('2.5'),
            'api_operator_code': 'AIRTEL'
        },
        {
            'id': '2',
            'name': 'Jio',
            'display_name': 'Reliance Jio',
            'type': ['prepaid'],
            'logo': 'jio.png',
            'validation_regex': r'^[6-9]\d{9}$',
            'active': True,
            'commission_rate': Decimal('2.0'),
            'api_operator_code': 'JIO'
        },
        {
            'id': '3',
            'name': 'Vi',
            'display_name': 'Vodafone Idea (Vi)',
            'type': ['prepaid', 'postpaid'],
            'logo': 'vi.png',
            'validation_regex': r'^[6-9]\d{9}$',
            'active': True,
            'commission_rate': Decimal('2.5'),
            'api_operator_code': 'VI'
        },
        {
            'id': '4',
            'name': 'BSNL',
            'display_name': 'Bharat Sanchar Nigam Limited',
            'type': ['prepaid', 'postpaid'],
            'logo': 'bsnl.png',
            'validation_regex': r'^[6-9]\d{9}$',
            'active': True,
            'commission_rate': Decimal('3.0'),
            'api_operator_code': 'BSNL'
        }
    ]
    
    DTH_OPERATORS = [
        {
            'id': '32',
            'name': 'Dish TV',
            'display_name': 'Dish TV Digital Service',
            'logo': 'dish-tv.png',
            'customer_id_format': 'VC Number (14 digits)',
            'validation_regex': r'^\d{14}$',
            'active': True,
            'commission_rate': Decimal('3.0'),
            'api_operator_code': 'DISH_TV'
        },
        {
            'id': '33',
            'name': 'Tata Sky',
            'display_name': 'Tata Sky',
            'logo': 'tata-sky.png',
            'customer_id_format': 'Subscriber ID (10 digits)',
            'validation_regex': r'^\d{10}$',
            'active': True,
            'commission_rate': Decimal('3.0'),
            'api_operator_code': 'TATA_SKY'
        },
        {
            'id': '34',
            'name': 'Airtel Digital TV',
            'display_name': 'Airtel Digital TV',
            'logo': 'airtel-dth.png',
            'customer_id_format': 'Customer ID (10 digits)',
            'validation_regex': r'^\d{10}$',
            'active': True,
            'commission_rate': Decimal('2.5'),
            'api_operator_code': 'AIRTEL_DTH'
        },
        {
            'id': '35',
            'name': 'Sun Direct',
            'display_name': 'Sun Direct',
            'logo': 'sun-direct.png',
            'customer_id_format': 'Subscriber ID (11 digits)',
            'validation_regex': r'^\d{11}$',
            'active': True,
            'commission_rate': Decimal('3.5'),
            'api_operator_code': 'SUN_DIRECT'
        }
    ]
    
    BILL_OPERATORS = [
        {
            'id': '59',
            'name': 'BESCOM',
            'display_name': 'Bangalore Electricity Supply Company',
            'state': 'Karnataka',
            'type': 'electricity',
            'logo': 'bescom.png',
            'validation_regex': r'^\d{8,12}$',
            'active': True,
            'commission_rate': Decimal('1.0'),
            'api_operator_code': 'BESCOM',
            'supports_view_bill': True
        },
        {
            'id': '31',
            'name': 'MSEDCL',
            'display_name': 'Maharashtra State Electricity Distribution Company',
            'state': 'Maharashtra',
            'type': 'electricity',
            'logo': 'msedcl.png',
            'validation_regex': r'^\d{10,12}$',
            'active': True,
            'commission_rate': Decimal('1.0'),
            'api_operator_code': 'MSEDCL',
            'supports_view_bill': True
        },
        {
            'id': '132',
            'name': 'TNEB',
            'display_name': 'Tamil Nadu Electricity Board',
            'state': 'Tamil Nadu',
            'type': 'electricity',
            'logo': 'tneb.png',
            'validation_regex': r'^\d{9,11}$',
            'active': True,
            'commission_rate': Decimal('1.0'),
            'api_operator_code': 'TNEB',
            'supports_view_bill': True
        },
        {
            'id': '175',
            'name': 'DHBVN',
            'display_name': 'Dakshin Haryana Bijli Vitran Nigam',
            'state': 'Haryana',
            'type': 'electricity',
            'logo': 'dhbvn.png',
            'validation_regex': r'^\d{10,12}$',
            'active': True,
            'commission_rate': Decimal('1.0'),
            'api_operator_code': 'DHBVN',
            'supports_view_bill': True
        }
    ]
    
    TELECOM_CIRCLES = [
        {'id': '1', 'name': 'Andhra Pradesh', 'code': 'AP'},
        {'id': '2', 'name': 'Assam', 'code': 'AS'},
        {'id': '3', 'name': 'Bihar & Jharkhand', 'code': 'BJ'},
        {'id': '4', 'name': 'Chennai', 'code': 'CH'},
        {'id': '5', 'name': 'Delhi & NCR', 'code': 'DL'},
        {'id': '6', 'name': 'Gujarat', 'code': 'GJ'},
        {'id': '7', 'name': 'Haryana', 'code': 'HR'},
        {'id': '8', 'name': 'Himachal Pradesh', 'code': 'HP'},
        {'id': '9', 'name': 'Jammu & Kashmir', 'code': 'JK'},
        {'id': '10', 'name': 'Karnataka', 'code': 'KA'},
        {'id': '11', 'name': 'Kerala', 'code': 'KL'},
        {'id': '12', 'name': 'Kolkata', 'code': 'KO'},
        {'id': '13', 'name': 'Maharashtra & Goa', 'code': 'MH'},
        {'id': '14', 'name': 'MP & Chattisgarh', 'code': 'MP'},
        {'id': '15', 'name': 'Mumbai', 'code': 'MU'},
        {'id': '16', 'name': 'North East', 'code': 'NE'},
        {'id': '17', 'name': 'Orissa', 'code': 'OR'},
        {'id': '18', 'name': 'Punjab', 'code': 'PB'},
        {'id': '19', 'name': 'Rajasthan', 'code': 'RJ'},
        {'id': '20', 'name': 'Tamil Nadu', 'code': 'TN'},
        {'id': '21', 'name': 'UP East', 'code': 'UE'},
        {'id': '22', 'name': 'UP West & Uttarakhand', 'code': 'UW'},
        {'id': '23', 'name': 'West Bengal', 'code': 'WB'},
        {'id': '51', 'name': 'All India', 'code': 'AI'}
    ]
    
    # =============================================================================
    # COMMISSION CONFIGURATION
    # =============================================================================
    
    COMMISSION_RULES = {
        'MOBILE_RECHARGE': {
            'default_rate': Decimal('2.0'),
            'retailer_rate': Decimal('1.0'),
            'distributor_rate': Decimal('0.5'),
            'master_distributor_rate': Decimal('0.3'),
            'white_label_rate': Decimal('0.2')
        },
        'DTH_RECHARGE': {
            'default_rate': Decimal('3.0'),
            'retailer_rate': Decimal('1.5'),
            'distributor_rate': Decimal('0.8'),
            'master_distributor_rate': Decimal('0.5'),
            'white_label_rate': Decimal('0.2')
        },
        'BILL_PAYMENT': {
            'default_rate': Decimal('1.0'),
            'retailer_rate': Decimal('0.5'),
            'distributor_rate': Decimal('0.3'),
            'master_distributor_rate': Decimal('0.1'),
            'white_label_rate': Decimal('0.1')
        }
    }
    
    # =============================================================================
    # BUSINESS RULES
    # =============================================================================
    
    # Transaction processing rules
    AUTO_PROCESS_LIMIT = Decimal('1000')  # Auto-process below this amount
    MANUAL_REVIEW_LIMIT = Decimal('10000')  # Manual review above this amount
    
    # Wallet rules
    MIN_WALLET_BALANCE = Decimal('10')
    WALLET_LOW_BALANCE_THRESHOLD = Decimal('100')
    
    # Retry logic
    MAX_RETRY_ATTEMPTS = 3
    RETRY_INTERVALS = [30, 120, 300]  # seconds: 30s, 2min, 5min
    
    # Session timeouts
    SESSION_TIMEOUT = timedelta(hours=2)
    TRANSACTION_TIMEOUT = timedelta(minutes=10)
    
    # =============================================================================
    # NOTIFICATION SETTINGS
    # =============================================================================
    
    NOTIFICATION_TEMPLATES = {
        'TRANSACTION_SUCCESS': {
            'sms': 'Transaction successful! Amount: Rs.{amount}, Service: {service}, Ref: {ref_id}',
            'email': 'Your {service} transaction of Rs.{amount} has been completed successfully.',
            'push': 'Transaction Success - Rs.{amount}'
        },
        'TRANSACTION_FAILED': {
            'sms': 'Transaction failed. Amount: Rs.{amount}, Reason: {reason}, Ref: {ref_id}',
            'email': 'Your {service} transaction of Rs.{amount} has failed. Reason: {reason}',
            'push': 'Transaction Failed - Rs.{amount}'
        },
        'LOW_BALANCE': {
            'sms': 'Low wallet balance alert! Current balance: Rs.{balance}. Recharge now.',
            'email': 'Your wallet balance is running low. Current balance: Rs.{balance}',
            'push': 'Low Balance Alert - Rs.{balance}'
        }
    }
    
    # =============================================================================
    # SECURITY SETTINGS
    # =============================================================================
    
    # API Security
    API_KEY_EXPIRY_DAYS = 365
    MAX_API_CALLS_PER_MINUTE = 100
    MAX_API_CALLS_PER_HOUR = 5000
    
    # Transaction Security
    MAX_FAILED_ATTEMPTS = 5
    ACCOUNT_LOCKOUT_DURATION = timedelta(hours=1)
    
    # IP Whitelisting (for production)
    ALLOWED_IP_RANGES = os.getenv('ALLOWED_IP_RANGES', '').split(',') if os.getenv('ALLOWED_IP_RANGES') else []
    
    # =============================================================================
    # CACHING CONFIGURATION
    # =============================================================================
    
    CACHE_CONFIG = {
        'plans_cache_duration': 3600,  # 1 hour
        'operator_status_cache': 300,  # 5 minutes
        'balance_cache_duration': 60,  # 1 minute
        'commission_cache_duration': 3600  # 1 hour
    }
    
    # =============================================================================
    # LOGGING CONFIGURATION
    # =============================================================================
    
    LOGGING_CONFIG = {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'standard': {
                'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
            },
            'detailed': {
                'format': '%(asctime)s [%(levelname)s] %(name)s:%(lineno)d: %(message)s'
            }
        },
        'handlers': {
            'default': {
                'level': 'INFO',
                'formatter': 'standard',
                'class': 'logging.StreamHandler'
            },
            'file': {
                'level': 'DEBUG',
                'formatter': 'detailed',
                'class': 'logging.handlers.RotatingFileHandler',
                'filename': 'logs/recharge.log',
                'maxBytes': 10485760,  # 10MB
                'backupCount': 5
            }
        },
        'loggers': {
            'recharge': {
                'handlers': ['default', 'file'],
                'level': 'DEBUG',
                'propagate': False
            }
        }
    }
    
    # =============================================================================
    # ENVIRONMENT-SPECIFIC SETTINGS
    # =============================================================================
    
    @classmethod
    def get_environment_config(cls):
        """Get environment-specific configuration"""
        env = os.getenv('FLASK_ENV', 'development')
        
        if env == 'production':
            return {
                'API_TIMEOUT': 15,
                'MAX_RETRY_ATTEMPTS': 2,
                'SESSION_TIMEOUT': timedelta(hours=1),
                'DEBUG_MODE': False,
                'CACHE_ENABLED': True
            }
        elif env == 'testing':
            return {
                'API_TIMEOUT': 5,
                'MAX_RETRY_ATTEMPTS': 1,
                'SESSION_TIMEOUT': timedelta(minutes=10),
                'DEBUG_MODE': True,
                'CACHE_ENABLED': False
            }
        else:  # development
            return {
                'API_TIMEOUT': 30,
                'MAX_RETRY_ATTEMPTS': 3,
                'SESSION_TIMEOUT': timedelta(hours=8),
                'DEBUG_MODE': True,
                'CACHE_ENABLED': False
            }
    
    # =============================================================================
    # UTILITY METHODS
    # =============================================================================
    
    @classmethod
    def get_operator_by_id(cls, operator_id: str, service_type: str) -> Dict[str, Any]:
        """Get operator configuration by ID"""
        operators_map = {
            'mobile': cls.MOBILE_OPERATORS,
            'dth': cls.DTH_OPERATORS,
            'bill': cls.BILL_OPERATORS
        }
        
        operators = operators_map.get(service_type, [])
        return next((op for op in operators if op['id'] == operator_id), None)
    
    @classmethod
    def get_circle_by_id(cls, circle_id: str) -> Dict[str, Any]:
        """Get circle configuration by ID"""
        return next((circle for circle in cls.TELECOM_CIRCLES if circle['id'] == circle_id), None)
    
    @classmethod
    def get_transaction_limits(cls, service_type: str) -> Dict[str, Decimal]:
        """Get transaction limits for service type"""
        return cls.TRANSACTION_LIMITS.get(service_type, {})
    
    @classmethod
    def get_commission_rate(cls, service_type: str, user_role: str) -> Decimal:
        """Get commission rate for service type and user role"""
        rules = cls.COMMISSION_RULES.get(service_type, {})
        role_key = f"{user_role.lower()}_rate"
        return rules.get(role_key, rules.get('default_rate', Decimal('0')))
    
    @classmethod
    def is_amount_valid(cls, service_type: str, amount: Decimal) -> tuple[bool, str]:
        """Validate transaction amount"""
        limits = cls.get_transaction_limits(service_type)
        
        if not limits:
            return False, "Service type not supported"
        
        min_amount = limits.get('min_amount', Decimal('0'))
        max_amount = limits.get('max_amount', Decimal('999999'))
        
        if amount < min_amount:
            return False, f"Minimum amount is ₹{min_amount}"
        
        if amount > max_amount:
            return False, f"Maximum amount is ₹{max_amount}"
        
        return True, "Valid amount"
    
    @classmethod
    def validate_mobile_number(cls, mobile_number: str, operator_id: str = None) -> tuple[bool, str]:
        """Validate mobile number format"""
        if not mobile_number or len(mobile_number) != 10:
            return False, "Mobile number must be 10 digits"
        
        if not mobile_number.isdigit():
            return False, "Mobile number must contain only digits"
        
        if not mobile_number.startswith(('6', '7', '8', '9')):
            return False, "Mobile number must start with 6, 7, 8, or 9"
        
        # Additional operator-specific validation if operator_id provided
        if operator_id:
            operator = cls.get_operator_by_id(operator_id, 'mobile')
            if operator and 'validation_regex' in operator:
                import re
                if not re.match(operator['validation_regex'], mobile_number):
                    return False, f"Invalid mobile number for {operator['name']}"
        
        return True, "Valid mobile number"
    
    @classmethod
    def validate_customer_id(cls, customer_id: str, operator_id: str, service_type: str) -> tuple[bool, str]:
        """Validate customer ID for DTH/Bill payment"""
        operator = cls.get_operator_by_id(operator_id, service_type)
        
        if not operator:
            return False, "Invalid operator"
        
        if 'validation_regex' in operator:
            import re
            if not re.match(operator['validation_regex'], customer_id):
                return False, f"Invalid customer ID format for {operator['name']}"
        
        return True, "Valid customer ID"


# =============================================================================
# DEVELOPMENT/TESTING HELPERS
# =============================================================================

class TestingConfig(RechargeConfig):
    """Testing-specific configuration"""
    
    # Override with test values
    MOBIKWIK_BASE_URL = 'http://localhost:5000/mock-api'
    API_TIMEOUT = 5
    MAX_RETRY_ATTEMPTS = 1
    
    # Test operators with mock responses
    TEST_MOBILE_NUMBERS = {
        'success': ['9999999999', '8888888888'],
        'failed': ['7777777777'],
        'pending': ['6666666666']
    }
    
    TEST_DTH_CUSTOMER_IDS = {
        'success': ['1234567890', '0987654321'],
        'failed': ['1111111111'],
        'pending': ['2222222222']
    }


# =============================================================================
# CONFIGURATION FACTORY
# =============================================================================

def get_recharge_config():
    """Factory function to get appropriate configuration"""
    env = os.getenv('FLASK_ENV', 'development')
    
    if env == 'testing':
        return TestingConfig()
    else:
        return RechargeConfig()


# Export for easy importing
config = get_recharge_config()