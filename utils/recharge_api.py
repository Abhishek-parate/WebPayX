# utils/recharge_api.py
"""
Recharge API Integration Utilities
==================================

This module provides utilities for integrating with external recharge APIs
including MobiKwik, operator APIs, and other service providers.
"""

import hashlib
import hmac
import json
import logging
import time
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Dict, List, Optional, Tuple, Any
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from functools import wraps
from config.recharge_config import RechargeConfig

# Configure logging
logger = logging.getLogger('recharge.api')

class APIError(Exception):
    """Custom exception for API errors"""
    def __init__(self, message: str, status_code: int = None, response_data: dict = None):
        super().__init__(message)
        self.status_code = status_code
        self.response_data = response_data or {}

class RateLimitExceeded(APIError):
    """Exception raised when API rate limit is exceeded"""
    pass

class TransactionTimeout(APIError):
    """Exception raised when transaction times out"""
    pass

# =============================================================================
# DECORATORS
# =============================================================================

def retry_on_failure(max_retries: int = 3, delay: float = 1.0, backoff: float = 2.0):
    """Decorator to retry API calls on failure"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except (requests.RequestException, APIError) as e:
                    last_exception = e
                    if attempt < max_retries - 1:
                        wait_time = delay * (backoff ** attempt)
                        logger.warning(f"API call failed, retrying in {wait_time}s. Attempt {attempt + 1}/{max_retries}")
                        time.sleep(wait_time)
                    else:
                        logger.error(f"API call failed after {max_retries} attempts")
                        
            raise last_exception
        return wrapper
    return decorator

def log_api_call(func):
    """Decorator to log API calls"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        func_name = func.__name__
        
        logger.info(f"Starting API call: {func_name}")
        
        try:
            result = func(*args, **kwargs)
            elapsed_time = time.time() - start_time
            logger.info(f"API call {func_name} completed successfully in {elapsed_time:.2f}s")
            return result
        except Exception as e:
            elapsed_time = time.time() - start_time
            logger.error(f"API call {func_name} failed after {elapsed_time:.2f}s: {str(e)}")
            raise
    return wrapper

# =============================================================================
# BASE API CLIENT
# =============================================================================

class BaseAPIClient:
    """Base class for API clients with common functionality"""
    
    def __init__(self, base_url: str, timeout: int = 30):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.session = self._create_session()
        
    def _create_session(self) -> requests.Session:
        """Create a requests session with retry strategy"""
        session = requests.Session()
        
        # Retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        
        # Mount adapter
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        return session
    
    def _make_request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """Make HTTP request with error handling"""
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        
        try:
            response = self.session.request(
                method=method,
                url=url,
                timeout=self.timeout,
                **kwargs
            )
            
            # Log request details
            logger.debug(f"{method} {url} - Status: {response.status_code}")
            
            return response
            
        except requests.exceptions.Timeout:
            raise TransactionTimeout(f"Request to {url} timed out after {self.timeout}s")
        except requests.exceptions.ConnectionError as e:
            raise APIError(f"Connection error: {str(e)}")
        except requests.exceptions.RequestException as e:
            raise APIError(f"Request error: {str(e)}")

# =============================================================================
# MOBIKWIK API CLIENT
# =============================================================================

class MobiKwikAPIClient(BaseAPIClient):
    """MobiKwik API client for recharge operations"""
    
    def __init__(self):
        super().__init__(RechargeConfig.MOBIKWIK_BASE_URL)
        self.api_key = RechargeConfig.MOBIKWIK_API_KEY
        self.user_id = RechargeConfig.MOBIKWIK_USER_ID
        self.password = RechargeConfig.MOBIKWIK_PASSWORD
        
    def _generate_checksum(self, data: dict) -> str:
        """Generate HMAC SHA256 checksum for request"""
        # Create the data string in the exact format required by MobiKwik
        data_string = json.dumps(data, separators=(',', ':'), sort_keys=True)
        
        # Generate HMAC SHA256 signature
        signature = hmac.new(
            self.api_key.encode('utf-8'),
            data_string.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        return signature
    
    @log_api_call
    @retry_on_failure(max_retries=2, delay=2.0)
    def check_balance(self) -> Dict[str, Any]:
        """Check wallet balance"""
        endpoint = "recharge/v1/retailerBalance"
        
        data = {
            "uid": self.user_id,
            "password": self.password,
            "memberId": self.user_id
        }
        
        headers = {
            'Content-Type': 'application/json',
            'X-MClient': '14'
        }
        
        response = self._make_request('POST', endpoint, json=data, headers=headers)
        
        if response.status_code != 200:
            raise APIError(f"Balance check failed: {response.status_code}", response.status_code)
        
        result = response.json()
        
        if not result.get('success'):
            raise APIError(f"Balance check failed: {result.get('message', 'Unknown error')}")
        
        return result
    
    @log_api_call
    @retry_on_failure(max_retries=2, delay=2.0)
    def validate_recharge(self, mobile: str, operator: str, circle: str, amount: Decimal) -> Dict[str, Any]:
        """Validate recharge parameters"""
        endpoint = "recharge/v1/retailerValidation"
        
        data = {
            "uid": self.user_id,
            "password": self.password,
            "amt": str(amount),
            "cir": circle,
            "cn": mobile,
            "op": operator,
            "adParams": {}
        }
        
        headers = {
            'Content-Type': 'application/json',
            'X-MClient': '14',
            'checkSum': self._generate_checksum(data)
        }
        
        response = self._make_request('POST', endpoint, json=data, headers=headers)
        
        if response.status_code != 200:
            raise APIError(f"Validation failed: {response.status_code}", response.status_code)
        
        result = response.json()
        
        return result
    
    @log_api_call
    @retry_on_failure(max_retries=2, delay=3.0)
    def process_recharge(self, mobile: str, operator: str, circle: str, amount: Decimal, 
                        request_id: str, **kwargs) -> Dict[str, Any]:
        """Process mobile recharge"""
        endpoint = "recharge.do"
        
        params = {
            'uid': self.user_id,
            'pwd': self.password,
            'cn': mobile,
            'op': operator,
            'cir': circle,
            'amt': str(amount),
            'reqid': request_id,
        }
        
        # Add optional parameters
        optional_params = ['pvalue', 'ad1', 'ad2', 'ad3', 'ad4', 'ad5', 'ad6',
                          'agtcode', 'initchl', 'trmnid', 'geocode', 'pstlcode', 'agtmob']
        
        for param in optional_params:
            if param in kwargs:
                params[param] = kwargs[param]
        
        response = self._make_request('GET', endpoint, params=params)
        
        if response.status_code != 200:
            raise APIError(f"Recharge failed: {response.status_code}", response.status_code)
        
        # Parse XML response
        return self._parse_xml_response(response.text)
    
    @log_api_call
    @retry_on_failure(max_retries=3, delay=2.0)
    def check_transaction_status(self, transaction_id: str) -> Dict[str, Any]:
        """Check transaction status"""
        endpoint = "rechargeStatus.do"
        
        params = {
            'uid': self.user_id,
            'pwd': self.password,
            'txId': transaction_id
        }
        
        response = self._make_request('GET', endpoint, params=params)
        
        if response.status_code != 200:
            raise APIError(f"Status check failed: {response.status_code}", response.status_code)
        
        return self._parse_xml_response(response.text)
    
    @log_api_call
    @retry_on_failure(max_retries=2, delay=2.0)
    def fetch_recharge_plans(self, operator_id: str, circle_id: str, plan_type: str = None) -> Dict[str, Any]:
        """Fetch recharge plans"""
        if plan_type:
            endpoint = f"recharge/v1/rechargePlansAPI/{operator_id}/{circle_id}/{plan_type}"
        else:
            endpoint = f"recharge/v1/rechargePlansAPI/{operator_id}/{circle_id}"
        
        headers = {
            'Content-Type': 'application/json',
            'X-MClient': '14'
        }
        
        response = self._make_request('GET', endpoint, headers=headers)
        
        if response.status_code != 200:
            raise APIError(f"Plans fetch failed: {response.status_code}", response.status_code)
        
        result = response.json()
        
        if not result.get('success'):
            raise APIError(f"Plans fetch failed: {result.get('message', 'Unknown error')}")
        
        return result
    
    @log_api_call
    @retry_on_failure(max_retries=2, delay=2.0)
    def view_bill(self, connection_number: str, operator_id: str, circle_id: str = None, **kwargs) -> Dict[str, Any]:
        """View bill details"""
        endpoint = "retailer/v2/retailerViewbill"
        
        data = {
            "uid": self.user_id,
            "pswd": self.password,
            "cn": connection_number,
            "op": operator_id,
            "adParams": {}
        }
        
        if circle_id:
            data["cir"] = circle_id
        
        # Add additional parameters
        if kwargs:
            data["adParams"].update(kwargs)
        
        headers = {
            'Content-Type': 'application/json',
            'X-MClient': '14'
        }
        
        response = self._make_request('POST', endpoint, json=data, headers=headers)
        
        if response.status_code != 200:
            raise APIError(f"View bill failed: {response.status_code}", response.status_code)
        
        result = response.json()
        
        if not result.get('success'):
            raise APIError(f"View bill failed: {result.get('message', 'Unknown error')}")
        
        return result
    
    def _parse_xml_response(self, xml_content: str) -> Dict[str, Any]:
        """Parse XML response from MobiKwik API"""
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml_content)
            
            result = {}
            for child in root:
                result[child.tag] = child.text
            
            return result
            
        except ET.ParseError as e:
            logger.error(f"Failed to parse XML response: {e}")
            raise APIError(f"Invalid XML response: {str(e)}")

# =============================================================================
# RECHARGE SERVICE MANAGER
# =============================================================================

class RechargeServiceManager:
    """High-level service manager for recharge operations"""
    
    def __init__(self):
        self.mobikwik_client = MobiKwikAPIClient()
        self.config = RechargeConfig()
        
    def validate_mobile_recharge(self, mobile: str, operator_id: str, circle_id: str, 
                               amount: Decimal) -> Tuple[bool, str, Dict[str, Any]]:
        """Validate mobile recharge parameters"""
        try:
            # Basic validation
            is_valid, message = self.config.validate_mobile_number(mobile, operator_id)
            if not is_valid:
                return False, message, {}
            
            is_valid, message = self.config.is_amount_valid('MOBILE_RECHARGE', amount)
            if not is_valid:
                return False, message, {}
            
            # API validation
            result = self.mobikwik_client.validate_recharge(mobile, operator_id, circle_id, amount)
            
            if result.get('success'):
                return True, "Validation successful", result.get('data', {})
            else:
                error_msg = result.get('message', {}).get('text', 'Validation failed')
                return False, error_msg, result.get('data', {})
                
        except APIError as e:
            logger.error(f"Mobile recharge validation error: {e}")
            return False, f"Validation error: {str(e)}", {}
        except Exception as e:
            logger.error(f"Unexpected error in mobile recharge validation: {e}")
            return False, "Validation failed due to system error", {}
    
    def process_mobile_recharge(self, mobile: str, operator_id: str, circle_id: str,
                              amount: Decimal, request_id: str, **kwargs) -> Dict[str, Any]:
        """Process mobile recharge transaction"""
        try:
            # Validate before processing
            is_valid, message, _ = self.validate_mobile_recharge(mobile, operator_id, circle_id, amount)
            if not is_valid:
                return {
                    'success': False,
                    'status': 'FAILED',
                    'message': message
                }
            
            # Process recharge
            result = self.mobikwik_client.process_recharge(
                mobile, operator_id, circle_id, amount, request_id, **kwargs
            )
            
            # Normalize response
            status = result.get('status', 'UNKNOWN')
            
            return {
                'success': status in ['SUCCESS', 'SUCCESSPENDING'],
                'status': self._normalize_status(status),
                'transaction_id': result.get('txId'),
                'operator_ref': result.get('opRefNo'),
                'balance': result.get('balance'),
                'raw_response': result
            }
            
        except APIError as e:
            logger.error(f"Mobile recharge processing error: {e}")
            return {
                'success': False,
                'status': 'FAILED',
                'message': str(e),
                'error_code': e.status_code
            }
        except Exception as e:
            logger.error(f"Unexpected error in mobile recharge processing: {e}")
            return {
                'success': False,
                'status': 'FAILED',
                'message': "Transaction failed due to system error"
            }
    
    def get_recharge_plans(self, operator_id: str, circle_id: str, 
                          plan_type: str = None) -> Dict[str, Any]:
        """Get recharge plans for operator and circle"""
        try:
            result = self.mobikwik_client.fetch_recharge_plans(operator_id, circle_id, plan_type)
            
            if result.get('success'):
                plans = result.get('data', {}).get('plans', [])
                
                # Process and categorize plans
                categorized_plans = self._categorize_plans(plans)
                
                return {
                    'success': True,
                    'plans': plans,
                    'categorized_plans': categorized_plans,
                    'total_plans': len(plans)
                }
            else:
                error_msg = result.get('message', {}).get('text', 'Plans not available')
                return {
                    'success': False,
                    'message': error_msg,
                    'plans': []
                }
                
        except APIError as e:
            logger.error(f"Plans fetch error: {e}")
            return {
                'success': False,
                'message': f"Error fetching plans: {str(e)}",
                'plans': []
            }
    
    def view_bill_details(self, connection_number: str, operator_id: str, 
                         service_type: str = 'bill') -> Dict[str, Any]:
        """View bill details for connection"""
        try:
            # Validate connection number
            is_valid, message = self.config.validate_customer_id(
                connection_number, operator_id, service_type
            )
            if not is_valid:
                return {
                    'success': False,
                    'message': message
                }
            
            result = self.mobikwik_client.view_bill(connection_number, operator_id)
            
            if result.get('success'):
                bill_data = result.get('data', [])
                if bill_data and len(bill_data) > 0:
                    return {
                        'success': True,
                        'bill_data': bill_data[0],  # Usually first element contains bill info
                        'raw_response': result
                    }
                else:
                    return {
                        'success': False,
                        'message': 'No bill information found'
                    }
            else:
                return {
                    'success': False,
                    'message': result.get('message', 'Bill fetch failed')
                }
                
        except APIError as e:
            logger.error(f"Bill view error: {e}")
            return {
                'success': False,
                'message': f"Error fetching bill: {str(e)}"
            }
    
    def check_transaction_status(self, transaction_id: str) -> Dict[str, Any]:
        """Check status of existing transaction"""
        try:
            result = self.mobikwik_client.check_transaction_status(transaction_id)
            
            query_status = result.get('queryStatus')
            transaction_status = result.get('status')
            
            if query_status == 'SUCCESS':
                return {
                    'success': True,
                    'status': self._normalize_status(transaction_status),
                    'transaction_id': result.get('txId'),
                    'operator_ref': result.get('operatorrefno'),
                    'amount': result.get('amount'),
                    'status_details': result.get('statusDetails'),
                    'raw_response': result
                }
            else:
                return {
                    'success': False,
                    'message': result.get('errorMsg', 'Status check failed'),
                    'raw_response': result
                }
                
        except APIError as e:
            logger.error(f"Transaction status check error: {e}")
            return {
                'success': False,
                'message': f"Error checking status: {str(e)}"
            }
    
    def check_balance(self) -> Dict[str, Any]:
        """Check API provider balance"""
        try:
            result = self.mobikwik_client.check_balance()
            
            if result.get('success'):
                balance_data = result.get('data', {})
                return {
                    'success': True,
                    'balance': balance_data.get('balance', 0),
                    'raw_response': result
                }
            else:
                return {
                    'success': False,
                    'message': result.get('message', 'Balance check failed')
                }
                
        except APIError as e:
            logger.error(f"Balance check error: {e}")
            return {
                'success': False,
                'message': f"Error checking balance: {str(e)}"
            }
    
    def _normalize_status(self, status: str) -> str:
        """Normalize API status to standard format"""
        status_mapping = {
            'SUCCESS': 'SUCCESS',
            'SUCCESSPENDING': 'PROCESSING',
            'RECHARGESUCCESS': 'SUCCESS',
            'RECHARGESUCCESSPENDING': 'PROCESSING',
            'FAILURE': 'FAILED',
            'RECHARGEFAILURE': 'FAILED',
            'FAILED': 'FAILED'
        }
        
        return status_mapping.get(status, 'UNKNOWN')
    
    def _categorize_plans(self, plans: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Categorize plans by type"""
        categorized = {
            'popular': [],
            'topup': [],
            'special': [],
            'data': [],
            'talktime': [],
            'sms': [],
            'other': []
        }
        
        for plan in plans:
            plan_type = plan.get('planType', 0)
            plan_name = plan.get('planName', '').lower()
            is_popular = plan.get('isPopular', 0)
            is_special = plan.get('special', False)
            
            if is_popular or 'popular' in plan_name:
                categorized['popular'].append(plan)
            elif plan_type == 3 or 'topup' in plan_name or 'talktime' in plan_name:
                categorized['topup'].append(plan)
            elif is_special or plan_type == 17 or 'special' in plan_name:
                categorized['special'].append(plan)
            elif 'data' in plan_name or plan_type in [9, 18]:
                categorized['data'].append(plan)
            elif 'sms' in plan_name or plan_type in [5, 6, 7]:
                categorized['sms'].append(plan)
            else:
                categorized['other'].append(plan)
        
        return categorized

# =============================================================================
# FACTORY FUNCTION
# =============================================================================

def get_recharge_service() -> RechargeServiceManager:
    """Factory function to get recharge service manager"""
    return RechargeServiceManager()

# =============================================================================
# TESTING UTILITIES
# =============================================================================

class MockRechargeAPI:
    """Mock API for testing purposes"""
    
    def __init__(self):
        self.test_responses = {
            'balance': {'success': True, 'data': {'balance': 100000.0}},
            'validation_success': {'success': True, 'data': {'status': 'RECHARGEVALIDATIONSUCCESS'}},
            'validation_failed': {'success': False, 'message': {'text': 'Invalid number'}},
            'recharge_success': {'status': 'SUCCESS', 'txId': 'TEST123', 'balance': '99950.0'},
            'recharge_pending': {'status': 'SUCCESSPENDING', 'txId': 'TEST124', 'balance': '99950.0'},
            'recharge_failed': {'status': 'FAILURE', 'errorMsg': 'Recharge failed'},
        }
    
    def get_mock_response(self, scenario: str) -> Dict[str, Any]:
        """Get mock response for testing"""
        return self.test_responses.get(scenario, {})


if __name__ == "__main__":
    # Example usage
    service = get_recharge_service()
    
    # Test balance check
    balance_result = service.check_balance()
    print("Balance check:", balance_result)
    
    # Test mobile validation
    validation_result = service.validate_mobile_recharge(
        mobile="9999999999",
        operator_id="1",
        circle_id="5",
        amount=Decimal("100")
    )
    print("Validation result:", validation_result)