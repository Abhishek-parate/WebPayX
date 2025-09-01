# utils/sms_service.py
import requests
from urllib.parse import quote
import logging
from typing import Dict, Any


logger = logging.getLogger(__name__)


class SMSService:
    """SMS service for sending OTP and notifications"""
    
    def __init__(self, api_url: str, api_key: str, sender_id: str):
        self.api_url = api_url
        self.api_key = api_key
        self.sender_id = sender_id
    
    def format_phone_number(self, phone_number: str) -> str:
        """Format phone number correctly for API"""
        # Ensure phone_number is always a string to prevent scientific notation
        phone_str = str(phone_number)
        
        # Remove any non-digit characters
        phone_clean = ''.join(filter(str.isdigit, phone_str))
        
        # Remove leading + if present
        if phone_clean.startswith('+'):
            phone_clean = phone_clean[1:]
        
        # Remove leading 0 if present
        if phone_clean.startswith('0'):
            phone_clean = phone_clean[1:]
        
        # Add 91 country code if not present
        if not phone_clean.startswith('91'):
            phone_clean = '91' + phone_clean
        
        return phone_clean
    
    def send_otp_sms(self, phone_number: str, otp_code: str, user_name: str = "User") -> Dict[str, Any]:
        """Send OTP via SMS using DLT approved template format"""
        try:
            # Format phone number properly - ensure it's always a string
            formatted_phone = self.format_phone_number(str(phone_number))
            
            # 🎯 UPDATED: Using your DLT approved template with actual OTP
            message = f"Dear user, your OTP for mobile verification is {otp_code}. Team OPTIONPAY"
            
            # Encode message for URL
            encoded_message = quote(message)
            
            # Construct API URL with EXACT parameter order
            url = f"{self.api_url}?apikey={self.api_key}&senderid={self.sender_id}&number={formatted_phone}&message={encoded_message}&format=json"
            
            # Log for debugging
            logger.info(f"Sending SMS to {formatted_phone}")
            logger.info(f"Message: {message}")
            logger.info(f"Generated URL: {url}")
            
            # Send SMS with proper headers
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'application/json',
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            
            response = requests.get(url, timeout=30, headers=headers)
            response.raise_for_status()
            
            # Parse response
            try:
                result = response.json()
            except ValueError:
                result = {"status": "ERROR", "message": "Invalid JSON response", "raw": response.text}
            
            logger.info(f"SMS API Response: {result}")
            
            # Check if SMS was successful
            if result.get('status') == 'OK':
                logger.info(f"SMS sent successfully to {formatted_phone}: {result.get('msgid')}")
                return {
                    'success': True,
                    'message': 'SMS sent successfully',
                    'response': result,
                    'phone_number': formatted_phone,
                    'message_id': result.get('msgid'),
                    'api_response': result,
                    'formatted_phone': formatted_phone,
                    'original_phone': str(phone_number),
                    'sent_message': message,  # Add this for debugging
                    'debug_url': url[:100] + "..."  # Truncated for security
                }
            else:
                logger.error(f"SMS sending failed for {formatted_phone}: {result}")
                return {
                    'success': False,
                    'error': f"SMS sending failed: {result.get('message', 'Unknown error')}",
                    'phone_number': formatted_phone,
                    'api_response': result,
                    'debug_url': url[:100] + "..."
                }
            
        except requests.exceptions.Timeout:
            logger.error(f"SMS API timeout for {phone_number}")
            return {
                'success': False,
                'error': 'SMS API request timed out',
                'phone_number': str(phone_number)
            }
        except requests.exceptions.RequestException as e:
            logger.error(f"SMS API request failed for {phone_number}: {str(e)}")
            return {
                'success': False,
                'error': f"SMS API request failed: {str(e)}",
                'phone_number': str(phone_number)
            }
        except Exception as e:
            logger.error(f"Unexpected error sending SMS to {phone_number}: {str(e)}")
            return {
                'success': False,
                'error': f"Unexpected error: {str(e)}",
                'phone_number': str(phone_number)
            }
    
    def send_password_reset_sms(self, phone_number: str, otp_code: str, user_name: str = "User") -> Dict[str, Any]:
        """Send password reset OTP via SMS using DLT approved template"""
        try:
            formatted_phone = self.format_phone_number(str(phone_number))
            
            # 🎯 UPDATED: Using DLT template for password reset
            message = f"Dear user, your OTP for mobile verification is {otp_code}. Team OPTIONPAY"
            encoded_message = quote(message)
            
            url = f"{self.api_url}?apikey={self.api_key}&senderid={self.sender_id}&number={formatted_phone}&message={encoded_message}&format=json"
            
            logger.info(f"Sending password reset SMS to {formatted_phone}")
            logger.info(f"Reset message: {message}")
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'application/json'
            }
            
            response = requests.get(url, timeout=30, headers=headers)
            response.raise_for_status()
            
            try:
                result = response.json()
            except ValueError:
                result = {"status": "ERROR", "message": "Invalid JSON response", "raw": response.text}
            
            logger.info(f"Password reset SMS API Response: {result}")
            
            if result.get('status') == 'OK':
                return {
                    'success': True,
                    'message': 'Password reset SMS sent successfully',
                    'response': result,
                    'phone_number': formatted_phone,
                    'message_id': result.get('msgid'),
                    'api_response': result,
                    'sent_message': message
                }
            else:
                return {
                    'success': False,
                    'error': f"Password reset SMS failed: {result.get('message', 'Unknown error')}",
                    'phone_number': formatted_phone,
                    'api_response': result
                }
            
        except Exception as e:
            logger.error(f"Password reset SMS error for {phone_number}: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'phone_number': str(phone_number)
            }


# Create SMS service instance with your working credentials
sms_service = SMSService(
    api_url="http://3.6.222.97/V2/http-api.php",
    api_key="0qJkwMLvC4sdrHVy",  # Your working API key
    sender_id="OPNPAY"
)
