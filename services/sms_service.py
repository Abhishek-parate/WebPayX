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
        # Remove any spaces, dashes, or special characters
        phone_number = ''.join(filter(str.isdigit, phone_number))
        
        # Remove leading + if present
        if phone_number.startswith('+'):
            phone_number = phone_number[1:]
        
        # Remove leading 0 if present
        if phone_number.startswith('0'):
            phone_number = phone_number[1:]
        
        # Add 91 country code if not present
        if not phone_number.startswith('91'):
            phone_number = '91' + phone_number
        
        return phone_number
    
    def send_otp_sms(self, phone_number: str, otp_code: str, user_name: str = "User") -> Dict[str, Any]:
        """Send OTP via SMS using exact template format"""
        try:
            # Format phone number properly
            formatted_phone = self.format_phone_number(phone_number)
            
            # Create message - EXACT template format
            message = f"Dear {user_name}, your OTP for mobile verification is {otp_code}. Team OPTIONPAY"
            
            # Encode message for URL
            encoded_message = quote(message)
            
            # Construct API URL with EXACT parameters
            url = f"{self.api_url}?apikey={self.api_key}&senderid={self.sender_id}&number={formatted_phone}&message={encoded_message}&format=json"
            
            # Log the request
            logger.info(f"Sending SMS to {formatted_phone[:5]}****{formatted_phone[-4:]}")
            logger.debug(f"SMS URL: {url[:150]}...")
            
            # Send SMS with timeout
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            # Parse response
            try:
                result = response.json()
            except ValueError:
                result = {"status": "ERROR", "message": "Invalid JSON response", "raw": response.text}
            
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
                    'original_phone': phone_number
                }
            else:
                logger.error(f"SMS sending failed for {formatted_phone}: {result}")
                return {
                    'success': False,
                    'error': f"SMS sending failed: {result.get('message', 'Unknown error')}",
                    'phone_number': formatted_phone,
                    'api_response': result
                }
            
        except requests.exceptions.Timeout:
            logger.error(f"SMS API timeout for {phone_number}")
            return {
                'success': False,
                'error': 'SMS API request timed out',
                'phone_number': phone_number
            }
        except requests.exceptions.RequestException as e:
            logger.error(f"SMS API request failed for {phone_number}: {str(e)}")
            return {
                'success': False,
                'error': f"SMS API request failed: {str(e)}",
                'phone_number': phone_number
            }
        except Exception as e:
            logger.error(f"Unexpected error sending SMS to {phone_number}: {str(e)}")
            return {
                'success': False,
                'error': f"Unexpected error: {str(e)}",
                'phone_number': phone_number
            }
    
    def send_password_reset_sms(self, phone_number: str, otp_code: str, user_name: str = "User") -> Dict[str, Any]:
        """Send password reset OTP via SMS"""
        try:
            formatted_phone = self.format_phone_number(phone_number)
            
            # Password reset message
            message = f"Dear {user_name}, your password reset OTP is {otp_code}. Valid for 10 minutes. Team OPTIONPAY"
            encoded_message = quote(message)
            
            url = f"{self.api_url}?apikey={self.api_key}&senderid={self.sender_id}&number={formatted_phone}&message={encoded_message}&format=json"
            
            logger.info(f"Sending password reset SMS to {formatted_phone[:5]}****{formatted_phone[-4:]}")
            
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            try:
                result = response.json()
            except ValueError:
                result = {"status": "ERROR", "message": "Invalid JSON response", "raw": response.text}
            
            if result.get('status') == 'OK':
                logger.info(f"Password reset SMS sent to {formatted_phone}")
                return {
                    'success': True,
                    'message': 'Password reset SMS sent successfully',
                    'response': result,
                    'phone_number': formatted_phone,
                    'message_id': result.get('msgid'),
                    'api_response': result
                }
            else:
                logger.error(f"Password reset SMS failed for {formatted_phone}: {result}")
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
                'phone_number': phone_number
            }

# CORRECTED: Create SMS service instance with proper parameter names
sms_service = SMSService(
    api_url="http://3.6.222.97/V2/http-api.php",
    api_key="0qJkwMLvC4sdrHVy",  # ✅ CORRECT: api_key (not api_secret)
    sender_id="OPNPAY"
)
