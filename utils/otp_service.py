# utils/otp_service.py
import random
import string
from datetime import datetime, timedelta
from typing import Optional
from models import OTPVerification, OTPType, OTPStatus, User, db
from utils.sms_service import sms_service
import logging

logger = logging.getLogger(__name__)

class OTPService:
    """OTP generation and verification service"""
    
    @staticmethod
    def generate_otp(length: int = 6) -> str:
        """Generate random OTP"""
        return ''.join(random.choices(string.digits, k=length))
    
    @staticmethod
    def send_login_otp(user_id: str, phone_number: str, user_name: str = "User", 
                      session_id: str = None, ip_address: str = None, user_agent: str = None) -> dict:
        """Send OTP for login verification"""
        try:
            # Generate OTP
            otp_code = OTPService.generate_otp()
            
            # Invalidate any existing login OTPs for this user
            OTPVerification.query.filter_by(
                user_id=user_id,
                otp_type=OTPType.LOGIN,
                status=OTPStatus.PENDING
            ).update({'status': OTPStatus.EXPIRED})
            
            # Create new OTP record
            otp_record = OTPVerification(
                user_id=user_id,
                phone_number=phone_number,
                otp_code=otp_code,
                otp_type=OTPType.LOGIN,
                status=OTPStatus.PENDING,
                expires_at=datetime.utcnow() + timedelta(minutes=5),
                ip_address=ip_address,
                user_agent=user_agent,
                session_id=session_id,
                meta_data={'purpose': 'login_verification'}
            )
            
            db.session.add(otp_record)
            db.session.flush()  # Get the ID before commit
            
            # Send SMS
            sms_result = sms_service.send_otp_sms(phone_number, otp_code, user_name)
            
            # Update OTP record with SMS result
            otp_record.meta_data.update({
                'sms_response': sms_result,
                'sms_sent_at': datetime.utcnow().isoformat()
            })
            
            if sms_result['success']:
                logger.info(f"Login OTP sent successfully to user {user_id}: {sms_result.get('message_id')}")
                db.session.commit()
                return {
                    'success': True,
                    'message': 'OTP sent successfully',
                    'otp_id': str(otp_record.id),
                    'expires_in_minutes': 5,
                    'sms_details': {
                        'message_id': sms_result.get('message_id'),
                        'status': sms_result.get('response', {}).get('status'),
                        'api_response': sms_result.get('api_response')
                    }
                }
            else:
                # Mark OTP as failed if SMS couldn't be sent
                otp_record.status = OTPStatus.FAILED
                otp_record.meta_data.update({'sms_error': sms_result['error']})
                db.session.commit()
                
                logger.error(f"Failed to send login OTP to user {user_id}: {sms_result['error']}")
                return {
                    'success': False,
                    'error': 'Failed to send OTP SMS',
                    'details': sms_result['error'],
                    'sms_response': sms_result.get('api_response')
                }
                
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error sending login OTP: {str(e)}")
            return {
                'success': False,
                'error': f'Error sending OTP: {str(e)}'
            }
    
    @staticmethod
    def send_password_reset_otp(phone_number: str, user_name: str = "User",
                              ip_address: str = None, user_agent: str = None) -> dict:
        """Send OTP for password reset"""
        try:
            # Generate OTP
            otp_code = OTPService.generate_otp()
            
            # Invalidate any existing password reset OTPs for this phone
            OTPVerification.query.filter_by(
                phone_number=phone_number,
                otp_type=OTPType.PASSWORD_RESET,
                status=OTPStatus.PENDING
            ).update({'status': OTPStatus.EXPIRED})
            
            # Create new OTP record
            otp_record = OTPVerification(
                phone_number=phone_number,
                otp_code=otp_code,
                otp_type=OTPType.PASSWORD_RESET,
                status=OTPStatus.PENDING,
                expires_at=datetime.utcnow() + timedelta(minutes=10),
                ip_address=ip_address,
                user_agent=user_agent,
                meta_data={'purpose': 'password_reset'}
            )
            
            db.session.add(otp_record)
            db.session.flush()
            
            # Send SMS
            sms_result = sms_service.send_password_reset_sms(phone_number, otp_code, user_name)
            
            # Update OTP record with SMS result
            otp_record.meta_data.update({
                'sms_response': sms_result,
                'sms_sent_at': datetime.utcnow().isoformat()
            })
            
            if sms_result['success']:
                logger.info(f"Password reset OTP sent to {phone_number}: {sms_result.get('message_id')}")
                db.session.commit()
                return {
                    'success': True,
                    'message': 'Password reset OTP sent successfully',
                    'otp_id': str(otp_record.id),
                    'expires_in_minutes': 10,
                    'sms_details': {
                        'message_id': sms_result.get('message_id'),
                        'status': sms_result.get('response', {}).get('status'),
                        'api_response': sms_result.get('api_response')
                    }
                }
            else:
                otp_record.status = OTPStatus.FAILED
                otp_record.meta_data.update({'sms_error': sms_result['error']})
                db.session.commit()
                
                logger.error(f"Failed to send password reset OTP to {phone_number}: {sms_result['error']}")
                return {
                    'success': False,
                    'error': 'Failed to send password reset OTP',
                    'details': sms_result['error'],
                    'sms_response': sms_result.get('api_response')
                }
                
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error sending password reset OTP: {str(e)}")
            return {
                'success': False,
                'error': f'Error sending password reset OTP: {str(e)}'
            }
    
    @staticmethod
    def verify_otp(phone_number: str, otp_code: str, otp_type: OTPType, 
                  user_id: str = None) -> dict:
        """Verify OTP"""
        try:
            # Find OTP record
            query = OTPVerification.query.filter_by(
                phone_number=phone_number,
                otp_type=otp_type,
                status=OTPStatus.PENDING
            )
            
            if user_id:
                query = query.filter_by(user_id=user_id)
            
            otp_record = query.order_by(OTPVerification.created_at.desc()).first()
            
            if not otp_record:
                return {
                    'success': False,
                    'error': 'No valid OTP found for this number'
                }
            
            # Check if OTP is expired
            if otp_record.is_expired:
                otp_record.status = OTPStatus.EXPIRED
                db.session.commit()
                return {
                    'success': False,
                    'error': 'OTP has expired'
                }
            
            # Check if max attempts reached
            if otp_record.is_max_attempts_reached:
                otp_record.status = OTPStatus.FAILED
                db.session.commit()
                return {
                    'success': False,
                    'error': 'Maximum verification attempts reached'
                }
            
            # Verify OTP
            if otp_record.otp_code == otp_code:
                # OTP is correct
                otp_record.status = OTPStatus.VERIFIED
                otp_record.verified_at = datetime.utcnow()
                db.session.commit()
                
                logger.info(f"OTP verified successfully for {phone_number}")
                return {
                    'success': True,
                    'message': 'OTP verified successfully',
                    'otp_id': str(otp_record.id)
                }
            else:
                # OTP is incorrect
                otp_record.increment_attempts()
                db.session.commit()
                
                remaining_attempts = otp_record.max_attempts - otp_record.attempts
                return {
                    'success': False,
                    'error': 'Invalid OTP',
                    'remaining_attempts': remaining_attempts
                }
                
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error verifying OTP: {str(e)}")
            return {
                'success': False,
                'error': f'Error verifying OTP: {str(e)}'
            }
    
    @staticmethod
    def resend_otp(phone_number: str, otp_type: OTPType, user_id: str = None, 
                  user_name: str = "User", ip_address: str = None) -> dict:
        """Resend OTP"""
        try:
            if otp_type == OTPType.LOGIN and user_id:
                return OTPService.send_login_otp(
                    user_id=user_id,
                    phone_number=phone_number,
                    user_name=user_name,
                    ip_address=ip_address
                )
            elif otp_type == OTPType.PASSWORD_RESET:
                return OTPService.send_password_reset_otp(
                    phone_number=phone_number,
                    user_name=user_name,
                    ip_address=ip_address
                )
            else:
                return {
                    'success': False,
                    'error': 'Invalid OTP type for resend'
                }
                
        except Exception as e:
            logger.error(f"Error resending OTP: {str(e)}")
            return {
                'success': False,
                'error': f'Error resending OTP: {str(e)}'
            }

# Create OTP service instance
otp_service = OTPService()
