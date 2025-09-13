# services/cashfree_service.py
import hashlib
import hmac
import json
import requests
import uuid
import base64
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Dict, Any, Optional
import urllib.parse


class EnhancedCashfreeGateway(PaymentGatewayInterface):
    """Enhanced Cashfree payment gateway with latest features"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.base_url = "https://sandbox.cashfree.com/pg" if self.sandbox_mode else "https://api.cashfree.com/pg"
        self.app_id = self.api_key
        self.secret_key = self.api_secret
        self.api_version = "2023-08-01"  # Latest API version
        
    def _get_headers(self) -> dict:
        """Get standard headers for Cashfree API"""
        return {
            "x-api-version": self.api_version,
            "x-client-id": self.app_id,
            "x-client-secret": self.secret_key,
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
    
    def create_order(self, amount: Decimal, currency: str, order_id: str, customer_info: dict) -> dict:
        """Create Cashfree order with enhanced features"""
        try:
            headers = self._get_headers()
            
            # Enhanced order data with more features
            order_data = {
                "order_id": order_id,
                "order_amount": float(amount),
                "order_currency": currency,
                "customer_details": {
                    "customer_id": customer_info.get("customer_id", str(uuid.uuid4())),
                    "customer_name": customer_info.get("name", "Customer"),
                    "customer_email": customer_info.get("email", "customer@example.com"),
                    "customer_phone": customer_info.get("phone", "9999999999")
                },
                "order_meta": {
                    "return_url": customer_info.get("callback_url"),
                    "notify_url": customer_info.get("webhook_url"),
                    "payment_methods": customer_info.get("payment_methods", "cc,dc,nb,upi,paylater,emi,cardlessemi,wallet")
                },
                "order_expiry_time": (datetime.utcnow() + timedelta(hours=24)).isoformat() + "Z",
                "order_note": customer_info.get("order_note", "Wallet Top-up"),
                "order_tags": {
                    "source": "wallet_topup",
                    "user_id": customer_info.get("user_id", ""),
                    "tenant_id": customer_info.get("tenant_id", "")
                }
            }
            
            response = requests.post(
                f"{self.base_url}/orders",
                json=order_data,
                headers=headers,
                timeout=30
            )
            
            result = response.json()
            
            if response.status_code == 200:
                return {
                    "success": True,
                    "order_id": order_id,
                    "amount": float(amount),
                    "currency": currency,
                    "gateway_order_id": order_id,
                    "payment_session_id": result.get("payment_session_id"),
                    "order_token": result.get("order_token"),
                    "checkout_data": {
                        "payment_session_id": result.get("payment_session_id"),
                        "order_token": result.get("order_token"),
                        "environment": "sandbox" if self.sandbox_mode else "production"
                    }
                }
            else:
                return {
                    "success": False,
                    "error": result.get("message", "Failed to create Cashfree order"),
                    "error_code": result.get("code"),
                    "error_details": result
                }
                
        except requests.RequestException as e:
            return {"success": False, "error": f"Network error: {str(e)}"}
        except Exception as e:
            return {"success": False, "error": f"Unexpected error: {str(e)}"}
    
    def verify_payment(self, payment_data: dict) -> dict:
        """Verify Cashfree payment with enhanced validation"""
        try:
            order_id = payment_data.get("order_id")
            cf_payment_id = payment_data.get("cf_payment_id")
            
            if not order_id:
                return {"success": False, "error": "Order ID is required for verification"}
            
            headers = self._get_headers()
            
            # Get order details
            order_response = requests.get(
                f"{self.base_url}/orders/{order_id}",
                headers=headers,
                timeout=30
            )
            
            if order_response.status_code != 200:
                return {"success": False, "error": "Failed to fetch order details"}
            
            order_result = order_response.json()
            
            # Get payment details
            payments_response = requests.get(
                f"{self.base_url}/orders/{order_id}/payments",
                headers=headers,
                timeout=30
            )
            
            if payments_response.status_code == 200:
                payments = payments_response.json()
                
                if payments and len(payments) > 0:
                    # Find the specific payment or get the latest successful one
                    payment = None
                    if cf_payment_id:
                        payment = next((p for p in payments if p.get("cf_payment_id") == cf_payment_id), None)
                    
                    if not payment:
                        # Get the latest successful payment
                        successful_payments = [p for p in payments if p.get("payment_status") == "SUCCESS"]
                        payment = successful_payments[0] if successful_payments else payments[0]
                    
                    if payment and payment.get("payment_status") == "SUCCESS":
                        return {
                            "success": True,
                            "payment_id": payment.get("cf_payment_id"),
                            "order_id": order_id,
                            "amount": payment.get("payment_amount"),
                            "status": "success",
                            "method": payment.get("payment_method"),
                            "payment_time": payment.get("payment_time"),
                            "bank_reference": payment.get("bank_reference"),
                            "gateway_response": payment
                        }
                    else:
                        status = payment.get("payment_status", "UNKNOWN") if payment else "NO_PAYMENT"
                        return {
                            "success": False,
                            "error": f"Payment not successful. Status: {status}",
                            "payment_status": status,
                            "gateway_response": payment
                        }
            
            return {"success": False, "error": "No payment found for this order"}
            
        except requests.RequestException as e:
            return {"success": False, "error": f"Network error during verification: {str(e)}"}
        except Exception as e:
            return {"success": False, "error": f"Verification failed: {str(e)}"}
    
    def get_redirect_url(self, order_data: dict) -> str:
        """Get Cashfree hosted checkout URL"""
        return f"{self.base_url}/checkout/hosted"
    
    def verify_webhook_signature(self, payload: str, signature: str, timestamp: str) -> bool:
        """Verify Cashfree webhook signature"""
        try:
            if not self.webhook_secret:
                return True  # Skip verification if no webhook secret configured
                
            # Cashfree signature format: timestamp.payload
            signed_payload = f"{timestamp}.{payload}"
            
            expected_signature = base64.b64encode(
                hmac.new(
                    self.webhook_secret.encode(),
                    signed_payload.encode(),
                    hashlib.sha256
                ).digest()
            ).decode()
            
            return hmac.compare_digest(signature, expected_signature)
            
        except Exception as e:
            print(f"Webhook signature verification failed: {e}")
            return False
    
    def refund_payment(self, payment_id: str, refund_amount: Decimal, refund_note: str = "") -> dict:
        """Create refund for a Cashfree payment"""
        try:
            headers = self._get_headers()
            
            refund_data = {
                "refund_amount": float(refund_amount),
                "refund_id": f"REFUND_{uuid.uuid4().hex[:12].upper()}",
                "refund_note": refund_note or "Wallet topup refund"
            }
            
            response = requests.post(
                f"{self.base_url}/orders/{payment_id}/refunds",
                json=refund_data,
                headers=headers,
                timeout=30
            )
            
            result = response.json()
            
            if response.status_code == 200:
                return {
                    "success": True,
                    "refund_id": result.get("cf_refund_id"),
                    "refund_amount": result.get("refund_amount"),
                    "refund_status": result.get("refund_status"),
                    "gateway_response": result
                }
            else:
                return {
                    "success": False,
                    "error": result.get("message", "Refund failed"),
                    "gateway_response": result
                }
                
        except Exception as e:
            return {"success": False, "error": f"Refund error: {str(e)}"}
    
    def get_settlement_details(self, order_id: str) -> dict:
        """Get settlement details for an order"""
        try:
            headers = self._get_headers()
            
            response = requests.get(
                f"{self.base_url}/orders/{order_id}/settlements",
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                return {
                    "success": True,
                    "settlements": response.json()
                }
            else:
                return {
                    "success": False,
                    "error": "Failed to fetch settlement details"
                }
                
        except Exception as e:
            return {"success": False, "error": f"Settlement fetch error: {str(e)}"}
