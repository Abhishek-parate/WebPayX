import hashlib
import hmac
import json
import requests
import uuid
import base64
from datetime import datetime, timedelta
from decimal import Decimal
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import urllib.parse

from models import PaymentGateway, PaymentGatewayType, db

class PaymentGatewayInterface(ABC):
    """Abstract base class for all payment gateways"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.gateway_id = config.get('gateway_id')
        self.api_key = config.get('api_key')
        self.api_secret = config.get('api_secret')
        self.merchant_id = config.get('merchant_id')
        self.sandbox_mode = config.get('sandbox_mode', True)
        
    @abstractmethod
    def create_order(self, amount: Decimal, currency: str, order_id: str, customer_info: dict) -> dict:
        pass
    
    @abstractmethod
    def verify_payment(self, payment_data: dict) -> dict:
        pass
    
    @abstractmethod
    def get_redirect_url(self, order_data: dict) -> str:
        pass

# 1. RAZORPAY GATEWAY
class RazorpayGateway(PaymentGatewayInterface):
    """Razorpay payment gateway integration"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.base_url = "https://api.razorpay.com/v1/"
        try:
            import razorpay
            self.client = razorpay.Client(auth=(self.api_key, self.api_secret))
        except ImportError:
            raise ImportError("razorpay package is required for Razorpay integration")
    
    def create_order(self, amount: Decimal, currency: str, order_id: str, customer_info: dict) -> dict:
        try:
            order_data = {
                "amount": int(amount * 100),
                "currency": currency,
                "receipt": order_id,
                "payment_capture": 1
            }
            
            order = self.client.order.create(data=order_data)
            
            return {
                "success": True,
                "order_id": order["id"],
                "amount": order["amount"],
                "currency": order["currency"],
                "gateway_order_id": order["id"],
                "checkout_data": {
                    "key": self.api_key,
                    "amount": order["amount"],
                    "currency": order["currency"],
                    "order_id": order["id"],
                    "name": customer_info.get("name", "WebPayX"),
                    "description": "Wallet Top-up",
                    "prefill": {
                        "name": customer_info.get("name"),
                        "email": customer_info.get("email"),
                        "contact": customer_info.get("phone")
                    }
                }
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def verify_payment(self, payment_data: dict) -> dict:
        try:
            razorpay_order_id = payment_data.get("razorpay_order_id")
            razorpay_payment_id = payment_data.get("razorpay_payment_id")
            razorpay_signature = payment_data.get("razorpay_signature")
            
            body = razorpay_order_id + "|" + razorpay_payment_id
            expected_signature = hmac.new(
                key=self.api_secret.encode(),
                msg=body.encode(),
                digestmod=hashlib.sha256
            ).hexdigest()
            
            if expected_signature == razorpay_signature:
                payment = self.client.payment.fetch(razorpay_payment_id)
                return {
                    "success": True,
                    "payment_id": razorpay_payment_id,
                    "order_id": razorpay_order_id,
                    "amount": payment["amount"] / 100,
                    "status": payment["status"],
                    "method": payment["method"]
                }
            else:
                return {"success": False, "error": "Invalid signature"}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def get_redirect_url(self, order_data: dict) -> str:
        return None

# 2. PAYU GATEWAY
class PayUGateway(PaymentGatewayInterface):
    """PayU payment gateway integration"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.salt = config.get('salt', self.api_secret)
        self.base_url = "https://test.payu.in/" if self.sandbox_mode else "https://secure.payu.in/"
    
    def create_order(self, amount: Decimal, currency: str, order_id: str, customer_info: dict) -> dict:
        try:
            txnid = f"TXN{order_id}"
            productinfo = "Wallet Top-up"
            firstname = customer_info.get("name", "Customer")
            email = customer_info.get("email", "customer@example.com")
            phone = customer_info.get("phone", "9999999999")
            
            hash_string = f"{self.api_key}|{txnid}|{amount}|{productinfo}|{firstname}|{email}|||||||||||{self.salt}"
            hash_value = hashlib.sha512(hash_string.encode()).hexdigest()
            
            return {
                "success": True,
                "order_id": txnid,
                "amount": float(amount),
                "currency": currency,
                "gateway_order_id": txnid,
                "checkout_data": {
                    "key": self.api_key,
                    "txnid": txnid,
                    "amount": str(amount),
                    "productinfo": productinfo,
                    "firstname": firstname,
                    "email": email,
                    "phone": phone,
                    "hash": hash_value,
                    "service_provider": "payu_paisa"
                }
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def verify_payment(self, payment_data: dict) -> dict:
        try:
            status = payment_data.get("status")
            firstname = payment_data.get("firstname")
            amount = payment_data.get("amount")
            txnid = payment_data.get("txnid")
            hash_value = payment_data.get("hash")
            email = payment_data.get("email")
            productinfo = payment_data.get("productinfo", "Wallet Top-up")
            
            hash_string = f"{self.salt}|{status}|||||||||||{email}|{firstname}|{productinfo}|{amount}|{txnid}|{self.api_key}"
            expected_hash = hashlib.sha512(hash_string.encode()).hexdigest()
            
            if hash_value == expected_hash and status == "success":
                return {
                    "success": True,
                    "payment_id": payment_data.get("payuMoneyId"),
                    "order_id": txnid,
                    "amount": float(amount),
                    "status": status,
                    "method": payment_data.get("mode")
                }
            else:
                return {"success": False, "error": "Payment verification failed"}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def get_redirect_url(self, order_data: dict) -> str:
        return f"{self.base_url}_payment"

# 3. PAYTM GATEWAY
class PaytmGateway(PaymentGatewayInterface):
    """Paytm payment gateway integration"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.website = "WEBSTAGING" if self.sandbox_mode else "DEFAULT"
        self.base_url = "https://securegw-stage.paytm.in/" if self.sandbox_mode else "https://securegw.paytm.in/"
    
    def create_order(self, amount: Decimal, currency: str, order_id: str, customer_info: dict) -> dict:
        try:
            try:
                from paytmchecksum import PaytmChecksum
            except ImportError:
                raise ImportError("paytmchecksum package is required for Paytm integration")
            
            paytm_params = {
                "MID": self.merchant_id,
                "WEBSITE": self.website,
                "ORDER_ID": order_id,
                "CUST_ID": customer_info.get("customer_id", str(uuid.uuid4())),
                "INDUSTRY_TYPE_ID": "Retail",
                "CHANNEL_ID": "WEB",
                "TXN_AMOUNT": str(amount),
                "CALLBACK_URL": customer_info.get("callback_url")
            }
            
            checksum = PaytmChecksum.generateSignature(paytm_params, self.api_secret)
            paytm_params["CHECKSUMHASH"] = checksum
            
            return {
                "success": True,
                "order_id": order_id,
                "amount": float(amount),
                "currency": currency,
                "gateway_order_id": order_id,
                "checkout_data": paytm_params
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def verify_payment(self, payment_data: dict) -> dict:
        try:
            from paytmchecksum import PaytmChecksum
            
            received_checksum = payment_data.pop("CHECKSUMHASH", None)
            is_valid = PaytmChecksum.verifySignature(payment_data, self.api_secret, received_checksum)
            
            if is_valid and payment_data.get("STATUS") == "TXN_SUCCESS":
                return {
                    "success": True,
                    "payment_id": payment_data.get("TXNID"),
                    "order_id": payment_data.get("ORDERID"),
                    "amount": float(payment_data.get("TXNAMOUNT", 0)),
                    "status": payment_data.get("STATUS"),
                    "method": payment_data.get("PAYMENTMODE")
                }
            else:
                return {"success": False, "error": "Payment verification failed"}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def get_redirect_url(self, order_data: dict) -> str:
        return f"{self.base_url}theia/processTransaction"

# 4. PHONEPE GATEWAY
class PhonePeGateway(PaymentGatewayInterface):
    """PhonePe payment gateway integration"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.base_url = "https://api-preprod.phonepe.com/apis/pg-sandbox" if self.sandbox_mode else "https://api.phonepe.com/apis/hermes"
        self.salt_key = config.get('salt_key', self.api_secret)
        self.salt_index = config.get('salt_index', 1)
    
    def create_order(self, amount: Decimal, currency: str, order_id: str, customer_info: dict) -> dict:
        try:
            request_data = {
                "merchantId": self.merchant_id,
                "merchantTransactionId": order_id,
                "merchantUserId": customer_info.get("customer_id", str(uuid.uuid4())),
                "amount": int(amount * 100),
                "redirectUrl": customer_info.get("callback_url"),
                "redirectMode": "POST",
                "callbackUrl": customer_info.get("callback_url"),
                "paymentInstrument": {
                    "type": "PAY_PAGE"
                }
            }
            
            # Create base64 encoded payload
            base64_payload = base64.b64encode(json.dumps(request_data).encode()).decode()
            
            # Create checksum
            string_to_hash = base64_payload + "/pg/v1/pay" + self.salt_key
            checksum = hashlib.sha256(string_to_hash.encode()).hexdigest()
            x_verify = f"{checksum}###{self.salt_index}"
            
            headers = {
                "Content-Type": "application/json",
                "X-VERIFY": x_verify
            }
            
            response = requests.post(
                f"{self.base_url}/pg/v1/pay",
                json={"request": base64_payload},
                headers=headers
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get("success"):
                    return {
                        "success": True,
                        "order_id": order_id,
                        "amount": float(amount),
                        "currency": currency,
                        "gateway_order_id": order_id,
                        "checkout_data": {
                            "payment_url": result["data"]["instrumentResponse"]["redirectInfo"]["url"]
                        }
                    }
            
            return {"success": False, "error": "Failed to create PhonePe order"}
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def verify_payment(self, payment_data: dict) -> dict:
        try:
            transaction_id = payment_data.get("transactionId")
            merchant_transaction_id = payment_data.get("merchantTransactionId")
            
            # Check payment status
            string_to_hash = f"/pg/v1/status/{self.merchant_id}/{merchant_transaction_id}" + self.salt_key
            checksum = hashlib.sha256(string_to_hash.encode()).hexdigest()
            x_verify = f"{checksum}###{self.salt_index}"
            
            headers = {"X-VERIFY": x_verify, "X-MERCHANT-ID": self.merchant_id}
            
            response = requests.get(
                f"{self.base_url}/pg/v1/status/{self.merchant_id}/{merchant_transaction_id}",
                headers=headers
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get("success") and result.get("data", {}).get("state") == "COMPLETED":
                    return {
                        "success": True,
                        "payment_id": transaction_id,
                        "order_id": merchant_transaction_id,
                        "amount": result["data"]["amount"] / 100,
                        "status": "success",
                        "method": result["data"]["paymentInstrument"]["type"]
                    }
            
            return {"success": False, "error": "Payment verification failed"}
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def get_redirect_url(self, order_data: dict) -> str:
        return order_data.get("checkout_data", {}).get("payment_url")

# 5. CASHFREE GATEWAY
class CashfreeGateway(PaymentGatewayInterface):
    """Cashfree payment gateway integration"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.base_url = "https://sandbox.cashfree.com/pg" if self.sandbox_mode else "https://api.cashfree.com/pg"
        self.app_id = self.api_key
        self.secret_key = self.api_secret
    
    def create_order(self, amount: Decimal, currency: str, order_id: str, customer_info: dict) -> dict:
        try:
            headers = {
                "x-api-version": "2022-01-01",
                "x-client-id": self.app_id,
                "x-client-secret": self.secret_key,
                "Content-Type": "application/json"
            }
            
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
                    "notify_url": customer_info.get("webhook_url")
                }
            }
            
            response = requests.post(
                f"{self.base_url}/orders",
                json=order_data,
                headers=headers
            )
            
            if response.status_code == 200:
                result = response.json()
                return {
                    "success": True,
                    "order_id": order_id,
                    "amount": float(amount),
                    "currency": currency,
                    "gateway_order_id": order_id,
                    "checkout_data": {
                        "payment_session_id": result.get("payment_session_id"),
                        "order_token": result.get("order_token")
                    }
                }
            
            return {"success": False, "error": "Failed to create Cashfree order"}
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def verify_payment(self, payment_data: dict) -> dict:
        try:
            order_id = payment_data.get("order_id")
            
            headers = {
                "x-api-version": "2022-01-01",
                "x-client-id": self.app_id,
                "x-client-secret": self.secret_key
            }
            
            response = requests.get(
                f"{self.base_url}/orders/{order_id}/payments",
                headers=headers
            )
            
            if response.status_code == 200:
                payments = response.json()
                if payments and len(payments) > 0:
                    payment = payments[0]
                    if payment.get("payment_status") == "SUCCESS":
                        return {
                            "success": True,
                            "payment_id": payment.get("cf_payment_id"),
                            "order_id": order_id,
                            "amount": payment.get("payment_amount"),
                            "status": "success",
                            "method": payment.get("payment_method")
                        }
            
            return {"success": False, "error": "Payment verification failed"}
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def get_redirect_url(self, order_data: dict) -> str:
        return f"{self.base_url}/checkout/hosted"

# 6. INSTAMOJO GATEWAY
class InstamojoGateway(PaymentGatewayInterface):
    """Instamojo payment gateway integration"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.base_url = "https://test.instamojo.com/api/1.1/" if self.sandbox_mode else "https://www.instamojo.com/api/1.1/"
        self.auth_token = None
        self._authenticate()
    
    def _authenticate(self):
        """Authenticate with Instamojo API"""
        try:
            auth_data = {
                "grant_type": "client_credentials",
                "client_id": self.api_key,
                "client_secret": self.api_secret
            }
            
            response = requests.post(
                f"{self.base_url}oauth2/token/",
                data=auth_data
            )
            
            if response.status_code == 200:
                result = response.json()
                self.auth_token = result.get("access_token")
                
        except Exception as e:
            print(f"Instamojo authentication failed: {e}")
    
    def create_order(self, amount: Decimal, currency: str, order_id: str, customer_info: dict) -> dict:
        try:
            if not self.auth_token:
                return {"success": False, "error": "Authentication failed"}
            
            headers = {
                "Authorization": f"Bearer {self.auth_token}",
                "Content-Type": "application/x-www-form-urlencoded"
            }
            
            payment_data = {
                "purpose": "Wallet Top-up",
                "amount": str(amount),
                "phone": customer_info.get("phone", "9999999999"),
                "buyer_name": customer_info.get("name", "Customer"),
                "redirect_url": customer_info.get("callback_url"),
                "send_email": True,
                "webhook": customer_info.get("webhook_url"),
                "allow_repeated_payments": False
            }
            
            response = requests.post(
                f"{self.base_url}payment-requests/",
                data=payment_data,
                headers=headers
            )
            
            if response.status_code == 201:
                result = response.json()
                payment_request = result.get("payment_request", {})
                return {
                    "success": True,
                    "order_id": order_id,
                    "amount": float(amount),
                    "currency": currency,
                    "gateway_order_id": payment_request.get("id"),
                    "checkout_data": {
                        "payment_url": payment_request.get("longurl"),
                        "payment_request_id": payment_request.get("id")
                    }
                }
            
            return {"success": False, "error": "Failed to create Instamojo payment request"}
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def verify_payment(self, payment_data: dict) -> dict:
        try:
            payment_id = payment_data.get("payment_id")
            payment_request_id = payment_data.get("payment_request_id")
            
            if not self.auth_token:
                return {"success": False, "error": "Authentication failed"}
            
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            
            response = requests.get(
                f"{self.base_url}payments/{payment_id}/",
                headers=headers
            )
            
            if response.status_code == 200:
                result = response.json()
                payment = result.get("payment", {})
                if payment.get("status") == "Credit":
                    return {
                        "success": True,
                        "payment_id": payment_id,
                        "order_id": payment_request_id,
                        "amount": float(payment.get("amount", 0)),
                        "status": "success",
                        "method": payment.get("instrument_type")
                    }
            
            return {"success": False, "error": "Payment verification failed"}
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def get_redirect_url(self, order_data: dict) -> str:
        return order_data.get("checkout_data", {}).get("payment_url")

# 7. CCAVENUE GATEWAY
class CCavenueGateway(PaymentGatewayInterface):
    """CCAvenue payment gateway integration"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.base_url = "https://test.ccavenue.com/" if self.sandbox_mode else "https://secure.ccavenue.com/"
        self.access_code = config.get('access_code', self.api_key)
        self.working_key = config.get('working_key', self.api_secret)
    
    def _encrypt(self, plain_text: str) -> str:
        """Encrypt data for CCAvenue"""
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import pad
            import binascii
            
            key = hashlib.md5(self.working_key.encode()).digest()
            iv = b'\x00' * 16
            
            cipher = AES.new(key, AES.MODE_CBC, iv)
            encrypted = cipher.encrypt(pad(plain_text.encode(), AES.block_size))
            
            return binascii.hexlify(encrypted).decode()
        except ImportError:
            raise ImportError("pycryptodome package is required for CCAvenue integration")
    
    def _decrypt(self, encrypted_text: str) -> str:
        """Decrypt data from CCAvenue"""
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import unpad
            import binascii
            
            key = hashlib.md5(self.working_key.encode()).digest()
            iv = b'\x00' * 16
            
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(binascii.unhexlify(encrypted_text))
            
            return unpad(decrypted, AES.block_size).decode()
        except Exception:
            return ""
    
    def create_order(self, amount: Decimal, currency: str, order_id: str, customer_info: dict) -> dict:
        try:
            merchant_data = f"merchant_id={self.merchant_id}&order_id={order_id}&amount={amount}&currency={currency}&redirect_url={customer_info.get('callback_url')}&cancel_url={customer_info.get('callback_url')}&language=EN&billing_name={customer_info.get('name', 'Customer')}&billing_email={customer_info.get('email', 'customer@example.com')}&billing_tel={customer_info.get('phone', '9999999999')}"
            
            encrypted_data = self._encrypt(merchant_data)
            
            return {
                "success": True,
                "order_id": order_id,
                "amount": float(amount),
                "currency": currency,
                "gateway_order_id": order_id,
                "checkout_data": {
                    "access_code": self.access_code,
                    "merchant_id": self.merchant_id,
                    "order_id": order_id,
                    "amount": str(amount),
                    "currency": currency,
                    "encrypted_data": encrypted_data
                }
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def verify_payment(self, payment_data: dict) -> dict:
        try:
            encrypted_response = payment_data.get("encResp")
            if not encrypted_response:
                return {"success": False, "error": "No encrypted response"}
            
            decrypted_data = self._decrypt(encrypted_response)
            response_params = dict(x.split('=') for x in decrypted_data.split('&'))
            
            if response_params.get("order_status") == "Success":
                return {
                    "success": True,
                    "payment_id": response_params.get("tracking_id"),
                    "order_id": response_params.get("order_id"),
                    "amount": float(response_params.get("amount", 0)),
                    "status": "success",
                    "method": response_params.get("payment_mode")
                }
            
            return {"success": False, "error": "Payment verification failed"}
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def get_redirect_url(self, order_data: dict) -> str:
        return f"{self.base_url}transaction/transaction.do?command=initiateTransaction"

# 8. STRIPE GATEWAY
class StripeGateway(PaymentGatewayInterface):
    """Stripe payment gateway integration"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        try:
            import stripe
            stripe.api_key = self.api_secret
            self.stripe = stripe
        except ImportError:
            raise ImportError("stripe package is required for Stripe integration")
    
    def create_order(self, amount: Decimal, currency: str, order_id: str, customer_info: dict) -> dict:
        try:
            intent = self.stripe.PaymentIntent.create(
                amount=int(amount * 100),
                currency=currency.lower(),
                metadata={'order_id': order_id}
            )
            
            return {
                "success": True,
                "order_id": order_id,
                "amount": float(amount),
                "currency": currency,
                "gateway_order_id": intent.id,
                "checkout_data": {
                    "client_secret": intent.client_secret,
                    "publishable_key": self.api_key
                }
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def verify_payment(self, payment_data: dict) -> dict:
        try:
            payment_intent_id = payment_data.get("payment_intent")
            intent = self.stripe.PaymentIntent.retrieve(payment_intent_id)
            
            if intent.status == "succeeded":
                return {
                    "success": True,
                    "payment_id": intent.id,
                    "order_id": intent.metadata.get("order_id"),
                    "amount": intent.amount / 100,
                    "status": intent.status,
                    "method": "card"
                }
            else:
                return {"success": False, "error": "Payment not completed"}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def get_redirect_url(self, order_data: dict) -> str:
        return None

# 9. PAYPAL GATEWAY
class PayPalGateway(PaymentGatewayInterface):
    """PayPal payment gateway integration"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.base_url = "https://api.sandbox.paypal.com" if self.sandbox_mode else "https://api.paypal.com"
        self.client_id = self.api_key
        self.client_secret = self.api_secret
        self.access_token = None
        self._authenticate()
    
    def _authenticate(self):
        """Get PayPal access token"""
        try:
            auth_string = base64.b64encode(f"{self.client_id}:{self.client_secret}".encode()).decode()
            
            headers = {
                "Authorization": f"Basic {auth_string}",
                "Content-Type": "application/x-www-form-urlencoded"
            }
            
            response = requests.post(
                f"{self.base_url}/v1/oauth2/token",
                data="grant_type=client_credentials",
                headers=headers
            )
            
            if response.status_code == 200:
                result = response.json()
                self.access_token = result.get("access_token")
                
        except Exception as e:
            print(f"PayPal authentication failed: {e}")
    
    def create_order(self, amount: Decimal, currency: str, order_id: str, customer_info: dict) -> dict:
        try:
            if not self.access_token:
                return {"success": False, "error": "Authentication failed"}
            
            headers = {
                "Authorization": f"Bearer {self.access_token}",
                "Content-Type": "application/json"
            }
            
            order_data = {
                "intent": "CAPTURE",
                "purchase_units": [{
                    "reference_id": order_id,
                    "amount": {
                        "currency_code": currency,
                        "value": str(amount)
                    }
                }],
                "application_context": {
                    "return_url": customer_info.get("callback_url"),
                    "cancel_url": customer_info.get("callback_url")
                }
            }
            
            response = requests.post(
                f"{self.base_url}/v2/checkout/orders",
                json=order_data,
                headers=headers
            )
            
            if response.status_code == 201:
                result = response.json()
                approval_url = None
                for link in result.get("links", []):
                    if link.get("rel") == "approve":
                        approval_url = link.get("href")
                        break
                
                return {
                    "success": True,
                    "order_id": order_id,
                    "amount": float(amount),
                    "currency": currency,
                    "gateway_order_id": result.get("id"),
                    "checkout_data": {
                        "approval_url": approval_url,
                        "paypal_order_id": result.get("id")
                    }
                }
            
            return {"success": False, "error": "Failed to create PayPal order"}
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def verify_payment(self, payment_data: dict) -> dict:
        try:
            paypal_order_id = payment_data.get("paypal_order_id")
            
            if not self.access_token:
                return {"success": False, "error": "Authentication failed"}
            
            headers = {"Authorization": f"Bearer {self.access_token}"}
            
            response = requests.get(
                f"{self.base_url}/v2/checkout/orders/{paypal_order_id}",
                headers=headers
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get("status") == "COMPLETED":
                    return {
                        "success": True,
                        "payment_id": paypal_order_id,
                        "order_id": result["purchase_units"][0]["reference_id"],
                        "amount": float(result["purchase_units"][0]["amount"]["value"]),
                        "status": "success",
                        "method": "paypal"
                    }
            
            return {"success": False, "error": "Payment verification failed"}
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def get_redirect_url(self, order_data: dict) -> str:
        return order_data.get("checkout_data", {}).get("approval_url")

# DYNAMIC PAYMENT GATEWAY MANAGER
class DynamicPaymentGatewayManager:
    """Manager for dynamically loading payment gateways from database"""
    
    _gateway_classes = {
        PaymentGatewayType.RAZORPAY: RazorpayGateway,
        PaymentGatewayType.PAYU: PayUGateway,
        PaymentGatewayType.PAYTM: PaytmGateway,
        PaymentGatewayType.PHONEPE: PhonePeGateway,
        PaymentGatewayType.CASHFREE: CashfreeGateway,
        PaymentGatewayType.INSTAMOJO: InstamojoGateway,
        PaymentGatewayType.CCAVENUE: CCavenueGateway,
        PaymentGatewayType.STRIPE: StripeGateway,
        PaymentGatewayType.PAYPAL: PayPalGateway,
    }
    
    @classmethod
    def get_gateway_by_id(cls, gateway_id: str) -> Optional[PaymentGatewayInterface]:
        """Dynamically load gateway by ID from database"""
        try:
            gateway_config = PaymentGateway.query.get(gateway_id)
            if not gateway_config or gateway_config.status != 'ACTIVE':
                return None
            
            return cls.create_gateway_from_config(gateway_config)
        except Exception as e:
            print(f"Error loading gateway {gateway_id}: {str(e)}")
            return None
    
    @classmethod
    def get_available_gateways(cls, tenant_id: str) -> list:
        """Get all available gateways for a tenant"""
        try:
            gateways = PaymentGateway.query.filter_by(
                tenant_id=tenant_id,
                status='ACTIVE'
            ).order_by(PaymentGateway.priority.asc()).all()
            
            return [cls.create_gateway_from_config(gw) for gw in gateways if gw.gateway_type in cls._gateway_classes]
        except Exception as e:
            print(f"Error loading gateways for tenant {tenant_id}: {str(e)}")
            return []
    
    @classmethod
    def create_gateway_from_config(cls, gateway_config: PaymentGateway) -> Optional[PaymentGatewayInterface]:
        """Create gateway instance from database configuration"""
        try:
            gateway_class = cls._gateway_classes.get(gateway_config.gateway_type)
            if not gateway_class:
                print(f"Gateway type {gateway_config.gateway_type} not supported")
                return None
            
            config = {
                'gateway_id': str(gateway_config.id),
                'gateway_type': gateway_config.gateway_type.value,
                'api_key': gateway_config.api_key,
                'api_secret': gateway_config.api_secret,
                'merchant_id': gateway_config.merchant_id,
                'sandbox_mode': gateway_config.sandbox_mode,
                'webhook_secret': gateway_config.webhook_secret,
                'callback_url': gateway_config.callback_url,
                'webhook_url': gateway_config.webhook_url,
                'processing_fee_percentage': float(gateway_config.processing_fee_percentage or 0),
                'processing_fee_fixed': float(gateway_config.processing_fee_fixed or 0),
                'min_amount': float(gateway_config.min_amount or 1),
                'max_amount': float(gateway_config.max_amount or 100000),
                **gateway_config.gateway_config
            }
            
            return gateway_class(config)
        except Exception as e:
            print(f"Error creating gateway instance: {str(e)}")
            return None
    
    @classmethod
    def register_gateway_class(cls, gateway_type: PaymentGatewayType, gateway_class):
        """Register a new gateway class dynamically"""
        cls._gateway_classes[gateway_type] = gateway_class
