import hashlib
import hmac
import json
import requests
import uuid
from datetime import datetime, timedelta
from decimal import Decimal
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

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
                "amount": int(amount * 100),  # Convert to paise
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
            
            # Verify signature
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
        return None  # Razorpay uses checkout.js

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
            
            # Create hash
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
            
            # Create verification hash
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

class PaytmGateway(PaymentGatewayInterface):
    """Paytm payment gateway integration"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.website = "WEBSTAGING" if self.sandbox_mode else "DEFAULT"
        self.base_url = "https://securegw-stage.paytm.in/" if self.sandbox_mode else "https://securegw.paytm.in/"
    
    def create_order(self, amount: Decimal, currency: str, order_id: str, customer_info: dict) -> dict:
        try:
            # Import Paytm SDK
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
                amount=int(amount * 100),  # Convert to cents
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
        return None  # Stripe uses Elements

# Additional gateways can be added here following the same pattern...

class DynamicPaymentGatewayManager:
    """Manager for dynamically loading payment gateways from database"""
    
    _gateway_classes = {
        PaymentGatewayType.RAZORPAY: RazorpayGateway,
        PaymentGatewayType.PAYU: PayUGateway,
        PaymentGatewayType.PAYTM: PaytmGateway,
        PaymentGatewayType.STRIPE: StripeGateway,
        # Add more gateway mappings here
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
                # Add any additional gateway-specific configuration
                **gateway_config.gateway_config  # Custom configuration from JSON field
            }
            
            return gateway_class(config)
        except Exception as e:
            print(f"Error creating gateway instance: {str(e)}")
            return None
    
    @classmethod
    def register_gateway_class(cls, gateway_type: PaymentGatewayType, gateway_class):
        """Register a new gateway class dynamically"""
        cls._gateway_classes[gateway_type] = gateway_class
