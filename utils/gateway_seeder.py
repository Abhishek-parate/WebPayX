from models import db, PaymentGateway, PaymentGatewayType
from decimal import Decimal
import uuid

def seed_payment_gateways(tenant_id: str, created_by: str = None):
    """Seed all payment gateways for a tenant"""
    
    gateways_data = [
        {
            "gateway_type": PaymentGatewayType.RAZORPAY,
            "gateway_name": "Razorpay",
            "merchant_id": "razorpay_merchant_id",
            "api_key": "rzp_test_api_key",
            "api_secret": "rzp_test_api_secret",
            "supported_methods": ["card", "netbanking", "wallet", "upi"],
            "priority": 1
        },
        {
            "gateway_type": PaymentGatewayType.PAYU,
            "gateway_name": "PayU",
            "merchant_id": "payu_merchant_id",
            "api_key": "payu_merchant_key",
            "api_secret": "payu_salt_key",
            "supported_methods": ["card", "netbanking", "wallet", "upi"],
            "priority": 2
        },
        {
            "gateway_type": PaymentGatewayType.PAYTM,
            "gateway_name": "Paytm",
            "merchant_id": "paytm_merchant_id",
            "api_key": "paytm_merchant_key",
            "api_secret": "paytm_merchant_secret",
            "supported_methods": ["wallet", "card", "netbanking", "upi"],
            "priority": 3
        },
        {
            "gateway_type": PaymentGatewayType.PHONEPE,
            "gateway_name": "PhonePe",
            "merchant_id": "phonepe_merchant_id",
            "api_key": "phonepe_merchant_id",
            "api_secret": "phonepe_salt_key",
            "supported_methods": ["upi", "card", "netbanking"],
            "priority": 4,
            "gateway_config": {"salt_index": 1}
        },
        {
            "gateway_type": PaymentGatewayType.CASHFREE,
            "gateway_name": "Cashfree",
            "merchant_id": "cashfree_merchant_id",
            "api_key": "cashfree_app_id",
            "api_secret": "cashfree_secret_key",
            "supported_methods": ["card", "netbanking", "wallet", "upi"],
            "priority": 5
        },
        {
            "gateway_type": PaymentGatewayType.INSTAMOJO,
            "gateway_name": "Instamojo",
            "merchant_id": "instamojo_merchant_id",
            "api_key": "instamojo_client_id",
            "api_secret": "instamojo_client_secret",
            "supported_methods": ["card", "netbanking", "wallet"],
            "priority": 6
        },
        {
            "gateway_type": PaymentGatewayType.CCAVENUE,
            "gateway_name": "CCAvenue",
            "merchant_id": "ccavenue_merchant_id",
            "api_key": "ccavenue_access_code",
            "api_secret": "ccavenue_working_key",
            "supported_methods": ["card", "netbanking", "wallet"],
            "priority": 7,
            "gateway_config": {"access_code": "ccavenue_access_code", "working_key": "ccavenue_working_key"}
        },
        {
            "gateway_type": PaymentGatewayType.STRIPE,
            "gateway_name": "Stripe",
            "merchant_id": "stripe_merchant_id",
            "api_key": "pk_test_stripe_publishable_key",
            "api_secret": "sk_test_stripe_secret_key",
            "supported_methods": ["card"],
            "priority": 8
        },
        {
            "gateway_type": PaymentGatewayType.PAYPAL,
            "gateway_name": "PayPal",
            "merchant_id": "paypal_merchant_id",
            "api_key": "paypal_client_id",
            "api_secret": "paypal_client_secret",
            "supported_methods": ["paypal"],
            "priority": 9
        }
    ]
    
    created_gateways = []
    
    for gateway_data in gateways_data:
        gateway = PaymentGateway(
            tenant_id=tenant_id,
            gateway_type=gateway_data["gateway_type"],
            gateway_name=gateway_data["gateway_name"],
            merchant_id=gateway_data["merchant_id"],
            api_key=gateway_data["api_key"],
            api_secret=gateway_data["api_secret"],
            sandbox_mode=True,
            status='ACTIVE',
            priority=gateway_data["priority"],
            min_amount=Decimal('1.00'),
            max_amount=Decimal('100000.00'),
            processing_fee_percentage=Decimal('0.02'),
            processing_fee_fixed=Decimal('5.00'),
            supported_methods=gateway_data["supported_methods"],
            gateway_config=gateway_data.get("gateway_config", {}),
            rate_limit_per_minute=100,
            auto_settlement=True,
            is_default=(gateway_data["priority"] == 1),
            created_by=created_by
        )
        
        db.session.add(gateway)
        created_gateways.append(gateway)
    
    db.session.commit()
    return created_gateways

# Usage example:
# from utils.gateway_seeder import seed_payment_gateways
# seed_payment_gateways(tenant_id="your-tenant-id", created_by="admin-user-id")
