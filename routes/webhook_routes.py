from flask import Blueprint, request, jsonify
import json

webhook_bp = Blueprint('webhook', __name__)

@webhook_bp.route('/webhooks/payment', methods=['POST'])
def payment_webhook():
    """Handle payment gateway callbacks"""
    payload = request.get_data(as_text=True)
    data = json.loads(payload)
    # Validate webhook signature here if needed
    # Process payment status update
    # Example:
    payment_id = data.get('payment_id')
    status = data.get('status')
    # Update transaction status accordingly
    # ...
    return jsonify({'message': 'Webhook received'}), 200
