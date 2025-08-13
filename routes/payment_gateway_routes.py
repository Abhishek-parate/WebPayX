from flask import Blueprint, request, jsonify
from models import PaymentGateway, db

payment_gateway_bp = Blueprint('payment_gateway', __name__)

@payment_gateway_bp.route('/payment-gateways', methods=['POST'])
def add_payment_gateway():
    data = request.get_json()
    try:
        new_gateway = PaymentGateway(
            name=data['name'],
            provider=data['provider'],
            credentials=data['credentials'],  # JSON or dict
            is_active=True
        )
        db.session.add(new_gateway)
        db.session.commit()
        return jsonify({'message': 'Payment gateway added', 'payment_gateway': new_gateway.to_dict()})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@payment_gateway_bp.route('/payment-gateways', methods=['GET'])
def list_payment_gateways():
    try:
        gateways = PaymentGateway.query.filter_by(is_active=True).all()
        return jsonify({'payment_gateways': [g.to_dict() for g in gateways]})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@payment_gateway_bp.route('/payment-gateways/<gw_id>', methods=['PUT'])
def update_payment_gateway(gw_id):
    data = request.get_json()
    try:
        gw = PaymentGateway.query.get(gw_id)
        if not gw:
            return jsonify({'error': 'Payment gateway not found'}), 404
        for key in ['name', 'credentials', 'is_active']:
            if key in data:
                setattr(gw, key, data[key])
        db.session.commit()
        return jsonify({'message': 'Payment gateway updated', 'payment_gateway': gw.to_dict()})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@payment_gateway_bp.route('/payment-gateways/<gw_id>', methods=['DELETE'])
def delete_payment_gateway(gw_id):
    try:
        gw = PaymentGateway.query.get(gw_id)
        if not gw:
            return jsonify({'error': 'Payment gateway not found'}), 404
        gw.is_active = False
        db.session.commit()
        return jsonify({'message': 'Payment gateway deactivated'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
