from flask import Blueprint, request, jsonify
from models import Commission, db

commission_bp = Blueprint('commission', __name__)

@commission_bp.route('/commissions', methods=['POST'])
def add_commission():
    data = request.get_json()
    try:
        new_commission = Commission(
            name=data['name'],
            rate=float(data['rate']),
            applicable_to=data.get('applicable_to'),  # e.g., 'product', 'user'
            is_active=True
        )
        db.session.add(new_commission)
        db.session.commit()
        return jsonify({'message': 'Commission rate added', 'commission': new_commission.to_dict()})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@commission_bp.route('/commissions', methods=['GET'])
def list_commissions():
    try:
        commissions = Commission.query.filter_by(is_active=True).all()
        return jsonify({'commissions': [c.to_dict() for c in commissions]})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@commission_bp.route('/commissions/<comm_id>', methods=['PUT'])
def update_commission(comm_id):
    data = request.get_json()
    try:
        comm = Commission.query.get(comm_id)
        if not comm:
            return jsonify({'error': 'Commission not found'}), 404
        if 'rate' in data:
            comm.rate = float(data['rate'])
        if 'is_active' in data:
            comm.is_active = data['is_active']
        db.session.commit()
        return jsonify({'message': 'Commission updated', 'commission': comm.to_dict()})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@commission_bp.route('/commissions/<comm_id>', methods=['DELETE'])
def delete_commission(comm_id):
    try:
        comm = Commission.query.get(comm_id)
        if not comm:
            return jsonify({'error': 'Commission not found'}), 404
        comm.is_active = False
        db.session.commit()
        return jsonify({'message': 'Commission deactivated'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
