from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from models import OrganizationBankAccount, db

bank_bp = Blueprint('bank', __name__)

@bank_bp.route('/bank-accounts', methods=['POST'])
@login_required
def create_bank_account():
    data = request.get_json()
    try:
        new_bank = OrganizationBankAccount(
            organization_id=data['organization_id'],
            bank_name=data['bank_name'],
            account_number=data['account_number'],
            branch_code=data.get('branch_code'),
            ifsc_code=data.get('ifsc_code'),
            account_holder_name=data['account_holder_name'],
            account_type=data.get('account_type', 'CURRENT'),
            is_active=True
        )
        db.session.add(new_bank)
        db.session.commit()
        return jsonify({'message': 'Bank account added', 'bank_account': new_bank.to_dict()})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@bank_bp.route('/bank-accounts', methods=['GET'])
@login_required
def get_bank_accounts():
    org_id = request.args.get('organization_id')
    try:
        query = OrganizationBankAccount.query.filter_by(is_active=True)
        if org_id:
            query = query.filter_by(organization_id=org_id)
        accounts = query.all()
        return jsonify({'bank_accounts': [acc.to_dict() for acc in accounts]})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bank_bp.route('/bank-accounts/<acc_id>', methods=['PUT'])
@login_required
def update_bank_account(acc_id):
    data = request.get_json()
    try:
        acc = OrganizationBankAccount.query.get(acc_id)
        if not acc:
            return jsonify({'error': 'Bank account not found'}), 404
        # permission checks here
        for key in data:
            setattr(acc, key, data[key])
        db.session.commit()
        return jsonify({'message': 'Bank account updated', 'bank_account': acc.to_dict()})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@bank_bp.route('/bank-accounts/<acc_id>', methods=['DELETE'])
@login_required
def delete_bank_account(acc_id):
    try:
        acc = OrganizationBankAccount.query.get(acc_id)
        if not acc:
            return jsonify({'error': 'Bank account not found'}), 404
        acc.is_active = False
        db.session.commit()
        return jsonify({'message': 'Bank account deactivated'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
