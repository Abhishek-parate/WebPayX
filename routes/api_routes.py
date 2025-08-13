from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from models import APIEndpoint, APIUsageLog, db
from datetime import datetime

api_bp = Blueprint('api', __name__)

# ============================
# API Endpoints Management
# ============================

@api_bp.route('/api/endpoints', methods=['POST'])
@login_required
def create_api_endpoint():
    """Register a new API endpoint"""
    data = request.get_json()
    name = data.get('name')
    route = data.get('route')
    method = data.get('method')
    description = data.get('description')
    endpoint = APIEndpoint(name=name, route=route, method=method, description=description)
    db.session.add(endpoint)
    db.session.commit()
    return jsonify({'message': 'API Endpoint registered', 'endpoint': endpoint.to_dict()})

@api_bp.route('/api/endpoints', methods=['GET'])
@login_required
def list_api_endpoints():
    """Get list of all API endpoints"""
    endpoints = APIEndpoint.query.all()
    return jsonify({'endpoints': [e.to_dict() for e in endpoints]})

@api_bp.route('/api/usage', methods=['POST'])
def log_api_usage():
    """Log API usage call"""
    data = request.get_json()
    endpoint_id = data.get('endpoint_id')
    user_id = data.get('user_id')
    usage_time = datetime.utcnow()
    usage_log = APIUsageLog(endpoint_id=endpoint_id, user_id=user_id, usage_time=usage_time)
    db.session.add(usage_log)
    db.session.commit()
    return jsonify({'message': 'API usage logged'})