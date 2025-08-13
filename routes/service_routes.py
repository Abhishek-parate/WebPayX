from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from models import Service, ServiceCategory, db

service_bp = Blueprint('service', __name__)

# ============================================
# CRUD for Service Categories
# ============================================

@service_bp.route('/service-categories', methods=['POST'])
@login_required
def create_service_category():
    """Create a new service category"""
    data = request.get_json()
    name = data.get('name')
    description = data.get('description')

    category = ServiceCategory(name=name, description=description)
    db.session.add(category)
    db.session.commit()

    return jsonify({'message': 'Category created', 'category': category.to_dict()})

@service_bp.route('/service-categories', methods=['GET'])
@login_required
def list_service_categories():
    """List all service categories"""
    categories = ServiceCategory.query.all()
    return jsonify({'categories': [c.to_dict() for c in categories]})

@service_bp.route('/service-categories/<int:category_id>', methods=['PUT'])
@login_required
def update_service_category(category_id):
    """Update a service category"""
    category = ServiceCategory.query.get_or_404(category_id)
    data = request.get_json()
    category.name = data.get('name', category.name)
    category.description = data.get('description', category.description)
    db.session.commit()
    return jsonify({'message': 'Category updated', 'category': category.to_dict()})

@service_bp.route('/service-categories/<int:category_id>', methods=['DELETE'])
@login_required
def delete_service_category(category_id):
    """Delete a category"""
    category = ServiceCategory.query.get_or_404(category_id)
    db.session.delete(category)
    db.session.commit()
    return jsonify({'message': 'Category deleted'})

# ============================================
# CRUD for Services
# ============================================

@service_bp.route('/services', methods=['POST'])
@login_required
def create_service():
    """Create a new service"""
    data = request.get_json()
    name = data.get('name')
    description = data.get('description')
    price = data.get('price')
    category_id = data.get('category_id')

    service = Service(
        name=name,
        description=description,
        price=price,
        category_id=category_id
    )
    db.session.add(service)
    db.session.commit()

    return jsonify({'message': 'Service created', 'service': service.to_dict()})

@service_bp.route('/services', methods=['GET'])
@login_required
def list_services():
    """List all services"""
    services = Service.query.all()
    return jsonify({'services': [s.to_dict() for s in services]})

@service_bp.route('/services/<int:service_id>', methods=['PUT'])
@login_required
def update_service(service_id):
    """Update service"""
    service = Service.query.get_or_404(service_id)
    data = request.get_json()
    service.name = data.get('name', service.name)
    service.description = data.get('description', service.description)
    service.price = data.get('price', service.price)
    db.session.commit()
    return jsonify({'message': 'Service updated', 'service': service.to_dict()})

@service_bp.route('/services/<int:service_id>', methods=['DELETE'])
@login_required
def delete_service(service_id):
    """Delete a service"""
    service = Service.query.get_or_404(service_id)
    db.session.delete(service)
    db.session.commit()
    return jsonify({'message': 'Service deleted'})