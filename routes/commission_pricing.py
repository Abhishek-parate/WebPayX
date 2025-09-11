from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, make_response
from flask_login import login_required, current_user
from models import (
    db, CommissionPlan, UserCommission, ServicePricing, User, UserRoleType, 
    ServiceType, CommissionMode, Tenant
)
from datetime import datetime, timedelta
from functools import wraps
import uuid
import csv
import io
import json
from sqlalchemy import and_, or_, desc, func
from decimal import Decimal, InvalidOperation

commission_pricing_bp = Blueprint('commission_pricing', __name__, url_prefix='/commission-pricing')

# ============================================================================
# DECORATORS AND UTILITIES - ENHANCED
# ============================================================================

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role.name not in ['SUPER_ADMIN', 'ADMIN']:
            flash('You do not have permission to access this page.', 'error')
            return redirect(url_for('dashboard.index'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def super_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role.name != 'SUPER_ADMIN':
            flash('You do not have permission to access this page.', 'error')
            return redirect(url_for('dashboard.index'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def role_required(allowed_roles):
    """
    Enhanced role-based access control decorator
    Usage: @role_required(['SUPER_ADMIN', 'ADMIN', 'WHITE_LABEL'])
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if current_user.role.name not in allowed_roles:
                flash('You do not have permission to access this page.', 'error')
                return redirect(url_for('dashboard.index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def validate_uuid(uuid_string):
    """Validate UUID format"""
    try:
        uuid.UUID(uuid_string)
        return True
    except (ValueError, TypeError):
        return False

def safe_decimal_conversion(value, default=Decimal('0')):
    """Safely convert value to Decimal"""
    try:
        return Decimal(str(value)) if value else default
    except (InvalidOperation, ValueError, TypeError):
        return default

# ============================================================================
# DASHBOARD AND OVERVIEW - ENHANCED
# ============================================================================

@commission_pricing_bp.route('/')
@login_required
@admin_required
def dashboard():
    """Commission & Pricing Dashboard"""
    try:
        # Get summary statistics with optimized queries
        base_query = CommissionPlan.query
        if current_user.role.name != 'SUPER_ADMIN':
            base_query = base_query.filter_by(tenant_id=current_user.tenant_id)
        
        # Single query for all plan statistics
        plan_stats = db.session.query(
            func.count(CommissionPlan.id).label('total_plans'),
            func.sum(CommissionPlan.is_active.cast(db.Integer)).label('active_plans'),
            func.sum((~CommissionPlan.is_active).cast(db.Integer)).label('inactive_plans'),
            func.sum(
                (CommissionPlan.valid_until < datetime.utcnow()).cast(db.Integer)
            ).label('expired_plans')
        )
        
        if current_user.role.name != 'SUPER_ADMIN':
            plan_stats = plan_stats.filter(CommissionPlan.tenant_id == current_user.tenant_id)
        
        stats_result = plan_stats.first()
        stats = {
            'total_plans': stats_result.total_plans or 0,
            'active_plans': stats_result.active_plans or 0,
            'inactive_plans': stats_result.inactive_plans or 0,
            'expired_plans': stats_result.expired_plans or 0,
        }
        
        # Service type distribution
        service_stats = db.session.query(
            CommissionPlan.service_type, 
            func.count(CommissionPlan.id).label('count')
        )
        if current_user.role.name != 'SUPER_ADMIN':
            service_stats = service_stats.filter_by(tenant_id=current_user.tenant_id)
        
        service_stats = service_stats.group_by(CommissionPlan.service_type).all()
        
        # Commission mode distribution
        mode_stats = db.session.query(
            CommissionPlan.commission_mode, 
            func.count(CommissionPlan.id).label('count')
        )
        if current_user.role.name != 'SUPER_ADMIN':
            mode_stats = mode_stats.filter_by(tenant_id=current_user.tenant_id)
        
        mode_stats = mode_stats.group_by(CommissionPlan.commission_mode).all()
        
        # Recent commission plans
        recent_plans = base_query.order_by(desc(CommissionPlan.created_at)).limit(5).all()
        
        # User commission assignments count
        user_assignments_query = db.session.query(func.count(UserCommission.id))
        if current_user.role.name != 'SUPER_ADMIN':
            user_assignments_query = user_assignments_query.join(
                User, User.id == UserCommission.user_id
            ).filter(User.tenant_id == current_user.tenant_id)
        
        user_assignments = user_assignments_query.scalar() or 0
        
        return render_template('commission_pricing/dashboard.html',
                             title='Commission & Pricing Dashboard',
                             subtitle='Manage Commission Plans and Service Pricing',
                             stats=stats,
                             service_stats=service_stats,
                             mode_stats=mode_stats,
                             recent_plans=recent_plans,
                             user_assignments=user_assignments)
    
    except Exception as e:
        flash(f'Error loading dashboard: {str(e)}', 'error')
        # Return safe dashboard with empty data
        empty_stats = {'total_plans': 0, 'active_plans': 0, 'inactive_plans': 0, 'expired_plans': 0}
        return render_template('commission_pricing/dashboard.html',
                             title='Commission & Pricing Dashboard',
                             subtitle='Manage Commission Plans and Service Pricing',
                             stats=empty_stats,
                             service_stats=[],
                             mode_stats=[],
                             recent_plans=[],
                             user_assignments=0)

# ============================================================================
# COMMISSION PLAN MANAGEMENT - ENHANCED
# ============================================================================

@commission_pricing_bp.route('/plans')
@login_required
@admin_required
def commission_plans():
    """List all commission plans"""
    try:
        # Get filter parameters with sanitization
        search = request.args.get('search', '').strip()
        service_type = request.args.get('service_type', '').strip()
        commission_mode = request.args.get('commission_mode', '').strip()
        status = request.args.get('status', '').strip()
        page = max(request.args.get('page', 1, type=int), 1)
        per_page = min(max(request.args.get('per_page', 20, type=int), 10), 100)
        
        # Base query with tenant filtering
        query = CommissionPlan.query
        if current_user.role.name != 'SUPER_ADMIN':
            query = query.filter_by(tenant_id=current_user.tenant_id)
        
        # Apply filters with validation
        if search:
            search_pattern = f'%{search}%'
            query = query.filter(
                or_(
                    CommissionPlan.plan_name.ilike(search_pattern),
                    CommissionPlan.description.ilike(search_pattern)
                )
            )
        
        if service_type:
            try:
                service_type_enum = ServiceType(service_type)
                query = query.filter_by(service_type=service_type_enum)
            except ValueError:
                flash(f'Invalid service type: {service_type}', 'warning')
        
        if commission_mode:
            try:
                commission_mode_enum = CommissionMode(commission_mode)
                query = query.filter_by(commission_mode=commission_mode_enum)
            except ValueError:
                flash(f'Invalid commission mode: {commission_mode}', 'warning')
        
        if status:
            if status == 'active':
                query = query.filter_by(is_active=True)
            elif status == 'inactive':
                query = query.filter_by(is_active=False)
            elif status == 'expired':
                query = query.filter(CommissionPlan.valid_until < datetime.utcnow())
        
        # Execute query with pagination and sorting
        plans = query.order_by(
            CommissionPlan.is_active.desc(),
            CommissionPlan.created_at.desc()
        ).paginate(
            page=page, 
            per_page=per_page, 
            error_out=False,
            max_per_page=100
        )
        
        return render_template('commission_pricing/plans.html',
                             title='Commission Plans',
                             subtitle='Manage All Commission Plans',
                             plans=plans,
                             service_types=ServiceType,
                             commission_modes=CommissionMode,
                             filters={
                                 'search': search,
                                 'service_type': service_type,
                                 'commission_mode': commission_mode,
                                 'status': status
                             })
    
    except Exception as e:
        flash(f'Error loading commission plans: {str(e)}', 'error')
        return redirect(url_for('commission_pricing.dashboard'))

@commission_pricing_bp.route('/plans/create', methods=['GET', 'POST'])
@login_required
@admin_required
def create_plan():
    """Create new commission plan"""
    if request.method == 'POST':
        try:
            # Extract and validate form data
            plan_name = request.form.get('plan_name', '').strip()
            description = request.form.get('description', '').strip()
            service_type = request.form.get('service_type', '').strip()
            commission_mode = request.form.get('commission_mode', '').strip()
            base_rate = request.form.get('base_rate', '0').strip()
            min_commission = request.form.get('min_commission', '').strip()
            max_commission = request.form.get('max_commission', '').strip()
            valid_from = request.form.get('valid_from', '').strip()
            valid_until = request.form.get('valid_until', '').strip()
            is_active = request.form.get('is_active') == 'on'
            stay_on_page = request.form.get('stay_on_page') == 'on'
            
            # Validation
            validation_errors = []
            if not plan_name:
                validation_errors.append('Plan name is required')
            if not service_type:
                validation_errors.append('Service type is required')
            if not commission_mode:
                validation_errors.append('Commission mode is required')
            
            if validation_errors:
                for error in validation_errors:
                    flash(error, 'error')
                return render_template('commission_pricing/create_plan.html',
                                     title='Create Commission Plan',
                                     subtitle='Add New Commission Plan',
                                     service_types=ServiceType,
                                     commission_modes=CommissionMode,
                                     now=datetime.now())
            
            # Validate enums
            try:
                service_type_enum = ServiceType(service_type)
                commission_mode_enum = CommissionMode(commission_mode)
            except ValueError as e:
                flash(f'Invalid service type or commission mode: {str(e)}', 'error')
                return render_template('commission_pricing/create_plan.html',
                                     title='Create Commission Plan',
                                     subtitle='Add New Commission Plan',
                                     service_types=ServiceType,
                                     commission_modes=CommissionMode,
                                     now=datetime.now())
            
            # Parse and validate dates
            try:
                valid_from_dt = datetime.strptime(valid_from, '%Y-%m-%d') if valid_from else datetime.utcnow()
                valid_until_dt = datetime.strptime(valid_until, '%Y-%m-%d') if valid_until else None
            except ValueError:
                flash('Invalid date format. Please use YYYY-MM-DD format.', 'error')
                return render_template('commission_pricing/create_plan.html',
                                     title='Create Commission Plan',
                                     subtitle='Add New Commission Plan',
                                     service_types=ServiceType,
                                     commission_modes=CommissionMode,
                                     now=datetime.now())
            
            # Validate date logic
            if valid_until_dt and valid_until_dt <= valid_from_dt:
                flash('Valid until date must be after valid from date', 'error')
                return render_template('commission_pricing/create_plan.html',
                                     title='Create Commission Plan',
                                     subtitle='Add New Commission Plan',
                                     service_types=ServiceType,
                                     commission_modes=CommissionMode,
                                     now=datetime.now())
            
            # Check for duplicate plan name within tenant
            existing_plan = CommissionPlan.query.filter_by(
                tenant_id=current_user.tenant_id,
                plan_name=plan_name
            ).first()
            
            if existing_plan:
                flash('A commission plan with this name already exists', 'error')
                return render_template('commission_pricing/create_plan.html',
                                     title='Create Commission Plan',
                                     subtitle='Add New Commission Plan',
                                     service_types=ServiceType,
                                     commission_modes=CommissionMode,
                                     now=datetime.now())
            
            # Handle slabs for slab-based commission
            slabs = []
            if commission_mode_enum == CommissionMode.SLAB_BASED:
                try:
                    slab_data = request.form.get('slabs_json', '[]')
                    slabs = json.loads(slab_data) if slab_data else []
                    # Validate slab data
                    if not validate_slabs(slabs):
                        flash('Invalid slab configuration. Please check your slab data.', 'error')
                        return render_template('commission_pricing/create_plan.html',
                                             title='Create Commission Plan',
                                             subtitle='Add New Commission Plan',
                                             service_types=ServiceType,
                                             commission_modes=CommissionMode,
                                             now=datetime.now())
                except (json.JSONDecodeError, TypeError):
                    flash('Invalid slab configuration format', 'error')
                    return render_template('commission_pricing/create_plan.html',
                                         title='Create Commission Plan',
                                         subtitle='Add New Commission Plan',
                                         service_types=ServiceType,
                                         commission_modes=CommissionMode,
                                         now=datetime.now())
            
            # Convert numeric values safely
            base_rate_decimal = safe_decimal_conversion(base_rate)
            min_commission_decimal = safe_decimal_conversion(min_commission) if min_commission else None
            max_commission_decimal = safe_decimal_conversion(max_commission) if max_commission else None
            
            # Validate commission limits
            if min_commission_decimal and max_commission_decimal:
                if min_commission_decimal > max_commission_decimal:
                    flash('Minimum commission cannot be greater than maximum commission', 'error')
                    return render_template('commission_pricing/create_plan.html',
                                         title='Create Commission Plan',
                                         subtitle='Add New Commission Plan',
                                         service_types=ServiceType,
                                         commission_modes=CommissionMode,
                                         now=datetime.now())
            
            # Create commission plan
            plan = CommissionPlan(
                tenant_id=current_user.tenant_id,
                plan_name=plan_name,
                description=description,
                service_type=service_type_enum,
                commission_mode=commission_mode_enum,
                base_rate=base_rate_decimal,
                min_commission=min_commission_decimal,
                max_commission=max_commission_decimal,
                slabs=slabs,
                is_active=is_active,
                valid_from=valid_from_dt,
                valid_until=valid_until_dt,
                created_by=current_user.id
            )
            
            db.session.add(plan)
            db.session.commit()
            
            success_message = f'Commission plan "{plan_name}" created successfully!'
            
            if stay_on_page:
                flash(success_message, 'success')
                return render_template('commission_pricing/create_plan.html',
                                     title='Create Commission Plan',
                                     subtitle='Add New Commission Plan',
                                     service_types=ServiceType,
                                     commission_modes=CommissionMode,
                                     now=datetime.now(),
                                     success_message=success_message,
                                     clear_form=True)
            else:
                flash(success_message, 'success')
                return redirect(url_for('commission_pricing.commission_plans'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating commission plan: {str(e)}', 'error')
    
    return render_template('commission_pricing/create_plan.html',
                         title='Create Commission Plan',
                         subtitle='Add New Commission Plan',
                         service_types=ServiceType,
                         commission_modes=CommissionMode,
                         now=datetime.now())

@commission_pricing_bp.route('/plans/<plan_id>')
@login_required
@admin_required
def plan_detail(plan_id):
    """View commission plan details"""
    try:
        if not validate_uuid(plan_id):
            flash('Invalid plan ID', 'error')
            return redirect(url_for('commission_pricing.commission_plans'))
        
        # Get plan with tenant filtering
        query = CommissionPlan.query
        if current_user.role.name != 'SUPER_ADMIN':
            query = query.filter_by(tenant_id=current_user.tenant_id)
        
        plan = query.filter_by(id=plan_id).first()
        if not plan:
            flash('Commission plan not found', 'error')
            return redirect(url_for('commission_pricing.commission_plans'))
        
        # Get assigned users with optimized query
        assigned_users = db.session.query(User, UserCommission).join(
            UserCommission, User.id == UserCommission.user_id
        ).filter(
            UserCommission.commission_plan_id == plan_id,
            UserCommission.is_active == True
        ).order_by(User.full_name).all()
        
        # Calculate plan statistics
        total_assigned = len(assigned_users)
        active_assignments = sum(1 for _, uc in assigned_users if uc.is_active)
        
        plan_stats = {
            'total_assigned': total_assigned,
            'active_assignments': active_assignments,
            'inactive_assignments': total_assigned - active_assignments
        }
        
        return render_template('commission_pricing/plan_detail.html',
                             title=f'Plan Details - {plan.plan_name}',
                             subtitle='Commission Plan Information',
                             plan=plan,
                             assigned_users=assigned_users,
                             plan_stats=plan_stats)
    
    except Exception as e:
        flash(f'Error loading plan details: {str(e)}', 'error')
        return redirect(url_for('commission_pricing.commission_plans'))

@commission_pricing_bp.route('/plans/<plan_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_plan(plan_id):
    """Edit commission plan"""
    try:
        if not validate_uuid(plan_id):
            flash('Invalid plan ID', 'error')
            return redirect(url_for('commission_pricing.commission_plans'))
        
        # Get plan with tenant filtering
        query = CommissionPlan.query
        if current_user.role.name != 'SUPER_ADMIN':
            query = query.filter_by(tenant_id=current_user.tenant_id)
        
        plan = query.filter_by(id=plan_id).first()
        if not plan:
            flash('Commission plan not found', 'error')
            return redirect(url_for('commission_pricing.commission_plans'))
        
        if request.method == 'POST':
            try:
                # Extract form data
                plan_name = request.form.get('plan_name', '').strip()
                description = request.form.get('description', '').strip()
                service_type = request.form.get('service_type', '').strip()
                commission_mode = request.form.get('commission_mode', '').strip()
                base_rate = request.form.get('base_rate', '0').strip()
                min_commission = request.form.get('min_commission', '').strip()
                max_commission = request.form.get('max_commission', '').strip()
                valid_from = request.form.get('valid_from', '').strip()
                valid_until = request.form.get('valid_until', '').strip()
                is_active = request.form.get('is_active') == 'on'
                
                # Validation
                if not plan_name:
                    flash('Plan name is required', 'error')
                    return render_template('commission_pricing/edit_plan.html',
                                         title=f'Edit Plan - {plan.plan_name}',
                                         subtitle='Update Commission Plan',
                                         plan=plan,
                                         service_types=ServiceType,
                                         commission_modes=CommissionMode,
                                         now=datetime.now())
                
                # Check for duplicate plan name (excluding current plan)
                existing_plan = CommissionPlan.query.filter(
                    CommissionPlan.tenant_id == current_user.tenant_id,
                    CommissionPlan.plan_name == plan_name,
                    CommissionPlan.id != plan_id
                ).first()
                
                if existing_plan:
                    flash('A commission plan with this name already exists', 'error')
                    return render_template('commission_pricing/edit_plan.html',
                                         title=f'Edit Plan - {plan.plan_name}',
                                         subtitle='Update Commission Plan',
                                         plan=plan,
                                         service_types=ServiceType,
                                         commission_modes=CommissionMode,
                                         now=datetime.now())
                
                # Update plan data
                plan.plan_name = plan_name
                plan.description = description
                
                if service_type:
                    plan.service_type = ServiceType(service_type)
                if commission_mode:
                    plan.commission_mode = CommissionMode(commission_mode)
                
                plan.base_rate = safe_decimal_conversion(base_rate)
                plan.min_commission = safe_decimal_conversion(min_commission) if min_commission else None
                plan.max_commission = safe_decimal_conversion(max_commission) if max_commission else None
                
                # Parse dates
                if valid_from:
                    plan.valid_from = datetime.strptime(valid_from, '%Y-%m-%d')
                if valid_until:
                    plan.valid_until = datetime.strptime(valid_until, '%Y-%m-%d')
                else:
                    plan.valid_until = None
                
                plan.is_active = is_active
                
                # Handle slabs for slab-based commission
                if plan.commission_mode == CommissionMode.SLAB_BASED:
                    try:
                        slab_data = request.form.get('slabs_json', '[]')
                        slabs = json.loads(slab_data) if slab_data else []
                        if validate_slabs(slabs):
                            plan.slabs = slabs
                        else:
                            flash('Invalid slab configuration', 'error')
                            return render_template('commission_pricing/edit_plan.html',
                                                 title=f'Edit Plan - {plan.plan_name}',
                                                 subtitle='Update Commission Plan',
                                                 plan=plan,
                                                 service_types=ServiceType,
                                                 commission_modes=CommissionMode,
                                                 now=datetime.now())
                    except (json.JSONDecodeError, TypeError):
                        flash('Invalid slab configuration format', 'error')
                        return render_template('commission_pricing/edit_plan.html',
                                             title=f'Edit Plan - {plan.plan_name}',
                                             subtitle='Update Commission Plan',
                                             plan=plan,
                                             service_types=ServiceType,
                                             commission_modes=CommissionMode,
                                             now=datetime.now())
                else:
                    plan.slabs = []
                
                plan.updated_at = datetime.utcnow()
                
                db.session.commit()
                flash(f'Commission plan "{plan.plan_name}" updated successfully', 'success')
                return redirect(url_for('commission_pricing.plan_detail', plan_id=plan_id))
                
            except ValueError as e:
                db.session.rollback()
                flash(f'Invalid data provided: {str(e)}', 'error')
            except Exception as e:
                db.session.rollback()
                flash(f'Error updating commission plan: {str(e)}', 'error')
        
        return render_template('commission_pricing/edit_plan.html',
                             title=f'Edit Plan - {plan.plan_name}',
                             subtitle='Update Commission Plan',
                             plan=plan,
                             service_types=ServiceType,
                             commission_modes=CommissionMode,
                             now=datetime.now())
    
    except Exception as e:
        flash(f'Error loading plan for editing: {str(e)}', 'error')
        return redirect(url_for('commission_pricing.commission_plans'))

@commission_pricing_bp.route('/plans/<plan_id>/delete', methods=['POST'])
@login_required
@super_admin_required
def delete_plan(plan_id):
    """Delete commission plan (SUPER_ADMIN only)"""
    try:
        if not validate_uuid(plan_id):
            flash('Invalid plan ID', 'error')
            return redirect(url_for('commission_pricing.commission_plans'))
        
        # Get plan with tenant filtering
        query = CommissionPlan.query
        if current_user.role.name != 'SUPER_ADMIN':
            query = query.filter_by(tenant_id=current_user.tenant_id)
        
        plan = query.filter_by(id=plan_id).first()
        if not plan:
            flash('Commission plan not found', 'error')
            return redirect(url_for('commission_pricing.commission_plans'))
        
        # Check for active user assignments
        active_assignments = UserCommission.query.filter_by(
            commission_plan_id=plan_id, 
            is_active=True
        ).count()
        
        if active_assignments > 0:
            flash(f'Cannot delete commission plan that has {active_assignments} active user assignments', 'error')
            return redirect(url_for('commission_pricing.plan_detail', plan_id=plan_id))
        
        plan_name = plan.plan_name
        db.session.delete(plan)
        db.session.commit()
        
        flash(f'Commission plan "{plan_name}" deleted successfully', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting commission plan: {str(e)}', 'error')
    
    return redirect(url_for('commission_pricing.commission_plans'))

@commission_pricing_bp.route('/plans/<plan_id>/toggle-status', methods=['POST'])
@login_required
@admin_required
def toggle_plan_status(plan_id):
    """Toggle commission plan active status"""
    try:
        if not validate_uuid(plan_id):
            return jsonify({'error': 'Invalid plan ID'}), 400
        
        # Get plan with tenant filtering
        query = CommissionPlan.query
        if current_user.role.name != 'SUPER_ADMIN':
            query = query.filter_by(tenant_id=current_user.tenant_id)
        
        plan = query.filter_by(id=plan_id).first()
        if not plan:
            return jsonify({'error': 'Commission plan not found'}), 404
        
        plan.is_active = not plan.is_active
        plan.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        status = 'activated' if plan.is_active else 'deactivated'
        
        if request.is_json:
            return jsonify({
                'success': True,
                'message': f'Commission plan "{plan.plan_name}" {status} successfully',
                'is_active': plan.is_active
            })
        else:
            flash(f'Commission plan "{plan.plan_name}" {status} successfully', 'success')
            return redirect(url_for('commission_pricing.plan_detail', plan_id=plan_id))
        
    except Exception as e:
        db.session.rollback()
        error_msg = f'Error updating commission plan status: {str(e)}'
        
        if request.is_json:
            return jsonify({'error': error_msg}), 500
        else:
            flash(error_msg, 'error')
            return redirect(url_for('commission_pricing.plan_detail', plan_id=plan_id))

# ============================================================================
# USER COMMISSION ASSIGNMENT - ENHANCED
# ============================================================================

@commission_pricing_bp.route('/user-commissions')
@login_required
@admin_required
def user_commissions():
    """Manage user commission assignments"""
    try:
        # Get filter parameters
        search = request.args.get('search', '').strip()
        plan_id = request.args.get('plan_id', '').strip()
        role = request.args.get('role', '').strip()
        page = max(request.args.get('page', 1, type=int), 1)
        per_page = min(max(request.args.get('per_page', 20, type=int), 10), 100)
        
        # Base query with optimized joins
        query = db.session.query(User).outerjoin(
            UserCommission, and_(
                User.id == UserCommission.user_id,
                UserCommission.is_active == True
            )
        ).outerjoin(
            CommissionPlan, UserCommission.commission_plan_id == CommissionPlan.id
        )
        
        # Tenant filtering
        if current_user.role.name != 'SUPER_ADMIN':
            query = query.filter(User.tenant_id == current_user.tenant_id)
        
        # Apply filters
        if search:
            search_pattern = f'%{search}%'
            query = query.filter(
                or_(
                    User.full_name.ilike(search_pattern),
                    User.username.ilike(search_pattern),
                    User.email.ilike(search_pattern)
                )
            )
        
        if plan_id and validate_uuid(plan_id):
            query = query.filter(UserCommission.commission_plan_id == plan_id)
        
        if role:
            try:
                role_enum = UserRoleType[role.upper()]
                query = query.filter(User.role == role_enum)
            except KeyError:
                flash(f'Invalid role: {role}', 'warning')
        
        # Execute query with pagination
        users = query.order_by(User.full_name).paginate(
            page=page, 
            per_page=per_page, 
            error_out=False,
            max_per_page=100
        )
        
        # Get user commission data
        user_commission_data = []
        for user in users.items:
            user_commissions = db.session.query(UserCommission, CommissionPlan).join(
                CommissionPlan, UserCommission.commission_plan_id == CommissionPlan.id
            ).filter(
                UserCommission.user_id == user.id,
                UserCommission.is_active == True
            ).all()
            
            user_commission_data.append({
                'user': user,
                'commissions': user_commissions
            })
        
        # Get available commission plans for dropdown
        plans_query = CommissionPlan.query.filter_by(is_active=True)
        if current_user.role.name != 'SUPER_ADMIN':
            plans_query = plans_query.filter_by(tenant_id=current_user.tenant_id)
        available_plans = plans_query.order_by(CommissionPlan.plan_name).all()
        
        return render_template('commission_pricing/user_commissions.html',
                             title='User Commissions',
                             subtitle='Manage User Commission Assignments',
                             user_commission_data=user_commission_data,
                             available_plans=available_plans,
                             user_roles=UserRoleType,
                             pagination=users,
                             filters={
                                 'search': search,
                                 'plan_id': plan_id,
                                 'role': role
                             })
    
    except Exception as e:
        flash(f'Error loading user commissions: {str(e)}', 'error')
        return redirect(url_for('commission_pricing.dashboard'))

@commission_pricing_bp.route('/user-commissions/<user_id>/assign', methods=['GET', 'POST'])
@login_required
@admin_required
def assign_commission(user_id):
    """Assign commission plan to user"""
    try:
        if not validate_uuid(user_id):
            flash('Invalid user ID', 'error')
            return redirect(url_for('commission_pricing.user_commissions'))
        
        # Get user with tenant filtering
        user_query = User.query
        if current_user.role.name != 'SUPER_ADMIN':
            user_query = user_query.filter_by(tenant_id=current_user.tenant_id)
        
        user = user_query.filter_by(id=user_id).first()
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('commission_pricing.user_commissions'))
        
        if request.method == 'POST':
            try:
                commission_plan_id = request.form.get('commission_plan_id', '').strip()
                custom_rate = request.form.get('custom_rate', '').strip()
                
                if not commission_plan_id:
                    flash('Please select a commission plan', 'error')
                    return redirect(url_for('commission_pricing.assign_commission', user_id=user_id))
                
                if not validate_uuid(commission_plan_id):
                    flash('Invalid commission plan selected', 'error')
                    return redirect(url_for('commission_pricing.assign_commission', user_id=user_id))
                
                # Verify plan exists and is active
                plan_query = CommissionPlan.query.filter_by(
                    id=commission_plan_id,
                    is_active=True
                )
                if current_user.role.name != 'SUPER_ADMIN':
                    plan_query = plan_query.filter_by(tenant_id=current_user.tenant_id)
                
                plan = plan_query.first()
                if not plan:
                    flash('Commission plan not found or not available', 'error')
                    return redirect(url_for('commission_pricing.assign_commission', user_id=user_id))
                
                # Convert custom rate safely
                custom_rate_decimal = safe_decimal_conversion(custom_rate) if custom_rate else None
                
                # Check for existing assignment
                existing = UserCommission.query.filter_by(
                    user_id=user_id,
                    commission_plan_id=commission_plan_id
                ).first()
                
                if existing:
                    # Update existing assignment
                    existing.custom_rate = custom_rate_decimal
                    existing.is_active = True
                    existing.assigned_at = datetime.utcnow()
                    existing.assigned_by = current_user.id
                    action = 'updated'
                else:
                    # Create new assignment
                    assignment = UserCommission(
                        user_id=user_id,
                        commission_plan_id=commission_plan_id,
                        custom_rate=custom_rate_decimal,
                        is_active=True,
                        assigned_by=current_user.id
                    )
                    db.session.add(assignment)
                    action = 'assigned'
                
                db.session.commit()
                flash(f'Commission plan {action} to {user.full_name} successfully', 'success')
                return redirect(url_for('commission_pricing.user_commissions'))
                
            except Exception as e:
                db.session.rollback()
                flash(f'Error assigning commission plan: {str(e)}', 'error')
        
        # Get available plans and current assignments
        plans_query = CommissionPlan.query.filter_by(is_active=True)
        if current_user.role.name != 'SUPER_ADMIN':
            plans_query = plans_query.filter_by(tenant_id=current_user.tenant_id)
        available_plans = plans_query.order_by(CommissionPlan.plan_name).all()
        
        current_assignments = db.session.query(UserCommission, CommissionPlan).join(
            CommissionPlan, UserCommission.commission_plan_id == CommissionPlan.id
        ).filter(
            UserCommission.user_id == user_id, 
            UserCommission.is_active == True
        ).order_by(CommissionPlan.plan_name).all()
        
        return render_template('commission_pricing/assign_commission.html',
                             title=f'Assign Commission - {user.full_name}',
                             subtitle='Manage User Commission Plans',
                             user=user,
                             available_plans=available_plans,
                             current_assignments=current_assignments)
    
    except Exception as e:
        flash(f'Error loading commission assignment page: {str(e)}', 'error')
        return redirect(url_for('commission_pricing.user_commissions'))

@commission_pricing_bp.route('/user-commissions/<user_id>/<assignment_id>/remove', methods=['POST'])
@login_required
@admin_required
def remove_commission(user_id, assignment_id):
    """Remove commission plan from user"""
    try:
        if not validate_uuid(user_id) or not validate_uuid(assignment_id):
            flash('Invalid user or assignment ID', 'error')
            return redirect(url_for('commission_pricing.user_commissions'))
        
        assignment = UserCommission.query.filter_by(
            id=assignment_id,
            user_id=user_id
        ).first()
        
        if not assignment:
            flash('Commission assignment not found', 'error')
            return redirect(url_for('commission_pricing.user_commissions'))
        
        # Verify user belongs to current tenant (if not super admin)
        if current_user.role.name != 'SUPER_ADMIN':
            user = User.query.filter_by(
                id=user_id, 
                tenant_id=current_user.tenant_id
            ).first()
            if not user:
                flash('User not found', 'error')
                return redirect(url_for('commission_pricing.user_commissions'))
        
        assignment.is_active = False
        assignment.removed_at = datetime.utcnow()
        assignment.removed_by = current_user.id
        
        db.session.commit()
        
        if request.is_json:
            return jsonify({
                'success': True,
                'message': 'Commission plan removed successfully'
            })
        else:
            flash('Commission plan removed successfully', 'success')
            return redirect(url_for('commission_pricing.user_commissions'))
        
    except Exception as e:
        db.session.rollback()
        error_msg = f'Error removing commission plan: {str(e)}'
        
        if request.is_json:
            return jsonify({'error': error_msg}), 500
        else:
            flash(error_msg, 'error')
            return redirect(url_for('commission_pricing.user_commissions'))

# ============================================================================
# SERVICE PRICING MANAGEMENT - ENHANCED
# ============================================================================

@commission_pricing_bp.route('/service-pricing')
@login_required
@admin_required
def service_pricing():
    """Manage service pricing"""
    try:
        # Get filter parameters
        search = request.args.get('search', '').strip()
        service_type = request.args.get('service_type', '').strip()
        status = request.args.get('status', '').strip()
        page = max(request.args.get('page', 1, type=int), 1)
        per_page = min(max(request.args.get('per_page', 20, type=int), 10), 100)
        
        # Base query with tenant filtering
        query = ServicePricing.query
        if current_user.role.name != 'SUPER_ADMIN':
            query = query.filter_by(tenant_id=current_user.tenant_id)
        
        # Apply filters
        if search:
            search_pattern = f'%{search}%'
            query = query.filter(
                or_(
                    ServicePricing.provider.ilike(search_pattern),
                    ServicePricing.description.ilike(search_pattern)
                )
            )
        
        if service_type:
            try:
                service_type_enum = ServiceType(service_type)
                query = query.filter_by(service_type=service_type_enum)
            except ValueError:
                flash(f'Invalid service type: {service_type}', 'warning')
        
        if status:
            query = query.filter_by(is_active=(status == 'active'))
        
        # Execute query with pagination and sorting
        pricing = query.order_by(
            ServicePricing.service_type,
            ServicePricing.provider
        ).paginate(
            page=page, 
            per_page=per_page, 
            error_out=False,
            max_per_page=100
        )
        
        return render_template('commission_pricing/service_pricing.html',
                             title='Service Pricing',
                             subtitle='Manage Service Provider Pricing',
                             pricing=pricing,
                             service_types=ServiceType,
                             filters={
                                 'search': search,
                                 'service_type': service_type,
                                 'status': status
                             })
    
    except Exception as e:
        flash(f'Error loading service pricing: {str(e)}', 'error')
        return redirect(url_for('commission_pricing.dashboard'))

@commission_pricing_bp.route('/service-pricing/create', methods=['GET', 'POST'])
@login_required
@admin_required
def create_pricing():
    """Create new service pricing"""
    if request.method == 'POST':
        try:
            # Extract form data
            service_type = request.form.get('service_type')
            provider = request.form.get('provider', '').strip()
            description = request.form.get('description', '').strip()
            base_cost = request.form.get('base_cost', '0')
            markup = request.form.get('markup', '0')
            min_amount = request.form.get('min_amount', '0')
            max_amount = request.form.get('max_amount', '')
            is_active = request.form.get('is_active') == 'on'
            effective_from = request.form.get('effective_from')
            
            # Validation
            validation_errors = []
            if not service_type:
                validation_errors.append('Service type is required')
            if not provider:
                validation_errors.append('Provider name is required')
            if not base_cost or safe_decimal_conversion(base_cost) <= 0:
                validation_errors.append('Base cost must be greater than 0')
            
            if validation_errors:
                for error in validation_errors:
                    flash(error, 'error')
                return render_template('commission_pricing/create_pricing.html',
                                     title='Create Service Pricing',
                                     subtitle='Add New Service Pricing',
                                     service_types=ServiceType,
                                     now=datetime.now())
            
            # Check for existing pricing
            existing = ServicePricing.query.filter_by(
                tenant_id=current_user.tenant_id,
                service_type=ServiceType(service_type),
                provider=provider
            ).first()
            
            if existing:
                flash('Pricing for this service type and provider already exists', 'error')
                return render_template('commission_pricing/create_pricing.html',
                                     title='Create Service Pricing',
                                     subtitle='Add New Service Pricing',
                                     service_types=ServiceType,
                                     now=datetime.now())
            
            # Create pricing with safe decimal conversions
            pricing = ServicePricing(
                tenant_id=current_user.tenant_id,
                service_type=ServiceType(service_type),
                provider=provider,
                description=description,
                base_cost=safe_decimal_conversion(base_cost),
                markup=safe_decimal_conversion(markup),
                min_amount=safe_decimal_conversion(min_amount) if min_amount else None,
                max_amount=safe_decimal_conversion(max_amount) if max_amount else None,
                is_active=is_active,
                effective_from=datetime.strptime(effective_from, '%Y-%m-%d') if effective_from else datetime.utcnow(),
                created_by=current_user.id
            )
            
            db.session.add(pricing)
            db.session.commit()
            
            flash(f'Service pricing for {provider} created successfully', 'success')
            return redirect(url_for('commission_pricing.service_pricing'))
            
        except ValueError as e:
            db.session.rollback()
            flash(f'Invalid data provided: {str(e)}', 'error')
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating service pricing: {str(e)}', 'error')
    
    return render_template('commission_pricing/create_pricing.html',
                         title='Create Service Pricing',
                         subtitle='Add New Service Pricing',
                         service_types=ServiceType,
                         now=datetime.now())

@commission_pricing_bp.route('/service-pricing/<pricing_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_pricing(pricing_id):
    """Edit service pricing"""
    try:
        if not validate_uuid(pricing_id):
            flash('Invalid pricing ID', 'error')
            return redirect(url_for('commission_pricing.service_pricing'))
        
        # Get pricing with tenant filtering
        query = ServicePricing.query
        if current_user.role.name != 'SUPER_ADMIN':
            query = query.filter_by(tenant_id=current_user.tenant_id)
        
        pricing = query.filter_by(id=pricing_id).first()
        if not pricing:
            flash('Service pricing not found', 'error')
            return redirect(url_for('commission_pricing.service_pricing'))
        
        if request.method == 'POST':
            try:
                # Update pricing fields
                pricing.provider = request.form.get('provider', '').strip()
                pricing.description = request.form.get('description', '').strip()
                pricing.base_cost = safe_decimal_conversion(request.form.get('base_cost', '0'))
                pricing.markup = safe_decimal_conversion(request.form.get('markup', '0'))
                pricing.min_amount = safe_decimal_conversion(request.form.get('min_amount')) if request.form.get('min_amount') else None
                pricing.max_amount = safe_decimal_conversion(request.form.get('max_amount')) if request.form.get('max_amount') else None
                pricing.is_active = request.form.get('is_active') == 'on'
                
                effective_from = request.form.get('effective_from')
                if effective_from:
                    pricing.effective_from = datetime.strptime(effective_from, '%Y-%m-%d')
                
                pricing.updated_at = datetime.utcnow()
                
                db.session.commit()
                flash(f'Service pricing for {pricing.provider} updated successfully', 'success')
                return redirect(url_for('commission_pricing.service_pricing'))
                
            except ValueError as e:
                db.session.rollback()
                flash(f'Invalid data provided: {str(e)}', 'error')
            except Exception as e:
                db.session.rollback()
                flash(f'Error updating service pricing: {str(e)}', 'error')
        
        return render_template('commission_pricing/edit_pricing.html',
                             title=f'Edit Pricing - {pricing.provider}',
                             subtitle='Update Service Pricing',
                             pricing=pricing,
                             service_types=ServiceType,
                             now=datetime.now())
    
    except Exception as e:
        flash(f'Error loading pricing for editing: {str(e)}', 'error')
        return redirect(url_for('commission_pricing.service_pricing'))

@commission_pricing_bp.route('/service-pricing/<pricing_id>/delete', methods=['POST'])
@login_required
@super_admin_required
def delete_pricing(pricing_id):
    """Delete service pricing (SUPER_ADMIN only)"""
    try:
        if not validate_uuid(pricing_id):
            flash('Invalid pricing ID', 'error')
            return redirect(url_for('commission_pricing.service_pricing'))
        
        # Get pricing with tenant filtering
        query = ServicePricing.query
        if current_user.role.name != 'SUPER_ADMIN':
            query = query.filter_by(tenant_id=current_user.tenant_id)
        
        pricing = query.filter_by(id=pricing_id).first()
        if not pricing:
            flash('Service pricing not found', 'error')
            return redirect(url_for('commission_pricing.service_pricing'))
        
        provider_name = pricing.provider
        db.session.delete(pricing)
        db.session.commit()
        
        flash(f'Service pricing for {provider_name} deleted successfully', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting service pricing: {str(e)}', 'error')
    
    return redirect(url_for('commission_pricing.service_pricing'))

# ============================================================================
# REPORTS AND ANALYTICS - ENHANCED
# ============================================================================

@commission_pricing_bp.route('/reports/commission-summary')
@login_required
@admin_required
def commission_summary_report():
    """Generate commission summary report"""
    try:
        # Get date parameters
        date_from = request.args.get('date_from', (datetime.utcnow() - timedelta(days=30)).strftime('%Y-%m-%d'))
        date_to = request.args.get('date_to', datetime.utcnow().strftime('%Y-%m-%d'))
        
        # Validate dates
        try:
            from_date = datetime.strptime(date_from, '%Y-%m-%d')
            to_date = datetime.strptime(date_to, '%Y-%m-%d')
        except ValueError:
            flash('Invalid date format', 'error')
            return redirect(url_for('commission_pricing.dashboard'))
        
        # Summary data query with enhanced statistics
        summary_data = db.session.query(
            CommissionPlan.id,
            CommissionPlan.plan_name,
            CommissionPlan.service_type,
            CommissionPlan.commission_mode,
            CommissionPlan.base_rate,
            func.count(UserCommission.id).label('assigned_users'),
            func.sum(UserCommission.is_active.cast(db.Integer)).label('active_assignments'),
            func.avg(
                func.coalesce(UserCommission.custom_rate, CommissionPlan.base_rate)
            ).label('avg_rate')
        ).outerjoin(
            UserCommission, and_(
                CommissionPlan.id == UserCommission.commission_plan_id,
                UserCommission.assigned_at.between(from_date, to_date)
            )
        ).group_by(
            CommissionPlan.id,
            CommissionPlan.plan_name, 
            CommissionPlan.service_type, 
            CommissionPlan.commission_mode,
            CommissionPlan.base_rate
        )
        
        # Apply tenant filtering
        if current_user.role.name != 'SUPER_ADMIN':
            summary_data = summary_data.filter(CommissionPlan.tenant_id == current_user.tenant_id)
        
        summary_data = summary_data.order_by(CommissionPlan.plan_name).all()
        
        # Calculate totals
        totals = {
            'total_plans': len(summary_data),
            'total_assignments': sum(row.assigned_users for row in summary_data),
            'active_assignments': sum(row.active_assignments or 0 for row in summary_data)
        }
        
        return render_template('commission_pricing/commission_summary.html',
                             title='Commission Summary Report',
                             subtitle='Commission Plan Analysis',
                             summary_data=summary_data,
                             totals=totals,
                             date_from=date_from,
                             date_to=date_to)
    
    except Exception as e:
        flash(f'Error generating commission summary report: {str(e)}', 'error')
        return redirect(url_for('commission_pricing.dashboard'))

# ============================================================================
# EXPORT FUNCTIONALITY - ENHANCED
# ============================================================================

@commission_pricing_bp.route('/export/commission-plans')
@login_required
@admin_required
def export_commission_plans():
    """Export commission plans to CSV"""
    try:
        # Get plans with tenant filtering
        query = CommissionPlan.query
        if current_user.role.name != 'SUPER_ADMIN':
            query = query.filter_by(tenant_id=current_user.tenant_id)
        
        plans = query.order_by(
            CommissionPlan.service_type, 
            CommissionPlan.plan_name
        ).all()
        
        # Create CSV output
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Enhanced CSV headers
        writer.writerow([
            'Plan Name', 'Description', 'Service Type', 'Commission Mode', 
            'Base Rate', 'Min Commission', 'Max Commission', 'Status', 
            'Valid From', 'Valid Until', 'Created At', 'Updated At',
            'Assigned Users', 'Has Slabs'
        ])
        
        # Write data with additional statistics
        for plan in plans:
            # Get assignment count
            assignment_count = UserCommission.query.filter_by(
                commission_plan_id=plan.id,
                is_active=True
            ).count()
            
            writer.writerow([
                plan.plan_name,
                plan.description or '',
                plan.service_type.value if plan.service_type else '',
                plan.commission_mode.value if plan.commission_mode else '',
                float(plan.base_rate) if plan.base_rate else 0,
                float(plan.min_commission) if plan.min_commission else '',
                float(plan.max_commission) if plan.max_commission else '',
                'Active' if plan.is_active else 'Inactive',
                plan.valid_from.strftime('%Y-%m-%d') if plan.valid_from else '',
                plan.valid_until.strftime('%Y-%m-%d') if plan.valid_until else '',
                plan.created_at.strftime('%Y-%m-%d %H:%M:%S') if plan.created_at else '',
                plan.updated_at.strftime('%Y-%m-%d %H:%M:%S') if plan.updated_at else '',
                assignment_count,
                'Yes' if plan.slabs else 'No'
            ])
        
        # Prepare response
        output.seek(0)
        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv; charset=utf-8'
        response.headers['Content-Disposition'] = f'attachment; filename="commission_plans_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.csv"'
        
        return response
        
    except Exception as e:
        flash(f'Error exporting commission plans: {str(e)}', 'error')
        return redirect(url_for('commission_pricing.commission_plans'))

@commission_pricing_bp.route('/plans/<plan_id>/export')
@login_required
@admin_required
def export_plan(plan_id):
    """Export individual commission plan data"""
    try:
        if not validate_uuid(plan_id):
            flash('Invalid plan ID', 'error')
            return redirect(url_for('commission_pricing.commission_plans'))
        
        # Get plan with tenant filtering
        query = CommissionPlan.query
        if current_user.role.name != 'SUPER_ADMIN':
            query = query.filter_by(tenant_id=current_user.tenant_id)
        
        plan = query.filter_by(id=plan_id).first()
        if not plan:
            flash('Commission plan not found', 'error')
            return redirect(url_for('commission_pricing.commission_plans'))
        
        # Get export format
        format_type = request.args.get('format', 'csv').lower()
        
        if format_type == 'csv':
            return export_plan_csv(plan)
        elif format_type == 'json':
            return export_plan_json(plan)
        else:
            return jsonify({'error': 'Invalid export format'}), 400
            
    except Exception as e:
        flash('Export failed. Please try again.', 'error')
        return redirect(url_for('commission_pricing.plan_detail', plan_id=plan_id))

def export_plan_csv(plan):
    """Export plan data as CSV with enhanced details"""
    try:
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Plan information section
        writer.writerow(['Commission Plan Export'])
        writer.writerow(['Generated at:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
        writer.writerow([])
        
        writer.writerow(['Plan Information'])
        writer.writerow(['Field', 'Value'])
        writer.writerow(['Plan Name', plan.plan_name])
        writer.writerow(['Description', plan.description or 'N/A'])
        writer.writerow(['Service Type', plan.service_type.value.replace('_', ' ').title()])
        writer.writerow(['Commission Mode', plan.commission_mode.value.replace('_', ' ').title()])
        writer.writerow(['Base Rate', f"{plan.base_rate}{'%' if plan.commission_mode.value == 'PERCENTAGE' else '₹'}"])
        writer.writerow(['Min Commission', f"₹{plan.min_commission}" if plan.min_commission else 'Not set'])
        writer.writerow(['Max Commission', f"₹{plan.max_commission}" if plan.max_commission else 'No limit'])
        writer.writerow(['Status', 'Active' if plan.is_active else 'Inactive'])
        writer.writerow(['Valid From', plan.valid_from.strftime('%d %b %Y') if plan.valid_from else 'N/A'])
        writer.writerow(['Valid Until', plan.valid_until.strftime('%d %b %Y') if plan.valid_until else 'No Expiry'])
        writer.writerow(['Created At', plan.created_at.strftime('%d %b %Y at %I:%M %p')])
        writer.writerow(['Last Updated', plan.updated_at.strftime('%d %b %Y at %I:%M %p') if plan.updated_at else 'Never'])
        
        # Commission slabs section
        if plan.commission_mode.value == 'SLAB_BASED' and plan.slabs:
            writer.writerow([])
            writer.writerow(['Commission Slabs'])
            writer.writerow(['Slab No.', 'Min Amount', 'Max Amount', 'Rate', 'Type'])
            for i, slab in enumerate(plan.slabs, 1):
                max_amount = slab.get('max_amount', 'Unlimited')
                if max_amount != 'Unlimited':
                    max_amount = f"₹{max_amount}"
                
                writer.writerow([
                    f"Slab {i}",
                    f"₹{slab.get('min_amount', 0)}",
                    max_amount,
                    slab.get('rate', 0),
                    slab.get('type', 'percentage').title()
                ])
        
        # Assigned users section
        assigned_users = db.session.query(User, UserCommission).join(
            UserCommission, User.id == UserCommission.user_id
        ).filter(
            UserCommission.commission_plan_id == plan.id,
            UserCommission.is_active == True
        ).order_by(User.full_name).all()
        
        if assigned_users:
            writer.writerow([])
            writer.writerow(['Assigned Users'])
            writer.writerow(['User Name', 'Email', 'Role', 'Commission Rate', 'Status', 'Assigned Date'])
            for user, commission in assigned_users:
                rate = commission.custom_rate if commission.custom_rate else plan.base_rate
                rate_display = f"{rate}{'%' if plan.commission_mode.value == 'PERCENTAGE' else '₹'}"
                
                writer.writerow([
                    user.full_name,
                    user.email,
                    user.role.value.replace('_', ' ').title(),
                    rate_display,
                    'Active' if commission.is_active else 'Inactive',
                    commission.assigned_at.strftime('%d %b %Y') if commission.assigned_at else 'N/A'
                ])
        
        # Statistics section
        writer.writerow([])
        writer.writerow(['Statistics'])
        writer.writerow(['Total Assigned Users', len(assigned_users)])
        writer.writerow(['Active Assignments', sum(1 for _, uc in assigned_users if uc.is_active)])
        
        # Prepare response
        output.seek(0)
        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv; charset=utf-8'
        response.headers['Content-Disposition'] = f'attachment; filename="{plan.plan_name}_detailed_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv"'
        
        return response
        
    except Exception as e:
        flash(f'Error exporting plan to CSV: {str(e)}', 'error')
        return redirect(url_for('commission_pricing.plan_detail', plan_id=plan.id))

def export_plan_json(plan):
    """Export plan data as JSON"""
    try:
        # Get assigned users
        assigned_users = db.session.query(User, UserCommission).join(
            UserCommission, User.id == UserCommission.user_id
        ).filter(
            UserCommission.commission_plan_id == plan.id,
            UserCommission.is_active == True
        ).all()
        
        # Prepare plan data
        plan_data = {
            'plan_info': {
                'id': str(plan.id),
                'plan_name': plan.plan_name,
                'description': plan.description,
                'service_type': plan.service_type.value,
                'commission_mode': plan.commission_mode.value,
                'base_rate': float(plan.base_rate) if plan.base_rate else 0,
                'min_commission': float(plan.min_commission) if plan.min_commission else None,
                'max_commission': float(plan.max_commission) if plan.max_commission else None,
                'is_active': plan.is_active,
                'valid_from': plan.valid_from.isoformat() if plan.valid_from else None,
                'valid_until': plan.valid_until.isoformat() if plan.valid_until else None,
                'created_at': plan.created_at.isoformat() if plan.created_at else None,
                'updated_at': plan.updated_at.isoformat() if plan.updated_at else None
            },
            'slabs': plan.slabs if plan.slabs else [],
            'assigned_users': [
                {
                    'user_id': str(user.id),
                    'full_name': user.full_name,
                    'email': user.email,
                    'role': user.role.value,
                    'custom_rate': float(commission.custom_rate) if commission.custom_rate else None,
                    'is_active': commission.is_active,
                    'assigned_at': commission.assigned_at.isoformat() if commission.assigned_at else None
                }
                for user, commission in assigned_users
            ],
            'statistics': {
                'total_assigned': len(assigned_users),
                'active_assignments': sum(1 for _, uc in assigned_users if uc.is_active)
            },
            'export_info': {
                'exported_at': datetime.now().isoformat(),
                'exported_by': current_user.full_name
            }
        }
        
        response = make_response(json.dumps(plan_data, indent=2))
        response.headers['Content-Type'] = 'application/json'
        response.headers['Content-Disposition'] = f'attachment; filename="{plan.plan_name}_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json"'
        
        return response
        
    except Exception as e:
        flash(f'Error exporting plan to JSON: {str(e)}', 'error')
        return redirect(url_for('commission_pricing.plan_detail', plan_id=plan.id))

# ============================================================================
# API ENDPOINTS - ENHANCED
# ============================================================================

@commission_pricing_bp.route('/api/commission-calculator')
@login_required
def commission_calculator():
    """Enhanced commission calculator API"""
    try:
        plan_id = request.args.get('plan_id', '').strip()
        amount = request.args.get('amount', '0').strip()
        custom_rate = request.args.get('custom_rate', '').strip()
        
        # Validation
        if not plan_id or not amount:
            return jsonify({'error': 'Plan ID and amount are required'}), 400
        
        if not validate_uuid(plan_id):
            return jsonify({'error': 'Invalid plan ID format'}), 400
        
        # Get commission plan
        query = CommissionPlan.query
        if current_user.role.name != 'SUPER_ADMIN':
            query = query.filter_by(tenant_id=current_user.tenant_id)
        
        plan = query.filter_by(id=plan_id, is_active=True).first()
        if not plan:
            return jsonify({'error': 'Commission plan not found'}), 404
        
        amount_decimal = safe_decimal_conversion(amount)
        if amount_decimal <= 0:
            return jsonify({'error': 'Amount must be greater than zero'}), 400
        
        # Use custom rate if provided and valid
        effective_rate = plan.base_rate
        if custom_rate:
            custom_rate_decimal = safe_decimal_conversion(custom_rate)
            if custom_rate_decimal > 0:
                effective_rate = custom_rate_decimal
        
        # Calculate commission
        commission = calculate_commission_with_rate(plan, amount_decimal, effective_rate)
        
        return jsonify({
            'success': True,
            'commission': float(commission),
            'plan_name': plan.plan_name,
            'commission_mode': plan.commission_mode.value,
            'base_rate': float(plan.base_rate),
            'effective_rate': float(effective_rate),
            'amount': float(amount_decimal),
            'min_commission': float(plan.min_commission) if plan.min_commission else None,
            'max_commission': float(plan.max_commission) if plan.max_commission else None
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@commission_pricing_bp.route('/api/plans/<plan_id>/toggle-status', methods=['POST'])
@login_required
@admin_required
def api_toggle_plan_status(plan_id):
    """API endpoint to toggle plan status"""
    return toggle_plan_status(plan_id)

# ============================================================================
# UTILITY FUNCTIONS - ENHANCED
# ============================================================================

def validate_slabs(slabs):
    """Validate slab configuration"""
    if not slabs or not isinstance(slabs, list):
        return True  # Empty slabs are valid
    
    try:
        for slab in slabs:
            if not isinstance(slab, dict):
                return False
            
            # Check required fields
            if 'min_amount' not in slab or 'rate' not in slab:
                return False
            
            # Validate numeric values
            min_amount = safe_decimal_conversion(slab.get('min_amount'))
            rate = safe_decimal_conversion(slab.get('rate'))
            
            if min_amount < 0 or rate < 0:
                return False
            
            # Validate max_amount if provided
            if 'max_amount' in slab and slab['max_amount']:
                max_amount = safe_decimal_conversion(slab.get('max_amount'))
                if max_amount <= min_amount:
                    return False
        
        return True
        
    except Exception:
        return False

def calculate_commission(plan, amount):
    """Calculate commission based on plan and amount"""
    return calculate_commission_with_rate(plan, amount, plan.base_rate)

def calculate_commission_with_rate(plan, amount, rate):
    """Calculate commission with custom rate support"""
    try:
        if plan.commission_mode == CommissionMode.PERCENTAGE:
            commission = amount * (rate / 100)
        elif plan.commission_mode == CommissionMode.FLAT:
            commission = rate
        elif plan.commission_mode == CommissionMode.SLAB_BASED:
            commission = calculate_slab_commission(plan.slabs, amount)
        elif plan.commission_mode == CommissionMode.VOLUME_BASED:
            # Enhanced volume-based calculation could be implemented here
            commission = amount * (rate / 100)
        else:
            commission = Decimal('0')
        
        # Apply min/max limits
        if plan.min_commission and commission < plan.min_commission:
            commission = plan.min_commission
        if plan.max_commission and commission > plan.max_commission:
            commission = plan.max_commission
        
        return max(commission, Decimal('0'))  # Ensure non-negative
        
    except Exception:
        return Decimal('0')

def calculate_slab_commission(slabs, amount):
    """Enhanced slab commission calculation"""
    try:
        if not slabs or not isinstance(slabs, list):
            return Decimal('0')
        
        commission = Decimal('0')
        remaining_amount = amount
        
        # Sort slabs by min_amount to ensure proper calculation
        sorted_slabs = sorted(slabs, key=lambda x: safe_decimal_conversion(x.get('min_amount', 0)))
        
        for slab in sorted_slabs:
            if remaining_amount <= 0:
                break
            
            min_amount = safe_decimal_conversion(slab.get('min_amount', 0))
            max_amount = safe_decimal_conversion(slab.get('max_amount', 0)) if slab.get('max_amount') else None
            rate = safe_decimal_conversion(slab.get('rate', 0))
            slab_type = slab.get('type', 'percentage').lower()
            
            # Check if amount qualifies for this slab
            if amount < min_amount:
                continue
            
            # Calculate applicable amount for this slab
            if max_amount and max_amount > min_amount:
                applicable_start = max(min_amount, amount - remaining_amount)
                applicable_end = min(max_amount, amount)
                slab_amount = max(applicable_end - applicable_start, Decimal('0'))
            else:
                # Unlimited upper bound
                slab_amount = remaining_amount
            
            if slab_amount > 0:
                # Calculate commission for this slab
                if slab_type == 'percentage':
                    slab_commission = slab_amount * (rate / 100)
                else:  # flat rate
                    slab_commission = rate
                
                commission += slab_commission
                remaining_amount -= slab_amount
        
        return commission
        
    except Exception:
        return Decimal('0')

def get_user_commission_rate(user_id, plan_id):
    """Get effective commission rate for a user and plan"""
    try:
        user_commission = UserCommission.query.filter_by(
            user_id=user_id,
            commission_plan_id=plan_id,
            is_active=True
        ).first()
        
        if user_commission and user_commission.custom_rate:
            return user_commission.custom_rate
        
        plan = CommissionPlan.query.get(plan_id)
        return plan.base_rate if plan else Decimal('0')
        
    except Exception:
        return Decimal('0')
