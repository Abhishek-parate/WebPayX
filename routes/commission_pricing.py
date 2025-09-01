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
from sqlalchemy import and_, or_, desc, func
from decimal import Decimal

commission_pricing_bp = Blueprint('commission_pricing', __name__, url_prefix='/commission-pricing')

# ============================================================================
# DECORATORS AND UTILITIES - FIXED ENDPOINTS
# ============================================================================

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role not in [UserRoleType.SUPER_ADMIN, UserRoleType.ADMIN]:
            flash('Access denied. Admin privileges required.', 'error')
            # FIX: Changed from 'main.dashboard' to correct endpoint
            return redirect(url_for('commission_pricing.dashboard'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def super_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role != UserRoleType.SUPER_ADMIN:
            flash('Access denied. Super Admin privileges required.', 'error')
            # FIX: Changed from 'main.dashboard' to correct endpoint
            return redirect(url_for('commission_pricing.dashboard'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# ============================================================================
# DASHBOARD AND OVERVIEW - FIXED EXCEPTION HANDLING
# ============================================================================

@commission_pricing_bp.route('/')
@login_required
@admin_required
def dashboard():
    """Commission & Pricing Dashboard"""
    try:
        # Get summary statistics
        base_query = CommissionPlan.query
        if current_user.role != UserRoleType.SUPER_ADMIN:
            base_query = base_query.filter_by(tenant_id=current_user.tenant_id)
        
        stats = {
            'total_plans': base_query.count(),
            'active_plans': base_query.filter_by(is_active=True).count(),
            'inactive_plans': base_query.filter_by(is_active=False).count(),
            'expired_plans': base_query.filter(
                CommissionPlan.valid_until < datetime.utcnow()
            ).count(),
        }
        
        # Service type distribution
        service_stats = db.session.query(
            CommissionPlan.service_type, 
            func.count(CommissionPlan.id).label('count')
        )
        if current_user.role != UserRoleType.SUPER_ADMIN:
            service_stats = service_stats.filter_by(tenant_id=current_user.tenant_id)
        
        service_stats = service_stats.group_by(CommissionPlan.service_type).all()
        
        # Commission mode distribution
        mode_stats = db.session.query(
            CommissionPlan.commission_mode, 
            func.count(CommissionPlan.id).label('count')
        )
        if current_user.role != UserRoleType.SUPER_ADMIN:
            mode_stats = mode_stats.filter_by(tenant_id=current_user.tenant_id)
        
        mode_stats = mode_stats.group_by(CommissionPlan.commission_mode).all()
        
        # Recent commission plans
        recent_plans = base_query.order_by(desc(CommissionPlan.created_at)).limit(5).all()
        
        # User commission assignments count with explicit join
        user_assignments_query = db.session.query(UserCommission).join(
            User, User.id == UserCommission.user_id
        )
        
        if current_user.role != UserRoleType.SUPER_ADMIN:
            user_assignments_query = user_assignments_query.filter(
                User.tenant_id == current_user.tenant_id
            )
        
        user_assignments = user_assignments_query.count()
        
        return render_template('commission_pricing/dashboard.html',
                             stats=stats,
                             service_stats=service_stats,
                             mode_stats=mode_stats,
                             recent_plans=recent_plans,
                             user_assignments=user_assignments)
    
    except Exception as e:
        flash(f'Error loading dashboard: {str(e)}', 'error')
        # FIX: Return safe dashboard with empty data instead of redirect
        return render_template('commission_pricing/dashboard.html',
                             stats={'total_plans': 0, 'active_plans': 0, 'inactive_plans': 0, 'expired_plans': 0},
                             service_stats=[],
                             mode_stats=[],
                             recent_plans=[],
                             user_assignments=0)

# ============================================================================
# COMMISSION PLAN MANAGEMENT - FIXED REDIRECTS
# ============================================================================

@commission_pricing_bp.route('/plans')
@login_required
@admin_required
def commission_plans():
    """List all commission plans"""
    try:
        # Get filter parameters
        search = request.args.get('search', '').strip()
        service_type = request.args.get('service_type', '').strip()
        commission_mode = request.args.get('commission_mode', '').strip()
        status = request.args.get('status', '').strip()
        page = request.args.get('page', 1, type=int)
        per_page = 20
        
        # Base query
        query = CommissionPlan.query
        if current_user.role != UserRoleType.SUPER_ADMIN:
            query = query.filter_by(tenant_id=current_user.tenant_id)
        
        # Apply filters with error handling
        if search:
            query = query.filter(CommissionPlan.plan_name.ilike(f'%{search}%'))
        
        if service_type:
            try:
                query = query.filter_by(service_type=ServiceType(service_type))
            except ValueError:
                pass
        
        if commission_mode:
            try:
                query = query.filter_by(commission_mode=CommissionMode(commission_mode))
            except ValueError:
                pass
        
        if status:
            if status == 'active':
                query = query.filter_by(is_active=True)
            elif status == 'inactive':
                query = query.filter_by(is_active=False)
            elif status == 'expired':
                query = query.filter(CommissionPlan.valid_until < datetime.utcnow())
        
        # Execute query with pagination
        plans = query.order_by(desc(CommissionPlan.created_at)).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        return render_template('commission_pricing/plans.html',
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
            # Get form data
            plan_name = request.form.get('plan_name', '').strip()
            service_type = request.form.get('service_type', '').strip()
            commission_mode = request.form.get('commission_mode', '').strip()
            base_rate = request.form.get('base_rate', '0').strip()
            min_commission = request.form.get('min_commission', '').strip()
            max_commission = request.form.get('max_commission', '').strip()
            valid_from = request.form.get('valid_from', '').strip()
            valid_until = request.form.get('valid_until', '').strip()
            is_active = request.form.get('is_active') == 'on'
            
            # ✅ NEW: Check if user wants to stay on the page
            stay_on_page = request.form.get('stay_on_page') == 'on'
            
            # Validation
            if not all([plan_name, service_type, commission_mode]):
                flash('Plan name, service type, and commission mode are required', 'error')
                return render_template('commission_pricing/create_plan.html',
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
                                     service_types=ServiceType,
                                     commission_modes=CommissionMode,
                                     now=datetime.now())
            
            # Parse dates with error handling
            try:
                valid_from_dt = datetime.strptime(valid_from, '%Y-%m-%d') if valid_from else datetime.utcnow()
                valid_until_dt = datetime.strptime(valid_until, '%Y-%m-%d') if valid_until else None
            except ValueError:
                flash('Invalid date format. Please use YYYY-MM-DD format.', 'error')
                return render_template('commission_pricing/create_plan.html',
                                     service_types=ServiceType,
                                     commission_modes=CommissionMode,
                                     now=datetime.now())
            
            # Validate date logic
            if valid_until_dt and valid_until_dt <= valid_from_dt:
                flash('Valid until date must be after valid from date', 'error')
                return render_template('commission_pricing/create_plan.html',
                                     service_types=ServiceType,
                                     commission_modes=CommissionMode,
                                     now=datetime.now())
            
            # Check for duplicate plan name
            existing_plan = CommissionPlan.query.filter_by(
                tenant_id=current_user.tenant_id,
                plan_name=plan_name
            ).first()
            
            if existing_plan:
                flash('A commission plan with this name already exists', 'error')
                return render_template('commission_pricing/create_plan.html',
                                     service_types=ServiceType,
                                     commission_modes=CommissionMode,
                                     now=datetime.now())
            
            # Handle slabs for slab-based commission
            slabs = []
            if commission_mode == CommissionMode.SLAB_BASED.value:
                try:
                    slab_data = request.form.get('slabs_json', '[]')
                    import json
                    slabs = json.loads(slab_data) if slab_data else []
                except (json.JSONDecodeError, TypeError):
                    flash('Invalid slab configuration', 'error')
                    return render_template('commission_pricing/create_plan.html',
                                         service_types=ServiceType,
                                         commission_modes=CommissionMode,
                                         now=datetime.now())
            
            # Create commission plan
            plan = CommissionPlan(
                tenant_id=current_user.tenant_id,
                plan_name=plan_name,
                service_type=service_type_enum,
                commission_mode=commission_mode_enum,
                base_rate=Decimal(base_rate) if base_rate else Decimal('0'),
                min_commission=Decimal(min_commission) if min_commission else None,
                max_commission=Decimal(max_commission) if max_commission else None,
                slabs=slabs,
                is_active=is_active,
                valid_from=valid_from_dt,
                valid_until=valid_until_dt,
                created_by=current_user.id
            )
            
            db.session.add(plan)
            db.session.commit()
            
            # ✅ SUCCESS MESSAGE with SweetAlert
            success_message = f'Commission plan "{plan_name}" created successfully!'
            
            if stay_on_page:
                # Stay on create page with success message
                flash(success_message, 'success')
                return render_template('commission_pricing/create_plan.html',
                                     service_types=ServiceType,
                                     commission_modes=CommissionMode,
                                     now=datetime.now(),
                                     success_message=success_message,
                                     clear_form=True)  # Flag to clear form with JS
            else:
                # Redirect to plans list
                flash(success_message, 'success')
                return redirect(url_for('commission_pricing.commission_plans'))
            
        except ValueError as e:
            db.session.rollback()
            flash(f'Invalid data provided: {str(e)}', 'error')
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating commission plan: {str(e)}', 'error')
    
    return render_template('commission_pricing/create_plan.html',
                         service_types=ServiceType,
                         commission_modes=CommissionMode,
                         now=datetime.now())



@commission_pricing_bp.route('/plans/<plan_id>')
@login_required
@admin_required
def plan_detail(plan_id):
    """View commission plan details"""
    try:
        # Validate UUID format
        try:
            uuid.UUID(plan_id)
        except ValueError:
            flash('Invalid plan ID', 'error')
            return redirect(url_for('commission_pricing.commission_plans'))
        
        query = CommissionPlan.query
        if current_user.role != UserRoleType.SUPER_ADMIN:
            query = query.filter_by(tenant_id=current_user.tenant_id)
        
        plan = query.filter_by(id=plan_id).first_or_404()
        
        # Get users assigned to this plan with explicit join
        assigned_users = db.session.query(User, UserCommission).join(
            UserCommission, User.id == UserCommission.user_id
        ).filter(
            UserCommission.commission_plan_id == plan_id,
            UserCommission.is_active == True
        ).all()
        
        return render_template('commission_pricing/plan_detail.html',
                             plan=plan,
                             assigned_users=assigned_users)
    
    except Exception as e:
        flash(f'Error loading plan details: {str(e)}', 'error')
        return redirect(url_for('commission_pricing.commission_plans'))

@commission_pricing_bp.route('/plans/<plan_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_plan(plan_id):
    """Edit commission plan"""
    try:
        # Validate UUID format
        try:
            uuid.UUID(plan_id)
        except ValueError:
            flash('Invalid plan ID', 'error')
            return redirect(url_for('commission_pricing.commission_plans'))
        
        query = CommissionPlan.query
        if current_user.role != UserRoleType.SUPER_ADMIN:
            query = query.filter_by(tenant_id=current_user.tenant_id)
        
        plan = query.filter_by(id=plan_id).first_or_404()
        
        if request.method == 'POST':
            try:
                # Get form data
                plan_name = request.form.get('plan_name', '').strip()
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
                                         plan=plan,
                                         service_types=ServiceType,
                                         commission_modes=CommissionMode,
                                         now=datetime.now())
                
                # Update plan data
                plan.plan_name = plan_name
                
                if service_type:
                    plan.service_type = ServiceType(service_type)
                if commission_mode:
                    plan.commission_mode = CommissionMode(commission_mode)
                
                plan.base_rate = Decimal(base_rate) if base_rate else Decimal('0')
                plan.min_commission = Decimal(min_commission) if min_commission else None
                plan.max_commission = Decimal(max_commission) if max_commission else None
                
                # Parse dates
                if valid_from:
                    plan.valid_from = datetime.strptime(valid_from, '%Y-%m-%d')
                if valid_until:
                    plan.valid_until = datetime.strptime(valid_until, '%Y-%m-%d')
                else:
                    plan.valid_until = None
                
                plan.is_active = is_active
                
                # Handle slabs
                if plan.commission_mode == CommissionMode.SLAB_BASED:
                    try:
                        slab_data = request.form.get('slabs_json', '[]')
                        import json
                        plan.slabs = json.loads(slab_data) if slab_data else []
                    except (json.JSONDecodeError, TypeError):
                        flash('Invalid slab configuration', 'error')
                        return render_template('commission_pricing/edit_plan.html',
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
    """Delete commission plan"""
    try:
        # Validate UUID format
        try:
            uuid.UUID(plan_id)
        except ValueError:
            flash('Invalid plan ID', 'error')
            return redirect(url_for('commission_pricing.commission_plans'))
        
        query = CommissionPlan.query
        if current_user.role != UserRoleType.SUPER_ADMIN:
            query = query.filter_by(tenant_id=current_user.tenant_id)
        
        plan = query.filter_by(id=plan_id).first_or_404()
        
        # Check if plan has any user assignments
        user_count = UserCommission.query.filter_by(
            commission_plan_id=plan_id, 
            is_active=True
        ).count()
        
        if user_count > 0:
            flash('Cannot delete commission plan that has active user assignments', 'error')
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
        # Validate UUID format
        try:
            uuid.UUID(plan_id)
        except ValueError:
            flash('Invalid plan ID', 'error')
            return redirect(url_for('commission_pricing.commission_plans'))
        
        query = CommissionPlan.query
        if current_user.role != UserRoleType.SUPER_ADMIN:
            query = query.filter_by(tenant_id=current_user.tenant_id)
        
        plan = query.filter_by(id=plan_id).first_or_404()
        plan.is_active = not plan.is_active
        plan.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        status = 'activated' if plan.is_active else 'deactivated'
        flash(f'Commission plan "{plan.plan_name}" {status} successfully', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating commission plan status: {str(e)}', 'error')
    
    return redirect(url_for('commission_pricing.plan_detail', plan_id=plan_id))

# ============================================================================
# EXPORT FUNCTIONALITY - ADDED MISSING ROUTES
# ============================================================================

@commission_pricing_bp.route('/plans/<plan_id>/export')
@login_required
@admin_required
def export_plan(plan_id):
    """Export commission plan data"""
    try:
        # Validate UUID format
        try:
            uuid.UUID(plan_id)
        except ValueError:
            flash('Invalid plan ID', 'error')
            return redirect(url_for('commission_pricing.commission_plans'))
        
        # Get the plan
        query = CommissionPlan.query
        if current_user.role != UserRoleType.SUPER_ADMIN:
            query = query.filter_by(tenant_id=current_user.tenant_id)
        
        plan = query.filter_by(id=plan_id).first_or_404()
        
        # Get format from query parameter
        format_type = request.args.get('format', 'csv').lower()
        
        if format_type == 'csv':
            return export_plan_csv(plan)
        elif format_type == 'pdf':
            return export_plan_pdf(plan)
        else:
            return jsonify({'error': 'Invalid format'}), 400
            
    except Exception as e:
        flash('Export failed. Please try again.', 'error')
        return redirect(url_for('commission_pricing.plan_detail', plan_id=plan_id))

def export_plan_csv(plan):
    """Export plan data as CSV"""
    try:
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write headers
        writer.writerow(['Plan Information'])
        writer.writerow(['Field', 'Value'])
        writer.writerow(['Plan Name', plan.plan_name])
        writer.writerow(['Service Type', plan.service_type.value.replace('_', ' ').title()])
        writer.writerow(['Commission Mode', plan.commission_mode.value.replace('_', ' ').title()])
        writer.writerow(['Base Rate', f"{plan.base_rate}{'%' if plan.commission_mode.value == 'PERCENTAGE' else '₹'}"])
        writer.writerow(['Min Commission', f"₹{plan.min_commission}" if plan.min_commission else 'Not set'])
        writer.writerow(['Max Commission', f"₹{plan.max_commission}" if plan.max_commission else 'No limit'])
        writer.writerow(['Status', 'Active' if plan.is_active else 'Inactive'])
        writer.writerow(['Valid From', plan.valid_from.strftime('%d %b %Y')])
        writer.writerow(['Valid Until', plan.valid_until.strftime('%d %b %Y') if plan.valid_until else 'No Expiry'])
        writer.writerow(['Created At', plan.created_at.strftime('%d %b %Y at %I:%M %p')])
        
        # Add slabs if applicable
        if plan.commission_mode.value == 'SLAB_BASED' and plan.slabs:
            writer.writerow([])
            writer.writerow(['Commission Slabs'])
            writer.writerow(['Slab', 'Min Amount', 'Max Amount', 'Rate', 'Type'])
            for i, slab in enumerate(plan.slabs, 1):
                writer.writerow([
                    f"Slab {i}",
                    f"₹{slab.get('min_amount', 0)}",
                    f"₹{slab.get('max_amount', 'Unlimited')}",
                    slab.get('rate', 0),
                    slab.get('type', 'percentage').title()
                ])
        
        # Add assigned users
        assigned_users = db.session.query(User, UserCommission).join(
            UserCommission, User.id == UserCommission.user_id
        ).filter(
            UserCommission.commission_plan_id == plan.id,
            UserCommission.is_active == True
        ).all()
        
        if assigned_users:
            writer.writerow([])
            writer.writerow(['Assigned Users'])
            writer.writerow(['User Name', 'Role', 'Commission Rate', 'Status', 'Assigned Date'])
            for user, commission in assigned_users:
                rate = commission.custom_rate if commission.custom_rate else plan.base_rate
                writer.writerow([
                    user.full_name,
                    user.role.value.replace('_', ' ').title(),
                    f"{rate}{'%' if plan.commission_mode.value == 'PERCENTAGE' else '₹'}",
                    'Active' if commission.is_active else 'Inactive',
                    commission.assigned_at.strftime('%d %b %Y')
                ])
        
        # Prepare response
        output.seek(0)
        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = f'attachment; filename="{plan.plan_name}_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv"'
        
        return response
        
    except Exception as e:
        flash(f'Error exporting to CSV: {str(e)}', 'error')
        return redirect(url_for('commission_pricing.plan_detail', plan_id=plan.id))

def export_plan_pdf(plan):
    """Export plan data as PDF (placeholder - implement with reportlab)"""
    return jsonify({
        'message': 'PDF export functionality not implemented yet',
        'plan_name': plan.plan_name
    }), 501

# ============================================================================
# USER COMMISSION ASSIGNMENT - FIXED REDIRECTS
# ============================================================================

@commission_pricing_bp.route('/user-commissions')
@login_required
@admin_required
def user_commissions():
    """Manage user commission assignments"""
    try:
        search = request.args.get('search', '').strip()
        plan_id = request.args.get('plan_id', '').strip()
        role = request.args.get('role', '').strip()
        page = request.args.get('page', 1, type=int)
        per_page = 20
        
        # Base query with explicit join conditions
        query = db.session.query(User, UserCommission, CommissionPlan).outerjoin(
            UserCommission, User.id == UserCommission.user_id
        ).outerjoin(
            CommissionPlan, UserCommission.commission_plan_id == CommissionPlan.id
        )
        
        if current_user.role != UserRoleType.SUPER_ADMIN:
            query = query.filter(User.tenant_id == current_user.tenant_id)
        
        # Apply filters
        if search:
            query = query.filter(
                or_(
                    User.full_name.ilike(f'%{search}%'),
                    User.username.ilike(f'%{search}%'),
                    User.email.ilike(f'%{search}%')
                )
            )
        
        if plan_id:
            try:
                uuid.UUID(plan_id)  # Validate UUID format
                query = query.filter(UserCommission.commission_plan_id == plan_id)
            except ValueError:
                pass
        
        if role:
            try:
                query = query.filter(User.role == UserRoleType(role))
            except ValueError:
                pass
        
        # Execute query with pagination
        user_commissions = query.order_by(User.full_name).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        # Get available commission plans
        plans_query = CommissionPlan.query.filter_by(is_active=True)
        if current_user.role != UserRoleType.SUPER_ADMIN:
            plans_query = plans_query.filter_by(tenant_id=current_user.tenant_id)
        available_plans = plans_query.all()
        
        return render_template('commission_pricing/user_commissions.html',
                             user_commissions=user_commissions,
                             available_plans=available_plans,
                             user_roles=UserRoleType,
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
        # Validate UUID format
        try:
            uuid.UUID(user_id)
        except ValueError:
            flash('Invalid user ID', 'error')
            return redirect(url_for('commission_pricing.user_commissions'))
        
        # Check if user exists and belongs to current tenant
        user_query = User.query
        if current_user.role != UserRoleType.SUPER_ADMIN:
            user_query = user_query.filter_by(tenant_id=current_user.tenant_id)
        
        user = user_query.filter_by(id=user_id).first_or_404()
        
        if request.method == 'POST':
            try:
                commission_plan_id = request.form.get('commission_plan_id', '').strip()
                custom_rate = request.form.get('custom_rate', '').strip()
                
                if not commission_plan_id:
                    flash('Please select a commission plan', 'error')
                    return redirect(url_for('commission_pricing.assign_commission', user_id=user_id))
                
                # Validate UUID format for plan ID
                try:
                    uuid.UUID(commission_plan_id)
                except ValueError:
                    flash('Invalid commission plan selected', 'error')
                    return redirect(url_for('commission_pricing.assign_commission', user_id=user_id))
                
                # Verify the plan exists and belongs to current tenant
                plan_query = CommissionPlan.query.filter_by(
                    id=commission_plan_id,
                    is_active=True
                )
                if current_user.role != UserRoleType.SUPER_ADMIN:
                    plan_query = plan_query.filter_by(tenant_id=current_user.tenant_id)
                
                plan = plan_query.first()
                if not plan:
                    flash('Commission plan not found or not available', 'error')
                    return redirect(url_for('commission_pricing.assign_commission', user_id=user_id))
                
                # Check if user already has this plan assigned
                existing = UserCommission.query.filter_by(
                    user_id=user_id,
                    commission_plan_id=commission_plan_id
                ).first()
                
                if existing:
                    # Update existing assignment
                    existing.custom_rate = Decimal(custom_rate) if custom_rate else None
                    existing.is_active = True
                    existing.assigned_at = datetime.utcnow()
                    existing.assigned_by = current_user.id
                    action = 'updated'
                else:
                    # Create new assignment
                    assignment = UserCommission(
                        user_id=user_id,
                        commission_plan_id=commission_plan_id,
                        custom_rate=Decimal(custom_rate) if custom_rate else None,
                        is_active=True,
                        assigned_by=current_user.id
                    )
                    db.session.add(assignment)
                    action = 'assigned'
                
                db.session.commit()
                flash(f'Commission plan {action} to {user.full_name} successfully', 'success')
                return redirect(url_for('commission_pricing.user_commissions'))
                
            except ValueError as e:
                db.session.rollback()
                flash(f'Invalid custom rate provided: {str(e)}', 'error')
            except Exception as e:
                db.session.rollback()
                flash(f'Error assigning commission plan: {str(e)}', 'error')
        
        # Get available commission plans
        plans_query = CommissionPlan.query.filter_by(is_active=True)
        if current_user.role != UserRoleType.SUPER_ADMIN:
            plans_query = plans_query.filter_by(tenant_id=current_user.tenant_id)
        available_plans = plans_query.all()
        
        # Get current assignments
        current_assignments = db.session.query(UserCommission, CommissionPlan).join(
            CommissionPlan, UserCommission.commission_plan_id == CommissionPlan.id
        ).filter(
            UserCommission.user_id == user_id, 
            UserCommission.is_active == True
        ).all()
        
        return render_template('commission_pricing/assign_commission.html',
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
        # Validate UUID formats
        try:
            uuid.UUID(user_id)
            uuid.UUID(assignment_id)
        except ValueError:
            flash('Invalid user or assignment ID', 'error')
            return redirect(url_for('commission_pricing.user_commissions'))
        
        assignment = UserCommission.query.filter_by(
            id=assignment_id,
            user_id=user_id
        ).first_or_404()
        
        # Verify user belongs to current tenant
        if current_user.role != UserRoleType.SUPER_ADMIN:
            user = User.query.filter_by(
                id=user_id, 
                tenant_id=current_user.tenant_id
            ).first_or_404()
        
        assignment.is_active = False
        db.session.commit()
        
        flash('Commission plan removed successfully', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error removing commission plan: {str(e)}', 'error')
    
    return redirect(url_for('commission_pricing.user_commissions'))

# ============================================================================
# SERVICE PRICING MANAGEMENT - ADDED MISSING ROUTES
# ============================================================================

@commission_pricing_bp.route('/service-pricing')
@login_required
@admin_required
def service_pricing():
    """Manage service pricing"""
    try:
        search = request.args.get('search', '')
        service_type = request.args.get('service_type', '')
        status = request.args.get('status', '')
        page = request.args.get('page', 1, type=int)
        per_page = 20
        
        # Base query
        query = ServicePricing.query
        if current_user.role != UserRoleType.SUPER_ADMIN:
            query = query.filter_by(tenant_id=current_user.tenant_id)
        
        # Apply filters
        if search:
            query = query.filter(ServicePricing.provider.ilike(f'%{search}%'))
        
        if service_type:
            try:
                query = query.filter_by(service_type=ServiceType(service_type))
            except ValueError:
                pass
        
        if status:
            query = query.filter_by(is_active=(status == 'active'))
        
        # Execute query with pagination
        pricing = query.order_by(ServicePricing.service_type, ServicePricing.provider).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        return render_template('commission_pricing/service_pricing.html',
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
            service_type = request.form.get('service_type')
            provider = request.form.get('provider', '').strip()
            base_cost = request.form.get('base_cost', '0')
            markup = request.form.get('markup', '0')
            min_amount = request.form.get('min_amount', '0')
            max_amount = request.form.get('max_amount', '')
            is_active = request.form.get('is_active') == 'on'
            effective_from = request.form.get('effective_from')
            
            # Validation
            if not all([service_type, provider, base_cost]):
                flash('Service type, provider, and base cost are required', 'error')
                return render_template('commission_pricing/create_pricing.html',
                                     service_types=ServiceType,
                                     now=datetime.now())
            
            # Check if pricing already exists
            existing = ServicePricing.query.filter_by(
                tenant_id=current_user.tenant_id,
                service_type=ServiceType(service_type),
                provider=provider
            ).first()
            
            if existing:
                flash('Pricing for this service type and provider already exists', 'error')
                return render_template('commission_pricing/create_pricing.html',
                                     service_types=ServiceType,
                                     now=datetime.now())
            
            # Create pricing
            pricing = ServicePricing(
                tenant_id=current_user.tenant_id,
                service_type=ServiceType(service_type),
                provider=provider,
                base_cost=Decimal(base_cost),
                markup=Decimal(markup),
                min_amount=Decimal(min_amount) if min_amount else None,
                max_amount=Decimal(max_amount) if max_amount else None,
                is_active=is_active,
                effective_from=datetime.strptime(effective_from, '%Y-%m-%d') if effective_from else datetime.utcnow()
            )
            
            db.session.add(pricing)
            db.session.commit()
            
            flash(f'Service pricing for {provider} created successfully', 'success')
            return redirect(url_for('commission_pricing.service_pricing'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating service pricing: {str(e)}', 'error')
    
    return render_template('commission_pricing/create_pricing.html',
                         service_types=ServiceType,
                         now=datetime.now())

@commission_pricing_bp.route('/service-pricing/<pricing_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_pricing(pricing_id):
    """Edit service pricing"""
    try:
        # Validate UUID format
        try:
            uuid.UUID(pricing_id)
        except ValueError:
            flash('Invalid pricing ID', 'error')
            return redirect(url_for('commission_pricing.service_pricing'))
        
        query = ServicePricing.query
        if current_user.role != UserRoleType.SUPER_ADMIN:
            query = query.filter_by(tenant_id=current_user.tenant_id)
        
        pricing = query.filter_by(id=pricing_id).first_or_404()
        
        if request.method == 'POST':
            try:
                pricing.provider = request.form.get('provider', '').strip()
                pricing.base_cost = Decimal(request.form.get('base_cost', '0'))
                pricing.markup = Decimal(request.form.get('markup', '0'))
                pricing.min_amount = Decimal(request.form.get('min_amount')) if request.form.get('min_amount') else None
                pricing.max_amount = Decimal(request.form.get('max_amount')) if request.form.get('max_amount') else None
                pricing.is_active = request.form.get('is_active') == 'on'
                
                effective_from = request.form.get('effective_from')
                if effective_from:
                    pricing.effective_from = datetime.strptime(effective_from, '%Y-%m-%d')
                
                db.session.commit()
                flash(f'Service pricing for {pricing.provider} updated successfully', 'success')
                return redirect(url_for('commission_pricing.service_pricing'))
                
            except Exception as e:
                db.session.rollback()
                flash(f'Error updating service pricing: {str(e)}', 'error')
        
        return render_template('commission_pricing/edit_pricing.html',
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
    """Delete service pricing"""
    try:
        # Validate UUID format
        try:
            uuid.UUID(pricing_id)
        except ValueError:
            flash('Invalid pricing ID', 'error')
            return redirect(url_for('commission_pricing.service_pricing'))
        
        query = ServicePricing.query
        if current_user.role != UserRoleType.SUPER_ADMIN:
            query = query.filter_by(tenant_id=current_user.tenant_id)
        
        pricing = query.filter_by(id=pricing_id).first_or_404()
        
        provider_name = pricing.provider
        db.session.delete(pricing)
        db.session.commit()
        
        flash(f'Service pricing for {provider_name} deleted successfully', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting service pricing: {str(e)}', 'error')
    
    return redirect(url_for('commission_pricing.service_pricing'))

# ============================================================================
# API ENDPOINTS AND UTILITIES
# ============================================================================

@commission_pricing_bp.route('/api/commission-calculator')
@login_required
def commission_calculator():
    """Calculate commission based on plan and amount"""
    plan_id = request.args.get('plan_id', '').strip()
    amount = request.args.get('amount', '0').strip()
    
    if not plan_id or not amount:
        return jsonify({'error': 'Plan ID and amount are required'}), 400
    
    try:
        # Validate UUID format
        try:
            uuid.UUID(plan_id)
        except ValueError:
            return jsonify({'error': 'Invalid plan ID format'}), 400
        
        # Get commission plan
        query = CommissionPlan.query
        if current_user.role != UserRoleType.SUPER_ADMIN:
            query = query.filter_by(tenant_id=current_user.tenant_id)
        
        plan = query.filter_by(id=plan_id, is_active=True).first()
        if not plan:
            return jsonify({'error': 'Commission plan not found'}), 404
        
        amount = Decimal(amount)
        if amount <= 0:
            return jsonify({'error': 'Amount must be greater than zero'}), 400
        
        commission = calculate_commission(plan, amount)
        
        return jsonify({
            'success': True,
            'commission': float(commission),
            'plan_name': plan.plan_name,
            'commission_mode': plan.commission_mode.value,
            'base_rate': float(plan.base_rate),
            'amount': float(amount)
        })
        
    except ValueError as e:
        return jsonify({'error': f'Invalid amount: {str(e)}'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@commission_pricing_bp.route('/reports/commission-summary')
@login_required
@admin_required
def commission_summary_report():
    """Generate commission summary report"""
    date_from = request.args.get('date_from', (datetime.utcnow() - timedelta(days=30)).strftime('%Y-%m-%d'))
    date_to = request.args.get('date_to', datetime.utcnow().strftime('%Y-%m-%d'))
    
    # Summary data query with explicit join condition
    summary_data = db.session.query(
        CommissionPlan.plan_name,
        CommissionPlan.service_type,
        CommissionPlan.commission_mode,
        func.count(UserCommission.id).label('assigned_users'),
        func.avg(UserCommission.custom_rate).label('avg_custom_rate')
    ).outerjoin(
        UserCommission, CommissionPlan.id == UserCommission.commission_plan_id
    ).group_by(
        CommissionPlan.id, CommissionPlan.plan_name, 
        CommissionPlan.service_type, CommissionPlan.commission_mode
    )
    
    if current_user.role != UserRoleType.SUPER_ADMIN:
        summary_data = summary_data.filter(CommissionPlan.tenant_id == current_user.tenant_id)
    
    summary_data = summary_data.all()
    
    return render_template('commission_pricing/commission_summary.html',
                         summary_data=summary_data,
                         date_from=date_from,
                         date_to=date_to)

@commission_pricing_bp.route('/export/commission-plans')
@login_required
@admin_required
def export_commission_plans():
    """Export commission plans to CSV"""
    query = CommissionPlan.query
    if current_user.role != UserRoleType.SUPER_ADMIN:
        query = query.filter_by(tenant_id=current_user.tenant_id)
    
    plans = query.order_by(CommissionPlan.service_type, CommissionPlan.plan_name).all()
    
    # Create CSV
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow([
        'Plan Name', 'Service Type', 'Commission Mode', 'Base Rate',
        'Min Commission', 'Max Commission', 'Status', 'Valid From', 'Valid Until',
        'Created At'
    ])
    
    # Write data
    for plan in plans:
        writer.writerow([
            plan.plan_name,
            plan.service_type.value,
            plan.commission_mode.value,
            float(plan.base_rate),
            float(plan.min_commission) if plan.min_commission else '',
            float(plan.max_commission) if plan.max_commission else '',
            'Active' if plan.is_active else 'Inactive',
            plan.valid_from.strftime('%Y-%m-%d'),
            plan.valid_until.strftime('%Y-%m-%d') if plan.valid_until else '',
            plan.created_at.strftime('%Y-%m-%d %H:%M:%S')
        ])
    
    # Prepare file
    output.seek(0)
    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = f'attachment; filename="commission_plans_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.csv"'
    
    return response

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def calculate_commission(plan, amount):
    """Calculate commission based on plan and amount"""
    try:
        if plan.commission_mode == CommissionMode.PERCENTAGE:
            commission = amount * (plan.base_rate / 100)
        elif plan.commission_mode == CommissionMode.FLAT:
            commission = plan.base_rate
        elif plan.commission_mode == CommissionMode.SLAB_BASED:
            commission = calculate_slab_commission(plan.slabs, amount)
        elif plan.commission_mode == CommissionMode.VOLUME_BASED:
            # This would require transaction history - simplified for now
            commission = amount * (plan.base_rate / 100)
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
    """Calculate commission based on slabs"""
    try:
        if not slabs or not isinstance(slabs, list):
            return Decimal('0')
        
        commission = Decimal('0')
        remaining_amount = amount
        
        # Sort slabs by min_amount
        sorted_slabs = sorted(slabs, key=lambda x: Decimal(str(x.get('min_amount', 0))))
        
        for slab in sorted_slabs:
            if remaining_amount <= 0:
                break
            
            min_amount = Decimal(str(slab.get('min_amount', 0)))
            max_amount = Decimal(str(slab.get('max_amount', 0))) if slab.get('max_amount') else None
            rate = Decimal(str(slab.get('rate', 0)))
            
            if amount < min_amount:
                continue
            
            # Calculate applicable amount for this slab
            if max_amount and max_amount > min_amount:
                slab_amount = min(remaining_amount, max_amount - min_amount + 1)
            else:
                slab_amount = remaining_amount
            
            # Calculate commission for this slab
            if slab.get('type') == 'percentage':
                slab_commission = slab_amount * (rate / 100)
            else:  # flat
                slab_commission = rate
            
            commission += slab_commission
            remaining_amount -= slab_amount
        
        return commission
        
    except Exception:
        return Decimal('0')
