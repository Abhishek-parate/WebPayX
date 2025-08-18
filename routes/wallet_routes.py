# /routes/wallet_routes.py

from flask import Blueprint, request, render_template, redirect, url_for, flash
from flask_login import login_required, current_user
from models import db, WalletTopupRequest, TransactionStatus, TopupMethod, UserRoleType
import uuid
from datetime import datetime, timedelta
from decimal import Decimal

wallet_bp = Blueprint("wallet", __name__, url_prefix="/wallet")



# =====================
# RBAC decorator
# =====================
def role_required(allowed_roles):
    def decorator(f):
        def wrapper(*args, **kwargs):
            if current_user.role.value not in allowed_roles:
                flash("Access denied!", "error")
                return redirect(url_for("dashboard"))
            return f(*args, **kwargs)
        wrapper.__name__ = f.__name__
        return wrapper
    return decorator


# =====================
# USER: Create Topup Request (Master, Distributor, Retailer)
# =====================
@wallet_bp.route("/topup/request", methods=["GET", "POST"])
@login_required
@role_required([UserRoleType.MASTER_DISTRIBUTOR.value,
                UserRoleType.DISTRIBUTOR.value,
                UserRoleType.RETAILER.value])
def request_topup():
    if request.method == "POST":
        amount = Decimal(request.form["amount"])
        trx_mode = request.form.get("transaction_mode")
        
        new_request = WalletTopupRequest(
            request_id=str(uuid.uuid4()),
            user_id=current_user.id,
            topup_method=TopupMethod.MANUAL_REQUEST,
            amount=amount,
            net_amount=amount,  # in real app subtract gateway fees
            transaction_mode=trx_mode,
            status=TransactionStatus.PENDING,
            expires_at=datetime.utcnow() + timedelta(hours=24)
        )
        db.session.add(new_request)
        db.session.commit()
        flash("Topup request submitted successfully!", "success")
        return redirect(url_for("wallet.my_requests"))

    return render_template("wallet/request_topup.html")


# =====================
# USER: View My Requests (Retailer/Distributor/Master Distributor)
# =====================
@wallet_bp.route("/topup/my")
@login_required
def my_requests():
    requests = WalletTopupRequest.query.filter_by(user_id=current_user.id).order_by(WalletTopupRequest.created_at.desc()).all()
    return render_template("wallet/my_requests.html", requests=requests)


# =====================
# ADMIN/WHITE LABEL: View & Manage All Requests
# =====================
@wallet_bp.route("/topup/manage")
@login_required
@role_required([UserRoleType.ADMIN.value, UserRoleType.WHITE_LABEL.value])
def manage_requests():
    requests = WalletTopupRequest.query.filter(WalletTopupRequest.status==TransactionStatus.PENDING).all()
    return render_template("wallet/manage_requests.html", requests=requests)


# =====================
# ADMIN: Approve or Cancel Request
# =====================
@wallet_bp.route("/topup/<req_id>/<action>", methods=["POST"])
@login_required
@role_required([UserRoleType.ADMIN.value, UserRoleType.WHITE_LABEL.value])
def update_request(req_id, action):
    req = WalletTopupRequest.query.filter_by(request_id=req_id).first_or_404()
    
    if action == "approve":
        req.status = TransactionStatus.SUCCESS
        req.approved_by = current_user.id
        req.processed_at = datetime.utcnow()
        flash("Topup request approved!", "success")

        # Credit wallet ledger here (Wallet model linked)
        wallet = req.user.wallet
        wallet.balance += req.net_amount
        wallet.total_credited += req.net_amount
    
    elif action == "cancel":
        req.status = TransactionStatus.CANCELLED
        req.admin_remarks = request.form.get("remarks", "")
        flash("Topup request cancelled!", "warning")
    
    db.session.commit()
    return redirect(url_for("wallet.manage_requests"))
