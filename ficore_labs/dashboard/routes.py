from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_required, current_user
from translations import trans
import utils
from bson import ObjectId
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

dashboard_bp = Blueprint('dashboard', __name__, url_prefix='/dashboard')

@dashboard_bp.route('/')
@login_required
def index():
    """Display the user's dashboard with recent activity and role-specific content."""
    try:
        db = utils.get_mongo_db()
        
        # Determine query based on user role
        query = {} if utils.is_admin() else {'user_id': str(current_user.id)}

        # Initialize data containers
        recent_creditors = []
        recent_debtors = []
        recent_payments = []
        recent_receipts = []
        recent_funds = []
        stats = {}

        # Fetch data based on user role
        if current_user.role in ['trader', 'startup', 'admin']:
            # Fetch recent data for business finance modules
            recent_creditors = list(db.records.find({**query, 'type': 'creditor'}).sort('created_at', -1).limit(5))
            recent_debtors = list(db.records.find({**query, 'type': 'debtor'}).sort('created_at', -1).limit(5))
            recent_payments = list(db.cashflows.find({**query, 'type': 'payment'}).sort('created_at', -1).limit(5))
            recent_receipts = list(db.cashflows.find({**query, 'type': 'receipt'}).sort('created_at', -1).limit(5))
            recent_funds = list(db.funds.find(query).sort('created_at', -1).limit(5))

            # Calculate stats
            stats = {
                'total_debtors': db.records.count_documents({**query, 'type': 'debtor'}),
                'total_creditors': db.records.count_documents({**query, 'type': 'creditor'}),
                'total_payments': db.cashflows.count_documents({**query, 'type': 'payment'}),
                'total_receipts': db.cashflows.count_documents({**query, 'type': 'receipt'}),
                'total_funds': db.funds.count_documents(query),
                'total_debtors_amount': sum(doc['amount_owed'] for doc in db.records.find({**query, 'type': 'debtor'})),
                'total_creditors_amount': sum(doc['amount_owed'] for doc in db.records.find({**query, 'type': 'creditor'})),
                'total_funds_amount': sum(doc['amount'] for doc in db.funds.find(query))
            }

        # Convert ObjectIds to strings for template rendering
        for item in recent_creditors + recent_debtors + recent_payments + recent_receipts + recent_funds:
            item['_id'] = str(item['_id'])

        # Check subscription status
        can_interact = current_user.is_trial_active or current_user.is_subscribed

        return render_template(
            'dashboard/index.html',
            recent_creditors=recent_creditors,
            recent_debtors=recent_debtors,
            recent_payments=recent_payments,
            recent_receipts=recent_receipts,
            recent_funds=recent_funds,
            stats=stats,
            can_interact=can_interact
        )
    except Exception as e:
        logger.error(f"Error fetching dashboard data for user {current_user.id}: {str(e)}")
        flash(trans('dashboard_load_error', default='An error occurred while loading the dashboard'), 'danger')
        return redirect(url_for('general_bp.home'))
