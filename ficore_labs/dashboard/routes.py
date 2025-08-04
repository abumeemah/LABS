from flask import Blueprint, render_template, redirect, url_for, flash, session
from flask_login import login_required, current_user
from translations import trans
import utils
from bson import ObjectId
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
import logging

logger = logging.getLogger(__name__)

dashboard_bp = Blueprint('dashboard', __name__, url_prefix='/dashboard')

@dashboard_bp.route('/')
@login_required
@utils.requires_role(['trader', 'startup', 'admin'])
def index():
    """Display the user's dashboard with recent activity and role-specific content."""
    try:
        db = utils.get_mongo_db()
        query = {'user_id': str(current_user.id)}

        # Initialize data containers
        recent_creditors = []
        recent_debtors = []
        recent_payments = []
        recent_receipts = []
        recent_funds = []
        stats = {}

        # Fetch recent data for business finance modules
        recent_creditors = list(db.records.find({**query, 'type': 'creditor'}).sort('created_at', -1).limit(5))
        recent_debtors = list(db.records.find({**query, 'type': 'debtor'}).sort('created_at', -1).limit(5))
        recent_payments = list(db.cashflows.find({**query, 'type': 'payment'}).sort('created_at', -1).limit(5))
        recent_receipts = list(db.cashflows.find({**query, 'type': 'receipt'}).sort('created_at', -1).limit(5))
        recent_funds = list(db.funds.find(query).sort('created_at', -1).limit(5))

        # Convert naive datetimes to timezone-aware and sanitize strings
        for item in recent_creditors + recent_debtors:
            if item.get('created_at') and item['created_at'].tzinfo is None:
                item['created_at'] = item['created_at'].replace(tzinfo=ZoneInfo("UTC"))
            if item.get('reminder_date') and item['reminder_date'].tzinfo is None:
                item['reminder_date'] = item['reminder_date'].replace(tzinfo=ZoneInfo("UTC"))
            item['name'] = utils.sanitize_input(item.get('name', ''), max_length=100)
            item['description'] = utils.sanitize_input(item.get('description', 'No description provided'), max_length=500)
            item['contact'] = utils.sanitize_input(item.get('contact', 'N/A'), max_length=50)
            item['_id'] = str(item['_id'])

        for item in recent_payments + recent_receipts:
            if item.get('created_at') and item['created_at'].tzinfo is None:
                item['created_at'] = item['created_at'].replace(tzinfo=ZoneInfo("UTC"))
            item['description'] = utils.sanitize_input(item.get('description', 'No description provided'), max_length=500)
            item['_id'] = str(item['_id'])

        for item in recent_funds:
            if item.get('created_at') and item['created_at'].tzinfo is None:
                item['created_at'] = item['created_at'].replace(tzinfo=ZoneInfo("UTC"))
            item['name'] = utils.sanitize_input(item.get('name', ''), max_length=100)
            item['description'] = utils.sanitize_input(item.get('description', 'No description provided'), max_length=500)
            item['_id'] = str(item['_id'])

        # Calculate stats with error handling for empty collections
        stats = {
            'total_debtors': db.records.count_documents({**query, 'type': 'debtor'}),
            'total_creditors': db.records.count_documents({**query, 'type': 'creditor'}),
            'total_payments': db.cashflows.count_documents({**query, 'type': 'payment'}),
            'total_receipts': db.cashflows.count_documents({**query, 'type': 'receipt'}),
            'total_funds': db.funds.count_documents(query),
            'total_debtors_amount': sum(doc['amount_owed'] for doc in db.records.find({**query, 'type': 'debtor'}) if 'amount_owed' in doc),
            'total_creditors_amount': sum(doc['amount_owed'] for doc in db.records.find({**query, 'type': 'creditor'}) if 'amount_owed' in doc),
            'total_funds_amount': sum(doc['amount'] for doc in db.funds.find(query) if 'amount' in doc)
        }

        # Check subscription status using utility function
        can_interact = utils.can_user_interact(current_user)

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
        logger.error(f"Error fetching dashboard data for user {current_user.id}: {str(e)}", extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('dashboard_load_error', default='An error occurred while loading the dashboard'), 'danger')
        return redirect(url_for('general_bp.home'))
