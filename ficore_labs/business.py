from flask import Blueprint, jsonify, render_template, session, request
from flask_login import current_user, login_required
from datetime import datetime
import utils
from utils import logger

business = Blueprint('business', __name__, url_prefix='/business')

@business.route('/home')
@login_required
@utils.requires_role(['trader', 'startup', 'admin'])
def home():
    """Render the Business Finance homepage with debt and cashflow summaries."""
    try:
        db = utils.get_mongo_db()
        user_id = current_user.id
        lang = session.get('lang', 'en')

        # Check trial/subscription status
        is_read_only = not current_user.is_subscribed and not current_user.is_trial_active()

        # Fetch debt summary
        creditors_pipeline = [
            {'$match': {'user_id': user_id, 'type': 'creditor'}},
            {'$group': {'_id': None, 'total': {'$sum': '$amount_owed'}}}
        ]
        creditors_result = list(db.records.aggregate(creditors_pipeline))
        total_i_owe = creditors_result[0]['total'] if creditors_result else 0

        debtors_pipeline = [
            {'$match': {'user_id': user_id, 'type': 'debtor'}},
            {'$group': {'_id': None, 'total': {'$sum': '$amount_owed'}}}
        ]
        debtors_result = list(db.records.aggregate(debtors_pipeline))
        total_i_am_owed = debtors_result[0]['total'] if debtors_result else 0

        # Fetch cashflow summary
        today = datetime.utcnow()
        start_of_month = datetime(today.year, today.month, 1)
        receipts_pipeline = [
            {'$match': {'user_id': user_id, 'type': 'receipt', 'created_at': {'$gte': start_of_month}}},
            {'$group': {'_id': None, 'total': {'$sum': '$amount'}}}
        ]
        receipts_result = list(db.cashflows.aggregate(receipts_pipeline))
        total_receipts = receipts_result[0]['total'] if receipts_result else 0

        payments_pipeline = [
            {'$match': {'user_id': user_id, 'type': 'payment', 'created_at': {'$gte': start_of_month}}},
            {'$group': {'_id': None, 'total': {'$sum': '$amount'}}}
        ]
        payments_result = list(db.cashflows.aggregate(payments_pipeline))
        total_payments = payments_result[0]['total'] if payments_result else 0
        net_cashflow = total_receipts - total_payments

        logger.info(f"Rendered business homepage for user {user_id}, read_only={is_read_only}", 
                    extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})

        return render_template(
            'general/home.html',
            total_i_owe=total_i_owe,
            total_i_am_owed=total_i_am_owed,
            net_cashflow=net_cashflow,
            total_receipts=total_receipts,
            total_payments=total_payments,
            title=utils.trans('business_home', lang=lang),
            format_currency=utils.format_currency,
            is_read_only=is_read_only,
            tools_for_template=utils.TRADER_NAV if current_user.role == 'trader' else utils.STARTUP_NAV if current_user.role == 'startup' else utils.ADMIN_NAV,
            explore_features_for_template=utils.get_explore_features(current_user.role)
        )
    except Exception as e:
        logger.error(f"Error rendering business homepage for user {user_id}: {str(e)}", 
                     extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
        return render_template(
            'general/error.html',
            error=utils.trans('dashboard_error', lang=lang),
            title=utils.trans('error', lang=lang)
        ), 500

@business.route('/view_data')
@login_required
@utils.requires_role(['trader', 'startup', 'admin'])
def view_data():
    """Render read-only view of user's financial data."""
    try:
        db = utils.get_mongo_db()
        user_id = current_user.id
        lang = session.get('lang', 'en')

        # Fetch debt records
        debt_records = list(db.records.find({'user_id': user_id}).sort('created_at', -1).limit(50))

        # Fetch cashflow records
        cashflows = list(db.cashflows.find({'user_id': user_id}).sort('created_at', -1).limit(50))

        logger.info(f"Rendered view_data for user {user_id}", 
                    extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})

        return render_template(
            'general/view_data.html',
            debt_records=debt_records,
            cashflows=cashflows,
            title=utils.trans('view_data_title', lang=lang),
            format_currency=utils.format_currency,
            is_read_only=True
        )
    except Exception as e:
        logger.error(f"Error rendering view_data for user {user_id}: {str(e)}", 
                     extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
        return render_template(
            'general/error.html',
            error=utils.trans('dashboard_error', lang=lang),
            title=utils.trans('error', lang=lang)
        ), 500

@business.route('/debt/summary')
@login_required
@utils.requires_role(['trader', 'startup', 'admin'])
def debt_summary():
    """Fetch debt summary (I Owe, I Am Owed) for the authenticated user."""
    try:
        db = utils.get_mongo_db()
        user_id = current_user.id
        creditors_pipeline = [
            {'$match': {'user_id': user_id, 'type': 'creditor'}},
            {'$group': {'_id': None, 'total': {'$sum': '$amount_owed'}}}
        ]
        creditors_result = list(db.records.aggregate(creditors_pipeline))
        total_i_owe = creditors_result[0]['total'] if creditors_result else 0
        debtors_pipeline = [
            {'$match': {'user_id': user_id, 'type': 'debtor'}},
            {'$group': {'_id': None, 'total': {'$sum': '$amount_owed'}}}
        ]
        debtors_result = list(db.records.aggregate(debtors_pipeline))
        total_i_am_owed = debtors_result[0]['total'] if debtors_result else 0
        logger.info(f"Fetched debt summary for user {user_id}: I Owe={total_i_owe}, I Am Owed={total_i_am_owed}", 
                    extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
        return jsonify({
            'totalIOwe': total_i_owe,
            'totalIAmOwed': total_i_am_owed
        })
    except Exception as e:
        logger.error(f"Error fetching debt summary for user {user_id}: {str(e)}", 
                     extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
        return jsonify({'error': utils.trans('debt_summary_error')}), 500

@business.route('/cashflow/summary')
@login_required
@utils.requires_role(['trader', 'startup', 'admin'])
def cashflow_summary():
    """Fetch the net cashflow (month-to-date) for the authenticated user."""
    try:
        db = utils.get_mongo_db()
        user_id = current_user.id
        today = datetime.utcnow()
        start_of_month = datetime(today.year, today.month, 1)
        receipts_pipeline = [
            {'$match': {'user_id': user_id, 'type': 'receipt', 'created_at': {'$gte': start_of_month}}},
            {'$group': {'_id': None, 'total': {'$sum': '$amount'}}}
        ]
        receipts_result = list(db.cashflows.aggregate(receipts_pipeline))
        total_receipts = receipts_result[0]['total'] if receipts_result else 0
        payments_pipeline = [
            {'$match': {'user_id': user_id, 'type': 'payment', 'created_at': {'$gte': start_of_month}}},
            {'$group': {'_id': None, 'total': {'$sum': '$amount'}}}
        ]
        payments_result = list(db.cashflows.aggregate(payments_pipeline))
        total_payments = payments_result[0]['total'] if payments_result else 0
        net_cashflow = total_receipts - total_payments
        logger.info(f"Fetched cashflow summary for user {user_id}: Net Cashflow={net_cashflow}", 
                    extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
        return jsonify({
            'netCashflow': net_cashflow,
            'totalReceipts': total_receipts,
            'totalPayments': total_payments
        })
    except Exception as e:
        logger.error(f"Error fetching cashflow summary for user {user_id}: {str(e)}", 
                     extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
        return jsonify({'error': utils.trans('cashflow_error')}), 500

@business.route('/recent_activity')
@login_required
@utils.requires_role(['trader', 'startup', 'admin'])
def recent_activity():
    """Fetch recent activities (debts, cashflows, feedback) for the authenticated user."""
    try:
        db = utils.get_mongo_db()
        user_id = current_user.id
        lang = session.get('lang', 'en')
        activities = []

        # Fetch recent debt records
        records = db.records.find({'user_id': user_id}).sort('created_at', -1).limit(3)
        for record in records:
            activity_type = 'debtor_added' if record.get('type') == 'debtor' else 'creditor_added' if record.get('type') == 'creditor' else record.get('type') + '_added'
            description_key = f"{record.get('type')}_added_description"
            description = utils.trans(
                description_key,
                lang=lang,
                default=f"{'Owed by' if record.get('type') == 'debtor' else 'Owe to' if record.get('type') == 'creditor' else record.get('type').capitalize()} {record.get('name', record.get('title', record.get('source', '')))}"
            )
            activities.append({
                'type': activity_type,
                'description': description,
                'amount': record.get('amount_owed', record.get('amount', record.get('projected_revenue', 0))),
                'timestamp': record.get('created_at').isoformat(),
                'icon': 'bi-person-plus' if record.get('type') in ['debtor', 'creditor'] else 'bi-file-earmark-plus'
            })

        # Fetch recent cashflows
        cashflows = db.cashflows.find({'user_id': user_id}).sort('created_at', -1).limit(3)
        for cashflow in cashflows:
            activity_type = 'money_in' if cashflow.get('type') == 'receipt' else 'money_out'
            description = utils.trans(
                'money_in_description' if cashflow.get('type') == 'receipt' else 'money_out_description',
                lang=lang,
                default=f"{'Received from' if cashflow.get('type') == 'receipt' else 'Paid to'} {cashflow.get('party_name')}"
            )
            activities.append({
                'type': activity_type,
                'description': description,
                'amount': cashflow.get('amount', 0),
                'timestamp': cashflow.get('created_at').isoformat(),
                'icon': 'bi-arrow-down-circle' if activity_type == 'money_in' else 'bi-arrow-up-circle'
            })

        # Fetch recent feedback
        feedback_records = db.feedback.find({'user_id': user_id}).sort('timestamp', -1).limit(3)
        for feedback in feedback_records:
            activities.append({
                'type': 'feedback_submitted',
                'description': utils.trans(
                    'feedback_submitted_description',
                    lang=lang,
                    default=f"Submitted feedback for {feedback.get('tool_name').capitalize()}"
                ),
                'amount': feedback.get('rating', 0),
                'timestamp': feedback.get('timestamp').isoformat(),
                'icon': 'bi-star-fill'
            })

        # Sort activities by timestamp (descending)
        activities.sort(key=lambda x: x['timestamp'], reverse=True)
        activities = activities[:5]

        logger.info(f"Fetched {len(activities)} recent activities for user {user_id}", 
                    extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
        return jsonify(activities)
    except Exception as e:
        logger.error(f"Error fetching recent activity for user {user_id}: {str(e)}", 
                     extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
        return jsonify({'error': utils.trans('activity_error')}), 500
