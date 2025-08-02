from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, current_app
from flask_login import login_required, current_user
from translations import trans
from models import update_user, get_mongo_db
import requests
import os
from datetime import datetime
import logging

subscribe_bp = Blueprint('subscribe_bp', __name__, url_prefix='/subscribe')

# Configure logger
logger = logging.getLogger('business_finance_app')
logger.setLevel(logging.INFO)

@subscribe_bp.route('/')
@login_required
def subscribe():
    """Render the subscription page with pricing plans."""
    try:
        lang = request.args.get('lang', 'en')
        plans = [
            {
                'name': trans('subscribe_monthly', lang=lang, default='Monthly Plan'),
                'price': '₦1,000',
                'duration': 'month',
                'description': trans('subscribe_monthly_description', lang=lang, default='Access all features for one month'),
                'plan_code': 'monthly'
            },
            {
                'name': trans('subscribe_yearly', lang=lang, default='Yearly Plan'),
                'price': '₦10,000',
                'duration': 'year',
                'description': trans('subscribe_yearly_description', lang=lang, default='Access all features for one year (save 17%)'),
                'plan_code': 'yearly'
            }
        ]
        logger.info(f"Rendering subscription page for user: {current_user.id}", extra={'session_id': request.sid or 'no-session-id'})
        return render_template(
            'subscribe/subscribe.html',
            title=trans('subscribe_title', lang=lang, default='Subscribe to FiCore'),
            plans=plans,
            paystack_public_key=os.getenv('PAYSTACK_PUBLIC_KEY')
        )
    except Exception as e:
        logger.error(f"Error rendering subscription page for user {current_user.id}: {str(e)}", 
                     exc_info=True, extra={'session_id': request.sid or 'no-session-id'})
        flash(trans('general_error', default='An error occurred while loading the subscription page'), 'danger')
        return redirect(url_for('general_bp.home'))

@subscribe_bp.route('/initiate-payment', methods=['POST'])
@login_required
def initiate_payment():
    """Initiate payment with Paystack."""
    try:
        plan_code = request.form.get('plan_code')
        if plan_code not in ['monthly', 'yearly']:
            logger.error(f"Invalid plan code: {plan_code} for user {current_user.id}", 
                         extra={'session_id': request.sid or 'no-session-id'})
            flash(trans('subscribe_invalid_plan', default='Invalid plan selected'), 'danger')
            return redirect(url_for('subscribe_bp.subscribe'))

        amount = 100000 if plan_code == 'monthly' else 1000000  # Amounts in kobo (₦1,000 = 100,000 kobo, ₦10,000 = 1,000,000 kobo)
        reference = f"ficore_{current_user.id}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"

        # Prepare Paystack API request
        headers = {
            'Authorization': f"Bearer {os.getenv('PAYSTACK_SECRET_KEY')}",
            'Content-Type': 'application/json'
        }
        payload = {
            'email': current_user.email,
            'amount': amount,
            'reference': reference,
            'callback_url': url_for('subscribe_bp.callback', _external=True)
        }

        # Initialize Paystack transaction
        response = requests.post(
            'https://api.paystack.co/transaction/initialize',
            headers=headers,
            json=payload
        )
        response_data = response.json()

        if response.status_code != 200 or not response_data.get('status'):
            logger.error(f"Paystack initialization failed for user {current_user.id}: {response_data.get('message', 'Unknown error')}", 
                         extra={'session_id': request.sid or 'no-session-id'})
            flash(trans('subscribe_payment_init_error', default='Failed to initiate payment'), 'danger')
            return redirect(url_for('subscribe_bp.subscribe'))

        logger.info(f"Payment initiated for user {current_user.id}, reference: {reference}, plan: {plan_code}", 
                    extra={'session_id': request.sid or 'no-session-id'})
        
        # Store pending transaction in session for verification
        session['pending_transaction'] = {
            'reference': reference,
            'plan_code': plan_code,
            'amount': amount
        }

        return jsonify({'authorization_url': response_data['data']['authorization_url']})
    except Exception as e:
        logger.error(f"Error initiating payment for user {current_user.id}: {str(e)}", 
                     exc_info=True, extra={'session_id': request.sid or 'no-session-id'})
        flash(trans('general_error', default='An error occurred during payment initiation'), 'danger')
        return redirect(url_for('subscribe_bp.subscribe'))

@subscribe_bp.route('/callback')
@login_required
def callback():
    """Handle Paystack payment callback."""
    try:
        reference = request.args.get('reference')
        pending_transaction = session.get('pending_transaction')

        if not reference or not pending_transaction or pending_transaction['reference'] != reference:
            logger.error(f"Invalid callback reference for user {current_user.id}: {reference}", 
                         extra={'session_id': request.sid or 'no-session-id'})
            flash(trans('subscribe_invalid_reference', default='Invalid payment reference'), 'danger')
            return redirect(url_for('subscribe_bp.subscribe'))

        # Verify transaction with Paystack
        headers = {
            'Authorization': f"Bearer {os.getenv('PAYSTACK_SECRET_KEY')}",
            'Content-Type': 'application/json'
        }
        response = requests.get(
            f"https://api.paystack.co/transaction/verify/{reference}",
            headers=headers
        )
        response_data = response.json()

        if response.status_code != 200 or not response_data.get('status') or response_data['data']['status'] != 'success':
            logger.error(f"Payment verification failed for user {current_user.id}: {response_data.get('message', 'Unknown error')}", 
                         extra={'session_id': request.sid or 'no-session-id'})
            flash(trans('subscribe_payment_failed', default='Payment verification failed'), 'danger')
            session.pop('pending_transaction', None)
            return redirect(url_for('subscribe_bp.subscribe'))

        # Update user subscription status
        db = get_mongo_db()
        update_data = {
            'is_subscribed': True,
            'subscription_plan': pending_transaction['plan_code'],
            'subscription_start': datetime.utcnow(),
            'subscription_end': datetime.utcnow() + timedelta(days=30 if pending_transaction['plan_code'] == 'monthly' else 365)
        }
        update_user(db, current_user.id, update_data)

        # Log audit event
        db.audit_logs.insert_one({
            'admin_id': 'system',
            'action': 'subscription_success',
            'details': {
                'user_id': current_user.id,
                'plan_code': pending_transaction['plan_code'],
                'reference': reference,
                'amount': pending_transaction['amount']
            },
            'timestamp': datetime.utcnow()
        })

        logger.info(f"Subscription successful for user {current_user.id}, plan: {pending_transaction['plan_code']}, reference: {reference}", 
                    extra={'session_id': request.sid or 'no-session-id'})
        flash(trans('subscribe_success', default='Subscription successful! You now have full access.'), 'success')
        session.pop('pending_transaction', None)
        return redirect(url_for('general_bp.home'))
    except Exception as e:
        logger.error(f"Error processing callback for user {current_user.id}: {str(e)}", 
                     exc_info=True, extra={'session_id': request.sid or 'no-session-id'})
        flash(trans('general_error', default='An error occurred during payment processing'), 'danger')
        session.pop('pending_transaction', None)
        return redirect(url_for('subscribe_bp.subscribe'))