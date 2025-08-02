from flask import Blueprint, render_template, redirect, url_for, flash, session, request, jsonify, make_response
from flask_login import login_required, current_user
from translations import trans
from jinja2.exceptions import TemplateNotFound
from datetime import datetime
from models import create_feedback, get_mongo_db, get_user
from flask_wtf.csrf import CSRFError
from flask import current_app
import utils

general_bp = Blueprint('general_bp', __name__, url_prefix='/general')

@general_bp.route('/landing')
def landing():
    """Render the public landing page."""
    try:
        current_app.logger.info(f"Accessing general.landing - User: {current_user.id if current_user.is_authenticated else 'Anonymous'}, Authenticated: {current_user.is_authenticated}, Session: {dict(session)}")
        explore_features = utils.get_explore_features()
        response = make_response(render_template(
            'general/landingpage.html',
            title=trans('general_welcome', lang=session.get('lang', 'en'), default='Welcome'),
            explore_features_for_template=explore_features
        ))
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    except Exception as e:
        current_app.logger.error(f"Error rendering landing page: {str(e)}", extra={'session_id': session.get('sid', 'unknown')})
        flash(trans('general_error', default='An error occurred'), 'danger')
        response = make_response(render_template(
            'general/error.html',
            error_message="Unable to load the landing page due to an internal error.",
            title=trans('general_welcome', lang=session.get('lang', 'en'), default='Welcome')
        ), 500)
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        return response

@general_bp.route('/home')
@login_required
def home():
    """Trader homepage with trial/subscription check."""
    if current_user.role not in ['trader', 'admin']:
        flash(trans('general_access_denied', default='You do not have permission to access this page.'), 'danger')
        return redirect(url_for('index'))
    
    user = get_user(get_mongo_db(), current_user.id)
    if not user.is_trial_active():
        flash(trans('general_subscription_required', default='Your trial has expired. Please subscribe to continue.'), 'warning')
        return redirect(url_for('general_bp.subscription_required'))
    
    return render_template(
        'general/home.html',
        title=trans('general_business_home', lang=session.get('lang', 'en'), default='Business Dashboard'),
        is_trial=user.is_trial,
        trial_end=user.trial_end
    )

@general_bp.route('/about')
def about():
    """Public about page."""
    return render_template(
        'general/about.html',
        title=trans('general_about', lang=session.get('lang', 'en'), default='About Us')
    )

@general_bp.route('/contact')
def contact():
    """Public contact page."""
    return render_template(
        'general/contact.html',
        title=trans('general_contact', lang=session.get('lang', 'en'), default='Contact Us')
    )

@general_bp.route('/privacy')
def privacy():
    """Public privacy policy page."""
    lang = session.get('lang', 'en')
    try:
        return render_template(
            'general/privacy.html',
            title=trans('general_privacy', lang=lang, default='Privacy Policy')
        )
    except TemplateNotFound as e:
        current_app.logger.error(f'Template not found: {str(e)}', exc_info=True)
        return render_template(
            'general/error.html',
            error=str(e),
            title=trans('general_privacy', lang=lang, default='Privacy Policy')
        ), 404

@general_bp.route('/terms')
def terms():
    """Public terms of service page."""
    lang = session.get('lang', 'en')
    try:
        return render_template(
            'general/terms.html',
            title=trans('general_terms', lang=lang, default='Terms of Service')
        )
    except TemplateNotFound as e:
        current_app.logger.error(f'Template not found: {str(e)}', exc_info=True)
        return render_template(
            'general/error.html',
            error=str(e),
            title=trans('general_terms', lang=lang, default='Terms of Service')
        ), 404

@general_bp.route('/business-finance-tips')
def business_finance_tips():
    """Public business finance tips page."""
    lang = session.get('lang', 'en')
    try:
        return render_template(
            'general/business_finance_tips.html',
            title=trans('business_finance_tips_title', lang=lang, default='Business Finance Tips')
        )
    except TemplateNotFound as e:
        current_app.logger.error(f'Template not found: {str(e)}', exc_info=True)
        return render_template(
            'general/error.html',
            error=str(e),
            title=trans('business_finance_tips_title', lang=lang, default='Business Finance Tips')
        ), 404

@general_bp.route('/feedback', methods=['GET', 'POST'])
@utils.limiter.limit('10 per minute')
def feedback():
    """Public feedback page for core business finance features."""
    lang = session.get('lang', 'en')
    current_app.logger.info('Handling feedback', extra={'ip_address': request.remote_addr})

    # Updated tool options to reflect only core business finance modules
    tool_options = [
        ['profile', trans('general_profile', default='Profile')],
        ['debtors', trans('debtors_dashboard', default='Debtors')],
        ['creditors', trans('creditors_dashboard', default='Creditors')],
        ['receipts', trans('receipts_dashboard', default='Receipts')],
        ['payment', trans('payments_dashboard', default='Payments')],
        ['report', trans('reports_dashboard', default='Business Reports')],
        ['fund', trans('fund_tracking', default='Fund Tracking')],
        ['investor_report', trans('investor_reports', default='Investor Reports')],
        ['forecast', trans('forecast_scenario', default='Forecast & Scenario')]
    ]

    if request.method == 'POST':
        try:
            tool_name = request.form.get('tool_name')
            rating = request.form.get('rating')
            comment = request.form.get('comment', '').strip()
            valid_tools = [option[0] for option in tool_options]
            
            # Validate inputs
            if not tool_name or tool_name not in valid_tools:
                current_app.logger.error(f'Invalid feedback tool: {tool_name}', extra={'ip_address': request.remote_addr})
                flash(trans('general_invalid_input', default='Please select a valid tool'), 'danger')
                return render_template('general/feedback.html', tool_options=tool_options, title=trans('general_feedback', lang=lang))
            
            if not rating or not rating.isdigit() or int(rating) < 1 or int(rating) > 5:
                current_app.logger.error(f'Invalid rating: {rating}', extra={'ip_address': request.remote_addr})
                flash(trans('general_invalid_input', default='Please provide a rating between 1 and 5'), 'danger')
                return render_template('general/feedback.html', tool_options=tool_options, title=trans('general_feedback', lang=lang))
            
            # Check trial/subscription status for authenticated users
            if current_user.is_authenticated:
                user = get_user(get_mongo_db(), current_user.id)
                if not user.is_trial_active():
                    flash(trans('general_subscription_required', default='Your trial has expired. Please subscribe to submit feedback.'), 'warning')
                    return redirect(url_for('general_bp.subscription_required'))
            
            # Store feedback
            with current_app.app_context():
                db = get_mongo_db()
                feedback_entry = {
                    'user_id': str(current_user.id) if current_user.is_authenticated else None,
                    'session_id': session.get('sid', 'no-session-id'),
                    'tool_name': tool_name,
                    'rating': int(rating),
                    'comment': comment or None,
                    'timestamp': datetime.utcnow()
                }
                create_feedback(db, feedback_entry)
                
                # Log audit entry
                db.audit_logs.insert_one({
                    'admin_id': 'system',
                    'action': 'submit_feedback',
                    'details': {
                        'user_id': str(current_user.id) if current_user.is_authenticated else None,
                        'tool_name': tool_name,
                        'rating': int(rating)
                    },
                    'timestamp': datetime.utcnow()
                })
            
            current_app.logger.info(f'Feedback submitted: tool={tool_name}, rating={rating}', 
                                   extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr})
            flash(trans('general_thank_you', default='Thank you for your feedback!'), 'success')
            return redirect(url_for('general_bp.home'))
        
        except ValueError as e:
            current_app.logger.error(f'Error processing feedback: {str(e)}', extra={'ip_address': request.remote_addr})
            flash(trans('general_error', default='Error occurred during feedback submission'), 'danger')
            return render_template('general/feedback.html', tool_options=tool_options, title=trans('general_feedback', lang=lang)), 400
        
        except Exception as e:
            current_app.logger.error(f'Error processing feedback: {str(e)}', exc_info=True, extra={'ip_address': request.remote_addr})
            flash(trans('general_error', default='Error occurred during feedback submission'), 'danger')
            try:
                return render_template('general/feedback.html', tool_options=tool_options, title=trans('general_feedback', lang=lang)), 500
            except TemplateNotFound as e:
                current_app.logger.error(f'Template not found: {str(e)}', exc_info=True)
                return render_template('general/error.html', error=str(e), title=trans('general_feedback', lang=lang)), 500
    
    # Handle GET request
    return render_template('general/feedback.html', tool_options=tool_options, title=trans('general_feedback', lang=lang))
