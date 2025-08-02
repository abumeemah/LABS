import logging
from bson import ObjectId
from flask import Blueprint, render_template, redirect, url_for, flash, request, session, Response
from flask_login import login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, FloatField, SelectField, SubmitField, DateField, validators
from wtforms.validators import DataRequired, NumberRange, ValidationError
from translations import trans
import utils
import datetime
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.units import inch
from io import BytesIO
import csv
from models import get_records, get_cashflows, get_audit_logs

logger = logging.getLogger(__name__)

admin_bp = Blueprint('admin', __name__, template_folder='templates/admin')

# Form Definitions
class TaxRateForm(FlaskForm):
    role = SelectField(trans('tax_role', default='Role'), choices=[('trader', 'Trader'), ('startup', 'Startup'), ('admin', 'Admin')], validators=[DataRequired()], render_kw={'class': 'form-select'})
    min_income = FloatField(trans('tax_min_income', default='Minimum Income'), validators=[DataRequired(), NumberRange(min=0)], render_kw={'class': 'form-control'})
    max_income = FloatField(trans('tax_max_income', default='Maximum Income'), validators=[DataRequired(), NumberRange(min=0)], render_kw={'class': 'form-control'})
    rate = FloatField(trans('tax_rate', default='Rate'), validators=[DataRequired(), NumberRange(min=0, max=1)], render_kw={'class': 'form-control'})
    description = StringField(trans('tax_description', default='Description'), validators=[DataRequired()], render_kw={'class': 'form-control'})
    submit = SubmitField(trans('tax_add_rate', default='Add Tax Rate'), render_kw={'class': 'btn btn-primary'})

    def validate_max_income(self, field):
        if field.data <= self.min_income.data:
            raise ValidationError(trans('tax_max_income_error', default='Maximum income must be greater than minimum income.'))

class RoleForm(FlaskForm):
    role = SelectField(trans('user_role', default='Role'), choices=[('trader', 'Trader'), ('startup', 'Startup'), ('admin', 'Admin')], validators=[DataRequired()], render_kw={'class': 'form-select'})
    submit = SubmitField(trans('user_update_role', default='Update Role'), render_kw={'class': 'btn btn-primary'})

class PaymentLocationForm(FlaskForm):
    name = StringField(trans('location_name', default='Location Name'), validators=[DataRequired(), validators.Length(min=2, max=100)], render_kw={'class': 'form-control'})
    address = StringField(trans('location_address', default='Address'), validators=[DataRequired(), validators.Length(min=5, max=200)], render_kw={'class': 'form-control'})
    city = StringField(trans('location_city', default='City'), validators=[DataRequired(), validators.Length(min=2, max=100)], render_kw={'class': 'form-control'})
    country = StringField(trans('location_country', default='Country'), validators=[DataRequired(), validators.Length(min=2, max=100)], render_kw={'class': 'form-control'})
    submit = SubmitField(trans('location_add', default='Add Payment Location'), render_kw={'class': 'btn btn-primary'})

class TaxDeadlineForm(FlaskForm):
    role = SelectField(trans('tax_role', default='Role'), choices=[('trader', 'Trader'), ('startup', 'Startup'), ('admin', 'Admin')], validators=[DataRequired()], render_kw={'class': 'form-select'})
    deadline_date = DateField(trans('tax_deadline_date', default='Deadline Date'), validators=[DataRequired()], format='%Y-%m-%d', render_kw={'class': 'form-control'})
    description = StringField(trans('tax_description', default='Description'), validators=[DataRequired(), validators.Length(min=5, max=200)], render_kw={'class': 'form-control'})
    submit = SubmitField(trans('tax_add_deadline', default='Add Tax Deadline'), render_kw={'class': 'btn btn-primary'})

class SubscriptionForm(FlaskForm):
    is_subscribed = SelectField(trans('subscription_status', default='Subscription Status'), choices=[('True', 'Subscribed'), ('False', 'Not Subscribed')], validators=[DataRequired()], render_kw={'class': 'form-select'})
    subscription_plan = SelectField(trans('subscription_plan', default='Subscription Plan'), choices=[('', 'None'), ('monthly', 'Monthly'), ('yearly', 'Yearly')], render_kw={'class': 'form-select'})
    subscription_end = DateField(trans('subscription_end', default='Subscription End Date'), format='%Y-%m-%d', validators=[validators.Optional()], render_kw={'class': 'form-control'})
    submit = SubmitField(trans('subscription_update', default='Update Subscription'), render_kw={'class': 'btn btn-primary'})

# Helper Functions
def log_audit_action(action, details=None):
    """Log an admin action to audit_logs collection."""
    try:
        db = utils.get_mongo_db()
        db.audit_logs.insert_one({
            'admin_id': str(current_user.id),
            'action': action,
            'details': details or {},
            'timestamp': datetime.datetime.utcnow()
        })
    except Exception as e:
        logger.error(f"Error logging audit action: {str(e)}",
                     extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})

# Routes
@admin_bp.route('/dashboard', methods=['GET'])
@login_required
@utils.requires_role('admin')
@utils.limiter.limit("50 per hour")
def dashboard():
    """Admin dashboard with system statistics."""
    try:
        db = utils.get_mongo_db()
        
        # Calculate system statistics
        stats = {
            'users': db.users.count_documents({}),
            'records': db.records.count_documents({}),
            'cashflows': db.cashflows.count_documents({}),
            'audit_logs': db.audit_logs.count_documents({}),
            'payment_locations': db.payment_locations.count_documents({}),
            'tax_deadlines': db.tax_deadlines.count_documents({}),
            'tax_rates': db.tax_rates.count_documents({})
        }
        
        # Get recent users with subscription status
        recent_users = list(db.users.find().sort('created_at', -1).limit(5))
        for user in recent_users:
            user['_id'] = str(user['_id'])
            user['is_trial_active'] = datetime.datetime.utcnow() <= user.get('trial_end') if user.get('is_trial') else user.get('is_subscribed') and datetime.datetime.utcnow() <= user.get('subscription_end', datetime.datetime.utcnow())
        
        logger.info(f"Admin {current_user.id} accessed dashboard at {datetime.datetime.utcnow()}",
                    extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        return render_template(
            'admin/dashboard.html',
            stats=stats,
            recent_users=recent_users,
            title=trans('admin_dashboard', default='Admin Dashboard')
        )
    except Exception as e:
        logger.error(f"Error loading admin dashboard for {current_user.id}: {str(e)}",
                     extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('admin_dashboard_error', default='An error occurred while loading the dashboard'), 'danger')
        return redirect(url_for('personal_bp.error'))

@admin_bp.route('/users', methods=['GET'])
@login_required
@utils.requires_role('admin')
@utils.limiter.limit("50 per hour")
def manage_users():
    """View and manage users."""
    try:
        db = utils.get_mongo_db()
        users = list(db.users.find({} if utils.is_admin() else {'role': {'$ne': 'admin'}}).sort('created_at', -1))
        for user in users:
            user['_id'] = str(user['_id'])
            user['username'] = user['_id']
            user['is_trial_active'] = datetime.datetime.utcnow() <= user.get('trial_end') if user.get('is_trial') else user.get('is_subscribed') and datetime.datetime.utcnow() <= user.get('subscription_end', datetime.datetime.utcnow())
        return render_template('admin/users.html', users=users, title=trans('admin_manage_users_title', default='Manage Users'))
    except Exception as e:
        logger.error(f"Error fetching users for admin: {str(e)}",
                     extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('admin_database_error', default='An error occurred while accessing the database'), 'danger')
        return render_template('admin/users.html', users=[]), 500

@admin_bp.route('/users/suspend/<user_id>', methods=['POST'])
@login_required
@utils.requires_role('admin')
@utils.limiter.limit("10 per hour")
def suspend_user(user_id):
    """Suspend a user account."""
    try:
        db = utils.get_mongo_db()
        user_query = utils.get_user_query(user_id)
        user = db.users.find_one(user_query)
        if not user:
            flash(trans('admin_user_not_found', default='User not found'), 'danger')
            return redirect(url_for('admin.manage_users'))
        result = db.users.update_one(
            user_query,
            {'$set': {'suspended': True, 'updated_at': datetime.datetime.utcnow()}}
        )
        if result.modified_count == 0:
            flash(trans('admin_user_not_updated', default='User could not be suspended'), 'danger')
        else:
            flash(trans('admin_user_suspended', default='User suspended successfully'), 'success')
            logger.info(f"Admin {current_user.id} suspended user {user_id}",
                        extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
            log_audit_action('suspend_user', {'user_id': user_id})
        return redirect(url_for('admin.manage_users'))
    except Exception as e:
        logger.error(f"Error suspending user {user_id}: {str(e)}",
                     extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('admin_database_error', default='An error occurred while accessing the database'), 'danger')
        return redirect(url_for('admin.manage_users'))

@admin_bp.route('/users/delete/<user_id>', methods=['POST'])
@login_required
@utils.requires_role('admin')
@utils.limiter.limit("5 per hour")
def delete_user(user_id):
    """Delete a user and their data."""
    try:
        db = utils.get_mongo_db()
        user_query = utils.get_user_query(user_id)
        user = db.users.find_one(user_query)
        if not user:
            flash(trans('admin_user_not_found', default='User not found'), 'danger')
            return redirect(url_for('admin.manage_users'))
        db.records.delete_many({'user_id': user_id})
        db.cashflows.delete_many({'user_id': user_id})
        db.audit_logs.delete_many({'details.user_id': user_id})
        result = db.users.delete_one(user_query)
        if result.deleted_count == 0:
            flash(trans('admin_user_not_deleted', default='User could not be deleted'), 'danger')
        else:
            flash(trans('admin_user_deleted', default='User deleted successfully'), 'success')
            logger.info(f"Admin {current_user.id} deleted user {user_id}",
                        extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
            log_audit_action('delete_user', {'user_id': user_id})
        return redirect(url_for('admin.manage_users'))
    except Exception as e:
        logger.error(f"Error deleting user {user_id}: {str(e)}",
                     extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('admin_database_error', default='An error occurred while accessing the database'), 'danger')
        return redirect(url_for('admin.manage_users'))

@admin_bp.route('/data/delete/<collection>/<item_id>', methods=['POST'])
@login_required
@utils.requires_role('admin')
@utils.limiter.limit("10 per hour")
def delete_item(collection, item_id):
    """Delete an item from a collection."""
    valid_collections = ['records', 'cashflows', 'payment_locations', 'tax_deadlines', 'tax_rates']
    if collection not in valid_collections:
        flash(trans('admin_invalid_collection', default='Invalid collection selected'), 'danger')
        return redirect(url_for('admin.dashboard'))
    try:
        db = utils.get_mongo_db()
        result = db[collection].delete_one({'_id': ObjectId(item_id)})
        if result.deleted_count == 0:
            flash(trans('admin_item_not_found', default='Item not found'), 'danger')
        else:
            flash(trans('admin_item_deleted', default='Item deleted successfully'), 'success')
            logger.info(f"Admin {current_user.id} deleted {collection} item {item_id}",
                        extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
            log_audit_action(f'delete_{collection}_item', {'item_id': item_id, 'collection': collection})
        return redirect(url_for(f'admin.{collection.replace("_", "")}' if collection in ['payment_locations', 'tax_deadlines', 'tax_rates'] else 'admin.dashboard'))
    except Exception as e:
        logger.error(f"Error deleting {collection} item {item_id}: {str(e)}",
                     extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('admin_database_error', default='An error occurred while accessing the database'), 'danger')
        return redirect(url_for('admin.dashboard'))

@admin_bp.route('/audit', methods=['GET'])
@login_required
@utils.requires_role('admin')
@utils.limiter.limit("50 per hour")
def audit():
    """View audit logs of admin actions."""
    try:
        db = utils.get_mongo_db()
        logs = list(get_audit_logs(db, {}).sort('timestamp', -1).limit(100))
        for log in logs:
            log['_id'] = str(log['_id'])
        return render_template('admin/audit.html', logs=logs, title=trans('admin_audit_title', default='Audit Logs'))
    except Exception as e:
        logger.error(f"Error fetching audit logs for admin {current_user.id}: {str(e)}",
                     extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        flash(trans('admin_database_error', default='An error occurred while accessing the database'), 'danger')
        return render_template('admin/audit.html', logs=[])

@admin_bp.route('/payment_locations', methods=['GET', 'POST'])
@login_required
@utils.requires_role('admin')
@utils.limiter.limit("50 per hour")
def manage_payment_locations():
    """Manage payment locations: list all locations and add new ones."""
    db = utils.get_mongo_db()
    form = PaymentLocationForm()
    if request.method == 'POST' and form.validate_on_submit():
        try:
            location = {
                'name': form.name.data,
                'address': form.address.data,
                'city': form.city.data,
                'country': form.country.data,
                'created_by': current_user.id,
                'created_at': datetime.datetime.utcnow()
            }
            result = db.payment_locations.insert_one(location)
            location_id = str(result.inserted_id)
            logger.info(f"Payment location added: id={location_id}, name={form.name.data}, user={current_user.id}",
                        extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
            log_audit_action('add_payment_location', {'location_id': location_id, 'name': form.name.data})
            flash(trans('payment_location_added', default='Payment location added successfully'), 'success')
            return redirect(url_for('admin.manage_payment_locations'))
        except Exception as e:
            logger.error(f"Error adding payment location: {str(e)}",
                         extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
            flash(trans('admin_database_error', default='An error occurred while accessing the database'), 'danger')
            return render_template('admin/payment_locations.html', form=form, locations=[])
    
    locations = list(db.payment_locations.find().sort('created_at', -1))
    for location in locations:
        location['_id'] = str(location['_id'])
    return render_template('admin/payment_locations.html', form=form, locations=locations, title=trans('admin_payment_locations_title', default='Manage Payment Locations'))

@admin_bp.route('/payment_locations/edit/<location_id>', methods=['GET', 'POST'])
@login_required
@utils.requires_role('admin')
@utils.limiter.limit("10 per hour")
def edit_payment_location(location_id):
    """Edit an existing payment location."""
    db = utils.get_mongo_db()
    location = db.payment_locations.find_one({'_id': ObjectId(location_id)})
    if not location:
        flash(trans('payment_location_not_found', default='Payment location not found'), 'danger')
        return redirect(url_for('admin.manage_payment_locations'))
    
    form = PaymentLocationForm(obj=location)
    if request.method == 'POST' and form.validate_on_submit():
        try:
            db.payment_locations.update_one(
                {'_id': ObjectId(location_id)},
                {'$set': {
                    'name': form.name.data,
                    'address': form.address.data,
                    'city': form.city.data,
                    'country': form.country.data,
                    'updated_at': datetime.datetime.utcnow()
                }}
            )
            logger.info(f"Payment location updated: id={location_id}, user={current_user.id}",
                        extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
            log_audit_action('edit_payment_location', {'location_id': location_id})
            flash(trans('payment_location_updated', default='Payment location updated successfully'), 'success')
            return redirect(url_for('admin.manage_payment_locations'))
        except Exception as e:
            logger.error(f"Error updating payment location {location_id}: {str(e)}",
                         extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
            flash(trans('admin_database_error', default='An error occurred while accessing the database'), 'danger')
            return render_template('admin/payment_location_edit.html', form=form, location=location, title=trans('admin_edit_payment_location_title', default='Edit Payment Location'))
    
    return render_template('admin/payment_location_edit.html', form=form, location=location, title=trans('admin_edit_payment_location_title', default='Edit Payment Location'))

@admin_bp.route('/payment_locations/delete/<location_id>', methods=['POST'])
@login_required
@utils.requires_role('admin')
@utils.limiter.limit("10 per hour")
def delete_payment_location(location_id):
    """Delete a payment location."""
    db = utils.get_mongo_db()
    result = db.payment_locations.delete_one({'_id': ObjectId(location_id)})
    if result.deleted_count > 0:
        logger.info(f"Payment location deleted: id={location_id}, user={current_user.id}",
                    extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        log_audit_action('delete_payment_location', {'location_id': location_id})
        flash(trans('payment_location_deleted', default='Payment location deleted successfully'), 'success')
    else:
        flash(trans('payment_location_not_found', default='Payment location not found'), 'danger')
    return redirect(url_for('admin.manage_payment_locations'))

@admin_bp.route('/tax_deadlines', methods=['GET', 'POST'])
@login_required
@utils.requires_role('admin')
@utils.limiter.limit("50 per hour")
def manage_tax_deadlines():
    """Manage tax deadlines: list all deadlines and add new ones."""
    db = utils.get_mongo_db()
    form = TaxDeadlineForm()
    if request.method == 'POST' and form.validate_on_submit():
        try:
            deadline = {
                'role': form.role.data,
                'deadline_date': form.deadline_date.data,
                'description': form.description.data,
                'created_by': current_user.id,
                'created_at': datetime.datetime.utcnow()
            }
            result = db.tax_deadlines.insert_one(deadline)
            deadline_id = str(result.inserted_id)
            logger.info(f"Tax deadline added: id={deadline_id}, role={form.role.data}, user={current_user.id}",
                        extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
            log_audit_action('add_tax_deadline', {'deadline_id': deadline_id, 'role': form.role.data})
            flash(trans('tax_deadline_added', default='Tax deadline added successfully'), 'success')
            return redirect(url_for('admin.manage_tax_deadlines'))
        except Exception as e:
            logger.error(f"Error adding tax deadline: {str(e)}",
                         extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
            flash(trans('admin_database_error', default='An error occurred while accessing the database'), 'danger')
            return render_template('admin/tax_deadlines.html', form=form, deadlines=[])
    
    deadlines = list(db.tax_deadlines.find().sort('deadline_date', -1))
    for deadline in deadlines:
        deadline['_id'] = str(deadline['_id'])
    return render_template('admin/tax_deadlines.html', form=form, deadlines=deadlines, title=trans('admin_tax_deadlines_title', default='Manage Tax Deadlines'))

@admin_bp.route('/tax_deadlines/edit/<deadline_id>', methods=['GET', 'POST'])
@login_required
@utils.requires_role('admin')
@utils.limiter.limit("10 per hour")
def edit_tax_deadline(deadline_id):
    """Edit an existing tax deadline."""
    db = utils.get_mongo_db()
    deadline = db.tax_deadlines.find_one({'_id': ObjectId(deadline_id)})
    if not deadline:
        flash(trans('tax_deadline_not_found', default='Tax deadline not found'), 'danger')
        return redirect(url_for('admin.manage_tax_deadlines'))
    
    form = TaxDeadlineForm(obj=deadline)
    if request.method == 'POST' and form.validate_on_submit():
        try:
            db.tax_deadlines.update_one(
                {'_id': ObjectId(deadline_id)},
                {'$set': {
                    'role': form.role.data,
                    'deadline_date': form.deadline_date.data,
                    'description': form.description.data,
                    'updated_at': datetime.datetime.utcnow()
                }}
            )
            logger.info(f"Tax deadline updated: id={deadline_id}, user={current_user.id}",
                        extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
            log_audit_action('edit_tax_deadline', {'deadline_id': deadline_id})
            flash(trans('tax_deadline_updated', default='Tax deadline updated successfully'), 'success')
            return redirect(url_for('admin.manage_tax_deadlines'))
        except Exception as e:
            logger.error(f"Error updating tax deadline {deadline_id}: {str(e)}",
                         extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
            flash(trans('admin_database_error', default='An error occurred while accessing the database'), 'danger')
            return render_template('admin/tax_deadline_edit.html', form=form, deadline=deadline, title=trans('admin_edit_tax_deadline_title', default='Edit Tax Deadline'))
    
    return render_template('admin/tax_deadline_edit.html', form=form, deadline=deadline, title=trans('admin_edit_tax_deadline_title', default='Edit Tax Deadline'))

@admin_bp.route('/tax_deadlines/delete/<deadline_id>', methods=['POST'])
@login_required
@utils.requires_role('admin')
@utils.limiter.limit("10 per hour")
def delete_tax_deadline(deadline_id):
    """Delete a tax deadline."""
    db = utils.get_mongo_db()
    result = db.tax_deadlines.delete_one({'_id': ObjectId(deadline_id)})
    if result.deleted_count > 0:
        logger.info(f"Tax deadline deleted: id={deadline_id}, user={current_user.id}",
                    extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        log_audit_action('delete_tax_deadline', {'deadline_id': deadline_id})
        flash(trans('tax_deadline_deleted', default='Tax deadline deleted successfully'), 'success')
    else:
        flash(trans('tax_deadline_not_found', default='Tax deadline not found'), 'danger')
    return redirect(url_for('admin.manage_tax_deadlines'))

@admin_bp.route('/tax_rates', methods=['GET', 'POST'])
@login_required
@utils.requires_role('admin')
@utils.limiter.limit("50 per hour")
def manage_tax_rates():
    """Manage tax rates: list all tax rates and add new ones."""
    db = utils.get_mongo_db()
    form = TaxRateForm()
    if request.method == 'POST' and form.validate_on_submit():
        try:
            tax_rate = {
                'role': form.role.data,
                'min_income': form.min_income.data,
                'max_income': form.max_income.data,
                'rate': form.rate.data,
                'description': form.description.data,
                'created_by': current_user.id,
                'created_at': datetime.datetime.utcnow()
            }
            result = db.tax_rates.insert_one(tax_rate)
            rate_id = str(result.inserted_id)
            logger.info(f"Tax rate added: id={rate_id}, role={form.role.data}, user={current_user.id}",
                        extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
            log_audit_action('add_tax_rate', {'rate_id': rate_id, 'role': form.role.data})
            flash(trans('tax_rate_added', default='Tax rate added successfully'), 'success')
            return redirect(url_for('admin.manage_tax_rates'))
        except Exception as e:
            logger.error(f"Error adding tax rate: {str(e)}",
                         extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
            flash(trans('admin_database_error', default='An error occurred while accessing the database'), 'danger')
            return render_template('admin/tax_rates.html', form=form, rates=[])
    
    rates = list(db.tax_rates.find().sort('created_at', -1))
    for rate in rates:
        rate['_id'] = str(rate['_id'])
    return render_template('admin/tax_rates.html', form=form, rates=rates, title=trans('admin_tax_rates_title', default='Manage Tax Rates'))

@admin_bp.route('/tax_rates/edit/<rate_id>', methods=['GET', 'POST'])
@login_required
@utils.requires_role('admin')
@utils.limiter.limit("10 per hour")
def edit_tax_rate(rate_id):
    """Edit an existing tax rate."""
    db = utils.get_mongo_db()
    rate = db.tax_rates.find_one({'_id': ObjectId(rate_id)})
    if not rate:
        flash(trans('tax_rate_not_found', default='Tax rate not found'), 'danger')
        return redirect(url_for('admin.manage_tax_rates'))
    
    form = TaxRateForm(obj=rate)
    if request.method == 'POST' and form.validate_on_submit():
        try:
            db.tax_rates.update_one(
                {'_id': ObjectId(rate_id)},
                {'$set': {
                    'role': form.role.data,
                    'min_income': form.min_income.data,
                    'max_income': form.max_income.data,
                    'rate': form.rate.data,
                    'description': form.description.data,
                    'updated_at': datetime.datetime.utcnow()
                }}
            )
            logger.info(f"Tax rate updated: id={rate_id}, user={current_user.id}",
                        extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
            log_audit_action('edit_tax_rate', {'rate_id': rate_id})
            flash(trans('tax_rate_updated', default='Tax rate updated successfully'), 'success')
            return redirect(url_for('admin.manage_tax_rates'))
        except Exception as e:
            logger.error(f"Error updating tax rate {rate_id}: {str(e)}",
                         extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
            flash(trans('admin_database_error', default='An error occurred while accessing the database'), 'danger')
            return render_template('admin/tax_rate_edit.html', form=form, rate=rate, title=trans('admin_edit_tax_rate_title', default='Edit Tax Rate'))
    
    return render_template('admin/tax_rate_edit.html', form=form, rate=rate, title=trans('admin_edit_tax_rate_title', default='Edit Tax Rate'))

@admin_bp.route('/tax_rates/delete/<rate_id>', methods=['POST'])
@login_required
@utils.requires_role('admin')
@utils.limiter.limit("10 per hour")
def delete_tax_rate(rate_id):
    """Delete a tax rate."""
    db = utils.get_mongo_db()
    result = db.tax_rates.delete_one({'_id': ObjectId(rate_id)})
    if result.deleted_count > 0:
        logger.info(f"Tax rate deleted: id={rate_id}, user={current_user.id}",
                    extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
        log_audit_action('delete_tax_rate', {'rate_id': rate_id})
        flash(trans('tax_rate_deleted', default='Tax rate deleted successfully'), 'success')
    else:
        flash(trans('tax_rate_not_found', default='Tax rate not found'), 'danger')
    return redirect(url_for('admin.manage_tax_rates'))

@admin_bp.route('/users/roles', methods=['GET', 'POST'])
@login_required
@utils.requires_role('admin')
@utils.limiter.limit("50 per hour")
def manage_user_roles():
    """Manage user roles: list all users and update their roles."""
    db = utils.get_mongo_db()
    users = list(db.users.find())
    form = RoleForm()
    if request.method == 'POST' and form.validate_on_submit():
        user_id = request.form.get('user_id')
        if not user_id:
            flash(trans('user_id_required', default='User ID is required'), 'danger')
            return redirect(url_for('admin.manage_user_roles'))
        try:
            user = db.users.find_one({'_id': user_id})
            if not user:
                flash(trans('user_not_found', default='User not found'), 'danger')
                return redirect(url_for('admin.manage_user_roles'))
            new_role = form.role.data
            db.users.update_one(
                {'_id': user_id},
                {'$set': {'role': new_role, 'updated_at': datetime.datetime.utcnow()}}
            )
            logger.info(f"User role updated: id={user_id}, new_role={new_role}, user={current_user.id}",
                        extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
            log_audit_action('update_user_role', {'user_id': user_id, 'new_role': new_role})
            flash(trans('user_role_updated', default='User role updated successfully'), 'success')
            return redirect(url_for('admin.manage_user_roles'))
        except Exception as e:
            logger.error(f"Error updating user role {user_id}: {str(e)}",
                         extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
            flash(trans('admin_database_error', default='An error occurred while accessing the database'), 'danger')
            return render_template('admin/user_roles.html', form=form, users=users, title=trans('admin_manage_user_roles_title', default='Manage User Roles'))
    
    for user in users:
        user['_id'] = str(user['_id'])
        user['is_trial_active'] = datetime.datetime.utcnow() <= user.get('trial_end') if user.get('is_trial') else user.get('is_subscribed') and datetime.datetime.utcnow() <= user.get('subscription_end', datetime.datetime.utcnow())
    return render_template('admin/user_roles.html', form=form, users=users, title=trans('admin_manage_user_roles_title', default='Manage User Roles'))

@admin_bp.route('/users/subscriptions', methods=['GET', 'POST'])
@login_required
@utils.requires_role('admin')
@utils.limiter.limit("50 per hour")
def manage_user_subscriptions():
    """Manage user subscriptions: list all users and update their subscription status."""
    db = utils.get_mongo_db()
    users = list(db.users.find())
    form = SubscriptionForm()
    if request.method == 'POST' and form.validate_on_submit():
        user_id = request.form.get('user_id')
        if not user_id:
            flash(trans('user_id_required', default='User ID is required'), 'danger')
            return redirect(url_for('admin.manage_user_subscriptions'))
        try:
            user = db.users.find_one({'_id': user_id})
            if not user:
                flash(trans('user_not_found', default='User not found'), 'danger')
                return redirect(url_for('admin.manage_user_subscriptions'))
            update_data = {
                'is_subscribed': form.is_subscribed.data == 'True',
                'subscription_plan': form.subscription_plan.data or None,
                'subscription_start': datetime.datetime.utcnow() if form.is_subscribed.data == 'True' else None,
                'subscription_end': form.subscription_end.data if form.subscription_end.data else None,
                'updated_at': datetime.datetime.utcnow()
            }
            if form.is_subscribed.data == 'True' and not form.subscription_end.data:
                # Default to 30 days for monthly, 365 days for yearly if no end date provided
                duration = 365 if form.subscription_plan.data == 'yearly' else 30
                update_data['subscription_end'] = datetime.datetime.utcnow() + datetime.timedelta(days=duration)
            db.users.update_one(
                {'_id': user_id},
                {'$set': update_data}
            )
            logger.info(f"User subscription updated: id={user_id}, subscribed={update_data['is_subscribed']}, plan={update_data['subscription_plan']}, user={current_user.id}",
                        extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
            log_audit_action('update_user_subscription', {'user_id': user_id, 'is_subscribed': update_data['is_subscribed'], 'subscription_plan': update_data['subscription_plan']})
            flash(trans('subscription_updated', default='User subscription updated successfully'), 'success')
            return redirect(url_for('admin.manage_user_subscriptions'))
        except Exception as e:
            logger.error(f"Error updating user subscription {user_id}: {str(e)}",
                         extra={'session_id': session.get('sid', 'no-session-id'), 'user_id': current_user.id})
            flash(trans('admin_database_error', default='An error occurred while accessing the database'), 'danger')
            return render_template('admin/user_subscriptions.html', form=form, users=users, title=trans('admin_manage_user_subscriptions_title', default='Manage User Subscriptions'))
    
    for user in users:
        user['_id'] = str(user['_id'])
        user['is_trial_active'] = datetime.datetime.utcnow() <= user.get('trial_end') if user.get('is_trial') else user.get('is_subscribed') and datetime.datetime.utcnow() <= user.get('subscription_end', datetime.datetime.utcnow())
    return render_template('admin/user_subscriptions.html', form=form, users=users, title=trans('admin_manage_user_subscriptions_title', default='Manage User Subscriptions'))

@admin_bp.route('/reports/customers', methods=['GET'])
@login_required
@utils.requires_role('admin')
@utils.limiter.limit("50 per hour")
def customer_reports():
    """Generate customer reports in HTML, PDF, or CSV format."""
    db = utils.get_mongo_db()
    format = request.args.get('format', 'html')
    users = list(db.users.find())
    for user in users:
        user['_id'] = str(user['_id'])
        user['is_trial_active'] = datetime.datetime.utcnow() <= user.get('trial_end') if user.get('is_trial') else user.get('is_subscribed') and datetime.datetime.utcnow() <= user.get('subscription_end', datetime.datetime.utcnow())
    
    if format == 'pdf':
        return generate_customer_report_pdf(users)
    elif format == 'csv':
        return generate_customer_report_csv(users)
    
    return render_template('admin/customer_reports.html', users=users, title=trans('admin_customer_reports_title', default='Customer Reports'))

def generate_customer_report_pdf(users):
    """Generate a PDF report of customer data."""
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=A4)
    p.setFont("Helvetica", 12)
    p.drawString(1 * inch, 10.5 * inch, trans('admin_customer_report_title', default='Customer Report'))
    p.drawString(1 * inch, 10.2 * inch, f"{trans('admin_generated_on', default='Generated on')}: {datetime.datetime.utcnow().strftime('%Y-%m-%d')}")
    y = 9.5 * inch
    p.drawString(1 * inch, y, trans('admin_username', default='Username'))
    p.drawString(2.5 * inch, y, trans('admin_email', default='Email'))
    p.drawString(4 * inch, y, trans('user_role', default='Role'))
    p.drawString(5.5 * inch, y, trans('admin_created_at', default='Created At'))
    p.drawString(7 * inch, y, trans('subscription_status', default='Subscription Status'))
    y -= 0.3 * inch
    for user in users:
        status = 'Subscribed' if user.get('is_subscribed') and datetime.datetime.utcnow() <= user.get('subscription_end', datetime.datetime.utcnow()) else 'Trial' if user.get('is_trial') and datetime.datetime.utcnow() <= user.get('trial_end') else 'Expired'
        p.drawString(1 * inch, y, user['_id'])
        p.drawString(2.5 * inch, y, user['email'])
        p.drawString(4 * inch, y, user['role'])
        p.drawString(5.5 * inch, y, user['created_at'].strftime('%Y-%m-%d'))
        p.drawString(7 * inch, y, status)
        y -= 0.3 * inch
        if y < 1 * inch:
            p.showPage()
            y = 10.5 * inch
    p.showPage()
    p.save()
    buffer.seek(0)
    return Response(buffer, mimetype='application/pdf', headers={'Content-Disposition': 'attachment;filename=customer_report.pdf'})

def generate_customer_report_csv(users):
    """Generate a CSV report of customer data."""
    output = [[trans('admin_username', default='Username'), trans('admin_email', default='Email'), trans('user_role', default='Role'), trans('admin_created_at', default='Created At'), trans('subscription_status', default='Subscription Status')]]
    for user in users:
        status = 'Subscribed' if user.get('is_subscribed') and datetime.datetime.utcnow() <= user.get('subscription_end', datetime.datetime.utcnow()) else 'Trial' if user.get('is_trial') and datetime.datetime.utcnow() <= user.get('trial_end') else 'Expired'
        output.append([user['_id'], user['email'], user['role'], user['created_at'].strftime('%Y-%m-%d'), status])
    buffer = BytesIO()
    writer = csv.writer(buffer, lineterminator='\n')
    writer.writerows(output)
    buffer.seek(0)
    return Response(buffer, mimetype='text/csv', headers={'Content-Disposition': 'attachment;filename=customer_report.csv'})
