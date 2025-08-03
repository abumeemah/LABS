from flask import Blueprint, render_template, redirect, url_for, flash, request, session, jsonify, send_file
from flask_login import login_required, current_user
from translations import trans
from utils import requires_role, is_valid_email, format_currency, get_mongo_db, is_admin
from bson import ObjectId
from datetime import datetime
from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed
from wtforms import StringField, TextAreaField, SubmitField, FileField
from wtforms.validators import DataRequired, Length, Email, Optional
from gridfs import GridFS
from io import BytesIO
from PIL import Image
import logging
import utils

logger = logging.getLogger(__name__)

settings_bp = Blueprint('settings', __name__, url_prefix='/settings')

class ProfileForm(FlaskForm):
    full_name = StringField(trans('general_full_name', default='Full Name'), [
        DataRequired(message=trans('general_full_name_required', default='Full name is required')),
        Length(min=1, max=100, message=trans('general_full_name_length', default='Full name must be between 1 and 100 characters'))
    ], render_kw={'class': 'form-control'})
    email = StringField(trans('general_email', default='Email'), [
        DataRequired(message=trans('general_email_required', default='Email is required')),
        Email(message=trans('general_email_invalid', default='Invalid email address'))
    ], render_kw={'class': 'form-control'})
    phone = StringField(trans('general_phone', default='Phone'), [
        Optional(),
        Length(max=20, message=trans('general_phone_length', default='Phone number too long'))
    ], render_kw={'class': 'form-control'})
    business_name = StringField(trans('general_business_name', default='Business Name'), [
        Optional(),
        Length(max=100, message=trans('general_business_name_length', default='Business name too long'))
    ], render_kw={'class': 'form-control'})
    business_address = TextAreaField(trans('general_business_address', default='Business Address'), [
        Optional(),
        Length(max=500, message=trans('general_business_address_length', default='Business address too long'))
    ], render_kw={'class': 'form-control'})
    industry = StringField(trans('general_industry', default='Industry'), [
        Optional(),
        Length(max=50, message=trans('general_industry_length', default='Industry name too long'))
    ], render_kw={'class': 'form-control'})
    products_services = StringField(trans('general_products_services', default='Products/Services'), [
        Optional(),
        Length(max=200, message=trans('general_products_services_length', default='Products/Services description too long'))
    ], render_kw={'class': 'form-control'})
    submit = SubmitField(trans('general_save_changes', default='Save Changes'), render_kw={'class': 'btn btn-primary w-100'})

def get_role_based_nav():
    """Helper function to determine role-based navigation data."""
    if current_user.role == 'trader':
        return utils.TRADER_TOOLS, utils.get_explore_features(), utils.TRADER_NAV
    elif current_user.role == 'startup':
        return utils.STARTUP_TOOLS, utils.get_explore_features(), utils.STARTUP_NAV
    elif current_user.role == 'admin':
        return utils.ALL_TOOLS, utils.get_explore_features(), utils.ADMIN_NAV
    else:
        return [], [], []  # Fallback for unexpected roles

@settings_bp.route('/')
@login_required
def index():
    """Display settings overview with KYC button."""
    db = get_mongo_db()
    kyc_record = db.kyc_records.find_one({'user_id': str(current_user.id)})
    session['kyc_status'] = kyc_record['status'] if kyc_record else 'not_submitted'
    try:
        return render_template(
            'settings/index.html',
            user=current_user,
            title=trans('settings_index_title', default='Settings', lang=session.get('lang', 'en'))
        )
    except Exception as e:
        logger.error(f"Error loading settings for user {current_user.id}: {str(e)}")
        flash(trans('general_something_went_wrong', default='An error occurred'), 'danger')
        return redirect(url_for('index'))

@settings_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """Unified profile management page with KYC status."""
    try:
        db = get_mongo_db()
        user_id = request.args.get('user_id', current_user.id) if is_admin() and request.args.get('user_id') else current_user.id
        user_query = get_user_query(user_id)
        user = db.users.find_one(user_query)
        if not user:
            flash(trans('general_user_not_found', default='User not found'), 'danger')
            return redirect(url_for('index'))
        form = ProfileForm()
        if request.method == 'GET':
            form.full_name.data = user.get('display_name', user.get('_id', ''))
            form.email.data = user.get('email', '')
            form.phone.data = user.get('phone', '')
            if user.get('business_details') and user.get('role') in ['trader', 'startup']:
                form.business_name.data = user['business_details'].get('name', '')
                form.business_address.data = user['business_details'].get('address', '')
                form.industry.data = user['business_details'].get('industry', '')
                form.products_services.data = user['business_details'].get('products_services', '')
        if form.validate_on_submit():
            try:
                if form.email.data != user['email'] and db.users.find_one({'email': form.email.data}):
                    flash(trans('general_email_exists', default='Email already in use'), 'danger')
                    return render_template(
                        'settings/profile.html',
                        form=form,
                        user=user,
                        title=trans('settings_profile_title', default='Profile Settings', lang=session.get('lang', 'en'))
                    )
                update_data = {
                    'display_name': form.full_name.data,
                    'email': form.email.data,
                    'phone': form.phone.data,
                    'updated_at': datetime.utcnow(),
                    'setup_complete': True
                }
                if user.get('role') in ['trader', 'startup'] and (form.business_name.data or form.business_address.data or form.industry.data or form.products_services.data):
                    update_data['business_details'] = {
                        'name': form.business_name.data or '',
                        'address': form.business_address.data or '',
                        'industry': form.industry.data or '',
                        'products_services': form.products_services.data or '',
                        'phone_number': form.phone.data or ''
                    }
                db.users.update_one(user_query, {'$set': update_data})
                flash(trans('general_profile_updated', default='Profile updated successfully'), 'success')
                logger.info(f"Profile updated for user: {user_id}")
                return redirect(url_for('settings.profile'))
            except Exception as e:
                logger.error(f"Error updating profile for user {user_id}: {str(e)}")
                flash(trans('general_something_went_wrong', default='An error occurred'), 'danger')
        user_display = {
            '_id': str(user['_id']),
            'email': user.get('email', ''),
            'display_name': user.get('display_name', ''),
            'phone': user.get('phone', ''),
            'coin_balance': user.get('coin_balance', 0),
            'role': user.get('role', 'trader'),
            'language': user.get('language', 'en'),
            'dark_mode': user.get('dark_mode', False),
            'business_details': user.get('business_details', {}),
            'settings': user.get('settings', {}),
            'security_settings': user.get('security_settings', {}),
            'profile_picture': user.get('profile_picture', None)
        }
        # Fetch KYC status
        kyc_record = db.kyc_records.find_one({'user_id': str(user_id)})
        user_display['kyc_status'] = kyc_record['status'] if kyc_record else 'not_submitted'
        session['kyc_status'] = user_display['kyc_status']
        return render_template(
            'settings/profile.html',
            form=form,
            user=user_display,
            title=trans('settings_profile_title', default='Profile Settings', lang=session.get('lang', 'en'))
        )
    except Exception as e:
        logger.error(f"Error in profile settings for user {current_user.id}: {str(e)}")
        flash(trans('general_something_went_wrong', default='An error occurred'), 'danger')
        return redirect(url_for('index'))

@settings_bp.route('/api/upload-profile-picture', methods=['POST'])
@login_required
def upload_profile_picture():
    """API endpoint to handle profile picture uploads."""
    try:
        db = get_mongo_db()
        fs = GridFS(db)
        user_query = get_user_query(str(current_user.id))
        user = db.users.find_one(user_query)
        if not user:
            return jsonify({"success": False, "message": trans('general_user_not_found', default='User not found.')}), 404

        if 'profile_picture' not in request.files:
            return jsonify({"success": False, "message": trans('general_no_file_uploaded', default='No file uploaded.')}), 400

        file = request.files['profile_picture']
        if file.filename == '':
            return jsonify({"success": False, "message": trans('general_no_file_selected', default='No file selected.')}), 400

        if file:
            # Validate file size (5MB limit)
            file.seek(0, 2)  # Move to end of file
            if file.tell() > 5 * 1024 * 1024:
                return jsonify({"success": False, "message": trans('settings_image_too_large', default='Image size must be less than 5MB.')}), 400
            file.seek(0)  # Reset file pointer

            # Validate file type using PIL
            try:
                file_content = file.read()
                img = Image.open(BytesIO(file_content))
                file_format = img.format.lower()
                if file_format not in ['jpeg', 'png', 'gif']:
                    return jsonify({"success": False, "message": trans('general_invalid_image_format', default='Only JPG, PNG, and GIF files are allowed.')}), 400
            except Exception as e:
                logger.error(f"Error validating image file: {str(e)}")
                return jsonify({"success": False, "message": trans('general_invalid_image_format', default='Only JPG, PNG, and GIF files are allowed.')}), 400

            # Delete existing profile picture if it exists
            if user.get('profile_picture'):
                fs.delete(ObjectId(user['profile_picture']))

            # Store new profile picture
            file_id = fs.put(file_content, filename=file.filename, content_type=file.content_type)
            db.users.update_one(user_query, {'$set': {
                'profile_picture': str(file_id),
                'updated_at': datetime.utcnow()
            }})

            return jsonify({
                "success": True,
                "message": trans('settings_profile_picture_updated', default='Profile picture updated successfully.'),
                "image_url": url_for('settings.get_profile_picture', user_id=user['_id'])
            })
    except Exception as e:
        logger.error(f"Error uploading profile picture for user {current_user.id}: {str(e)}")
        return jsonify({"success": False, "message": trans('general_something_went_wrong', default='An error occurred.')}), 500

@settings_bp.route('/profile-picture/<user_id>')
@login_required
def get_profile_picture(user_id):
    """Serve the user's profile picture."""
    try:
        db = get_mongo_db()
        fs = GridFS(db)
        user_query = get_user_query(user_id)
        user = db.users.find_one(user_query)
        if not user or not user.get('profile_picture'):
            return redirect(url_for('static', filename='img/default_profile.png'))
        
        file_id = ObjectId(user['profile_picture'])
        grid_out = fs.get(file_id)
        return send_file(BytesIO(grid_out.read()), mimetype=grid_out.content_type)
    except Exception as e:
        logger.error(f"Error retrieving profile picture for user {user_id}: {str(e)}")
        return redirect(url_for('static', filename='img/default_profile.png'))

@settings_bp.route('/api/update-user-setting', methods=['POST'])
@login_required
def update_user_setting():
    """API endpoint to update user settings via AJAX."""
    try:
        data = request.get_json()
        setting_name = data.get('setting')
        value = data.get('value')
        if setting_name not in ['showKoboToggle', 'incognitoModeToggle', 'appSoundsToggle', 
                               'fingerprintPasswordToggle', 'fingerprintPinToggle', 'hideSensitiveDataToggle']:
            return jsonify({"success": False, "message": trans('general_invalid_setting', default='Invalid setting name.')}), 400
        db = get_mongo_db()
        user_query = get_user_query(str(current_user.id))
        user = db.users.find_one(user_query)
        if not user:
            return jsonify({"success": False, "message": trans('general_user_not_found', default='User not found.')}), 404
        settings = user.get('settings', {})
        security_settings = user.get('security_settings', {})
        if setting_name == 'showKoboToggle':
            settings['show_kobo'] = value
        elif setting_name == 'incognitoModeToggle':
            settings['incognito_mode'] = value
        elif setting_name == 'appSoundsToggle':
            settings['app_sounds'] = value
        elif setting_name == 'fingerprintPasswordToggle':
            security_settings['fingerprint_password'] = value
        elif setting_name == 'fingerprintPinToggle':
            security_settings['fingerprint_pin'] = value
        elif setting_name == 'hideSensitiveDataToggle':
            security_settings['hide_sensitive_data'] = value
        update_data = {
            'settings': settings,
            'security_settings': security_settings,
            'updated_at': datetime.utcnow()
        }
        db.users.update_one(user_query, {'$set': update_data})
        return jsonify({"success": True, "message": trans('general_setting_updated', default='Setting updated successfully.')})
    except Exception as e:
        logger.error(f"Error updating user setting: {str(e)}")
        return jsonify({"success": False, "message": trans('general_setting_update_error', default='An error occurred while updating the setting.')}), 500
