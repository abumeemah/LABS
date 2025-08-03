from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, FileField, SubmitField
from wtforms.validators import DataRequired
from werkzeug.utils import secure_filename
from datetime import datetime
from bson import ObjectId
from functools import wraps
import os
from utils import get_mongo_db

kyc_bp = Blueprint('kyc', __name__, url_prefix='/kyc')

# Form for KYC submission
class KYCForm(FlaskForm):
    full_name = StringField('Full Name', validators=[DataRequired()])
    id_type = SelectField('ID Type', choices=[('NIN', 'NIN'), ('Voters Card', 'Voter’s Card'), ('Passport', 'Passport')], validators=[DataRequired()])
    id_number = StringField('ID Number', validators=[DataRequired()])
    id_photo = FileField('ID Photo', validators=[DataRequired()])
    submit = SubmitField('Submit')

# Admin-only decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

@kyc_bp.route('/submit', methods=['GET', 'POST'])
@login_required
def submit():
    form = KYCForm()
    if form.validate_on_submit():
        # Handle file upload
        file = form.id_photo.data
        filename = secure_filename(file.filename)
        file_path = os.path.join('uploads', filename)
        file.save(file_path)
        
        # Save KYC record
        kyc_record = {
            'user_id': str(current_user.id),
            'full_name': form.full_name.data,
            'id_type': form.id_type.data,
            'id_number': form.id_number.data,
            'uploaded_id_photo_url': file_path,
            'status': 'pending',
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }
        db = get_mongo_db()
        db.kyc_records.insert_one(kyc_record)
        
        # Update session with KYC status
        session['kyc_status'] = 'pending'
        
        flash('KYC submitted successfully!', 'success')
        return redirect(url_for('kyc.status'))
    return render_template('kyc/submit.html', form=form)

@kyc_bp.route('/status')
@login_required
def status():
    db = get_mongo_db()
    kyc_record = db.kyc_records.find_one({'user_id': str(current_user.id)})
    if kyc_record:
        status = kyc_record['status']
        session['kyc_status'] = status  # Update session cache
        if status == 'rejected':
            return render_template('kyc/status.html', status=status, allow_resubmit=True)
        return render_template('kyc/status.html', status=status)
    else:
        session['kyc_status'] = 'not_submitted'
        flash('No KYC record found. Please submit your KYC information.', 'warning')
        return redirect(url_for('kyc.submit'))

@kyc_bp.route('/admin')
@login_required
@admin_required
def admin():
    db = get_mongo_db()
    kyc_records = db.kyc_records.find()
    return render_template('kyc/admin.html', kyc_records=kyc_records)

@kyc_bp.route('/admin/approve/<kyc_id>', methods=['POST'])
@login_required
@admin_required
def approve(kyc_id):
    db = get_mongo_db()
    db.kyc_records.update_one({'_id': ObjectId(kyc_id)}, {'$set': {'status': 'approved', 'updated_at': datetime.utcnow()}})
    flash('KYC approved successfully!', 'success')
    return redirect(url_for('kyc.admin'))

@kyc_bp.route('/admin/reject/<kyc_id>', methods=['POST'])
@login_required
@admin_required
def reject(kyc_id):
    db = get_mongo_db()
    db.kyc_records.update_one({'_id': ObjectId(kyc_id)}, {'$set': {'status': 'rejected', 'updated_at': datetime.utcnow()}})
    flash('KYC rejected successfully!', 'success')
    return redirect(url_for('kyc.admin'))