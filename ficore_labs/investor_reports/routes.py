from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, Response, session
from flask_login import login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField, DateField
from wtforms.validators import DataRequired, Optional
from bson import ObjectId
from datetime import datetime
import logging
import io
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch
from helpers.branding_helpers import draw_ficore_pdf_header, ficore_csv_header
import csv
import utils
from translations import trans

logger = logging.getLogger(__name__)

class InvestorReportForm(FlaskForm):
    title = StringField(trans('investor_reports_title', default='Report Title'), validators=[DataRequired()])
    report_date = DateField(trans('investor_reports_date', default='Report Date'), validators=[DataRequired()])
    summary = TextAreaField(trans('investor_reports_summary', default='Summary'), validators=[DataRequired()])
    financial_highlights = TextAreaField(trans('investor_reports_financial_highlights', default='Financial Highlights'), validators=[Optional()])
    submit = SubmitField(trans('investor_reports_add_report', default='Add Investor Report'))

investor_reports_bp = Blueprint('investor_reports', __name__, url_prefix='/investor_reports')

@investor_reports_bp.route('/')
@login_required
@utils.requires_role('startup')
def index():
    """List all investor reports for the current user."""
    try:
        db = utils.get_mongo_db()
        query = {'type': 'investor_report'} if utils.is_admin() else {'user_id': str(current_user.id), 'type': 'investor_report'}
        reports = list(db.records.find(query).sort('report_date', -1))
        
        return render_template(
            'investor_reports/index.html',
            reports=reports,
            title=trans('investor_reports_index', default='Investor Reports', lang=session.get('lang', 'en'))
        )
    except Exception as e:
        logger.error(f"Error fetching investor reports for user {current_user.id}: {str(e)}")
        flash(trans('investor_reports_fetch_error', default='An error occurred'), 'danger')
        return redirect(url_for('dashboard.index'))

@investor_reports_bp.route('/manage')
@login_required
@utils.requires_role('startup')
def manage():
    """List all investor reports for management (edit/delete) by the current user."""
    try:
        db = utils.get_mongo_db()
        query = {'type': 'investor_report'} if utils.is_admin() else {'user_id': str(current_user.id), 'type': 'investor_report'}
        reports = list(db.records.find(query).sort('report_date', -1))
        
        return render_template(
            'investor_reports/manage_reports.html',
            reports=reports,
            title=trans('investor_reports_manage', default='Manage Investor Reports', lang=session.get('lang', 'en'))
        )
    except Exception as e:
        logger.error(f"Error fetching investor reports for manage page for user {current_user.id}: {str(e)}")
        flash(trans('investor_reports_fetch_error', default='An error occurred'), 'danger')
        return redirect(url_for('investor_reports.index'))

@investor_reports_bp.route('/view/<id>')
@login_required
@utils.requires_role('startup')
def view(id):
    """View detailed information about a specific investor report (JSON API)."""
    try:
        db = utils.get_mongo_db()
        query = {'_id': ObjectId(id), 'type': 'investor_report'} if utils.is_admin() else {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'investor_report'}
        report = db.records.find_one(query)
        if not report:
            return jsonify({'error': trans('investor_reports_record_not_found', default='Record not found')}), 404
        
        report['_id'] = str(report['_id'])
        report['report_date'] = report['report_date'].isoformat() if report.get('report_date') else None
        report['created_at'] = report['created_at'].isoformat() if report.get('created_at') else None
        
        return jsonify(report)
    except Exception as e:
        logger.error(f"Error fetching investor report {id} for user {current_user.id}: {str(e)}")
        return jsonify({'error': trans('investor_reports_fetch_error', default='An error occurred')}), 500

@investor_reports_bp.route('/view_page/<id>')
@login_required
@utils.requires_role('startup')
def view_page(id):
    """Render a detailed view page for a specific investor report."""
    try:
        db = utils.get_mongo_db()
        query = {'_id': ObjectId(id), 'type': 'investor_report'} if utils.is_admin() else {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'investor_report'}
        report = db.records.find_one(query)
        if not report:
            flash(trans('investor_reports_record_not_found', default='Record not found'), 'danger')
            return redirect(url_for('investor_reports.index'))
        
        return render_template(
            'investor_reports/view.html',
            report=report,
            title=trans('investor_reports_details', default='Investor Report Details', lang=session.get('lang', 'en'))
        )
    except Exception as e:
        logger.error(f"Error rendering investor report view page {id} for user {current_user.id}: {str(e)}")
        flash(trans('investor_reports_view_error', default='An error occurred'), 'danger')
        return redirect(url_for('investor_reports.index'))

@investor_reports_bp.route('/generate_report/<id>')
@login_required
@utils.requires_role('startup')
def generate_report(id):
    """Generate PDF report for an investor report."""
    try:
        db = utils.get_mongo_db()
        query = {'_id': ObjectId(id), 'type': 'investor_report'} if utils.is_admin() else {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'investor_report'}
        report = db.records.find_one(query)
        
        if not report:
            flash(trans('investor_reports_record_not_found', default='Record not found'), 'danger')
            return redirect(url_for('investor_reports.index'))
        
        if not utils.is_admin() and not utils.check_ficore_credit_balance(1):
            flash(trans('investor_reports_insufficient_credits', default='Insufficient Ficore Credits to generate report'), 'danger')
            return redirect(url_for('agents_bp.manage_credits'))
        
        buffer = io.BytesIO()
        p = canvas.Canvas(buffer, pagesize=letter)
        draw_ficore_pdf_header(p, current_user, y_start=10.5)
        
        header_height = 0.7
        extra_space = 0.2
        title_y = 10.5 - header_height - extra_space
        
        p.setFont("Helvetica-Bold", 24)
        p.drawString(inch, title_y * inch, trans('investor_reports_report_title', default='FiCore Records - Investor Report'))
        
        p.setFont("Helvetica", 12)
        y_position = title_y - 0.5
        p.drawString(inch, y_position * inch, f"{trans('investor_reports_title', default='Title')}: {report['title']}")
        y_position -= 0.3
        p.drawString(inch, y_position * inch, f"{trans('investor_reports_date', default='Report Date')}: {utils.format_date(report['report_date'])}")
        y_position -= 0.3
        p.drawString(inch, y_position * inch, f"{trans('investor_reports_summary', default='Summary')}: {report['summary']}")
        y_position -= 0.3
        p.drawString(inch, y_position * inch, f"{trans('investor_reports_financial_highlights', default='Financial Highlights')}: {report.get('financial_highlights', 'No highlights provided')}")
        y_position -= 0.3
        p.drawString(inch, y_position * inch, f"{trans('investor_reports_date_recorded', default='Date Recorded')}: {utils.format_date(report['created_at'])}")
        
        p.setFont("Helvetica-Oblique", 10)
        p.drawString(inch, inch, trans('investor_reports_report_footer', default='This document serves as an investor report recorded on FiCore Records.'))
        
        p.showPage()
        p.save()
        
        if not utils.is_admin():
            user_query = utils.get_user_query(str(current_user.id))
            db.users.update_one(user_query, {'$inc': {'ficore_credit_balance': -1}})
            db.ficore_credit_transactions.insert_one({
                'user_id': str(current_user.id),
                'amount': -1,
                'type': 'spend',
                'date': datetime.utcnow(),
                'ref': f"Investor report generated for {report['title']}"
            })
        
        buffer.seek(0)
        return Response(
            buffer.getvalue(),
            mimetype='application/pdf',
            headers={
                'Content-Disposition': f'attachment; filename=FiCore_Investor_Report_{report["title"]}.pdf'
            }
        )
        
    except Exception as e:
        logger.error(f"Error generating investor report {id}: {str(e)}")
        flash(trans('investor_reports_report_generation_error', default='An error occurred'), 'danger')
        return redirect(url_for('investor_reports.index'))

@investor_reports_bp.route('/generate_report_csv/<id>')
@login_required
@utils.requires_role('startup')
def generate_report_csv(id):
    """Generate CSV report for an investor report."""
    try:
        db = utils.get_mongo_db()
        query = {'_id': ObjectId(id), 'type': 'investor_report'} if utils.is_admin() else {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'investor_report'}
        report = db.records.find_one(query)
        
        if not report:
            flash(trans('investor_reports_record_not_found', default='Record not found'), 'danger')
            return redirect(url_for('investor_reports.index'))
        
        if not utils.is_admin() and not utils.check_ficore_credit_balance(1):
            flash(trans('investor_reports_insufficient_credits', default='Insufficient Ficore Credits to generate report'), 'danger')
            return redirect(url_for('agents_bp.manage_credits'))
        
        output = []
        output.extend(ficore_csv_header(current_user))
        output.append([trans('investor_reports_report_title', default='FiCore Records - Investor Report')])
        output.append([''])
        output.append([trans('investor_reports_title', default='Title'), report['title']])
        output.append([trans('investor_reports_date', default='Report Date'), utils.format_date(report['report_date'])])
        output.append([trans('investor_reports_summary', default='Summary'), report['summary']])
        output.append([trans('investor_reports_financial_highlights', default='Financial Highlights'), report.get('financial_highlights', 'No highlights provided')])
        output.append([trans('investor_reports_date_recorded', default='Date Recorded'), utils.format_date(report['created_at'])])
        output.append([''])
        output.append([trans('investor_reports_report_footer', default='This document serves as an investor report recorded on FiCore Records.')])
        
        if not utils.is_admin():
            user_query = utils.get_user_query(str(current_user.id))
            db.users.update_one(user_query, {'$inc': {'ficore_credit_balance': -1}})
            db.ficore_credit_transactions.insert_one({
                'user_id': str(current_user.id),
                'amount': -1,
                'type': 'spend',
                'date': datetime.utcnow(),
                'ref': f"Investor report CSV generated for {report['title']}"
            })
        
        buffer = io.BytesIO()
        writer = csv.writer(buffer, lineterminator='\n')
        writer.writerows(output)
        buffer.seek(0)
        
        return Response(
            buffer,
            mimetype='text/csv',
            headers={
                'Content-Disposition': f'attachment; filename=FiCore_Investor_Report_{report["title"]}.csv'
            }
        )
        
    except Exception as e:
        logger.error(f"Error generating investor report CSV {id}: {str(e)}")
        flash(trans('investor_reports_report_generation_error', default='An error occurred'), 'danger')
        return redirect(url_for('investor_reports.index'))

@investor_reports_bp.route('/add', methods=['GET', 'POST'])
@login_required
@utils.requires_role('startup')
def add():
    """Add a new investor report."""
    form = InvestorReportForm()
    if not utils.is_admin() and not utils.check_ficore_credit_balance(1):
        flash(trans('investor_reports_insufficient_credits', default='Insufficient Ficore Credits to add report'), 'danger')
        return redirect(url_for('agents_bp.manage_credits'))

    if form.validate_on_submit():
        try:
            db = utils.get_mongo_db()
            report_data = {
                'user_id': str(current_user.id),
                'type': 'investor_report',
                'title': form.title.data,
                'report_date': form.report_date.data,
                'summary': form.summary.data,
                'financial_highlights': form.financial_highlights.data,
                'created_at': datetime.utcnow()
            }
            db.records.insert_one(report_data)
            
            if not utils.is_admin():
                user_query = utils.get_user_query(str(current_user.id))
                db.users.update_one(user_query, {'$inc': {'ficore_credit_balance': -1}})
                db.ficore_credit_transactions.insert_one({
                    'user_id': str(current_user.id),
                    'amount': -1,
                    'type': 'spend',
                    'date': datetime.utcnow(),
                    'ref': f"Investor report added: {form.title.data}"
                })
            
            flash(trans('investor_reports_add_success', default='Investor report added successfully'), 'success')
            return redirect(url_for('investor_reports.index'))
        except Exception as e:
            logger.error(f"Error adding investor report for user {current_user.id}: {str(e)}")
            flash(trans('investor_reports_add_error', default='An error occurred while adding report'), 'danger')

    return render_template(
        'investor_reports/add.html',
        form=form,
        title=trans('investor_reports_add_report', default='Add Investor Report', lang=session.get('lang', 'en'))
    )

@investor_reports_bp.route('/edit/<id>', methods=['GET', 'POST'])
@login_required
@utils.requires_role('startup')
def edit(id):
    """Edit an existing investor report."""
    try:
        db = utils.get_mongo_db()
        query = {'_id': ObjectId(id), 'type': 'investor_report'} if utils.is_admin() else {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'investor_report'}
        report = db.records.find_one(query)
        
        if not report:
            flash(trans('investor_reports_record_not_found', default='Record not found'), 'danger')
            return redirect(url_for('investor_reports.index'))

        form = InvestorReportForm(data={
            'title': report['title'],
            'report_date': report['report_date'],
            'summary': report['summary'],
            'financial_highlights': report.get('financial_highlights', '')
        })

        if form.validate_on_submit():
            try:
                updated_record = {
                    'title': form.title.data,
                    'report_date': form.report_date.data,
                    'summary': form.summary.data,
                    'financial_highlights': form.financial_highlights.data,
                    'updated_at': datetime.utcnow()
                }
                db.records.update_one(
                    {'_id': ObjectId(id)},
                    {'$set': updated_record}
                )
                flash(trans('investor_reports_edit_success', default='Investor report updated successfully'), 'success')
                return redirect(url_for('investor_reports.index'))
            except Exception as e:
                logger.error(f"Error updating investor report {id} for user {current_user.id}: {str(e)}")
                flash(trans('investor_reports_edit_error', default='An error occurred'), 'danger')

        return render_template(
            'investor_reports/edit.html',
            form=form,
            report=report,
            title=trans('investor_reports_edit_report', default='Edit Investor Report', lang=session.get('lang', 'en'))
        )
    except Exception as e:
        logger.error(f"Error fetching investor report {id} for user {current_user.id}: {str(e)}")
        flash(trans('investor_reports_record_not_found', default='Record not found'), 'danger')
        return redirect(url_for('investor_reports.index'))

@investor_reports_bp.route('/delete/<id>', methods=['POST'])
@login_required
@utils.requires_role('startup')
def delete(id):
    """Delete an investor report."""
    try:
        db = utils.get_mongo_db()
        query = {'_id': ObjectId(id), 'type': 'investor_report'} if utils.is_admin() else {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'investor_report'}
        result = db.records.delete_one(query)
        if result.deleted_count:
            flash(trans('investor_reports_delete_success', default='Investor report deleted successfully'), 'success')
        else:
            flash(trans('investor_reports_record_not_found', default='Record not found'), 'danger')
    except Exception as e:
        logger.error(f"Error deleting investor report {id} for user {current_user.id}: {str(e)}")
        flash(trans('investor_reports_delete_error', default='An error occurred'), 'danger')
    return redirect(url_for('investor_reports.index'))
