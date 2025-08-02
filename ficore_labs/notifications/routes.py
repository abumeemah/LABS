from flask import Blueprint, jsonify
from flask_login import current_user, login_required
from utils import get_mongo_db, logger, trans
from flask import request, session

notifications = Blueprint('notifications', __name__, url_prefix='/notifications')

@notifications.route('/count', methods=['GET'])
@login_required
def count():
    """Fetch the count of unread notifications for the authenticated user."""
    try:
        db = get_mongo_db()
        user_id = current_user.id
        
        # Query the notifications collection for unread notifications
        unread_count = db.notifications.count_documents({
            'user_id': user_id,
            'read': False
        })
        
        logger.info(
            f"Fetched notification count for user {user_id}: {unread_count}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr}
        )
        
        return jsonify({'count': unread_count})
    except Exception as e:
        logger.error(
            f"Error fetching notification count for user {user_id}: {str(e)}",
            extra={'session_id': session.get('sid', 'no-session-id'), 'ip_address': request.remote_addr}
        )
        return jsonify({'error': trans('notification_count_error', lang=session.get('lang', 'en'))}), 500