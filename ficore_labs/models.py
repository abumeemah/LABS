from pymongo import MongoClient, ASCENDING, DESCENDING
from bson import ObjectId
from datetime import datetime, timedelta
import uuid
import logging
from werkzeug.security import generate_password_hash
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError, DuplicateKeyError, OperationFailure
from functools import lru_cache
import time
from translations import trans
from utils import get_mongo_db, logger

# Configure logger for the application
logger = logging.getLogger('business_app')
logger.setLevel(logging.INFO)

def get_db():
    """
    Get MongoDB database connection using the global client from utils.py.
    
    Returns:
        Database object
    """
    try:
        db = get_mongo_db()
        logger.info(f"Successfully connected to MongoDB database: {db.name}", extra={'session_id': 'no-session-id'})
        return db
    except Exception as e:
        logger.error(f"Error connecting to database: {str(e)}", exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def initialize_app_data(app):
    """
    Initialize MongoDB collections and indexes for business finance features.
    
    Args:
        app: Flask application instance
    """
    max_retries = 3
    retry_delay = 1
    
    with app.app_context():
        for attempt in range(max_retries):
            try:
                db = get_db()
                db.command('ping')
                logger.info(f"Attempt {attempt + 1}/{max_retries} - {trans('general_database_connection_established', default='MongoDB connection established')}", 
                           extra={'session_id': 'no-session-id'})
                break
            except Exception as e:
                logger.error(f"Failed to initialize database (attempt {attempt + 1}/{max_retries}): {str(e)}", 
                            exc_info=True, extra={'session_id': 'no-session-id'})
                if attempt == max_retries - 1:
                    raise RuntimeError(trans('general_database_connection_failed', default='MongoDB connection failed after max retries'))
                time.sleep(retry_delay)
        
        try:
            db_instance = get_db()
            logger.info(f"MongoDB database: {db_instance.name}", extra={'session_id': 'no-session-id'})
            collections = db_instance.list_collection_names()
            
            # Define collection schemas for business finance features
            collection_schemas = {
                'users': {
                    'validator': {
                        '$jsonSchema': {
                            'bsonType': 'object',
                            'required': ['_id', 'email', 'password_hash', 'role', 'is_trial', 'trial_start', 'trial_end', 'is_subscribed'],
                            'properties': {
                                '_id': {'bsonType': 'string'},
                                'email': {'bsonType': 'string', 'pattern': r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'},
                                'password_hash': {'bsonType': 'string'},
                                'role': {'enum': ['business', 'admin']},
                                'is_trial': {'bsonType': 'bool'},
                                'trial_start': {'bsonType': ['date', 'null']},
                                'trial_end': {'bsonType': ['date', 'null']},
                                'is_subscribed': {'bsonType': 'bool'},
                                'language': {'enum': ['en', 'ha']},
                                'created_at': {'bsonType': 'date'},
                                'display_name': {'bsonType': ['string', 'null']},
                                'is_admin': {'bsonType': 'bool'},
                                'setup_complete': {'bsonType': 'bool'},
                                'reset_token': {'bsonType': ['string', 'null']},
                                'reset_token_expiry': {'bsonType': ['date', 'null']},
                                'otp': {'bsonType': ['string', 'null']},
                                'otp_expiry': {'bsonType': ['date', 'null']},
                                'business_details': {
                                    'bsonType': ['object', 'null'],
                                    'properties': {
                                        'name': {'bsonType': 'string'},
                                        'address': {'bsonType': 'string'},
                                        'industry': {'bsonType': 'string'},
                                        'products_services': {'bsonType': 'string'},
                                        'phone_number': {'bsonType': 'string'}
                                    }
                                }
                            }
                        }
                    },
                    'indexes': [
                        {'key': [('email', ASCENDING)], 'unique': True},
                        {'key': [('reset_token', ASCENDING)], 'sparse': True},
                        {'key': [('role', ASCENDING)]}
                    ]
                },
                'records': {
                    'validator': {
                        '$jsonSchema': {
                            'bsonType': 'object',
                            'required': ['user_id', 'type'],
                            'properties': {
                                'user_id': {'bsonType': 'string'},
                                'type': {'enum': ['debtor', 'creditor', 'forecast', 'fund', 'investor_report']},
                                'name': {'bsonType': ['string', 'null']},
                                'contact': {'bsonType': ['string', 'null']},
                                'amount_owed': {'bsonType': ['number', 'null'], 'minimum': 0},
                                'description': {'bsonType': ['string', 'null']},
                                'reminder_count': {'bsonType': ['int', 'null'], 'minimum': 0},
                                'title': {'bsonType': ['string', 'null']},
                                'projected_revenue': {'bsonType': ['number', 'null'], 'minimum': 0},
                                'projected_expenses': {'bsonType': ['number', 'null'], 'minimum': 0},
                                'forecast_date': {'bsonType': ['date', 'null']},
                                'source': {'bsonType': ['string', 'null']},
                                'amount': {'bsonType': ['number', 'null'], 'minimum': 0},
                                'category': {'bsonType': ['string', 'null']},
                                'report_date': {'bsonType': ['date', 'null']},
                                'summary': {'bsonType': ['string', 'null']},
                                'financial_highlights': {'bsonType': ['string', 'null']},
                                'created_at': {'bsonType': 'date'},
                                'updated_at': {'bsonType': ['date', 'null']}
                            }
                        }
                    },
                    'indexes': [
                        {'key': [('user_id', ASCENDING), ('type', ASCENDING)]},
                        {'key': [('created_at', DESCENDING)]}
                    ]
                },
                'cashflows': {
                    'validator': {
                        '$jsonSchema': {
                            'bsonType': 'object',
                            'required': ['user_id', 'type', 'party_name', 'amount'],
                            'properties': {
                                'user_id': {'bsonType': 'string'},
                                'type': {'enum': ['receipt', 'payment']},
                                'party_name': {'bsonType': 'string'},
                                'amount': {'bsonType': 'number', 'minimum': 0},
                                'method': {'bsonType': ['string', 'null']},
                                'category': {'bsonType': ['string', 'null']},
                                'created_at': {'bsonType': 'date'},
                                'updated_at': {'bsonType': ['date', 'null']}
                            }
                        }
                    },
                    'indexes': [
                        {'key': [('user_id', ASCENDING), ('type', ASCENDING)]},
                        {'key': [('created_at', DESCENDING)]}
                    ]
                },
                'audit_logs': {
                    'validator': {
                        '$jsonSchema': {
                            'bsonType': 'object',
                            'required': ['admin_id', 'action', 'timestamp'],
                            'properties': {
                                'admin_id': {'bsonType': 'string'},
                                'action': {'bsonType': 'string'},
                                'details': {'bsonType': ['object', 'null']},
                                'timestamp': {'bsonType': 'date'}
                            }
                        }
                    },
                    'indexes': [
                        {'key': [('admin_id', ASCENDING)]},
                        {'key': [('timestamp', DESCENDING)]}
                    ]
                }
            }
                
            # Initialize collections and indexes
            for collection_name, config in collection_schemas.items():
                if collection_name in collections:
                    try:
                        db_instance.command('collMod', collection_name, validator=config.get('validator', {}))
                        logger.info(f"Updated validator for collection: {collection_name}", 
                                    extra={'session_id': 'no-session-id'})
                    except Exception as e:
                        logger.error(f"Failed to update validator for collection {collection_name}: {str(e)}", 
                                    exc_info=True, extra={'session_id': 'no-session-id'})
                        raise
                else:
                    try:
                        db_instance.create_collection(collection_name, validator=config.get('validator', {}))
                        logger.info(f"{trans('general_collection_created', default='Created collection')}: {collection_name}", 
                                   extra={'session_id': 'no-session-id'})
                    except Exception as e:
                        logger.error(f"Failed to create collection {collection_name}: {str(e)}", 
                                    exc_info=True, extra={'session_id': 'no-session-id'})
                        raise
                
                existing_indexes = db_instance[collection_name].index_information()
                for index in config.get('indexes', []):
                    keys = index['key']
                    options = {k: v for k, v in index.items() if k != 'key'}
                    index_key_tuple = tuple(keys)
                    index_name = '_'.join(f"{k}_{v if isinstance(v, int) else str(v).replace(' ', '_')}" for k, v in keys)
                    index_exists = False
                    for existing_index_name, existing_index_info in existing_indexes.items():
                        if tuple(existing_index_info['key']) == index_key_tuple:
                            existing_options = {k: v for k, v in existing_index_info.items() if k not in ['key', 'v', 'ns']}
                            if existing_options == options:
                                logger.info(f"{trans('general_index_exists', default='Index already exists on')} {collection_name}: {keys} with options {options}", 
                                           extra={'session_id': 'no-session-id'})
                                index_exists = True
                            else:
                                if existing_index_name == '_id_':
                                    logger.info(f"Skipping drop of _id index on {collection_name}", 
                                               extra={'session_id': 'no-session-id'})
                                    continue
                                try:
                                    db_instance[collection_name].drop_index(existing_index_name)
                                    logger.info(f"Dropped conflicting index {existing_index_name} on {collection_name}", 
                                               extra={'session_id': 'no-session-id'})
                                except Exception as e:
                                    logger.error(f"Failed to drop index {existing_index_name} on {collection_name}: {str(e)}", 
                                                exc_info=True, extra={'session_id': 'no-session-id'})
                                    raise
                            break
                    if not index_exists:
                        try:
                            db_instance[collection_name].create_index(keys, name=index_name, **options)
                            logger.info(f"{trans('general_index_created', default='Created index on')} {collection_name}: {keys} with options {options}", 
                                       extra={'session_id': 'no-session-id'})
                        except Exception as e:
                            if 'IndexKeySpecsConflict' in str(e):
                                logger.info(f"Attempting to resolve index conflict for {collection_name}: {index_name}", 
                                           extra={'session_id': 'no-session-id'})
                                if index_name != '_id_':
                                    db_instance[collection_name].drop_index(index_name)
                                    db_instance[collection_name].create_index(keys, name=index_name, **options)
                                    logger.info(f"Recreated index on {collection_name}: {keys} with options {options}", 
                                               extra={'session_id': 'no-session-id'})
                                else:
                                    logger.info(f"Skipping recreation of _id index on {collection_name}", 
                                               extra={'session_id': 'no-session-id'})
                            else:
                                logger.error(f"Failed to create index on {collection_name}: {str(e)}", 
                                            exc_info=True, extra={'session_id': 'no-session-id'})
                                raise
            
            # Fix existing user documents to include trial fields
            if 'users' in collections:
                try:
                    fix_flag = db_instance.system_config.find_one({'_id': 'user_fixes_applied'})
                    if fix_flag and fix_flag.get('value') is True:
                        logger.info("User fixes already applied, skipping.", extra={'session_id': 'no-session-id'})
                    else:
                        users_to_fix = db_instance.users.find({
                            '$or': [
                                {'password_hash': {'$exists': False}},
                                {'is_trial': {'$exists': False}},
                                {'trial_start': {'$exists': False}},
                                {'trial_end': {'$exists': False}},
                                {'is_subscribed': {'$exists': False}}
                            ]
                        })
                        for user in users_to_fix:
                            updates = {}
                            if 'password_hash' not in user:
                                temp_password = str(uuid.uuid4())
                                updates['password_hash'] = generate_password_hash(temp_password)
                                logger.info(
                                    f"Added password_hash for user {user['_id']}. Temporary password: {temp_password} (for admin use only)",
                                    extra={'session_id': 'no-session-id'}
                                )
                                try:
                                    db_instance.temp_passwords.update_one(
                                        {'user_id': str(user['_id'])},
                                        {
                                            '$set': {
                                                'temp_password': temp_password,
                                                'created_at': datetime.utcnow(),
                                                'expires_at': datetime.utcnow() + timedelta(days=7)
                                            },
                                            '$setOnInsert': {
                                                '_id': ObjectId(),
                                                'user_id': str(user['_id'])
                                            }
                                        },
                                        upsert=True
                                    )
                                    logger.info(
                                        f"Stored temporary password for user {user['_id']} in temp_passwords collection",
                                        extra={'session_id': 'no-session-id'}
                                    )
                                except Exception as e:
                                    logger.error(
                                        f"Failed to store temporary password for user {user['_id']}: {str(e)}",
                                        exc_info=True, extra={'session_id': 'no-session-id'}
                                    )
                                    raise
                            if 'is_trial' not in user:
                                updates['is_trial'] = True
                                updates['trial_start'] = datetime.utcnow()
                                updates['trial_end'] = datetime.utcnow() + timedelta(days=30)
                                updates['is_subscribed'] = False
                                logger.info(
                                    f"Initialized trial fields for user {user['_id']}",
                                    extra={'session_id': 'no-session-id'}
                                )
                            if updates:
                                db_instance.users.update_one(
                                    {'_id': user['_id']},
                                    {'$set': updates}
                                )
                        
                        db_instance.system_config.update_one(
                            {'_id': 'user_fixes_applied'},
                            {'$set': {'value': True}},
                            upsert=True
                        )
                        logger.info("Marked user fixes as applied in system_config", extra={'session_id': 'no-session-id'})
                except Exception as e:
                    logger.error(f"Failed to fix user documents: {str(e)}", 
                                exc_info=True, extra={'session_id': 'no-session-id'})
                    raise
        except Exception as e:
            logger.error(f"{trans('general_database_initialization_failed', default='Failed to initialize database')}: {str(e)}", 
                        exc_info=True, extra={'session_id': 'no-session-id'})
            raise

class User:
    def __init__(self, id, email, display_name=None, role='business', is_admin=False, setup_complete=False, 
                 is_trial=True, trial_start=None, trial_end=None, is_subscribed=False, language='en'):
        self.id = id
        self.email = email
        self.username = display_name or email.split('@')[0]
        self.role = role
        self.display_name = display_name or self.username
        self.is_admin = is_admin
        self.setup_complete = setup_complete
        self.is_trial = is_trial
        self.trial_start = trial_start or datetime.utcnow()
        self.trial_end = trial_end or (self.trial_start + timedelta(days=30))
        self.is_subscribed = is_subscribed
        self.language = language

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

    def get(self, key, default=None):
        return getattr(self, key, default)

    def has_access(self):
        """
        Check if user has access based on trial or subscription status.
        
        Returns:
            bool: True if user has access, False otherwise
        """
        if self.is_subscribed or self.is_admin:
            return True
        if self.is_trial and self.trial_end >= datetime.utcnow():
            return True
        return False

def create_user(db, user_data):
    """
    Create a new user in the users collection with trial fields.
    
    Args:
        db: MongoDB database instance
        user_data: Dictionary containing user information
    
    Returns:
        User: Created User object
    """
    try:
        user_id = user_data.get('username', user_data['email'].split('@')[0]).lower()
        if 'password' not in user_data:
            user_data['password'] = str(uuid.uuid4())
        user_data['password_hash'] = generate_password_hash(user_data['password'])
        
        trial_start = datetime.utcnow()
        user_doc = {
            '_id': user_id,
            'email': user_data['email'].lower(),
            'password_hash': user_data['password_hash'],
            'role': user_data.get('role', 'business'),
            'display_name': user_data.get('display_name', user_id),
            'is_admin': user_data.get('is_admin', False),
            'setup_complete': user_data.get('setup_complete', False),
            'is_trial': True,
            'trial_start': trial_start,
            'trial_end': trial_start + timedelta(days=30),
            'is_subscribed': False,
            'language': user_data.get('language', 'en'),
            'created_at': user_data.get('created_at', datetime.utcnow()),
            'business_details': user_data.get('business_details')
        }
        
        db.users.insert_one(user_doc)
        logger.info(f"Created user with ID: {user_id} with 30-day trial", 
                   extra={'session_id': 'no-session-id'})
        get_user.cache_clear()
        get_user_by_email.cache_clear()
        return User(
            id=user_doc['_id'],
            email=user_doc['email'],
            role=user_doc['role'],
            display_name=user_doc['display_name'],
            is_admin=user_doc['is_admin'],
            setup_complete=user_doc['setup_complete'],
            is_trial=user_doc['is_trial'],
            trial_start=user_doc['trial_start'],
            trial_end=user_doc['trial_end'],
            is_subscribed=user_doc['is_subscribed'],
            language=user_doc['language']
        )
    except Exception as e:
        logger.error(f"Error creating user: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise ValueError("User with this email or username already exists")

@lru_cache(maxsize=128)
def get_user_by_email(db, email):
    """
    Retrieve a user by email from the users collection.
    
    Args:
        db: MongoDB database instance
        email: Email address of the user
    
    Returns:
        User: User object or None if not found
    """
    try:
        user_doc = db.users.find_one({'email': email.lower()})
        if user_doc:
            return User(
                id=user_doc['_id'],
                email=user_doc['email'],
                role=user_doc.get('role', 'business'),
                display_name=user_doc.get('display_name'),
                is_admin=user_doc.get('is_admin', False),
                setup_complete=user_doc.get('setup_complete', False),
                is_trial=user_doc.get('is_trial', True),
                trial_start=user_doc.get('trial_start'),
                trial_end=user_doc.get('trial_end'),
                is_subscribed=user_doc.get('is_subscribed', False),
                language=user_doc.get('language', 'en')
            )
        return None
    except Exception as e:
        logger.error(f"{trans('general_user_fetch_error', default='Error getting user by email')} {email}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

@lru_cache(maxsize=128)
def get_user(db, user_id):
    """
    Retrieve a user by ID from the users collection.
    
    Args:
        db: MongoDB database instance
        user_id: ID of the user
    
    Returns:
        User: User object or None if not found
    """
    try:
        user_doc = db.users.find_one({'_id': user_id})
        if user_doc:
            return User(
                id=user_doc['_id'],
                email=user_doc['email'],
                role=user_doc.get('role', 'business'),
                display_name=user_doc.get('display_name'),
                is_admin=user_doc.get('is_admin', False),
                setup_complete=user_doc.get('setup_complete', False),
                is_trial=user_doc.get('is_trial', True),
                trial_start=user_doc.get('trial_start'),
                trial_end=user_doc.get('trial_end'),
                is_subscribed=user_doc.get('is_subscribed', False),
                language=user_doc.get('language', 'en')
            )
        return None
    except Exception as e:
        logger.error(f"{trans('general_user_fetch_error', default='Error getting user by ID')} {user_id}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def update_user(db, user_id, update_data):
    """
    Update a user in the users collection.
    
    Args:
        db: MongoDB database instance
        user_id: The ID of the user to update
        update_data: Dictionary containing fields to update
    
    Returns:
        bool: True if updated, False if not found or no changes made
    """
    try:
        if 'password' in update_data:
            update_data['password_hash'] = generate_password_hash(update_data.pop('password'))
        result = db.users.update_one(
            {'_id': user_id},
            {'$set': update_data}
        )
        if result.modified_count > 0:
            logger.info(f"{trans('general_user_updated', default='Updated user with ID')}: {user_id}", 
                       extra={'session_id': 'no-session-id'})
            get_user.cache_clear()
            get_user_by_email.cache_clear()
            return True
        logger.info(f"{trans('general_user_no_change', default='No changes made to user with ID')}: {user_id}", 
                   extra={'session_id': 'no-session-id'})
        return False
    except Exception as e:
        logger.error(f"{trans('general_user_update_error', default='Error updating user with ID')} {user_id}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def create_record(db, record_data):
    """
    Create a new record in the records collection (debtors, creditors, forecasts, funds, investor reports).
    
    Args:
        db: MongoDB database instance
        record_data: Dictionary containing record information
    
    Returns:
        str: ID of the created record
    """
    try:
        required_fields = ['user_id', 'type']
        if not all(field in record_data for field in required_fields):
            raise ValueError(trans('general_missing_record_fields', default='Missing required record fields'))
        result = db.records.insert_one(record_data)
        logger.info(f"{trans('general_record_created', default='Created record with ID')}: {result.inserted_id}", 
                   extra={'session_id': record_data.get('session_id', 'no-session-id')})
        return str(result.inserted_id)
    except Exception as e:
        logger.error(f"{trans('general_record_creation_error', default='Error creating record')}: {str(e)}", 
                    exc_info=True, extra={'session_id': record_data.get('session_id', 'no-session-id')})
        raise

def get_records(db, filter_kwargs):
    """
    Retrieve records based on filter criteria.
    
    Args:
        db: MongoDB database instance
        filter_kwargs: Dictionary of filter criteria
    
    Returns:
        list: List of records
    """
    try:
        return list(db.records.find(filter_kwargs).sort('created_at', DESCENDING))
    except Exception as e:
        logger.error(f"{trans('general_records_fetch_error', default='Error getting records')}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def update_record(db, record_id, update_data):
    """
    Update a record in the records collection.
    
    Args:
        db: MongoDB database instance
        record_id: The ID of the record to update
        update_data: Dictionary containing fields to update
    
    Returns:
        bool: True if updated, False if not found or no changes made
    """
    try:
        update_data['updated_at'] = datetime.utcnow()
        result = db.records.update_one(
            {'_id': ObjectId(record_id)},
            {'$set': update_data}
        )
        if result.modified_count > 0:
            logger.info(f"{trans('general_record_updated', default='Updated record with ID')}: {record_id}", 
                       extra={'session_id': 'no-session-id'})
            return True
        logger.info(f"{trans('general_record_no_change', default='No changes made to record with ID')}: {record_id}", 
                   extra={'session_id': 'no-session-id'})
        return False
    except Exception as e:
        logger.error(f"{trans('general_record_update_error', default='Error updating record with ID')} {record_id}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def create_cashflow(db, cashflow_data):
    """
    Create a new cashflow record in the cashflows collection.
    
    Args:
        db: MongoDB database instance
        cashflow_data: Dictionary containing cashflow information
    
    Returns:
        str: ID of the created cashflow record
    """
    try:
        required_fields = ['user_id', 'type', 'party_name', 'amount']
        if not all(field in cashflow_data for field in required_fields):
            raise ValueError(trans('general_missing_cashflow_fields', default='Missing required cashflow fields'))
        result = db.cashflows.insert_one(cashflow_data)
        logger.info(f"{trans('general_cashflow_created', default='Created cashflow record with ID')}: {result.inserted_id}", 
                   extra={'session_id': cashflow_data.get('session_id', 'no-session-id')})
        return str(result.inserted_id)
    except Exception as e:
        logger.error(f"{trans('general_cashflow_creation_error', default='Error creating cashflow record')}: {str(e)}", 
                    exc_info=True, extra={'session_id': cashflow_data.get('session_id', 'no-session-id')})
        raise

def get_cashflows(db, filter_kwargs):
    """
    Retrieve cashflow records based on filter criteria.
    
    Args:
        db: MongoDB database instance
        filter_kwargs: Dictionary of filter criteria
    
    Returns:
        list: List of cashflow records
    """
    try:
        return list(db.cashflows.find(filter_kwargs).sort('created_at', DESCENDING))
    except Exception as e:
        logger.error(f"{trans('general_cashflows_fetch_error', default='Error getting cashflows')}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def update_cashflow(db, cashflow_id, update_data):
    """
    Update a cashflow record in the cashflows collection.
    
    Args:
        db: MongoDB database instance
        cashflow_id: The ID of the cashflow record to update
        update_data: Dictionary containing fields to update
    
    Returns:
        bool: True if updated, False if not found or no changes made
    """
    try:
        update_data['updated_at'] = datetime.utcnow()
        result = db.cashflows.update_one(
            {'_id': ObjectId(cashflow_id)},
            {'$set': update_data}
        )
        if result.modified_count > 0:
            logger.info(f"{trans('general_cashflow_updated', default='Updated cashflow record with ID')}: {cashflow_id}", 
                       extra={'session_id': 'no-session-id'})
            return True
        logger.info(f"{trans('general_cashflow_no_change', default='No changes made to cashflow record with ID')}: {cashflow_id}", 
                   extra={'session_id': 'no-session-id'})
        return False
    except Exception as e:
        logger.error(f"{trans('general_cashflow_update_error', default='Error updating cashflow record with ID')} {cashflow_id}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def create_audit_log(db, audit_data):
    """
    Create a new audit log in the audit_logs collection.
    
    Args:
        db: MongoDB database instance
        audit_data: Dictionary containing audit log information
    
    Returns:
        str: ID of the created audit log
    """
    try:
        required_fields = ['admin_id', 'action', 'timestamp']
        if not all(field in audit_data for field in required_fields):
            raise ValueError(trans('general_missing_audit_fields', default='Missing required audit log fields'))
        result = db.audit_logs.insert_one(audit_data)
        logger.info(f"{trans('general_audit_log_created', default='Created audit log with ID')}: {result.inserted_id}", 
                   extra={'session_id': audit_data.get('session_id', 'no-session-id')})
        return str(result.inserted_id)
    except Exception as e:
        logger.error(f"{trans('general_audit_log_creation_error', default='Error creating audit log')}: {str(e)}", 
                    exc_info=True, extra={'session_id': audit_data.get('session_id', 'no-session-id')})
        raise

def get_audit_logs(db, filter_kwargs):
    """
    Retrieve audit log records based on filter criteria.
    
    Args:
        db: MongoDB database instance
        filter_kwargs: Dictionary of filter criteria
    
    Returns:
        list: List of audit log records
    """
    try:
        return list(db.audit_logs.find(filter_kwargs).sort('timestamp', DESCENDING))
    except Exception as e:
        logger.error(f"{trans('general_audit_logs_fetch_error', default='Error getting audit logs')}: {str(e)}", 
                    exc_info=True, extra={'session_id': 'no-session-id'})
        raise

def to_dict_user(user):
    """Convert user object to dictionary."""
    if not user:
        return {'id': None, 'email': None}
    return {
        'id': user.id,
        'email': user.email,
        'username': user.username,
        'role': user.role,
        'display_name': user.display_name,
        'is_admin': user.is_admin,
        'setup_complete': user.setup_complete,
        'is_trial': user.is_trial,
        'trial_start': user.trial_start,
        'trial_end': user.trial_end,
        'is_subscribed': user.is_subscribed,
        'language': user.language
    }

def to_dict_record(record):
    """Convert record to dictionary."""
    if not record:
        return {'type': None}
    return {
        'id': str(record.get('_id', '')),
        'user_id': record.get('user_id', ''),
        'type': record.get('type', ''),
        'name': record.get('name', ''),
        'contact': record.get('contact', ''),
        'amount_owed': record.get('amount_owed', 0),
        'description': record.get('description', ''),
        'reminder_count': record.get('reminder_count', 0),
        'title': record.get('title', ''),
        'projected_revenue': record.get('projected_revenue', 0),
        'projected_expenses': record.get('projected_expenses', 0),
        'forecast_date': record.get('forecast_date'),
        'source': record.get('source', ''),
        'amount': record.get('amount', 0),
        'category': record.get('category', ''),
        'report_date': record.get('report_date'),
        'summary': record.get('summary', ''),
        'financial_highlights': record.get('financial_highlights', ''),
        'created_at': record.get('created_at'),
        'updated_at': record.get('updated_at')
    }

def to_dict_cashflow(record):
    """Convert cashflow record to dictionary."""
    if not record:
        return {'party_name': None, 'amount': None}
    return {
        'id': str(record.get('_id', '')),
        'user_id': record.get('user_id', ''),
        'type': record.get('type', ''),
        'party_name': record.get('party_name', ''),
        'amount': record.get('amount', 0),
        'method': record.get('method', ''),
        'category': record.get('category', ''),
        'created_at': record.get('created_at'),
        'updated_at': record.get('updated_at')
    }

def to_dict_audit_log(record):
    """Convert audit log record to dictionary."""
    if not record:
        return {'action': None, 'timestamp': None}
    return {
        'id': str(record.get('_id', '')),
        'admin_id': record.get('admin_id', ''),
        'action': record.get('action', ''),
        'details': record.get('details', {}),
        'timestamp': record.get('timestamp')
    }
