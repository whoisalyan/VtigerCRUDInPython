from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Text, Date, DateTime, func, DECIMAL, BigInteger, TIMESTAMP
from sqlalchemy import text
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from datetime import datetime, timedelta, date
from typing import Dict, Any, Optional
from zoneinfo import ZoneInfo
import re
import time
from collections import defaultdict
import json
import hashlib
import hmac
import bcrypt
import os
from utils.local_cache import json_hgetall, json_hget, json_hset, json_delete, json_set, json_get
import redis
import traceback
from urllib.parse import urlparse, urlunparse



r = redis.Redis(decode_responses=True)

# Custom JSON serializer for datetime objects
def datetime_serializer(obj):
    """JSON serializer for datetime and date objects"""
    if isinstance(obj, datetime):
        return obj.strftime('%Y-%m-%d %H:%M:%S')
    elif isinstance(obj, date):
        return obj.strftime('%Y-%m-%d')
    raise TypeError(f"Object {obj} of type {type(obj)} is not JSON serializable")

def get_monday(date_str):
    """
    Given a date string 'YYYY-MM-DD', return the Monday of that week.
    """
    # Accept either a string 'YYYY-MM-DD' or a date/datetime object
    if isinstance(date_str, (date, datetime)):
        date_obj = date_str if isinstance(date_str, datetime) else datetime.combine(date_str, datetime.min.time())
    elif isinstance(date_str, str):
        date_obj = datetime.strptime(date_str, "%Y-%m-%d")
    else:
        raise ValueError("get_monday expects a date string or date/datetime object")

    monday = date_obj - timedelta(days=date_obj.weekday())  # weekday() -> 0 for Monday
    # Return ISO-formatted date string for consistency across callers
    return monday.date().isoformat()


def extract_base_url(url: str) -> str:
    """
    Extracts the base URL keeping the scheme (http/https) and domain (including www if present),
    removing paths, query parameters, and fragments.
    """
    parsed_url = urlparse(url)
    base_url = urlunparse((parsed_url.scheme, parsed_url.netloc, '', '', '', ''))
    return base_url


# Get MySQL connection details from environment variables
user =os.environ.get('MYSQL_USER', '')
password = os.environ.get('MYSQL_PASSWORD', 'B!')
host = os.environ.get('MYSQL_HOST', '')
port = os.environ.get('MYSQL_PORT', '')
database =os.environ.get('MYSQL_DATABASE', '')

# Construct database URL
dbUrl = f"mysql+pymysql://{user}:{password}@{host}:{port}/{database}"

# Create engine with connection pooling and timeouts
engine = create_engine(
    dbUrl,
    pool_size=10,
    max_overflow=20,
    pool_recycle=3600,
    pool_pre_ping=True,
    echo=False,
    connect_args={
        'connect_timeout': 30,
        'read_timeout': 120,
        'write_timeout': 120
    }
)
Session = sessionmaker(bind=engine)
Base = declarative_base()

class VtigerCrmentitySeq(Base):
    __tablename__ = 'vtiger_crmentity_seq'
    id = Column(Integer, primary_key=True)

class VtigerCrmentity(Base):
    __tablename__ = 'vtiger_crmentity'

    crmid = Column(Integer, primary_key=True)
    smcreatorid = Column(Integer, nullable=False, server_default='0')  
    smownerid = Column(Integer, nullable=False, server_default='0')    
    modifiedby = Column(Integer, nullable=False, server_default='0')   
    setype = Column(String(100), nullable=True)
    description = Column(String(64000), nullable=True)  
    createdtime = Column(DateTime, nullable=False)    
    modifiedtime = Column(DateTime, nullable=False)  
    viewedtime = Column(DateTime, nullable=True)  
    status = Column(String(50), nullable=True)
    version = Column(Integer, nullable=False, server_default='0')  
    presence = Column(Integer, nullable=True, server_default='1')  
    deleted = Column(Integer, nullable=False, server_default='0')  
    source = Column(String(100), nullable=True)
    label = Column(String(255), nullable=True)

class vtigerAccount(Base):
    __tablename__ = 'vtiger_account'  

    accountid = Column(Integer, ForeignKey("vtiger_crmentity.crmid"), primary_key=True)
    account_no = Column(String(100), nullable=False)
    accountname = Column(String(100), nullable=False)
    parentid = Column(Integer, nullable=True)
    account_type = Column(String(200), nullable=True)
    industry = Column(String(200), nullable=True)
    annualrevenue = Column(DECIMAL(25, 8), nullable=True)
    rating = Column(String(200), nullable=True)
    ownership = Column(String(50), nullable=True)
    siccode = Column(String(50), nullable=True)
    tickersymbol = Column(String(30), nullable=True)
    phone = Column(String(30), nullable=True)
    otherphone = Column(String(30), nullable=True)
    email1 = Column(String(100), nullable=True)
    email2 = Column(String(100), nullable=True)
    website = Column(String(100), nullable=True)
    fax = Column(String(30), nullable=True)
    employees = Column(Integer, nullable=True)
    emailoptout = Column(String(3), nullable=True)
    notify_owner = Column(String(3), nullable=True)
    isconvertedfromlead = Column(String(3), nullable=True)
    tags = Column(String(1), nullable=True)
    
    VtigerCrmentity = relationship("VtigerCrmentity", backref="vtigerAccount", uselist=False)
    
    
class VtigerAccountBillAddress(Base):
    __tablename__ = 'vtiger_accountbillads'

    accountaddressid = Column(Integer, ForeignKey("vtiger_crmentity.crmid"), primary_key=True, server_default='0')
    bill_city = Column(String(30), nullable=True)
    bill_code = Column(String(30), nullable=True)
    bill_country = Column(String(30), nullable=True)
    bill_state = Column(String(30), nullable=True)
    bill_street = Column(String(250), nullable=True)
    bill_pobox = Column(String(30), nullable=True)

    # Relationship to account (assuming accountaddressid is a foreign key to vtiger_account)
    account = relationship(
        "VtigerCrmentity", 
        foreign_keys=[accountaddressid],
        backref="addresses"
    )  
    
    
class VtigerAccountsCf(Base):
    __tablename__ = 'vtiger_accountscf'

    accountid = Column(
        Integer, 
        ForeignKey('vtiger_account.accountid'),  # References the account table
        primary_key=True,
        server_default='0'
    )
    cf_869 = Column(String(255), nullable=True, server_default='') #Domain Name
    cf_871 = Column(BigInteger, nullable=True)  #Organization ID
    cf_879 = Column(String(255), nullable=True, server_default='') #Linkedin
    cf_881 = Column(String(255), nullable=True, server_default='') #Facebook
    cf_883 = Column(String(255), nullable=True, server_default='') #Twitter/X
    cf_885 = Column(Date, nullable=True) #Founded on
    cf_887 = Column(String(255), nullable=True, server_default='')  #CrunchBase Link
    cf_889 = Column(Integer, nullable=True) #Funding Rounds
    cf_891 = Column(DECIMAL(23, 5), nullable=True)  #Last Funding Round Amounts
    cf_893 = Column(String(255), nullable=True, server_default='')  #Logo URL
    cf_895 = Column(String(255), nullable=True, server_default='')  #Annual Revenue Range
    cf_897 = Column(String(85), nullable=True, server_default='')  #FIPS Code
    cf_899 = Column(String(255), nullable=True, server_default='')  #Employee Range
    cf_901 = Column(String(55), nullable=True, server_default='')  #Partner Level
    cf_903 = Column(String(255), nullable=True, server_default='')  #Partner Name
    cf_905 = Column(String(55), nullable=True, server_default='')  #Partner Type
    cf_909 = Column(String(25), nullable=True, server_default='')  #Third Phone
    cf_911 = Column(String(25), nullable=True, server_default='')  #Forth Phone
    cf_913 = Column(String(25), nullable=True, server_default='') #Fifth Phone
    cf_915 = Column(String(25), nullable=True, server_default='') #Sixth Phone
    cf_917 = Column(String(25), nullable=True, server_default='') #Seventh Phone
    cf_919 = Column(String(25), nullable=True, server_default='') #Eight Phone
    cf_921 = Column(String(25), nullable=True, server_default='') #Nineth Phone
    cf_925 = Column(Date, nullable=True)  #Classification Date
    cf_933 = Column(String(3), nullable=False)  #is Active Customer
    cf_935 = Column(Date, nullable=True)  #First License Purchase Date
    cf_937 = Column(Date, nullable=True) #Become Ex Customer

    # Relationship to the main account table
    account = relationship("vtigerAccount", backref="custom_fields")
    
    
class VtigerAccountShipAddress(Base):
    __tablename__ = 'vtiger_accountshipads'

    accountaddressid = Column(Integer, ForeignKey("vtiger_crmentity.crmid"), primary_key=True, nullable=False, server_default="0")
    ship_city = Column(String(30))
    ship_code = Column(String(30))
    ship_country = Column(String(30))
    ship_state = Column(String(30))
    ship_pobox = Column(String(30))
    ship_street = Column(String(250))
    
    # Relationship to the main account table
    account = relationship("VtigerCrmentity", backref="Shipping_Address")
    
    
    
class VtigerContactDetails(Base):
    __tablename__ = 'vtiger_contactdetails'

    contactid = Column(Integer, ForeignKey("vtiger_crmentity.crmid"), primary_key=True)
    contact_no = Column(String(100), nullable=False, default=lambda: f"CON{int(time.time())}")  
    accountid = Column(Integer, ForeignKey('vtiger_account.accountid'), nullable=True)  # Uncommented FK
    salutation = Column(String(200), nullable=True)
    firstname = Column(String(40), nullable=True)  
    lastname = Column(String(80), nullable=False)
    email = Column(String(100), nullable=True)
    phone = Column(String(50), nullable=True)
    mobile = Column(String(50), nullable=True)
    title = Column(String(255), nullable=True)
    department = Column(String(30), nullable=True)
    fax = Column(String(50), nullable=True)
    reportsto = Column(String(30), nullable=True)
    training = Column(String(50), nullable=True)
    usertype = Column(String(50), nullable=True)  
    contacttype = Column(String(50), nullable=True)
    otheremail = Column(String(100), nullable=True)
    secondaryemail = Column(String(100), nullable=True)
    donotcall = Column(String(3), nullable=True)
    emailoptout = Column(String(3), nullable=True, server_default='0')  # Added default
    imagename = Column(String(150), nullable=True)
    reference = Column(String(3), nullable=True)
    notify_owner = Column(String(3), nullable=True, server_default='0')  # Added default
    isconvertedfromlead = Column(String(3), nullable=True, server_default='0')  # Added default
    tags = Column(String(1), nullable=True)
    
    VtigerCrmentity = relationship("VtigerCrmentity", backref="vtigerContactDetails", uselist=False)
    vtigerAccount = relationship("vtigerAccount", backref="vtigerContactDetails")
    
        
class VtigerContactAddress(Base):
    __tablename__ = 'vtiger_contactaddress'

    contactaddressid = Column(
        Integer, 
        ForeignKey("vtiger_contactdetails.contactid"), 
        primary_key=True,
        server_default='0'  # Added default value
    )
    mailingcity = Column(String(40), nullable=True)
    mailingstreet = Column(String(250), nullable=True)
    mailingcountry = Column(String(40), nullable=True)
    othercountry = Column(String(30), nullable=True)
    mailingstate = Column(String(30), nullable=True)
    mailingpobox = Column(String(30), nullable=True)
    othercity = Column(String(40), nullable=True)
    otherstate = Column(String(50), nullable=True)
    mailingzip = Column(String(30), nullable=True)
    otherzip = Column(String(30), nullable=True)
    otherstreet = Column(String(250), nullable=True)
    otherpobox = Column(String(30), nullable=True) 
    
    VtigerCrmentity = relationship("VtigerContactDetails", backref="vtigerContactAddress")
 
 
class VtigerContactSubDetails(Base):
    __tablename__ = 'vtiger_contactsubdetails'

    contactsubscriptionid = Column(
        Integer, 
        ForeignKey("vtiger_crmentity.crmid"), 
        primary_key=True,
        default=0  # Add default if needed
    )
    homephone = Column(String(50), nullable=True)  
    otherphone = Column(String(50), nullable=True)
    assistant = Column(String(30), nullable=True)
    assistantphone = Column(String(50), nullable=True)
    birthday = Column(Date, nullable=True)
    laststayintouchrequest = Column(Integer, nullable=True, default=0)
    laststayintouchsavedate = Column(Integer, nullable=True, default=0)
    leadsource = Column(String(200), nullable=True)
    
    VtigerCrmentity = relationship("VtigerCrmentity", backref="vtigerContactSubDetails")   
    
    
class VtigerContactsCf(Base):
    __tablename__ = 'vtiger_contactscf'  

    contactid = Column(
        Integer, 
        ForeignKey("vtiger_crmentity.crmid"), 
        primary_key=True,
        default=0  # Added default to match database
    )
    cf_853 = Column(String(255), nullable=True)  # Linkedin URL
    cf_855 = Column(String(20), nullable=True)   # Email Status
    cf_857 = Column(Text, nullable=True)         # Company Size
    cf_859 = Column(String(20), nullable=True)   # TimeZone
    cf_863 = Column(String(20), nullable=True)   # Incoming Source
    cf_867 = Column(String(20), nullable=True)   # Industry
    cf_875 = Column(String(255), nullable=True)  # Facebook
    cf_877 = Column(String(255), nullable=True)  # Twitter
    cf_907 = Column(String(255), nullable=True)  # Email Verification Status
    cf_923 = Column(Date, nullable=True)         # last Email Verification
    cf_927 = Column(String(3), nullable=False)  #is Active Customer  (Newer fields)
    cf_929 = Column(Date, nullable=True)  #First Licence Purchase Date
    cf_931 = Column(Date, nullable=True)  #When Become Ex Customer
    cf_939 = Column(Date, nullable=True)  #Last Email EMTP Check
    
    VtigerCrmentity = relationship("VtigerCrmentity", backref="vtigerContactsCf")   

class VtigerUsers(Base):
    __tablename__ = 'vtiger_users'
    
    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # User credentials and basic info
    user_name = Column(String(255), index=True)
    user_password = Column(String(200), index=True)
    cal_color = Column(String(25), default='#E6FAD8')
    first_name = Column(String(30))
    last_name = Column(String(30))
    reports_to_id = Column(String(36))
    is_admin = Column(String(3), default='0')
    currency_id = Column(Integer, nullable=False, default=1)
    description = Column(Text)
    
    # Timestamps
    date_entered = Column(TIMESTAMP, nullable=False, 
                         server_default='CURRENT_TIMESTAMP', 
                         onupdate='CURRENT_TIMESTAMP')
    date_modified = Column(DateTime)
    modified_user_id = Column(String(36))
    
    # Professional info
    title = Column(String(50))
    department = Column(String(50))
    
    # Contact information
    phone_home = Column(String(50))
    phone_mobile = Column(String(50))
    phone_work = Column(String(50))
    phone_other = Column(String(50))
    phone_fax = Column(String(50))
    email1 = Column(String(100))
    email2 = Column(String(100))
    secondaryemail = Column(String(100))
    
    # User status and preferences
    status = Column(String(25))
    signature = Column(Text)
    
    # Address
    address_street = Column(String(150))
    address_city = Column(String(100))
    address_state = Column(String(100))
    address_country = Column(String(25))
    address_postalcode = Column(String(9))
    
    # Preferences
    user_preferences = Column(Text)
    tz = Column(String(30))
    holidays = Column(String(60))
    namedays = Column(String(60))
    workdays = Column(String(30))
    weekstart = Column(Integer)
    date_format = Column(String(200))
    hour_format = Column(String(30), default='am/pm')
    start_hour = Column(String(30), default='10:00')
    end_hour = Column(String(30), default='23:00')
    
    # Permissions and roles
    is_owner = Column(String(100), default='0')
    activity_view = Column(String(200), default='Today')
    lead_view = Column(String(200), default='Today')
    
    # Profile and images
    imagename = Column(String(250))
    
    # System flags
    deleted = Column(Integer, nullable=False, default=0)
    confirm_password = Column(String(300))
    internal_mailer = Column(String(3), nullable=False, default='1')
    
    # Reminder settings
    reminder_interval = Column(String(100))
    reminder_next_time = Column(String(100))
    
    # Security and authentication
    crypt_type = Column(String(20), nullable=False, default='MD5')
    accesskey = Column(String(36))
    
    # UI and localization
    theme = Column(String(100))
    language = Column(String(36))
    time_zone = Column(String(200))
    
    # Currency formatting
    currency_grouping_pattern = Column(String(100))
    currency_decimal_separator = Column(String(2))
    currency_grouping_separator = Column(String(2))
    currency_symbol_placement = Column(String(20))
    
    # Labels and navigation
    userlabel = Column(String(255))
    defaultlandingpage = Column(String(200))
    
    # Phone system
    phone_crm_extension = Column(String(100))
    
    # Number formatting
    no_of_currency_decimals = Column(String(2))
    truncate_trailing_zeros = Column(String(3))
    
    # Calendar and scheduling preferences
    dayoftheweek = Column(String(100))
    callduration = Column(String(100))
    othereventduration = Column(String(100))
    calendarsharedtype = Column(String(100))
    default_record_view = Column(String(10))
    leftpanelhide = Column(String(3))
    rowheight = Column(String(10))
    defaulteventstatus = Column(String(50))
    defaultactivitytype = Column(String(50))
    hidecompletedevents = Column(Integer)
    defaultcalendarview = Column(String(100))


def get_user_by_username(username: str):
    """
    Get user information by username.
    Follows the same pattern as getContactbyID and getAccountbyID functions.
    
    Args:
        username: The username to look up
        
    Returns:
        dict: User information structured with field values,
              or None if user not found
    """
    with Session() as session:
        try:
            # Query using ORM, matching your existing pattern
            user = session.query(VtigerUsers).filter(
                VtigerUsers.user_name == username,
                VtigerUsers.deleted == 0
            ).first()
            
            if not user:
                return None
            
            # Convert datetime objects to string values
            date_entered_str = user.date_entered.strftime('%Y-%m-%d %H:%M:%S') if user.date_entered else None
            date_modified_str = user.date_modified.strftime('%Y-%m-%d %H:%M:%S') if user.date_modified else None
            
            # Structure the data according to your existing pattern
            user_dict = {
                'id': user.id,
                'user_name': user.user_name,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'user_password': user.user_password,
                'title': user.title,
                'email1': user.email1,
                'email2': user.email2,
                'secondaryemail': user.secondaryemail
                }
            
            
            return user_dict
            
        except Exception as e:
            print(f"Error querying database for username {username}: {str(e)}")
            import traceback
            print(f"Full traceback: {traceback.format_exc()}")
            return None

def authenticate_and_get_user(username: str, password: str, remember_session=False) -> Optional[Dict]:
    """
    Authenticate a vtiger user supporting PHASH (bcrypt) and MD5.
    Creates and stores session data in file storage.
    
    Args:
        username: The username to authenticate
        password: The password to verify
        remember_session: Whether to create a longer session (default: False)
    
    Returns:
        Dict containing user data and session_id if authentication successful,
        None otherwise
    """
    try:
        # Import session storage
        from utils.session_storage import session_storage
        import uuid
        
        user_data = get_user_by_username(username)
        if not user_data:
            return None

        stored_hash = user_data.get("user_password")
        if not stored_hash:
            return None

        stored_hash = stored_hash.strip()
        authenticated = False

        # --- Detect bcrypt automatically ---
        if stored_hash.startswith("$2y$") or stored_hash.startswith("$2b$") or stored_hash.startswith("$2a$"):
            try:
                authenticated = bcrypt.checkpw(
                    password.encode("utf-8"),
                    stored_hash.encode("utf-8")
                )
            except Exception:
                authenticated = False

        # --- Fallback: MD5 legacy vtiger ---
        else:
            computed_hash = hashlib.md5(password.encode("utf-8")).hexdigest().lower()
            authenticated = hmac.compare_digest(
                computed_hash,
                stored_hash.lower()
            )

        # Auth failed
        if not authenticated:
            return None

        # --- Create sanitized user data ---
        safe_user = user_data.copy()
        for field in ("user_password", "confirm_password", "accesskey"):
            safe_user.pop(field, None)
        
        # Add authentication timestamp
        safe_user['authenticated_at'] = datetime.now().isoformat()
        safe_user['ip_address'] = os.environ.get('REMOTE_ADDR', 'unknown')
        
        # --- Generate session ID ---
        session_id = str(uuid.uuid4())
        
        # --- Save session data ---
        expiry_hours = 720 if remember_session else 24  # 30 days for "remember me", 24 hours otherwise
        if session_storage.save_session(session_id, safe_user, expiry_hours):
            safe_user['session_id'] = session_id
            return safe_user
        
        return None

    except Exception:
        print(f"[Auth Error] {traceback.format_exc()}")
        return None


def authenticate_and_get_user_old(username: str, password: str) -> Optional[Dict]:
    """
    Authenticate a vtiger user supporting PHASH (bcrypt) and MD5.
    Compatible with the new get_user_by_username() return structure.
    """

    try:
        user_data = get_user_by_username(username)
        if not user_data:
            return None

        stored_hash = user_data.get("user_password")
        if not stored_hash:
            return None

        stored_hash = stored_hash.strip()
        authenticated = False

        # --- Detect bcrypt automatically ---
        if stored_hash.startswith("$2y$") or stored_hash.startswith("$2b$") or stored_hash.startswith("$2a$"):
            try:
                authenticated = bcrypt.checkpw(
                    password.encode("utf-8"),
                    stored_hash.encode("utf-8")
                )
            except Exception:
                authenticated = False

        # --- Fallback: MD5 legacy vtiger ---
        else:
            computed_hash = hashlib.md5(password.encode("utf-8")).hexdigest().lower()
            authenticated = hmac.compare_digest(
                computed_hash,
                stored_hash.lower()
            )

        # Auth failed
        if not authenticated:
            return None

        # --- Return sanitized user ---
        safe_user = user_data.copy()
        for field in ("user_password", "confirm_password", "accesskey"):
            safe_user.pop(field, None)

        return safe_user

    except Exception:
        print(f"[Auth Error] {traceback.format_exc()}")
        return None


        
def getAccountbyID(id: int):
    with Session() as session:
        # Query joining all related Account tables
        result = (session.query(VtigerCrmentity, vtigerAccount,
                            VtigerAccountBillAddress, VtigerAccountShipAddress,
                            VtigerAccountsCf)
                 .join(vtigerAccount, vtigerAccount.accountid == VtigerCrmentity.crmid)
                 .join(VtigerAccountBillAddress, VtigerAccountBillAddress.accountaddressid == VtigerCrmentity.crmid)
                 .join(VtigerAccountShipAddress, VtigerAccountShipAddress.accountaddressid == VtigerCrmentity.crmid)
                 .join(VtigerAccountsCf, VtigerAccountsCf.accountid == VtigerCrmentity.crmid)
                 .filter(VtigerCrmentity.crmid == id)
                 .first())
        
        if not result:
            return None
        
        # Unpack the result tuple
        crmentity, AccountDetail, AccountBillAddress, AccountShipAddress, AccountCF = result
        
        # Combine all data into a single dictionary
        Account_dict = {
            "crmentity": {a.name: getattr(crmentity, a.name) for a in crmentity.__table__.columns},
            "contact_details": {a.name: getattr(AccountDetail, a.name) for a in AccountDetail.__table__.columns},
            "contact_subdetails": {a.name: getattr(AccountBillAddress, a.name) for a in AccountBillAddress.__table__.columns},
            "contact_address": {a.name: getattr(AccountShipAddress, a.name) for a in AccountShipAddress.__table__.columns},
            "custom_fields": {a.name: getattr(AccountCF, a.name) for a in AccountCF.__table__.columns}
        }
        
        return Account_dict
        


def getContactbyID(id: int):
    with Session() as session:
        # Query joining all related contact tables
        result = (session.query(VtigerCrmentity, VtigerContactDetails,
                            VtigerContactSubDetails, VtigerContactAddress,
                            VtigerContactsCf)
                 .join(VtigerContactDetails, VtigerContactDetails.contactid == VtigerCrmentity.crmid)
                 .join(VtigerContactSubDetails, VtigerContactSubDetails.contactsubscriptionid == VtigerCrmentity.crmid)
                 .join(VtigerContactAddress, VtigerContactAddress.contactaddressid == VtigerCrmentity.crmid)
                 .join(VtigerContactsCf, VtigerContactsCf.contactid == VtigerCrmentity.crmid)
                 .filter(VtigerCrmentity.crmid == id)
                 .first())
        
        if not result:
            return None
        
        # Unpack the result tuple
        crmentity, contact_details, contact_subdetails, contact_address, contact_cf = result
        
        # Combine all data into a single dictionary
        contact_dict = {
            "crmentity": {c.name: getattr(crmentity, c.name) for c in crmentity.__table__.columns},
            "contact_details": {c.name: getattr(contact_details, c.name) for c in contact_details.__table__.columns},
            "contact_subdetails": {c.name: getattr(contact_subdetails, c.name) for c in contact_subdetails.__table__.columns},
            "contact_address": {c.name: getattr(contact_address, c.name) for c in contact_address.__table__.columns},
            "custom_fields": {c.name: getattr(contact_cf, c.name) for c in contact_cf.__table__.columns}
        }
        
        return contact_dict
    
def get_contact_count_based_on_account_type():
    """
    Get contact counts grouped by their associated account types.
    """
    from sqlalchemy import func
    with Session() as session:
        results = (session.query(
                        vtigerAccount.account_type,
                        func.count(VtigerContactDetails.contactid).label('contact_count')
                    )
                    .join(vtigerAccount, VtigerContactDetails.accountid == vtigerAccount.accountid)
                    .group_by(vtigerAccount.account_type)
                    .all())
        
        # Convert results to list of dictionaries
        contact_counts = [
            {
                'account_type': account_type,
                'contact_count': contact_count
            }
            for account_type, contact_count in results
        ]
        
        return contact_counts

def get_address_pivot_enhance_metrics(start_date: str, end_date: str = None, limit: int = 1000):
    """
    Weekly pivot table for address enhancement metrics.
    Columns are weekly date ranges:  '2025-01-01 → 2025-01-07'
    """

    from sqlalchemy import text
    import traceback
    from datetime import datetime

    # Parse and validate dates
    try:
        start_date_dt = datetime.strptime(start_date, "%Y-%m-%d")
    except ValueError:
        print(f"Invalid start_date '{start_date}', use YYYY-MM-DD")
        return []

    if end_date:
        try:
            end_date_dt = datetime.strptime(end_date, "%Y-%m-%d")
        except ValueError:
            print(f"Invalid end_date '{end_date}', use YYYY-MM-DD")
            return []
    else:
        end_date_dt = datetime.utcnow()

    sql = """
        SELECT 
            metric_type,

            -- ISO week start
            DATE_FORMAT(
                DATE_SUB(DATE(date_field), INTERVAL DAYOFWEEK(DATE(date_field))-2 DAY),
                '%Y-%m-%d'
            ) AS week_start,

            -- ISO week end = start + 6
            DATE_FORMAT(
                DATE_ADD(
                    DATE_SUB(DATE(date_field), INTERVAL DAYOFWEEK(DATE(date_field))-2 DAY),
                    INTERVAL 6 DAY
                ),
                '%Y-%m-%d'
            ) AS week_end,

            COUNT(*) AS total

        FROM (
            -- Enhanced Accounts / Contacts
            SELECT 
                CASE 
                    WHEN module = 'Accounts' THEN 'Accounts_Enhanced'
                    WHEN module = 'Contacts' THEN 'Contacts_Enhanced'
                    ELSE CONCAT(module, '_Enhanced')
                END AS metric_type,
                tagged_on AS date_field
            FROM vtiger_freetagged_objects
            WHERE tag_id = 12
              AND tagger_id = 16
              AND module IS NOT NULL
              AND tagged_on IS NOT NULL

            UNION ALL

            -- Started: Accounts
            SELECT
                'Accounts_Started' AS metric_type,
                cf_943 AS date_field
            FROM vtiger_accountscf
            WHERE cf_943 IS NOT NULL

            UNION ALL

            -- Started: Contacts
            SELECT
                'Contacts_Started' AS metric_type,
                cf_941 AS date_field
            FROM vtiger_contactscf
            WHERE cf_941 IS NOT NULL
        ) AS combined

        WHERE date_field >= :start_date
          AND date_field <= :end_date
        GROUP BY metric_type, week_start, week_end
        ORDER BY metric_type, week_start
        LIMIT :limit;
    """

    try:
        with engine.connect() as conn:
            rows = conn.execute(
                text(sql),
                {
                    "start_date": start_date_dt,
                    "end_date": end_date_dt,
                    "limit": limit
                }
            ).mappings().all()

        # STEP 1: Build unique week columns
        week_columns = []
        for r in rows:
            col_name = f"{r['week_start']} → {r['week_end']}"
            if col_name not in week_columns:
                week_columns.append(col_name)

        # STEP 2: Pivot
        pivot = {}
        for r in rows:
            metric = r["metric_type"]
            col = f"{r['week_start']} → {r['week_end']}"
            total = int(r["total"])

            if metric not in pivot:
                pivot[metric] = {"metric_type": metric}

            pivot[metric][col] = total

        # STEP 3: Ensure missing weeks = 0
        final = []
        for metric, record in pivot.items():
            for w in week_columns:
                record.setdefault(w, 0)
            final.append(record)

        return final

    except Exception:
        print("Error in get_address_pivot_enhance_metrics:")
        print(traceback.format_exc())
        return []

    
def get_simple_Address_pivot_enhance_metrics(start_date: str, end_date: str = None, limit: int = 1000):
    """
    Generate dynamic weekly pivot report for address enhancement metrics.
    Returns data with weekly columns dynamically generated based on date range.
    """
    try:
        from sqlalchemy import text
        from datetime import datetime, timedelta

        # Parse dates
        start_date_dt = datetime.strptime(start_date, "%Y-%m-%d").date()
        
        if end_date:
            end_date_dt = datetime.strptime(end_date, "%Y-%m-%d").date()
        else:
            end_date_dt = datetime.utcnow().date()
        
        # Adjust to Monday if needed
        if start_date_dt.weekday() != 0:
            start_date_dt -= timedelta(days=start_date_dt.weekday())

        # Generate weeks
        weeks = []
        current = start_date_dt
        while current <= end_date_dt:
            week_end = min(current + timedelta(days=6), end_date_dt)
            weeks.append((current, week_end))
            current += timedelta(days=7)

        # Build week columns
        week_columns = []
        for week_start, week_end in weeks:
            col_name = f"{week_start}_to_{week_end}"
            week_columns.append(
                f"SUM(CASE WHEN week_start = '{week_start}' THEN weekly_count ELSE 0 END) AS `{col_name}`"
            )
        
        week_sql = ",\n            ".join(week_columns)

        # Build the query using subquery for weekly aggregation first
        sql = f"""
        WITH weekly_data AS (
            SELECT 
                metric_type,
                category,
                DATE_SUB(date_field, INTERVAL WEEKDAY(date_field) DAY) as week_start,
                COUNT(*) as weekly_count
            FROM (
                -- Tagging data = ENHANCED records
                SELECT 
                    CASE 
                        WHEN module = 'Accounts' THEN 'Accounts_Enhanced'
                        WHEN module = 'Contacts' THEN 'Contacts_Enhanced'
                        ELSE CONCAT(module, '_Enhanced')
                    END as metric_type,
                    module as category,
                    tagged_on as date_field
                FROM vtiger_freetagged_objects
                WHERE module IS NOT NULL 
                    AND tag_id = 12 
                    AND tagger_id = 16
                    AND tagged_on IS NOT NULL
                    AND tagged_on BETWEEN '{start_date_dt}' AND '{end_date_dt}'
                
                UNION ALL
                
                -- Accounts custom field = STARTED records
                SELECT 
                    'Accounts_Started' as metric_type,
                    'Accounts' as category,
                    cf_943 as date_field
                FROM vtiger_accountscf 
                WHERE cf_943 IS NOT NULL
                    AND cf_943 BETWEEN '{start_date_dt}' AND '{end_date_dt}'
                
                UNION ALL
                
                -- Contacts custom field = STARTED records
                SELECT 
                    'Contacts_Started' as metric_type,
                    'Contacts' as category,
                    cf_941 as date_field
                FROM vtiger_contactscf 
                WHERE cf_941 IS NOT NULL
                    AND cf_941 BETWEEN '{start_date_dt}' AND '{end_date_dt}'
            ) combined_data
            WHERE date_field BETWEEN '{start_date_dt}' AND '{end_date_dt}'
            GROUP BY metric_type, category, DATE_SUB(date_field, INTERVAL WEEKDAY(date_field) DAY)
        )
        SELECT 
            metric_type as module,
            {week_sql},
            SUM(weekly_count) as total
        FROM weekly_data
        GROUP BY metric_type, category
        ORDER BY 
            CASE metric_type 
                WHEN 'Accounts_Started' THEN 1
                WHEN 'Contacts_Started' THEN 2
                WHEN 'Accounts_Enhanced' THEN 3
                WHEN 'Contacts_Enhanced' THEN 4
                ELSE 5
            END
        LIMIT :limit;
        """
        
        with engine.connect() as conn:
            result = conn.execute(text(sql), {"limit": limit})
            return [dict(r) for r in result.mappings().all()]
    
    except Exception as e:
        print(f"Error in get_Address_pivot_enhance_metrics: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return []

def get_Address_enhance_metrics(limit: int = 100):
    """
    Run the tagging metrics aggregation query with specific tag and tagger filters
    and return a list of dicts with keys: module, last_24h, last_7d, last_30d, total
    """
    try:
        import traceback
        from sqlalchemy import text

        sql = """
        SELECT 
            metric_type as module,
            COUNT(CASE WHEN date_field >= DATE_SUB(CURDATE(), INTERVAL 1 DAY) THEN 1 END) as last_24h,
            COUNT(CASE WHEN date_field >= DATE_SUB(CURDATE(), INTERVAL 7 DAY) THEN 1 END) as last_7d,
            COUNT(CASE WHEN date_field >= DATE_SUB(CURDATE(), INTERVAL 30 DAY) THEN 1 END) as last_30d,
            COUNT(*) as total
        FROM (
            -- Tagging data = ENHANCED records
            SELECT 
                CASE 
                    WHEN module = 'Accounts' THEN 'Accounts_Enhanced'
                    WHEN module = 'Contacts' THEN 'Contacts_Enhanced'
                    ELSE CONCAT(module, '_Enhanced')
                END as metric_type,
                module as category,
                tagged_on as date_field
            FROM vtiger_freetagged_objects
            WHERE module IS NOT NULL 
                AND tag_id = 12 
                AND tagger_id = 16
            
            UNION ALL
            
            -- Accounts custom field = STARTED records
            SELECT 
                'Accounts_Started' as metric_type,
                'Accounts' as category,
                cf_943 as date_field
            FROM vtiger_accountscf 
            WHERE cf_943 IS NOT NULL
            
            UNION ALL
            
            -- Contacts custom field = STARTED records
            SELECT 
                'Contacts_Started' as metric_type,
                'Contacts' as category,
                cf_941 as date_field
            FROM vtiger_contactscf 
            WHERE cf_941 IS NOT NULL
        ) combined_data
        GROUP BY metric_type, category
        ORDER BY 
            CASE metric_type 
                WHEN 'Accounts_Started' THEN 1
                WHEN 'Contacts_Started' THEN 2
                WHEN 'Accounts_Enhanced' THEN 3
                WHEN 'Contacts_Enhanced' THEN 4
                ELSE 5
            END
        LIMIT :limit;
        """
        with engine.connect() as conn:
            result = conn.execute(text(sql), {"limit": limit})
            raw_rows = [dict(r) for r in result.mappings().all()]

        # Normalize keys for templates
        rows = []
        for r in raw_rows:
            rows.append({
                "module": r.get("module") or "Unknown",
                "last_24h": int(r.get("last_24h") or 0),
                "last_7d": int(r.get("last_7d") or 0),
                "last_30d": int(r.get("last_30d") or 0),
                "total": int(r.get("total") or 0)
            })
        return rows
    
    except Exception as e:
        print(f"Error in get_tagging_metrics_filtered: {str(e)}")
        print(traceback.format_exc())
        return []



def update_interaction_data():
    """
    Run all interaction analytics queries and save results into Redis under HKEY 'interactiondata'.
    Also store the last update timestamp.
    Returns True on success, False on failure.
    """
    # Using local JSON-backed storage instead of Redis
    
    try:
        with engine.connect() as conn:
            # Store timestamp
            updated_at = datetime.now().isoformat()
            
            # Clear previous data to avoid stale fields
            try:
                json_delete("interactiondata")
            except Exception:
                pass
            
            # ============================================
            # 1. EXECUTIVE SUMMARY
            # ============================================
            exec_summary_query = text("""
                SELECT 
                    COUNT(*) AS total_interactions,
                    COUNT(DISTINCT email) AS total_unique_users,
                    COUNT(DISTINCT interaction_type_id) AS total_interaction_types,
                    COUNT(DISTINCT post_url) AS total_unique_posts,
                    ROUND(COUNT(*) / NULLIF(COUNT(DISTINCT email), 0), 2) AS avg_interactions_per_user,
                    MIN(occurred_at) AS first_interaction_date,
                    MAX(occurred_at) AS last_interaction_date,
                    DATEDIFF(MAX(occurred_at), MIN(occurred_at)) AS days_of_activity,
                    ROUND(COUNT(*) / NULLIF(DATEDIFF(MAX(occurred_at), MIN(occurred_at)), 0), 2) AS avg_daily_interactions
                FROM interactions
            """)
            
            result = conn.execute(exec_summary_query)
            exec_summary = [dict(row) for row in result.mappings().all()]
            json_hset("interactiondata", "executive_summary", 
                          _sanitize_data(exec_summary))
            
            # ============================================
            # 2. INTERACTION TYPE BREAKDOWN
            # ============================================
            interaction_type_query = text("""
                SELECT 
                    it.name AS interaction_type,
                    it.description,
                    COUNT(i.id) AS total_count,
                    COUNT(DISTINCT i.email) AS unique_users,
                    ROUND(COUNT(i.id) * 100.0 / SUM(COUNT(i.id)) OVER(), 2) AS percentage_of_total,
                    ROUND(COUNT(i.id) / NULLIF(COUNT(DISTINCT i.email), 0), 2) AS avg_per_user,
                    MIN(i.occurred_at) AS first_occurrence,
                    MAX(i.occurred_at) AS last_occurrence,
                    COUNT(DISTINCT DATE(i.occurred_at)) AS active_days
                FROM interactions i
                INNER JOIN interaction_types it ON i.interaction_type_id = it.id
                GROUP BY it.id, it.name, it.description
                ORDER BY total_count DESC
            """)
            
            result = conn.execute(interaction_type_query)
            interaction_types = [dict(row) for row in result.mappings().all()]
            json_hset("interactiondata", "interaction_type_breakdown", 
                          _sanitize_data(interaction_types))
            
            # ============================================
            # 3. WEEKLY ACTIVITY TRENDS (Last 30 Days)
            # ============================================
            weekly_trends_query_dashboard = text("""
                SELECT 
                    it.name AS interaction_type,
                    COALESCE(i.status, 'No Status') AS status,
                    COUNT(CASE WHEN i.occurred_at >= DATE_SUB(CURRENT_DATE, INTERVAL 1 WEEK) THEN 1 END) AS current_week,
                    COUNT(CASE WHEN i.occurred_at >= DATE_SUB(CURRENT_DATE, INTERVAL 2 WEEK) 
                                AND i.occurred_at < DATE_SUB(CURRENT_DATE, INTERVAL 1 WEEK) THEN 1 END) AS previous_week,
                    COUNT(CASE WHEN i.occurred_at >= DATE_SUB(CURRENT_DATE, INTERVAL 3 WEEK) 
                                AND i.occurred_at < DATE_SUB(CURRENT_DATE, INTERVAL 2 WEEK) THEN 1 END) AS two_weeks_ago,
                    COUNT(CASE WHEN i.occurred_at >= DATE_SUB(CURRENT_DATE, INTERVAL 4 WEEK) 
                                AND i.occurred_at < DATE_SUB(CURRENT_DATE, INTERVAL 3 WEEK) THEN 1 END) AS three_weeks_ago,
                    COUNT(*) AS total_4_weeks
                FROM interactions i
                INNER JOIN interaction_types it ON i.interaction_type_id = it.id
                WHERE i.occurred_at >= DATE_SUB(CURRENT_DATE, INTERVAL 4 WEEK)
                GROUP BY it.name, i.status
                ORDER BY it.name, total_4_weeks DESC
            """)
            
            result = conn.execute(weekly_trends_query_dashboard)
            weekly_trends_dashboard = [dict(row) for row in result.mappings().all()]
            json_hset("interactiondata", "weekly_trends_dashboard", 
                          _sanitize_data(weekly_trends_dashboard))

            # ============================================
            # 4. DAILY ACTIVITY TRENDS (Last 30 Days)
            # ============================================
            daily_trends_query = text("""
                SELECT 
                    DATE(occurred_at) AS activity_date,
                    DAYNAME(occurred_at) AS day_of_week,
                    COUNT(*) AS total_interactions,
                    COUNT(DISTINCT email) AS unique_users,
                    COUNT(DISTINCT interaction_type_id) AS interaction_types_used,
                    COUNT(DISTINCT post_url) AS unique_posts_engaged,
                    ROUND(COUNT(*) / NULLIF(COUNT(DISTINCT email), 0), 2) AS avg_interactions_per_user
                FROM interactions
                WHERE occurred_at >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
                GROUP BY DATE(occurred_at), DAYNAME(occurred_at)
                ORDER BY activity_date DESC
            """)
            
            result = conn.execute(daily_trends_query)
            daily_trends = [dict(row) for row in result.mappings().all()]
            json_hset("interactiondata", "daily_trends_30d", 
                          _sanitize_data(daily_trends))
            
            # ============================================
            # 5. HOURLY ENGAGEMENT PATTERNS
            # ============================================
            hourly_patterns_query = text("""
                SELECT 
                    HOUR(occurred_at) AS hour_of_day,
                    COUNT(*) AS total_interactions,
                    COUNT(DISTINCT email) AS unique_users,
                    ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER(), 2) AS percentage_of_total
                FROM interactions
                GROUP BY HOUR(occurred_at)
                ORDER BY total_interactions DESC
            """)
            
            result = conn.execute(hourly_patterns_query)
            hourly_patterns = [dict(row) for row in result.mappings().all()]
            json_hset("interactiondata", "hourly_patterns", 
                          _sanitize_data(hourly_patterns))
            
            # ============================================
            # 6. DAY OF WEEK ANALYSIS
            # ============================================
            day_of_week_query = text("""
                SELECT 
                    DAYNAME(occurred_at) AS day_name,
                    DAYOFWEEK(occurred_at) AS day_number,
                    COUNT(*) AS total_interactions,
                    COUNT(DISTINCT email) AS unique_users,
                    ROUND(AVG(HOUR(occurred_at)), 2) AS avg_hour_of_interaction,
                    COUNT(DISTINCT interaction_type_id) AS interaction_types_used
                FROM interactions
                GROUP BY DAYNAME(occurred_at), DAYOFWEEK(occurred_at)
                ORDER BY day_number
            """)
            
            result = conn.execute(day_of_week_query)
            day_of_week = [dict(row) for row in result.mappings().all()]
            json_hset("interactiondata", "day_of_week_analysis", 
                          _sanitize_data(day_of_week))
            
            # ============================================
            # 7. USER ENGAGEMENT SEGMENTATION
            # ============================================
            segmentation_query = text("""
                SELECT 
                    CASE 
                        WHEN interaction_count >= 20 THEN 'Power Users (20+)'
                        WHEN interaction_count >= 10 THEN 'Active Users (10-19)'
                        WHEN interaction_count >= 5 THEN 'Regular Users (5-9)'
                        WHEN interaction_count >= 2 THEN 'Casual Users (2-4)'
                        ELSE 'One-time Users (1)'
                    END AS user_segment,
                    COUNT(*) AS users_in_segment,
                    ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER(), 2) AS percentage_of_users,
                    SUM(interaction_count) AS total_interactions_from_segment,
                    ROUND(AVG(interaction_count), 2) AS avg_interactions_per_user,
                    ROUND(AVG(days_active), 2) AS avg_days_active
                FROM (
                    SELECT 
                        email,
                        COUNT(*) AS interaction_count,
                        COUNT(DISTINCT DATE(occurred_at)) AS days_active
                    FROM interactions
                    WHERE email IS NOT NULL
                    GROUP BY email
                ) user_stats
                GROUP BY user_segment
                ORDER BY MIN(interaction_count) DESC
            """)
            
            result = conn.execute(segmentation_query)
            segmentation = [dict(row) for row in result.mappings().all()]
            json_hset("interactiondata", "user_segmentation", 
                          _sanitize_data(segmentation))
            
            # ============================================
            # 8. TOP USERS BY ACTIVITY (Top 50)
            # ============================================
            top_users_query = text("""
                SELECT 
                    email,
                    COUNT(*) AS total_interactions,
                    COUNT(DISTINCT interaction_type_id) AS interaction_types_used,
                    COUNT(DISTINCT DATE(occurred_at)) AS days_active,
                    MIN(occurred_at) AS first_interaction,
                    MAX(occurred_at) AS last_interaction,
                    DATEDIFF(MAX(occurred_at), MIN(occurred_at)) + 1 AS engagement_span_days,
                    GROUP_CONCAT(DISTINCT it.name ORDER BY it.name SEPARATOR ', ') AS interaction_types
                FROM interactions i
                INNER JOIN interaction_types it ON i.interaction_type_id = it.id
                WHERE email IS NOT NULL
                GROUP BY email
                ORDER BY total_interactions DESC
                LIMIT 50
            """)
            
            result = conn.execute(top_users_query)
            top_users = [dict(row) for row in result.mappings().all()]
            json_hset("interactiondata", "top_users", 
                          _sanitize_data(top_users))
            
            # ============================================
            # 9. STATUS DISTRIBUTION
            # ============================================
            status_dist_query = text("""
                SELECT 
                    it.name AS interaction_type,
                    COALESCE(i.status, 'No Status') AS status,
                    COUNT(*) AS count,
                    COUNT(DISTINCT i.email) AS unique_users,
                    ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER(PARTITION BY it.name), 2) AS pct_within_type
                FROM interactions i
                INNER JOIN interaction_types it ON i.interaction_type_id = it.id
                GROUP BY it.name, i.status
                ORDER BY it.name, count DESC
            """)
            
            result = conn.execute(status_dist_query)
            status_dist = [dict(row) for row in result.mappings().all()]
            json_hset("interactiondata", "status_distribution", 
                          _sanitize_data(status_dist))
            
            # ============================================
            # 10. POST PERFORMANCE ANALYSIS (Top 100)
            # ============================================
            post_performance_query = text("""
                SELECT 
                    post_url,
                    COUNT(*) AS total_interactions,
                    COUNT(DISTINCT email) AS unique_engagers,
                    COUNT(DISTINCT interaction_type_id) AS interaction_types,
                    COUNT(DISTINCT status) AS unique_statuses,
                    MIN(occurred_at) AS first_interaction,
                    MAX(occurred_at) AS last_interaction,
                    DATEDIFF(MAX(occurred_at), MIN(occurred_at)) + 1 AS engagement_span_days,
                    GROUP_CONCAT(DISTINCT it.name ORDER BY it.name SEPARATOR ', ') AS interaction_types_list
                FROM interactions i
                INNER JOIN interaction_types it ON i.interaction_type_id = it.id
                WHERE post_url IS NOT NULL
                GROUP BY post_url
                ORDER BY total_interactions DESC
                LIMIT 100
            """)
            
            result = conn.execute(post_performance_query)
            post_performance = [dict(row) for row in result.mappings().all()]
            json_hset("interactiondata", "post_performance", 
                          _sanitize_data(post_performance))
            
            # ============================================
            # 11. MONTHLY TRENDS
            # ============================================
            monthly_trends_query = text("""
                SELECT
                    YEAR(occurred_at) AS year,
                    MONTH(occurred_at) AS month,
                    DATE_FORMAT(occurred_at, '%Y-%m') AS `year_month`,
                    COUNT(*) AS total_interactions,
                    COUNT(DISTINCT email) AS monthly_active_users,
                    COUNT(DISTINCT interaction_type_id) AS interaction_types_used,
                    COUNT(DISTINCT post_url) AS unique_posts,
                    ROUND(COUNT(*) / NULLIF(COUNT(DISTINCT email), 0), 2) AS avg_interactions_per_user,
                    COUNT(DISTINCT DATE(occurred_at)) AS active_days_in_month
                FROM interactions
                GROUP BY YEAR(occurred_at), MONTH(occurred_at)
                ORDER BY year DESC, month DESC
            """)
            
            result = conn.execute(monthly_trends_query)
            monthly_trends = [dict(row) for row in result.mappings().all()]
            json_hset("interactiondata", "monthly_trends", 
                          _sanitize_data(monthly_trends))
            
            # ============================================
            # 12. RETENTION ANALYSIS
            # ============================================
            retention_query = text("""
                SELECT 
                    COUNT(DISTINCT email) AS total_users_with_email,
                    SUM(CASE WHEN interaction_count = 1 THEN 1 ELSE 0 END) AS one_time_users,
                    SUM(CASE WHEN interaction_count > 1 THEN 1 ELSE 0 END) AS returning_users,
                    ROUND(SUM(CASE WHEN interaction_count > 1 THEN 1 ELSE 0 END) * 100.0 / COUNT(DISTINCT email), 2) AS retention_rate_pct,
                    ROUND(AVG(interaction_count), 2) AS avg_interactions_per_user,
                    MAX(interaction_count) AS max_interactions_by_single_user
                FROM (
                    SELECT email, COUNT(*) AS interaction_count
                    FROM interactions
                    WHERE email IS NOT NULL
                    GROUP BY email
                ) user_counts
            """)
            
            result = conn.execute(retention_query)
            retention = [dict(row) for row in result.mappings().all()]
            json_hset("interactiondata", "retention_analysis", 
                          _sanitize_data(retention))
            
            # ============================================
            # 13. RECENT ACTIVITY (Last 7 Days)
            # ============================================
            recent_activity_query = text("""
                SELECT 
                    DATE(occurred_at) AS activity_date,
                    it.name AS interaction_type,
                    COUNT(*) AS interactions,
                    COUNT(DISTINCT email) AS unique_users,
                    GROUP_CONCAT(DISTINCT status ORDER BY status SEPARATOR ', ') AS statuses_used
                FROM interactions i
                INNER JOIN interaction_types it ON i.interaction_type_id = it.id
                WHERE occurred_at >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
                GROUP BY DATE(occurred_at), it.name
                ORDER BY activity_date DESC, interactions DESC
            """)
            
            result = conn.execute(recent_activity_query)
            recent_activity = [dict(row) for row in result.mappings().all()]
            json_hset("interactiondata", "recent_activity_7d", 
                          _sanitize_data(recent_activity))
            
            # ============================================
            # 14. ENGAGEMENT VELOCITY (Top 50)
            # ============================================
            velocity_query = text("""
                SELECT 
                    email,
                    MIN(occurred_at) AS first_interaction,
                    MAX(occurred_at) AS last_interaction,
                    COUNT(*) AS total_interactions,
                    DATEDIFF(MAX(occurred_at), MIN(occurred_at)) AS days_between_first_last,
                    ROUND(COUNT(*) / NULLIF(DATEDIFF(MAX(occurred_at), MIN(occurred_at)), 0), 2) AS interactions_per_day
                FROM interactions
                WHERE email IS NOT NULL
                GROUP BY email
                HAVING COUNT(*) > 1 AND DATEDIFF(MAX(occurred_at), MIN(occurred_at)) > 0
                ORDER BY interactions_per_day DESC
                LIMIT 50
            """)
            
            result = conn.execute(velocity_query)
            velocity = [dict(row) for row in result.mappings().all()]
            json_hset("interactiondata", "engagement_velocity", 
                          _sanitize_data(velocity))
            
            # ============================================
            # 15. INACTIVE USERS (Last 30+ Days)
            # ============================================
            inactive_users_query = text("""
                SELECT 
                    email,
                    MAX(occurred_at) AS last_interaction,
                    DATEDIFF(CURDATE(), MAX(occurred_at)) AS days_since_last_interaction,
                    COUNT(*) AS total_historical_interactions,
                    COUNT(DISTINCT interaction_type_id) AS interaction_types_used
                FROM interactions
                WHERE email IS NOT NULL
                GROUP BY email
                HAVING DATEDIFF(CURDATE(), MAX(occurred_at)) > 30
                ORDER BY days_since_last_interaction DESC
                LIMIT 100
            """)
            
            result = conn.execute(inactive_users_query)
            inactive_users = [dict(row) for row in result.mappings().all()]
            json_hset("interactiondata", "inactive_users", 
                          _sanitize_data(inactive_users))
            
            # Store last update timestamp
            json_hset("interactiondata", "_last_update", updated_at)
            
            print(f"Interaction data updated in Redis at {updated_at}")
            return True
            
    except Exception as e:
        print(f"Error updating interaction data: {e}")
        import traceback
        print(traceback.format_exc())
        return False


def get_interaction_data():
    """
    Retrieve all interaction analytics data from Redis.
    Returns a dictionary with all stored metrics, or None on failure.
    """
    try:
        raw_data = json_hgetall("interactiondata")
        if not raw_data:
            return None

        parsed_data = {}
        for key, value in raw_data.items():
            key_str = str(key)
            # metadata fields start with underscore and should be kept as-is
            if key_str.startswith('_'):
                parsed_data[key_str] = value
                continue

            # value may already be a native object or a JSON string
            if isinstance(value, str):
                try:
                    parsed_data[key_str] = json.loads(value)
                except Exception:
                    parsed_data[key_str] = value
            else:
                parsed_data[key_str] = value

        return parsed_data
    except Exception as e:
        print(f"Error retrieving interaction data from storage: {e}")
        import traceback
        print(traceback.format_exc())
        return None


def _sanitize_data(data):
    """
    Helper function to sanitize data for JSON serialization.
    Converts dates, decimals, and other non-JSON types to strings.
    """
    if isinstance(data, list):
        return [_sanitize_data(item) for item in data]
    elif isinstance(data, dict):
        sanitized = {}
        for key, value in data.items():
            if isinstance(value, (datetime, date)):
                sanitized[key] = value.isoformat()
            elif isinstance(value, (list, dict)):
                sanitized[key] = _sanitize_data(value)
            else:
                sanitized[key] = value
        return sanitized
    elif isinstance(data, (datetime, date)):
        return data.isoformat()
    else:
        return data
    

def get_email_verification_metrics(limit: int = 100):
    """
    Run the email verification aggregation query and return a list of dicts with
    keys: email, last_24h, last_7d, last_30d, total
    """
    try:
        import traceback
        from sqlalchemy import text

        sql = """
        SELECT 
            cf_907 as email_status,
            COUNT(CASE WHEN cf_923 >= DATE_SUB(NOW(), INTERVAL 24 HOUR) THEN 1 END) as last_24h,
            COUNT(CASE WHEN cf_923 >= DATE_SUB(NOW(), INTERVAL 7 DAY) THEN 1 END) as last_7d,
            COUNT(CASE WHEN cf_923 >= DATE_SUB(NOW(), INTERVAL 1 MONTH) THEN 1 END) as last_30d,
            COUNT(*) as total
        FROM vtiger_contactscf
        WHERE (cf_907 IS NOT NULL OR cf_923 IS NOT NULL)
        AND cf_907 != ''
        AND cf_907 <> ''
        GROUP BY cf_907
        ORDER BY total DESC
        LIMIT :limit
        """
        with engine.connect() as conn:
            result = conn.execute(text(sql), {"limit": limit})
            raw_rows = [dict(r) for r in result.mappings().all()]

        # Normalize keys for templates
        rows = []
        for r in raw_rows:
            rows.append({
                "email_status": r.get("email_status"),
                "last_24h": int(r.get("last_24h") or 0),
                "last_7d": int(r.get("last_7d") or 0),
                "last_30d": int(r.get("last_30d") or 0),
                "total": int(r.get("total") or 0)
            })
        return rows
    
    except Exception as e:
        print(f"Error in get_cf907_metrics: {str(e)}")
        print(traceback.format_exc())
        return []
    
def get_email_verification_weekly_pivot(start_date, end_date):
    """
    Return weekly pivot table for email verification logs (cf_907 = email_status)
    where each column is a date range such as:
    
        "2025-01-01 → 2025-01-07"
    
    Output example:
    [
        {
            "email_status": "valid",
            "2025-01-01 → 2025-01-07": 120,
            "2025-01-08 → 2025-01-14": 98
        },
        ...
    ]
    """
    from sqlalchemy import text
    import traceback

    sql = """
        SELECT 
            COALESCE(cf_907, 'Unknown') AS email_status,

            -- Week start (ISO: Monday as first day)
            DATE_FORMAT(
                DATE_SUB(DATE(cf_923), INTERVAL DAYOFWEEK(DATE(cf_923))-2 DAY),
                '%Y-%m-%d'
            ) AS week_start,

            -- Week end (start + 6 days)
            DATE_FORMAT(
                DATE_ADD(
                    DATE_SUB(DATE(cf_923), INTERVAL DAYOFWEEK(DATE(cf_923))-2 DAY),
                    INTERVAL 6 DAY
                ),
                '%Y-%m-%d'
            ) AS week_end,

            COUNT(*) AS total

        FROM vtiger_contactscf
        WHERE cf_923 >= :start_date
          AND cf_923 <= :end_date
          AND cf_907 IS NOT NULL
          AND cf_907 <> ''
        GROUP BY email_status, week_start, week_end
        ORDER BY email_status, week_start;
    """

    try:
        with engine.connect() as conn:
            rows = conn.execute(
                text(sql),
                {"start_date": start_date, "end_date": end_date}
            ).mappings().all()

        # Collect unique date-range week columns
        week_columns = []
        for r in rows:
            col = f"{r['week_start']} → {r['week_end']}"
            if col not in week_columns:
                week_columns.append(col)

        # Build pivot structure
        pivot = {}
        for r in rows:
            status = r["email_status"]
            col_name = f"{r['week_start']} → {r['week_end']}"
            total = int(r["total"])

            if status not in pivot:
                pivot[status] = {"email_status": status}

            pivot[status][col_name] = total

        # Fill missing weeks with zeros for consistency
        final_rows = []
        for status, record in pivot.items():
            for wc in week_columns:
                record.setdefault(wc, 0)
            final_rows.append(record)

        return final_rows

    except Exception:
        print("Error creating weekly pivot for email verification:")
        print(traceback.format_exc())
        return []

def accountTypeClassificationPivot(start_date, end_date):
    """
    Generate a weekly pivot table for account classification activity.
    Weeks appear as columns using actual date range labels.
    account_type appears as rows.

    Example column name: '2024-11-01_to_2024-11-07'
    """

    # --- Normalize date inputs ---
    def to_date(d):
        if isinstance(d, (date, datetime)):
            return d.date() if isinstance(d, datetime) else d
        return datetime.strptime(d, "%Y-%m-%d").date()

    start = to_date(start_date)
    end = to_date(end_date)

    if start > end:
        raise ValueError("start_date must be <= end_date")

    # --- Build weekly buckets ---
    week_ranges = []
    cursor = start

    while cursor <= end:
        week_start = cursor
        week_end = min(cursor + timedelta(days=6), end)

        label = f"{week_start.isoformat()}_to_{week_end.isoformat()}"
        week_ranges.append((week_start, week_end, label))

        cursor = week_end + timedelta(days=1)

    # --- Query DB for all events within range ---
    query = text("""
        SELECT 
            a.accountid,
            COALESCE(NULLIF(a.account_type, ''), 'Unclassified') AS account_type,
            DATE(acf.cf_925) AS created_date
        FROM vtiger_account a
        INNER JOIN vtiger_accountscf acf ON a.accountid = acf.accountid
        WHERE acf.cf_925 >= :start_date
          AND acf.cf_925 <= :end_date
          AND acf.cf_925 > '1970-01-01'
    """)

    with engine.connect() as conn:
        result = conn.execute(
            query.execution_options(timeout=300),
            {"start_date": start, "end_date": end}
        )
        rows = [dict(row) for row in result.mappings().all()]

    # --- Prepare pivot structure ---
    pivot = defaultdict(lambda: {label: 0 for _, _, label in week_ranges})

    # --- Fill pivot ---
    for row in rows:
        acc_type = row["account_type"]
        created = row["created_date"]

        for week_start, week_end, label in week_ranges:
            if week_start <= created <= week_end:
                pivot[acc_type][label] += 1
                break

    # Convert defaultdict → normal dict
    return {k: dict(v) for k, v in pivot.items()}

def get_weekly_phone_enrichment_pivot(start_date, end_date):
    """
    Return weekly pivot table for phone enrichment logs where each column
    represents a weekly date range, e.g.:

        "2025-01-01 → 2025-01-07"

    Output example:
    [
        {"platform": "Apollo", "2025-01-01 → 2025-01-07": 120, ...},
        {"platform": "ZoomInfo", "2025-01-01 → 2025-01-07": 98, ...},
        ...
    ]
    """

    from sqlalchemy import text
    import traceback

    sql = """
        SELECT 
            COALESCE(Platform, 'Unknown') AS platform,

            -- Start of week (ISO week: Monday as first day)
            -- Use DATE_SUB to go back to Monday (DAYOFWEEK: 1=Sun, 2=Mon, so Mon is 2)
            DATE_FORMAT(
                DATE_SUB(DATE(Datetime), INTERVAL DAYOFWEEK(DATE(Datetime))-2 DAY),
                '%Y-%m-%d'
            ) AS week_start,

            -- End of week (Monday + 6 days = Sunday)
            DATE_FORMAT(
                DATE_ADD(
                    DATE_SUB(DATE(Datetime), INTERVAL DAYOFWEEK(DATE(Datetime))-2 DAY),
                    INTERVAL 6 DAY
                ),
                '%Y-%m-%d'
            ) AS week_end,

            COUNT(*) AS total

        FROM phone_enrichment_logs_new
        WHERE Datetime >= :start_date
          AND Datetime <= :end_date
          AND Phone IS NOT NULL 
          AND Phone <> '' 
          AND Phone <> 'None'
        GROUP BY platform, week_start, week_end
        ORDER BY platform, week_start;
    """

    try:
        with engine.connect() as conn:
            rows = conn.execute(
                text(sql),
                {"start_date": start_date, "end_date": end_date}
            ).mappings().all()

        # Build unique week column names (date ranges)
        week_columns = []
        for r in rows:
            col = f"{r['week_start']} → {r['week_end']}"
            if col not in week_columns:
                week_columns.append(col)

        # Pivot structure
        pivot = {}
        for r in rows:
            platform = r["platform"]
            col_name = f"{r['week_start']} → {r['week_end']}"
            total = int(r["total"])

            if platform not in pivot:
                pivot[platform] = {"platform": platform}

            pivot[platform][col_name] = total

        # Fill missing weeks with zero
        final = []
        for platform, data in pivot.items():
            for wc in week_columns:
                data.setdefault(wc, 0)
            final.append(data)

        return final

    except Exception:
        print("Error creating weekly pivot:")
        print(traceback.format_exc())
        return []



def get_phone_enrichment_metrics(limit: int = 100):
    """
    Run the phone enrichment aggregation query and return a list of dicts with
    keys: platform, last_24h, last_7d, last_30d, total
    """
    try:
        import traceback
        from sqlalchemy import text

        sql = """
        SELECT 
            Platform,
            SUM(CASE 
                    WHEN Datetime >= NOW() - INTERVAL 1 DAY 
                         AND Phone IS NOT NULL AND Phone <> '' AND Phone <> 'None' 
                    THEN 1 ELSE 0 END) AS last_24h,
            SUM(CASE 
                    WHEN Datetime >= NOW() - INTERVAL 7 DAY 
                         AND Phone IS NOT NULL AND Phone <> '' AND Phone <> 'None' 
                    THEN 1 ELSE 0 END) AS last_7d,
            SUM(CASE 
                    WHEN Datetime >= NOW() - INTERVAL 30 DAY 
                         AND Phone IS NOT NULL AND Phone <> '' AND Phone <> 'None' 
                    THEN 1 ELSE 0 END) AS last_30d,
            SUM(CASE 
                    WHEN Phone IS NOT NULL AND Phone <> '' AND Phone <> 'None' 
                    THEN 1 ELSE 0 END) AS total
        FROM phone_enrichment_logs_new
        GROUP BY Platform
        ORDER BY total DESC
        LIMIT :limit
        """
        with engine.connect() as conn:
            result = conn.execute(text(sql), {"limit": limit})
            raw_rows = [dict(r) for r in result.mappings().all()]

        # Normalize keys for templates (use lowercase attribute-style names)
        rows = []
        for r in raw_rows:
            rows.append({
                "platform": r.get("Platform") or r.get("platform") or "Unknown",
                "last_24h": int(r.get("last_24h") or 0),
                "last_7d": int(r.get("last_7d") or 0),
                "last_30d": int(r.get("last_30d") or 0),
                "total": int(r.get("total") or 0)
            })
        return rows

    except Exception:
        import traceback
        print("Error fetching phone enrichment metrics:")
        print(traceback.format_exc())
        return []


def get_pivoted_classification_data(start_date, end_date):
    """
    Safe wrapper around existing pivot helpers.
    - Accepts `start_date`/`end_date` as 'YYYY-MM-DD' strings or date/datetime objects.
    - Converts to Monday-Sunday week boundaries automatically.
    - Returns a dict with keys:
        - account_classification: list of rows (dict) with 'account_type' key + week columns
        - phone_enrichment: list of rows (dict) (unchanged)
        - email_verification: list of rows (dict) (unchanged)
        - address_enhancement: list of rows (dict) (unchanged)
        - contact_count_by_account_type: list of rows (dict) with 'account_type' and 'contact_count'
      plus metadata key '_requested_range'.
    - On per-metric failure returns {"error": "<Type>: <msg>"} for that metric.
    """
    from datetime import datetime, date, timedelta

    def norm_date(d):
        if isinstance(d, (date, datetime)):
            return d.date() if isinstance(d, datetime) else d
        if isinstance(d, str):
            try:
                return datetime.strptime(d, "%Y-%m-%d").date()
            except ValueError:
                raise ValueError("Dates must be 'YYYY-MM-DD'")
        raise ValueError("start_date/end_date must be str or date/datetime")

    # Normalize both dates
    start_date_obj = norm_date(start_date)
    end_date_obj = norm_date(end_date)
    
    # Convert start to Monday of its week
    start_monday = start_date_obj - timedelta(days=start_date_obj.weekday())
    
    # Convert end to Sunday of its week (Monday + 6 days)
    end_sunday = end_date_obj - timedelta(days=end_date_obj.weekday()) + timedelta(days=6)
    
    # Convert back to ISO strings
    start = start_monday.isoformat()
    end = end_sunday.isoformat()

    out = {"_requested_range": {"start_date": start, "end_date": end}}

    # account classification (convert dict -> list)
    try:
        acct = accountTypeClassificationPivot(start, end) or {}
        # acct is dict: {account_type: {label: count, ...}, ...}
        acct_rows = []
        for account_type, counts in acct.items():
            row = {"account_type": account_type}
            row.update(counts)
            acct_rows.append(row)
        out["account_classification"] = acct_rows
    except Exception as e:
        out["account_classification"] = {"error": f"{type(e).__name__}: {e}"}

    # phone enrichment
    try:
        out["phone_enrichment"] = get_weekly_phone_enrichment_pivot(start, end) or []
    except Exception as e:
        out["phone_enrichment"] = {"error": f"{type(e).__name__}: {e}"}

    # email verification
    try:
        out["email_verification"] = get_email_verification_weekly_pivot(start, end) or []
    except Exception as e:
        out["email_verification"] = {"error": f"{type(e).__name__}: {e}"}

    # address enhancement
    try:
        out["address_enhancement"] = get_address_pivot_enhance_metrics(start, end) or []
    except Exception as e:
        out["address_enhancement"] = {"error": f"{type(e).__name__}: {e}"}

    # contact count by account type
    try:
        out["contact_count_by_account_type"] = get_contact_count_based_on_account_type() or []
    except Exception as e:
        out["contact_count_by_account_type"] = {"error": f"{type(e).__name__}: {e}"}

    return out


def update_classification_data():
    """
    Run classification stats query and save result into Redis under HKEY 'classificationdata'.
    Also store the last update timestamp.
    """
    # Using local JSON-backed storage instead of Redis
    query = text("""
    WITH date_counts AS (
        SELECT 
            a.accountid,
            COALESCE(NULLIF(a.account_type, ''), 'Unclassified') AS account_type_group,
            CASE WHEN acf.cf_925 >= NOW() - INTERVAL 1 DAY THEN 1 ELSE 0 END AS is_24h,
            CASE WHEN acf.cf_925 >= NOW() - INTERVAL 7 DAY THEN 1 ELSE 0 END AS is_7d,
            CASE WHEN acf.cf_925 >= NOW() - INTERVAL 30 DAY THEN 1 ELSE 0 END AS is_30d,
            acf.cf_925
        FROM vtiger_account a
        INNER JOIN vtiger_accountscf acf ON a.accountid = acf.accountid
        WHERE acf.cf_925 > '1970-01-01'
    )
    SELECT
        account_type_group,
        SUM(is_24h) AS last_24h,
        SUM(is_7d) AS last_7d,
        SUM(is_30d) AS last_30d,
        COUNT(*) AS total,
        MIN(cf_925) AS oldest_date,
        MAX(cf_925) AS newest_date,
        (SELECT MIN(cf_925) FROM vtiger_accountscf WHERE cf_925 > '1970-01-01') AS overall_oldest_date
    FROM date_counts
    GROUP BY account_type_group
    ORDER BY account_type_group;

    """)

    try:
        with engine.connect() as conn:
            result = conn.execute(query.execution_options(timeout=300))
            rows = [dict(row) for row in result.mappings().all()]


        updated_at = datetime.now().isoformat()

        # Clear previous data to avoid stale fields and ensure a clean replace
        try:
            json_delete("classificationdata")
        except Exception:
            pass

    # Save each row in Redis hash. Convert non-JSON types (dates, decimals) to strings.
        for idx, row in enumerate(rows):
            try:
                # Normalize account_type_group (from SQL query) to account_type
                account_type = row.get("account_type") or row.get("account_type_group") or f"Unclassified_{idx}"
                
                # If account_type is missing or empty, use a stable fallback key
                if not account_type or str(account_type).strip() == "":
                    field_key = "Unclassified"
                else:
                    # Normalize to string and strip
                    field_key = str(account_type).strip()

                # Create JSON-safe copy
                safe_row = {}
                for k, v in row.items():
                    # Convert date/datetime to ISO string
                    if isinstance(v, (datetime, date)):
                        safe_row[k] = v.isoformat()
                    else:
                        safe_row[k] = v

                # Normalize account type: rename account_type_group to account_type for template compatibility
                if 'account_type_group' in safe_row and 'account_type' not in safe_row:
                    safe_row['account_type'] = safe_row.pop('account_type_group')
                
                # Ensure account_type exists
                safe_row['account_type'] = safe_row.get('account_type') or field_key
                
                # Attach update timestamp
                safe_row["updated_at"] = updated_at

                # Normalize per-row oldest/newest date
                safe_row['oldest_date'] = safe_row.get('oldest_date') or 'N/A'
                safe_row['newest_date'] = safe_row.get('newest_date') or 'N/A'

                # Store overall oldest date separately (same for all rows) after loop below

                # Use default=str as a final fallback for decimals or other types
                json_str = json.dumps(safe_row, default=str)
                json_hset("classificationdata", field_key, json_str)
            except Exception as row_e:
                # Log and continue with next row
                print(f"Failed to store classification row for '{row.get('account_type', '')}': {row_e}")

        # Also store the global updated_at key
        json_hset("classificationdata", "_last_update", updated_at)

        # Store overall oldest date (single value) for top-of-page display
        overall_oldest = None
        if rows and isinstance(rows, list) and len(rows) > 0:
            overall_oldest = rows[0].get('overall_oldest_date')
        try:
            json_hset("classificationdata", "_overall_oldest_date", overall_oldest)
        except Exception:
            try:
                json_hset("classificationdata", "_overall_oldest_date", str(overall_oldest))
            except Exception:
                pass

        # Also compute and store auxiliary metrics (phone, email verification, address enhancement)
        try:
            try:
                phone_metrics = get_phone_enrichment_metrics()
            except Exception:
                phone_metrics = []

            try:
                email_metrics = get_email_verification_metrics()
            except Exception:
                email_metrics = []

            try:
                address_metrics = get_Address_enhance_metrics()
            except Exception:
                address_metrics = []

            # Normalize and store as JSON strings under sentinel keys
            try:
                json_hset("classificationdata", "_phone_metrics", phone_metrics)
            except Exception:
                try:
                    json_hset("classificationdata", "_phone_metrics", str(phone_metrics))
                except Exception:
                    pass

            try:
                json_hset("classificationdata", "_email_status_metrics", email_metrics)
            except Exception:
                try:
                    json_hset("classificationdata", "_email_status_metrics", str(email_metrics))
                except Exception:
                    pass

            try:
                json_hset("classificationdata", "_address_enhance_metrics", address_metrics)
            except Exception:
                try:
                    json_hset("classificationdata", "_address_enhance_metrics", str(address_metrics))
                except Exception:
                    pass
        except Exception:
            # Best-effort only; do not fail the main update if these metrics can't be computed
            pass

        print(f"Classification data updated in Redis with {len(rows)} records at {updated_at}.")
        return True
    except Exception as e:
        print(f"Error updating classification data: {e}")
        import traceback
        print(traceback.format_exc())
        return False




def get_classification_data():
    """
    Fetch classification stats from Redis 'classificationdata' and return as dict:
    {
        "data": [...list of rows...],
        "last_update": "timestamp"
    }
    """
    try:
        # Read from JSON-backed storage
        data = json_hgetall("classificationdata")  # dict of {account_type: json_str or timestamp}
        if not data:
            print("No classification data found in storage.")
            return {"data": [], "last_update": None}

        results = []
        last_update = None
        overall_oldest = None
        phone_metrics = None
        email_status_metrics = None
        address_enhance_metrics = None

        for k, v in data.items():
            key_str = str(k)
            # v may be a JSON string or a native object
            if isinstance(v, str):
                val_str = v
            else:
                try:
                    val_str = json.dumps(v, default=str)
                except Exception:
                    val_str = str(v)

            # Handle last update sentinel
            if key_str == "_last_update":
                last_update = val_str
                continue

            # Handle overall oldest sentinel
            if key_str == "_overall_oldest_date":
                try:
                    overall_oldest = json.loads(val_str)
                except Exception:
                    overall_oldest = val_str
                continue

            # Phone/email/address sentinel keys
            if key_str == "_phone_metrics":
                try:
                    phone_metrics = json.loads(val_str)
                except Exception:
                    phone_metrics = val_str
                continue

            if key_str == "_email_status_metrics":
                try:
                    email_status_metrics = json.loads(val_str)
                except Exception:
                    email_status_metrics = val_str
                continue

            if key_str == "_address_enhance_metrics":
                try:
                    address_enhance_metrics = json.loads(val_str)
                except Exception:
                    address_enhance_metrics = val_str
                continue

            try:
                obj = json.loads(val_str)
            except Exception:
                # If value isn't JSON, store raw as value
                obj = {"value": val_str}

            # Ensure account_type is present for template display; fallback to hash field name
            if not obj.get('account_type'):
                obj['account_type'] = key_str
            
            # Convert numeric string values back to integers for template calculations
            numeric_fields = ['last_24h', 'last_7d', 'last_30d', 'total']
            for field in numeric_fields:
                if field in obj:
                    try:
                        obj[field] = int(obj[field])
                    except (ValueError, TypeError):
                        obj[field] = 0

            results.append(obj)

        return {
            "data": results,
            "last_update": last_update,
            "overall_oldest_date": overall_oldest,
            "phone_metrics": phone_metrics,
            "email_status_metrics": email_status_metrics,
            "address_enhance_metrics": address_enhance_metrics
        }
    except Exception as e:
        print(f"Error fetching classification data: {e}")
        return {"data": [], "last_update": None, "overall_oldest_date": None}




def get_new_id_from_db(session):
    try:
        max_id = session.query(VtigerCrmentitySeq.id).scalar() or -1
        #increase by 1 to get next id
        if max_id > 0:
            next_id = max_id + 1
            #save the new id in the vtiger_crmentity_seq table
            crmEntitySeqData = {'id': next_id}
            session.query(VtigerCrmentitySeq).update(crmEntitySeqData)
            return next_id
        else:
            return -1
    except Exception as e:
        print(f'get_new_id_from_db failed with error {e}')
        return -1


def getAccountByDOmainFromDatabase(domain: str):
    with Session() as session:
        result = (session.query(
            vtigerAccount.accountid,
            vtigerAccount.accountname,
            vtigerAccount.phone,
            vtigerAccount.otherphone,
            VtigerAccountsCf.cf_869,  # Domain Name
            VtigerAccountsCf.cf_909,  #Throird Phone
            VtigerAccountsCf.cf_911,  #Forth Phone
            VtigerAccountsCf.cf_913,  #Fifth Phone  
            VtigerAccountsCf.cf_915,  #Sixth Phone
            VtigerAccountsCf.cf_917,  #Seventh Phone
            VtigerAccountsCf.cf_919,  #Eight Phone
            VtigerAccountsCf.cf_921,  #Nineth Phone
        )
        .select_from(vtigerAccount)
        .join(VtigerAccountsCf, VtigerAccountsCf.accountid == vtigerAccount.accountid)
		.join(VtigerCrmentity, VtigerCrmentity.crmid == vtigerAccount.accountid)
        .filter(VtigerAccountsCf.cf_869 == domain, VtigerCrmentity.deleted == 0)
        .first()
        )

    if not result:
        return None

    account_dict = {
        "crmentity": {
            "crmid": result.accountid
        },
        "account_detail": {
            "accountid": result.accountid,
            "accountname": result.accountname,
            "phone": result.phone,
            "otherphone": result.otherphone
        },
        "account_custom_fields": {
            "cf_869": result.cf_869,
            "cf_909": result.cf_909,
            "cf_911": result.cf_911,
            "cf_913": result.cf_913,
            "cf_915": result.cf_915,
            "cf_917": result.cf_917,
            "cf_919": result.cf_919,
            "cf_921": result.cf_921
        }
    }

    return account_dict


def getContactByEmailFromDatabase(email: str):
    with Session() as session:  # Use Session() to create a session instance
        result = (session.query(
                    VtigerCrmentity.crmid,
                    VtigerContactDetails.contactid,
                    VtigerContactDetails.firstname, 
                    VtigerContactDetails.lastname,
                    VtigerContactDetails.email,
                    VtigerContactDetails.phone,
                    VtigerContactDetails.mobile,
                    VtigerContactSubDetails.homephone,
                    VtigerContactSubDetails.otherphone,
                    VtigerContactSubDetails.assistantphone
                )
                .select_from(VtigerContactDetails)
                .join(VtigerCrmentity, VtigerContactDetails.contactid == VtigerCrmentity.crmid)
                .join(VtigerContactSubDetails, VtigerContactSubDetails.contactsubscriptionid == VtigerCrmentity.crmid)
                .filter(VtigerContactDetails.email == email, VtigerCrmentity.deleted == 0)
                .first())
        
        if not result:
            return None
        
        # Map the result to your desired format using only available columns
        contact_dict = {
            "crmentity": {
                "crmid": result.crmid
            },
            "contact_details": {
                "contactid": result.contactid,
                "firstname": result.firstname,
                "lastname": result.lastname,
                "email": result.email,
                "phone": result.phone,
                "mobile": result.mobile
            },
            "contact_subdetails": {
                "homephone": result.homephone,
                "otherphone": result.otherphone,
                "assistantphone": result.assistantphone
            }
        }
        
        return contact_dict


def _create_crmentity(session, entity_data, set_type):
    """
    Helper function to create a VtigerCrmentity record and return the crmid.
    Raises exception on failure.
    
    Args:
        session: SQLAlchemy session
        entity_data: Dictionary of crmentity fields
        set_type: Entity type (e.g., 'Accounts', 'Contacts')
        
    Returns:
        int: Newly created crmid
    """
    try:
        # (Old Implementation -- DO NOT USE) Get the next available ID
        #max_id = session.query(func.max(VtigerCrmentity.crmid)).scalar() or 0
        #next_id = max_id + 1

        # (New Implementation) first get max_id from vtiger_crmentity_seq table
        next_id = get_new_id_from_db(session)
        if next_id == -1:
            raise ValueError("crm_entity.id cannot be fetched from db. ")

        # Validate input
        if not isinstance(entity_data, dict):
            raise ValueError("entity_data must be a dictionary")
        if 'source' not in entity_data:
            raise ValueError("The 'source' field is required in crmentity data")


        # Prepare crmentity data with default values
        crmentity_data = {
            'crmid': next_id,
            'smcreatorid': entity_data.get('smcreatorid', 1),
            'smownerid': entity_data.get('smownerid', 1),
            'modifiedby': entity_data.get('modifiedby', 1),
            'setype': set_type,
            'description': entity_data.get('description'),
            'createdtime': entity_data.get('createdtime', datetime.now()),
            'modifiedtime': entity_data.get('modifiedtime', datetime.now()),
            'viewedtime': entity_data.get('viewedtime'),
            'status': entity_data.get('status'),
            'version': entity_data.get('version', 0),
            'presence': entity_data.get('presence', 1),
            'deleted': entity_data.get('deleted', 0),
            'source': entity_data['source'],
            'label': entity_data.get('label')
        }

        # Create and persist record
        crmentity = VtigerCrmentity(**crmentity_data)
        session.add(crmentity)
        session.flush()  # Ensure immediate persistence
        
        return next_id
        
    except Exception as e:
        session.rollback()
        raise RuntimeError(f"Failed to create crmentity record: {str(e)}") from e




def insertIntoAccounts(Account_data: dict):
    """
    Insert a new Account into all related tables with proper transaction management.
    
    Args:
        Account_data: A dictionary containing data for all tables with keys:
            - crmentity: dict of VtigerCrmentity fields (must include 'source')
            - Account_Detail: dict of vtigerAccount fields
            - Account_BillAd: dict of VtigerAccountBillads fields (optional)
            - Account_ShipAd: dict of VtigerShipAds fields (optional)
            - Account_custom_fields: dict of VtigerAccountCf fields (optional)
            
    Returns:
        int: The newly created account ID
        
    Raises:
        ValueError: If required fields are missing
        Exception: For any database errors
    """
    with Session() as db_session:
        try:
            # Start a transaction
            db_session.begin()

            # Validate input data structure
            if not isinstance(Account_data, dict):
                raise ValueError("Account_data must be a dictionary")
            
            # Process and truncate website field if present
            website = Account_data.get("account_detail", {}).get("website", "")
            if website:
                website = extract_base_url(website)
                website = website[:100]
                Account_data["account_detail"]["website"] = website

            # Create crmentity record first
            crmentity_data = Account_data.get('crmentity', {})
            if not crmentity_data or 'source' not in crmentity_data:
                raise ValueError("The 'source' field is required in crmentity data")

            # Generate new crmid
            next_id = _create_crmentity(db_session, crmentity_data, set_type='Accounts')

            # Account Details - validate required fields
            if 'accountphone' in Account_data['account_detail']:
                Account_data['account_detail']['phone'] = Account_data['account_detail']['accountphone']
                Account_data['account_detail'].pop('accountphone')
            if 'account_detail' in Account_data and 'employees' in Account_data['account_detail'] and Account_data['account_detail']['employees']=='':
                Account_data['account_detail'].pop('employees')

            Account_details_data = Account_data.get('account_detail', {})
            if not Account_details_data:
                raise ValueError("Account_Detail data is required")

            Account_details_data['accountid'] = next_id
            Account_details_data.setdefault('account_no', f"ACC{next_id}")

            if 'accountname' not in Account_details_data:
                raise ValueError("accountname is required in Account_Detail")

            # Clean and validate phone numbers
            for phone_field in ['phone', 'otherphone']:
                if phone_field in Account_details_data and Account_details_data[phone_field] == '':
                    Account_details_data[phone_field] = None

            # Create account record
            account = vtigerAccount(**Account_details_data)
            db_session.add(account)
            db_session.flush()  # Ensure account is persisted before addresses

            # Process Billing Address if provided
            Account_billadd_data = Account_data.get('account_billads', {})
            if Account_billadd_data:
                Account_billadd_data['accountaddressid'] = next_id
                # Clean empty strings
                for field in ['bill_city', 'bill_code', 'bill_country', 'bill_state', 'bill_street', 'bill_pobox']:
                    if field in Account_billadd_data and Account_billadd_data[field] == '':
                        Account_billadd_data[field] = None
                Account_BillAdd_Detail = VtigerAccountBillAddress(**Account_billadd_data)
                db_session.add(Account_BillAdd_Detail)

            # Process Shipping Address if provided
            Account_ShipAdd_data = Account_data.get('account_shipad', {})
            if Account_ShipAdd_data:
                Account_ShipAdd_data['accountaddressid'] = next_id
                # Clean empty strings
                for field in ['ship_city', 'ship_code', 'ship_country', 'ship_state', 'ship_pobox', 'ship_street']:
                    if field in Account_ShipAdd_data and Account_ShipAdd_data[field] == '':
                        Account_ShipAdd_data[field] = None
                Account_ShipAdd_Detail = VtigerAccountShipAddress(**Account_ShipAdd_data)
                db_session.add(Account_ShipAdd_Detail)

            # Process Custom Fields if provided
            custom_fields_data = Account_data.get('account_custom_fields', {})
            if custom_fields_data:
                custom_fields_data['accountid'] = next_id

                # Clean and validate numeric fields
                numeric_fields = {
                    'cf_871': 'integer',  # Organization ID
                    'cf_889': 'integer',  # Funding Rounds
                    'cf_891': 'decimal'   # Last Funding Amount
                }

                for field, field_type in numeric_fields.items():
                    if field in custom_fields_data:
                        try:
                            if custom_fields_data[field] == '':
                                custom_fields_data[field] = None
                            elif custom_fields_data[field] is not None:
                                if field_type == 'integer':
                                    custom_fields_data[field] = int(custom_fields_data[field])
                                elif field_type == 'decimal':
                                    custom_fields_data[field] = float(custom_fields_data[field])
                        except (ValueError, TypeError):
                            custom_fields_data[field] = None

                # Clean empty strings for other fields
                for field in custom_fields_data:
                    if isinstance(custom_fields_data[field], str) and custom_fields_data[field].strip() == '':
                        custom_fields_data[field] = None
                #set CF_925 to 1970-01-01 if not provided
                if 'cf_925' not in custom_fields_data or not custom_fields_data['cf_925']:
                    custom_fields_data['cf_925'] = datetime(1970, 1, 1)

                Account_custom_fields = VtigerAccountsCf(**custom_fields_data)
                db_session.add(Account_custom_fields)

            db_session.commit()
            return next_id

        except Exception as e:
            db_session.rollback()
            raise e



def insertIntoContact(contact_data: dict):
    """
    Insert a new contact into all related tables.
    
    Args:
        contact_data: A dictionary containing data for all tables with keys:
            - crmentity: dict of VtigerCrmentity fields
            - contact_details: dict of VtigerContactDetails fields
            - contact_subdetails: dict of VtigerContactSubDetails fields
            - contact_address: dict of VtigerContactAddress fields
            - custom_fields: dict of VtigerContactsCf fields
    """
    with Session() as db_session:
        try:
            crmentity_data = contact_data.get('crmentity', {})
            contact_id = _create_crmentity(db_session, crmentity_data, set_type='Contacts')

            # Contact Details
            if 'contactphone' in contact_data['contact_details']:
                contact_data['contact_details']['phone'] = contact_data['contact_details']['contactphone']
                contact_data['contact_details'].pop('contactphone')

            if 'firstname' in contact_data['contact_details'] and contact_data['contact_details']['firstname']:
                contact_data['contact_details']['firstname']=contact_data['contact_details']['firstname'][:40]

            contact_details_data = contact_data.get('contact_details', {})

            contact_details_data['contactid'] = contact_id
            contact_details = VtigerContactDetails(**contact_details_data)
            db_session.add(contact_details)

            # Contact Sub Details
            contact_subdetails_data = contact_data.get('contact_subdetails', {})
            contact_subdetails_data['contactsubscriptionid'] = contact_id
            contact_subdetails = VtigerContactSubDetails(**contact_subdetails_data)
            db_session.add(contact_subdetails)

            # Contact Address
            contact_address_data = contact_data.get('contact_address', {})
            contact_address_data['contactaddressid'] = contact_id
            contact_address = VtigerContactAddress(**contact_address_data)
            db_session.add(contact_address)

            # Custom Fields
            contact_cf_data = contact_data.get('custom_fields', {})
            contact_cf_data['contactid'] = contact_id
            contact_cf = VtigerContactsCf(**contact_cf_data)
            db_session.add(contact_cf)

            db_session.commit()
            return contact_id

        except Exception as e:
            db_session.rollback()
            raise e



def getAccountByDomain(domain: str):
    """
    Retrieve account information by domain (cf_869) from database only.
    
    Args:
        domain (str): Domain to search for (case-insensitive)
        
    Returns:
        dict: Account data structured with tables as keys and field values,
              or None if account not found
    """
    try:
        with Session() as db_session:
            # Query joining all related account tables
            result = (db_session.query(VtigerCrmentity, vtigerAccount,
                                VtigerAccountBillAddress, VtigerAccountShipAddress,
                                VtigerAccountsCf)
                     .join(vtigerAccount, vtigerAccount.accountid == VtigerCrmentity.crmid)
                     .join(VtigerAccountBillAddress, VtigerAccountBillAddress.accountaddressid == VtigerCrmentity.crmid)
                     .join(VtigerAccountShipAddress, VtigerAccountShipAddress.accountaddressid == VtigerCrmentity.crmid)
                     .join(VtigerAccountsCf, VtigerAccountsCf.accountid == VtigerCrmentity.crmid)
                     .filter(VtigerCrmentity.deleted == 0,
                             func.lower(VtigerAccountsCf.cf_869) == domain.lower())
                     .first())
            
            if not result:
                return None
            
            # Unpack the result tuple
            crmentity, account_details, bill_address, ship_address, account_cf = result
            
            # Convert datetime objects to string values
            created_time_str = crmentity.createdtime.strftime('%Y-%m-%d %H:%M:%S') if crmentity.createdtime else None
            modified_time_str = crmentity.modifiedtime.strftime('%Y-%m-%d %H:%M:%S') if crmentity.modifiedtime else None
            viewed_time_str = crmentity.viewedtime.strftime('%Y-%m-%d %H:%M:%S') if crmentity.viewedtime else None
            
            # Convert date objects to string values
            cf_885_str = account_cf.cf_885.strftime('%Y-%m-%d') if account_cf.cf_885 else None
            
            # Structure the data according to account table structure
            account_dict = {
                "crmentity": {
                    'crmid': crmentity.crmid,
                    'smownerid': crmentity.smownerid,
                    'smcreatorid': crmentity.smcreatorid,
                    'modifiedby': crmentity.modifiedby,
                    'setype': crmentity.setype,
                    'description': crmentity.description,
                    'createdtime': created_time_str,  # String value
                    'modifiedtime': modified_time_str,  # String value
                    'viewedtime': viewed_time_str,  # String value
                    'status': crmentity.status,
                    'version': crmentity.version,
                    'presence': crmentity.presence,
                    'deleted': crmentity.deleted,
                    'source': crmentity.source,
                    'label': crmentity.label
                },
                "account_details": {
                    'account_no': account_details.account_no,
                    'accountname': account_details.accountname,
                    'parentid': account_details.parentid,
                    'account_type': account_details.account_type,
                    'industry': account_details.industry,
                    'annualrevenue': float(account_details.annualrevenue) if account_details.annualrevenue else None,
                    'rating': account_details.rating,
                    'ownership': account_details.ownership,
                    'siccode': account_details.siccode,
                    'tickersymbol': account_details.tickersymbol,
                    'phone': account_details.phone,
                    'otherphone': account_details.otherphone,
                    'email1': account_details.email1,
                    'email2': account_details.email2,
                    'website': account_details.website,
                    'fax': account_details.fax,
                    'employees': account_details.employees,
                    'emailoptout': account_details.emailoptout,
                    'notify_owner': account_details.notify_owner,
                    'isconvertedfromlead': account_details.isconvertedfromlead,
                    'tags': account_details.tags
                },
                "account_billads": {
                    'bill_city': bill_address.bill_city,
                    'bill_code': bill_address.bill_code,
                    'bill_country': bill_address.bill_country,
                    'bill_state': bill_address.bill_state,
                    'bill_street': bill_address.bill_street,
                    'bill_pobox': bill_address.bill_pobox
                },
                "account_shipads": {
                    'ship_city': ship_address.ship_city,
                    'ship_code': ship_address.ship_code,
                    'ship_country': ship_address.ship_country,
                    'ship_state': ship_address.ship_state,
                    'ship_pobox': ship_address.ship_pobox,
                    'ship_street': ship_address.ship_street
                },
                "account_custom_fields": {
                    'cf_869': account_cf.cf_869,  # Domain name
                    'cf_871': account_cf.cf_871,  # Organization ID
                    'cf_879': account_cf.cf_879,  # Linkedin
                    'cf_881': account_cf.cf_881,  # Facebook
                    'cf_883': account_cf.cf_883,  # Twitter/X
                    'cf_885': cf_885_str,  # Founded on (string value)
                    'cf_887': account_cf.cf_887,  # CrunchBase Link
                    'cf_889': account_cf.cf_889,  # Funding Rounds
                    'cf_891': float(account_cf.cf_891) if account_cf.cf_891 else None,  # Last Funding Round Amounts
                    'cf_893': account_cf.cf_893,  # Logo URL
                    'cf_895': account_cf.cf_895,  # Annual Revenue Range
                    'cf_897': account_cf.cf_897,  # FIPS Code
                    'cf_899': account_cf.cf_899,  # Employee Range
                    'cf_901': account_cf.cf_901,  # Partner Level
                    'cf_903': account_cf.cf_903,  # Partner Name
                    'cf_905': account_cf.cf_905,  # Partner Type
                    'cf_909': account_cf.cf_909,  # Third Phone
                    'cf_911': account_cf.cf_911,  # Forth Phone
                    'cf_913': account_cf.cf_913,  # Fifth Phone
                    'cf_915': account_cf.cf_915,  # Sixth Phone
                    'cf_917': account_cf.cf_917,  # Seventh Phone
                    'cf_919': account_cf.cf_919,  # Eight Phone
                    'cf_921': account_cf.cf_921  # Nineth Phone
                }
            }
            
            return account_dict
            
    except Exception as e:
        print(f"Error querying database for domain {domain}: {str(e)}")
        import traceback
        print(f"Full traceback: {traceback.format_exc()}")
        return None

def getContactsByEmail(email: str):
    """
    Retrieve contact information by email address from database only.
    
    Args:
        email (str): Email address to search for (case-insensitive)
        
    Returns:
        dict: Contact data structured with tables as keys and field values,
              or None if contact not found
    """
    try:
        with Session() as db_session:
            # Query joining all related contact tables
            result = (db_session.query(VtigerCrmentity, VtigerContactDetails,
                                VtigerContactSubDetails, VtigerContactAddress,
                                VtigerContactsCf)
                     .join(VtigerContactDetails, VtigerContactDetails.contactid == VtigerCrmentity.crmid)
                     .join(VtigerContactSubDetails, VtigerContactSubDetails.contactsubscriptionid == VtigerCrmentity.crmid)
                     .join(VtigerContactAddress, VtigerContactAddress.contactaddressid == VtigerCrmentity.crmid)
                     .join(VtigerContactsCf, VtigerContactsCf.contactid == VtigerCrmentity.crmid)
                     .filter(VtigerCrmentity.deleted == 0,
                             func.lower(VtigerContactDetails.email) == email.lower())
                     .first())
            
            if not result:
                return None
            
            # Unpack the result tuple
            crmentity, contact_details, contact_subdetails, contact_address, contact_cf = result
            
            # Convert datetime objects to string values
            created_time_str = crmentity.createdtime.strftime('%Y-%m-%d %H:%M:%S') if crmentity.createdtime else None
            modified_time_str = crmentity.modifiedtime.strftime('%Y-%m-%d %H:%M:%S') if crmentity.modifiedtime else None
            viewed_time_str = crmentity.viewedtime.strftime('%Y-%m-%d %H:%M:%S') if crmentity.viewedtime else None
            
            # Convert date objects to string values
            birthday_str = contact_subdetails.birthday.strftime('%Y-%m-%d') if contact_subdetails.birthday else None
            cf_923_str = contact_cf.cf_923.strftime('%Y-%m-%d') if contact_cf.cf_923 else None
            
            # Structure the data according to the required format
            contact_dict = {
                "crmentity": {
                    "crmid": crmentity.crmid,
                    'smownerid': crmentity.smownerid,
                    'smcreatorid': crmentity.smcreatorid,
                    'modifiedby': crmentity.modifiedby,
                    'setype': crmentity.setype,
                    'description': crmentity.description,
                    'createdtime': created_time_str,  # String value
                    'modifiedtime': modified_time_str,  # String value
                    'viewedtime': viewed_time_str,  # String value
                    'status': crmentity.status,
                    'version': crmentity.version,
                    'presence': crmentity.presence,
                    'deleted': crmentity.deleted,
                    'source': crmentity.source,
                    'label': crmentity.label
                },
                "contact_details": {
                    'contact_no': contact_details.contact_no,
                    'accountid': contact_details.accountid,
                    'salutation': contact_details.salutation,
                    'firstname': contact_details.firstname,
                    'lastname': contact_details.lastname,
                    'email': contact_details.email,
                    'contactphone': contact_details.phone,
                    'mobile': contact_details.mobile,
                    'title': contact_details.title,
                    'department': contact_details.department,
                    'fax': contact_details.fax,
                    'reportsto': contact_details.reportsto,
                    'training': contact_details.training,
                    'usertype': contact_details.usertype,
                    'contacttype': contact_details.contacttype,
                    'otheremail': contact_details.otheremail,
                    'secondaryemail': contact_details.secondaryemail,
                    'donotcall': contact_details.donotcall,
                    'emailoptout': contact_details.emailoptout,
                    'imagename': contact_details.imagename,
                    'reference': contact_details.reference,
                    'notify_owner': contact_details.notify_owner,
                    'isconvertedfromlead': contact_details.isconvertedfromlead,
                    'tags': contact_details.tags
                },
                "contact_subdetails": {
                    'homephone': contact_subdetails.homephone,
                    'otherphone': contact_subdetails.otherphone,
                    'assistant': contact_subdetails.assistant,
                    'assistantphone': contact_subdetails.assistantphone,
                    'birthday': birthday_str,  # String value
                    'laststayintouchrequest': contact_subdetails.laststayintouchrequest,
                    'laststayintouchsavedate': contact_subdetails.laststayintouchsavedate,
                    'leadsource': contact_subdetails.leadsource
                },
                "contact_address": {
                    'mailingcity': contact_address.mailingcity,
                    'mailingstreet': contact_address.mailingstreet,
                    'mailingcountry': contact_address.mailingcountry,
                    'othercountry': contact_address.othercountry,
                    'mailingstate': contact_address.mailingstate,
                    'mailingpobox': contact_address.mailingpobox,
                    'othercity': contact_address.othercity,
                    'otherstate': contact_address.otherstate,
                    'mailingzip': contact_address.mailingzip,
                    'otherzip': contact_address.otherzip,
                    'otherstreet': contact_address.otherstreet,
                    'otherpobox': contact_address.otherpobox
                },
                "custom_fields": {
                    'cf_853': contact_cf.cf_853,
                    'cf_855': contact_cf.cf_855,
                    'cf_857': contact_cf.cf_857,
                    'cf_859': contact_cf.cf_859,
                    'cf_863': contact_cf.cf_863,
                    'cf_867': contact_cf.cf_867,
                    'cf_875': contact_cf.cf_875,
                    'cf_877': contact_cf.cf_877,
                    'cf_907': contact_cf.cf_907,
                    'cf_923': cf_923_str  # String value
                }
            }
            
            return contact_dict
            
    except Exception as e:
        print(f"Error querying database for email {email}: {str(e)}")
        import traceback
        print(f"Full traceback: {traceback.format_exc()}")
        return None

def updateAccounts(account_id: int, account_data: dict):
    """
    Update an existing account in all related tables.
    
    Args:
        account_id: The CRM ID of the account to update
        account_data: A dictionary containing data to update with keys:
            - crmentity: dict of VtigerCrmentity fields to update
            - account_details: dict of vtigerAccount fields to update
            - account_billads: dict of VtigerAccountBillAddress fields to update
            - account_ship_address: dict of VtigerAccountShipAddress fields to update
            - account_custom_fields: dict of VtigerAccountsCf fields to update
    """
    with Session() as db_session:
        try:
            # Update crmentity
            crmentity_data = account_data.get('crmentity', {})
            if crmentity_data:
                crmentity_data['modifiedtime'] = datetime.now()
                db_session.query(VtigerCrmentity).filter(VtigerCrmentity.crmid == account_id).update(crmentity_data)
            
            # Process and truncate website field if present
            if 'website' in account_data.get('account_detail', {}):
                website = account_data['account_detail']['website']
                if website:
                    website = extract_base_url(website)
                    website = website[:100]
                    account_data['account_detail']['website'] = website
                    
            #turncate empty string in employee field
            if 'employees' in account_data.get('account_detail', {}) and account_data['account_detail']['employees']=='':
                account_data['account_detail'].pop('employees')

            # Update account details
            if 'accountphone' in account_data['account_detail']:
                account_data['account_detail']['phone'] = account_data['account_detail']['accountphone']
                account_data['account_detail'].pop('accountphone')
            account_details_data = account_data.get('account_detail', {})
            if account_details_data:
                db_session.query(vtigerAccount).filter(vtigerAccount.accountid == account_id).update(account_details_data)

            # Update billing address
            bill_address_data = account_data.get('account_billads', {})
            if bill_address_data:
                db_session.query(VtigerAccountBillAddress).filter(VtigerAccountBillAddress.accountaddressid == account_id).update(bill_address_data)

            # Update shipping address
            ship_address_data = account_data.get('account_ship_address', {})
            if ship_address_data:
                db_session.query(VtigerAccountShipAddress).filter(VtigerAccountShipAddress.accountaddressid == account_id).update(ship_address_data)

            # Update custom fields
            custom_fields_data = account_data.get('account_custom_fields', {})
            if custom_fields_data:
                db_session.query(VtigerAccountsCf).filter(VtigerAccountsCf.accountid == account_id).update(custom_fields_data)

            db_session.commit()
            return True

        except Exception as e:
            db_session.rollback()
            raise e




def updateContacts(contact_id: int, contact_data: dict):
    """
    Update an existing contact in all related tables.
    
    Args:
        contact_id: The CRM ID of the contact to update
        contact_data: A dictionary containing data to update with keys:
            - crmentity: dict of VtigerCrmentity fields to update
            - contact_details: dict of VtigerContactDetails fields to update
            - contact_subdetails: dict of VtigerContactSubDetails fields to update
            - contact_address: dict of VtigerContactAddress fields to update
            - custom_fields: dict of VtigerContactsCf fields to update
    """
    with Session() as db_session:
        try:
            # Update crmentity
            crmentity_data = contact_data.get('crmentity', {})
            if crmentity_data:
                crmentity_data['modifiedtime'] = datetime.now()
                db_session.query(VtigerCrmentity).filter(VtigerCrmentity.crmid == contact_id).update(crmentity_data)

            # Update contact details
            if 'contactphone' in contact_data['contact_details']:
                contact_data['contact_details']['phone'] = contact_data['contact_details']['contactphone']
                contact_data['contact_details'].pop('contactphone')
            if 'firstname' in contact_data['contact_details'] and contact_data['contact_details']['firstname']:
                contact_data['contact_details']['firstname']=contact_data['contact_details']['firstname'][:40]

            contact_details_data = contact_data.get('contact_details', {})
            if contact_details_data:
                db_session.query(VtigerContactDetails).filter(VtigerContactDetails.contactid == contact_id).update(contact_details_data)

            # Update contact sub details
            contact_subdetails_data = contact_data.get('contact_subdetails', {})
            if contact_subdetails_data:
                db_session.query(VtigerContactSubDetails).filter(VtigerContactSubDetails.contactsubscriptionid == contact_id).update(contact_subdetails_data)

            # Update contact address
            contact_address_data = contact_data.get('contact_address', {})
            if contact_address_data:
                db_session.query(VtigerContactAddress).filter(VtigerContactAddress.contactaddressid == contact_id).update(contact_address_data)

            # Update custom fields
            contact_cf_data = contact_data.get('custom_fields', {})
            if contact_cf_data:
                db_session.query(VtigerContactsCf).filter(VtigerContactsCf.contactid == contact_id).update(contact_cf_data)

            db_session.commit()
            return True

        except Exception as e:
            db_session.rollback()
            raise e



def save_email_status(data):
    """Save email delivery status items into vtiger contact custom fields (cf_907, cf_923).

    Args:
        data: iterable of dict items. Each item expected to contain at least:
            - recipient (email)
            - delivery_log: dict with optional keys 'status', 'response_code', 'bounce_type', 'date'/'timestamp'

    Returns:
        int: number of contacts updated

    Behavior:
        - Normalizes cf_907 into one of ('good','bad','risky'). If unable to coerce, the item is skipped.
        - Ensures cf_923 is in 'YYYY-MM-DD' format. If a date is provided attempts to parse it, otherwise uses UTC today.
        - Performs a single UPDATE statement per email using SQL executed via SQLAlchemy session.
        - Updates Redis CONTACTS hash for the updated contact (if present).
    """
    import logging
    from datetime import datetime
    # Using local JSON-backed storage instead of Redis

    if not data:
        logging.info("No email status data to save.")
        return 0

    updated = 0
    details = []
    session = Session()
    # no-op: local storage will be accessed when needed via json_hget/json_hset
    # helper to normalize cf_907
    def normalize_cf_907(value, delivery_status=None):
        if not value and delivery_status:
            # derive from delivery_status
            value = delivery_status
        if not value:
            return None
        v = str(value).strip().lower()
        mapping = {
            'delivered': 'good',
            'good': 'good',
            'ok': 'good',
            'success': 'good',
            'bounced': 'bad',
            'bounce': 'bad',
            'failed': 'bad',
            'undeliverable': 'bad',
            'bad': 'bad',
            'spam': 'risky',
            'complaint': 'risky',
            'risky': 'risky'
        }
        return mapping.get(v)

    # helper to coerce date to YYYY-MM-DD
    def coerce_date(value):
        if not value:
            return datetime.utcnow().strftime('%Y-%m-%d')
        # If already in YYYY-MM-DD-ish format, try to normalize
        try:
            if isinstance(value, (int, float)):
                # epoch
                dt = datetime.utcfromtimestamp(int(value))
                return dt.strftime('%Y-%m-%d')
            s = str(value).strip()
            # common ISO formats or other common formats
            for fmt in ('%Y-%m-%d', '%Y/%m/%d', '%d-%m-%Y', '%d/%m/%Y', '%m/%d/%Y', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S'):
                try:
                    dt = datetime.strptime(s, fmt)
                    return dt.strftime('%Y-%m-%d')
                except Exception:
                    continue
            # fallback: try to parse year-month-day numbers
            digits = ''.join(c for c in s if c.isdigit())
            if len(digits) >= 8:
                # try YYYYMMDD
                try:
                    dt = datetime.strptime(digits[:8], '%Y%m%d')
                    return dt.strftime('%Y-%m-%d')
                except Exception:
                    pass
            # last resort: utc today
            return datetime.utcnow().strftime('%Y-%m-%d')
        except Exception:
            return datetime.utcnow().strftime('%Y-%m-%d')
    # Use a transaction for the whole batch
    try:
        session.begin()

        for item in data:
            try:
                delivery_log = item.get('delivery_log') or {}
                delivery_status = str(delivery_log.get('status', '')).strip() if delivery_log else ''
                delivery_response_code = str(delivery_log.get('response_code', '')).strip() if delivery_log else ''
                delivery_bounce_type = str(delivery_log.get('bounce_type', '')).strip() if delivery_log else ''
                email = str(item.get('recipient', '') or item.get('email', '')).strip().lower()

                if not email or not (delivery_status or delivery_bounce_type):
                    msg = "Missing email or delivery status/bounce info"
                    logging.warning(f"Skipping incomplete email status item: {item}")
                    details.append({"email": email or '', "status": "skipped", "message": msg})
                    continue

                # map custom fields
                cf_907_raw = delivery_bounce_type or ''
                if delivery_status.lower() == 'delivered':
                    cf_907_mapped = 'good'
                else:
                    cf_907_mapped = normalize_cf_907(cf_907_raw, delivery_status=delivery_status)

                if cf_907_mapped not in ('good', 'bad', 'risky'):
                    msg = f"Unable to coerce cf_907 from raw '{cf_907_raw}' and status '{delivery_status}'"
                    logging.warning(f"{msg} - skipping for email {email}")
                    details.append({"email": email, "status": "skipped", "message": msg})
                    continue

                # cf_923: prefer provided timestamp in delivery_log, else utc today
                date_value = delivery_log.get('date') or delivery_log.get('timestamp') or delivery_log.get('time')
                cf_923_value = coerce_date(date_value)

                # Perform UPDATE using raw SQL to match existing architecture
                sql = text("""
                    UPDATE vtiger_contactscf AS cf
                    JOIN vtiger_contactdetails AS cd ON cf.contactid = cd.contactid
                    SET cf.cf_907 = :cf_907,
                        cf.cf_923 = :cf_923
                    WHERE LOWER(cd.email) = :email
                """)


                params = {'cf_907': cf_907_mapped, 'cf_923': cf_923_value, 'email': email}
                res = session.execute(sql, params)

                # SQLAlchemy result.rowcount may be unavailable for some backends; use res.rowcount when present
                rowcount = getattr(res, 'rowcount', None)
                if rowcount is None:
                    # best-effort: check via a follow-up select to see if record exists
                    check = session.execute(text("SELECT cd.contactid FROM vtiger_contactdetails cd WHERE LOWER(cd.email)=:email"), {'email': email}).fetchone()
                    if check:
                        updated += 1
                        details.append({"email": email, "status": "updated", "message": "Updated (rowcount unknown)"})
                    else:
                        msg = "No matching contact found"
                        logging.warning(f"No matching contact found for email: {email}")
                        details.append({"email": email, "status": "skipped", "message": msg})
                else:
                    if rowcount > 0:
                        updated += rowcount
                        details.append({"email": email, "status": "updated", "message": f"Updated ({rowcount})"})
                    else:
                        msg = "No matching contact found"
                        logging.warning(f"No matching contact found for email: {email}")
                        details.append({"email": email, "status": "skipped", "message": msg})

                # Update local JSON storage entry if present
                try:
                    key = email
                    contact_json = json_hget('CONTACTS', key)
                    if contact_json:
                        if isinstance(contact_json, str):
                            contact = json.loads(contact_json)
                        else:
                            contact = contact_json
                        contact.setdefault('custom_fields', {})['cf_907'] = cf_907_mapped
                        contact.setdefault('custom_fields', {})['cf_923'] = cf_923_value
                        json_hset('CONTACTS', key, contact)
                except Exception:
                    logging.exception(f"Failed to update storage for email {email}")

            except Exception as e:
                msg = str(e)
                logging.warning(f"Failed to process email status item {item}: {e}")
                details.append({"email": item.get('recipient') or '', "status": "error", "message": msg})
                # continue with next item
                continue

        session.commit()
    except Exception as e:
        logging.error(f"Database error while saving email status: {e}")
        try:
            session.rollback()
        except Exception:
            pass
        skipped = sum(1 for d in details if d.get('status') != 'updated')
        return {"updated": updated, "skipped": skipped, "details": details}
    finally:
        try:
            session.close()
        except Exception:
            pass

    skipped = sum(1 for d in details if d.get('status') != 'updated')
    return {"updated": updated, "skipped": skipped, "details": details}



def generate_weekly_interaction_query(start_date_str: str, end_date_str: str = None) -> str:
    """
    Generate dynamic SQL query for weekly aggregation of interactions
    starting from a fixed date to the current week.
    """
    start_date = datetime.strptime(start_date_str, "%Y-%m-%d").date()
    today = datetime.strptime(end_date_str, "%Y-%m-%d").date() if end_date_str else datetime.utcnow().date()

    # Align to Monday for consistent week grouping (optional)
    if start_date.weekday() != 0:
        start_date -= timedelta(days=start_date.weekday())

    # Prepare week ranges
    weeks = []
    current_start = start_date
    while current_start <= today:
        week_end = current_start + timedelta(days=6)
        weeks.append((current_start, week_end))
        current_start += timedelta(days=7)

    # Generate dynamic CASE WHEN columns
    week_clauses = []
    for start, end in weeks:
        label = f"{start}_to_{end}"
        clause = (
            f"COUNT(CASE WHEN i.occurred_at >= '{start}' "
            f"AND i.occurred_at <= '{end}' THEN 1 END) AS `{label}`"
        )
        week_clauses.append(clause)

    week_sql = ",\n    ".join(week_clauses)

    query = f"""
    SELECT 
        it.name AS interaction_type,
        CASE 
            WHEN it.id = 2 THEN 
                CASE 
                    WHEN i.status LIKE '%Like%' THEN 'Like'
                    WHEN i.status LIKE '%Comment%' THEN 'Comment'
                    WHEN i.status LIKE '%Repost%' THEN 'Share'
                    ELSE COALESCE(i.status, 'No Status')
                END
            ELSE COALESCE(i.status, 'No Status')
        END AS status,
        {week_sql},
        COUNT(*) AS total_interactions
    FROM interactions i
    INNER JOIN interaction_types it ON i.interaction_type_id = it.id
    WHERE i.occurred_at BETWEEN '{start_date}' AND '{today}'
    GROUP BY it.name,
        CASE 
            WHEN it.id = 2 THEN 
                CASE 
                    WHEN i.status LIKE '%Like%' THEN 'Like'
                    WHEN i.status LIKE '%Comment%' THEN 'Comment'
                    WHEN i.status LIKE '%Repost%' THEN 'Share'
                    ELSE COALESCE(i.status, 'No Status')
                END
            ELSE COALESCE(i.status, 'No Status')
        END
    ORDER BY it.name, total_interactions DESC;
    """

    return query.strip()

def get_wweekly_interaction_report(start_date_str: str, end_date_str: str = None):
    """
    Execute the weekly interaction aggregation query and return results.
    """
    query = generate_weekly_interaction_query(start_date_str, end_date_str)
    
    with Session() as db_session:
        try:
            result = db_session.execute(text(query))
            columns = result.keys()
            rows = result.fetchall()
            
            # Convert to list of dicts for easier consumption
            report = [dict(zip(columns, row)) for row in rows]
            return report
            
        except Exception as e:
            print(f"❌ Database error during weekly report generation: {str(e)}")
            import traceback
            print(f"Full traceback: {traceback.format_exc()}")
            return []


def save_interaction_to_db(interaction_data):
    """
    POST interaction Data into interaction Table in MariaDB
    """
    print("=== Starting database save operation ===")
    
    with Session() as db_session:
        try:
            email = interaction_data.get('email')
            post_url = interaction_data.get('FormName', '')
            description = interaction_data.get('Description', '')
            
            print(f"Extracted data - email: '{email}', description: '{description}'")
            
            if not email:
                print("❌ Email is required but not provided")
                return False
            
            print("✅ Email validation passed")
            
            # Include ALL required columns from your schema
            query = text("""
            INSERT INTO interactions 
            (interaction_type_id, occurred_at, email, description, status, post_url) 
            VALUES (:interaction_type_id, NOW(), :email, :description, :status, :post_url)
            """)
            
            params = {
                "interaction_type_id": 42,
                "email": email,
                "description": description[:255],  # Truncate to 255 chars
                "status": "Web Form Submitted",
                "post_url": post_url  # Add appropriate value for post_url
            }
            
            print(f"Executing query with params: {params}")
            result = db_session.execute(query, params)
            print(f"Query executed, rows affected: {result.rowcount}")
            
            db_session.commit()
            print("✅ Commit successful - interaction saved")
            return True
            
        except Exception as e:
            print(f"❌ Database error: {str(e)}")
            import traceback
            print(f"Full traceback: {traceback.format_exc()}")
            db_session.rollback()
            return False
        finally:
            db_session.close()
            print("Database session closed")
            
            
def updateNewCustomerStatus(data: Dict[str, Any]) -> bool:
    """
    Mark customer as Active (contact or account). If not found, create new record.
    Optimized with timeout protection and minimal required fields.
    """
    try:
        data_type = data.get('dataType')
        
        # --- CONTACT ---
        if data_type == 'contact':
            email = data.get('email')
            if not email:
                print("[ERROR] Email is required for contact updates")
                return False
            
            # Quick database check with timeout
            with Session() as session:
                session.execute(text("SET SESSION wait_timeout = 10"))
                session.execute(text("SET SESSION interactive_timeout = 10"))
                
                # Check if contact exists (fast query)
                result = session.execute(
                    text("""
                        SELECT cd.contactid, cf.cf_927 
                        FROM vtiger_contactdetails cd
                        JOIN vtiger_contactscf cf ON cd.contactid = cf.contactid
                        JOIN vtiger_crmentity ce ON cd.contactid = ce.crmid
                        WHERE LOWER(cd.email) = :email AND ce.deleted = 0
                        LIMIT 1
                    """),
                    {"email": email.lower()}
                ).fetchone()
                
                if result:
                    # Update existing contact
                    contact_id = result[0]
                    session.execute(
                        text("""
                            UPDATE vtiger_contactscf 
                            SET cf_927 = '1', cf_929 = :date
                            WHERE contactid = :contact_id
                        """),
                        {"contact_id": contact_id, "date": datetime.now().strftime("%Y-%m-%d")}
                    )
                    session.commit()
                    print(f"[INFO] Customer status updated for contact ID {contact_id}")
                    
                    
                    return True
                
                # Create new contact - MINIMAL required fields only
                try:
                    customer_data = {
                        "crmentity": {
                            "smownerid": 1,
                            "smcreatorid": 1,
                            "modifiedby": 1,
                            "source": "Customer Status Update",
                        },
                        "contact_details": {
                            "firstname": data.get('firstname', 'Valued')[:40],  # Truncate
                            "lastname": data.get('lastname', 'Customer')[:80],
                            "email": email,
                        },
                        "contact_subdetails": {},  # Empty but required
                        "contact_address": {},      # Empty but required
                        "custom_fields": {
                            "cf_927": "1",
                            "cf_929": datetime.now().strftime("%Y-%m-%d"),
                        },
                    }
                    
                    contact_id = insertIntoContact(customer_data)
                    print(f"[INFO] New contact created: {contact_id} for {email}")
                                        
                    return True
                    
                except Exception as insert_error:
                    print(f"[ERROR] Failed to insert contact: {insert_error}")
                    session.rollback()
                    return False
        
        # --- ACCOUNT ---
        elif data_type == 'account':
            domain = data.get('domain')
            if not domain:
                print("[ERROR] Domain is required for account updates")
                return False
            
            with Session() as session:
                session.execute(text("SET SESSION wait_timeout = 10"))
                session.execute(text("SET SESSION interactive_timeout = 10"))
                
                # Check if account exists (fast query)
                result = session.execute(
                    text("""
                        SELECT a.accountid, cf.cf_933
                        FROM vtiger_account a
                        JOIN vtiger_accountscf cf ON a.accountid = cf.accountid
                        JOIN vtiger_crmentity ce ON a.accountid = ce.crmid
                        WHERE LOWER(cf.cf_869) = :domain AND ce.deleted = 0
                        LIMIT 1
                    """),
                    {"domain": domain.lower()}
                ).fetchone()
                
                if result:
                    # Update existing account
                    account_id = result[0]
                    session.execute(
                        text("""
                            UPDATE vtiger_accountscf 
                            SET cf_933 = '1', cf_935 = :date
                            WHERE accountid = :account_id
                        """),
                        {"account_id": account_id, "date": datetime.now().strftime("%Y-%m-%d")}
                    )
                    session.commit()
                    print(f"[INFO] Customer status updated for account ID {account_id}")
                              
                    return True
                
                # Create new account - MINIMAL required fields
                try:
                    customer_data = {
                        "crmentity": {
                            "smownerid": 1,
                            "smcreatorid": 1,
                            "modifiedby": 1,
                            "source": "Customer Status Update",
                        },
                        "account_detail": {
                            "accountname": data.get('accountname', domain)[:100],
                        },
                        "account_billads": {},  # Empty but required
                        "account_shipad": {},   # Empty but required
                        "account_custom_fields": {
                            "cf_869": domain,
                            "cf_933": "1",
                            "cf_935": datetime.now().strftime("%Y-%m-%d"),
                        },
                    }
                    
                    account_id = insertIntoAccounts(customer_data)
                    print(f"[INFO] New account created: {account_id} for {domain}")
                
                    
                    return True
                    
                except Exception as insert_error:
                    print(f"[ERROR] Failed to insert account: {insert_error}")
                    session.rollback()
                    return False
        
        else:
            print(f"[WARN] Invalid dataType: {data_type}")
            return False
    
    except Exception as e:
        import traceback
        print(f"[ERROR] updateNewCustomerStatus failed: {e}")
        print(traceback.format_exc())
        return False


def UpdateExCustomerStatus(data: Dict[str, Any]) -> bool:
    """
    Mark customer as Inactive (Ex-Customer). Optimized with direct SQL.
    """
    try:
        data_type = data.get('dataType')
        
        # --- CONTACT ---
        if data_type == 'contact':
            email = data.get('email')
            if not email:
                print("[ERROR] Email is required")
                return False
            
            with Session() as session:
                session.execute(text("SET SESSION wait_timeout = 10"))
                
                result = session.execute(
                    text("""
                        UPDATE vtiger_contactscf cf
                        JOIN vtiger_contactdetails cd ON cf.contactid = cd.contactid
                        JOIN vtiger_crmentity ce ON cd.contactid = ce.crmid
                        SET cf.cf_927 = '0', cf.cf_931 = :date
                        WHERE LOWER(cd.email) = :email AND ce.deleted = 0
                    """),
                    {"email": email.lower(), "date": datetime.now().strftime("%Y-%m-%d")}
                )
                
                session.commit()
                
                if result.rowcount > 0:
                    print(f"[INFO] Ex-customer status set for {email}")
                    return True
                else:
                    print(f"[WARN] No contact found for {email}")
                    return False
        
        # --- ACCOUNT ---
        elif data_type == 'account':
            domain = data.get('domain')
            if not domain:
                print("[ERROR] Domain is required")
                return False
            
            with Session() as session:
                session.execute(text("SET SESSION wait_timeout = 10"))
                
                result = session.execute(
                    text("""
                        UPDATE vtiger_accountscf cf
                        JOIN vtiger_crmentity ce ON cf.accountid = ce.crmid
                        SET cf.cf_933 = '0', cf.cf_937 = :date
                        WHERE LOWER(cf.cf_869) = :domain AND ce.deleted = 0
                    """),
                    {"domain": domain.lower(), "date": datetime.now().strftime("%Y-%m-%d")}
                )
                
                session.commit()
                
                if result.rowcount > 0:
                    print(f"[INFO] Ex-customer status set for {domain}")
                    return True
                else:
                    print(f"[WARN] No account found for {domain}")
                    return False
        
        else:
            print(f"[WARN] Invalid dataType: {data_type}")
            return False
    
    except Exception as e:
        import traceback
        print(f"[ERROR] UpdateExCustomerStatus failed: {e}")
        print(traceback.format_exc())
        return False

def save_click_events_to_db(events):
    if not events:
        #print("No events to save.")
        return

    session = Session()
    inserted_count = 0
    
    try:
        for event in events:
            campaign_id = event['campaign_id']
            email = event['email'].lower().strip()
            link = re.sub(r"\s+", "", event.get('link', ''))
            iso_timestamp = event['timestamp']
            event_type = event['event_type']
            campaign_name = event['Campaign_name']
            
            try:
                # Convert nanoseconds timestamp to datetime
                timestamp_ns = int(iso_timestamp)
                timestamp_seconds = timestamp_ns / 1e9
                dt_utc = datetime.fromtimestamp(timestamp_seconds)
                dt_local = dt_utc.astimezone(ZoneInfo("Asia/Karachi"))
                timestamp = dt_local.strftime('%Y-%m-%d %H:%M:%S')
            except Exception as e:
                #print(f"Invalid timestamp '{iso_timestamp}', using now. Error: {e}")
                dt_local = datetime.now(ZoneInfo("Asia/Karachi"))
                timestamp = dt_local.strftime('%Y-%m-%d %H:%M:%S')

            # Check for duplicate using raw SQL
            result = session.execute(
                text("""
                    SELECT 1 FROM email_clicks 
                    WHERE campaign_id = :campaign_id AND email = :email AND link = :link
                """),
                {
                    'campaign_id': campaign_id,
                    'email': email,
                    'link': link
                }
            )
            
            if result.fetchone():
                continue  # Skip duplicates

            # Insert with raw SQL
            try:
                session.execute(
                    text("""
                        INSERT INTO email_clicks 
                        (event_type, campaign_id, email, link, timestamp, 
                        processed, campaignName, platform, salesforceID, lead_owner_id)
                        VALUES (:event_type, :campaign_id, :email, :link, :timestamp, 
                                :processed, :campaign_name, :platform, :salesforce_id, :lead_owner_id)
                    """),
                    {
                        'event_type': event_type,
                        'campaign_id': campaign_id,
                        'email': email,
                        'link': link,
                        'timestamp': timestamp,
                        'processed': 0,
                        'campaign_name': campaign_name,
                        'platform': 'sendx',
                        'salesforce_id': '',
                        'lead_owner_id': ''
                    }
                )
                inserted_count += 1
                #print(f"Inserted click event: {email} | Campaign: {campaign_id} | Link: {link[:50]}...")
                
            except Exception as e:
                #print(f"Insert failed for event: {event} - Error: {e}")
                session.rollback()
                continue

        session.commit()
        #print(f"Total inserted records: {inserted_count}")
        
    except Exception as db_err:
        #print(f"Database connection or insertion error: {db_err}")
        session.rollback()
    finally:
        session.close()


def updateCustomerStatus(data: Dict[str, Any]) -> bool:
    """
    Dispatcher with timeout protection and validation.
    """
    try:
        status = data.get('status', '').lower().strip()
        
        if status == 'active':
            return updateNewCustomerStatus(data)
        elif status == 'inactive':
            return UpdateExCustomerStatus(data)
        else:
            print(f"[WARN] Invalid status: {status}")
            return False
    
    except Exception as e:
        import traceback
        print(f"[ERROR] updateCustomerStatus failed: {e}")
        print(traceback.format_exc())
        return False

