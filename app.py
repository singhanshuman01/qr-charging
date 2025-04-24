from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
import requests
import mysql.connector
from datetime import datetime, timedelta
import os
import re
import bcrypt
import secrets
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', secrets.token_hex(32))
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to cookies
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Session timeout

# Setup rate limiting
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# Global variable to store NodeMCU IP with validation
nodeMCU_IP = None

# MySQL Database Connection
db_config = {
    "host": os.getenv('DB_HOST', 'localhost'),
    "user": os.getenv('DB_USER', 'root'),
    "password": os.getenv('DB_PASSWORD', ''),
    "database": os.getenv('DB_NAME', 'rfid_charging'),
    "use_pure": True,
    "ssl_ca": os.getenv('SSL_CA_PATH', None),  # Path to CA cert
    "ssl_verify_cert": True,
    "ssl_disabled": False
}

# Security helper functions
def validate_ip(ip):
    """Validate IP address format"""
    pattern = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    return bool(re.match(pattern, ip))

def generate_csrf_token():
    """Generate CSRF token"""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

def login_required(f):
    """Decorator for requiring login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def connect_to_db():
    """Create a secure database connection"""
    try:
        conn = mysql.connector.connect(**db_config)
        return conn
    except mysql.connector.Error as err:
        logger.error(f"Database connection error: {err}")
        return None

def safe_db_query(query, params=None, fetch_one=False, commit=False):
    """Execute database query with error handling"""
    conn = None
    cursor = None
    result = None
    
    try:
        conn = connect_to_db()
        if not conn:
            return None
            
        cursor = conn.cursor(dictionary=True)
        cursor.execute(query, params or ())
        
        if fetch_one:
            result = cursor.fetchone()
        elif not commit:
            result = cursor.fetchall()
            
        if commit:
            conn.commit()
            result = cursor.rowcount
            
        return result
    except mysql.connector.Error as err:
        logger.error(f"Database query error: {err}")
        return None
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# Function to log data into MySQL
def log_charging(user_id, start_time=None, stop_time=None):
    """Log charging activity securely"""
    try:
        if start_time and not stop_time:  # Log start time
            query = "INSERT INTO charging_logs (user_id, start_time) VALUES (%s, %s)"
            safe_db_query(query, (user_id, start_time), commit=True)
        elif stop_time:  # Update stop time
            query = "UPDATE charging_logs SET stop_time = %s WHERE user_id = %s AND stop_time IS NULL ORDER BY start_time DESC LIMIT 1"
            safe_db_query(query, (stop_time, user_id), commit=True)
    except Exception as err:
        logger.error(f"Log charging error: {err}")

@app.before_request
def before_request():
    """Actions to perform before each request"""
    # Add security headers to every response
    @app.after_request
    def add_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Content-Security-Policy'] = "default-src 'self'"
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        return response
    
    # Force HTTPS in production
    if not request.is_secure and app.env == 'production':
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)

@app.route("/", methods=["GET"])
def index():
    """Home page"""
    return redirect(url_for("login"))

@app.route("/register_ip", methods=["POST"])
@limiter.limit("10 per minute")
def register_ip():
    """Register NodeMCU IP with validation and authentication"""
    global nodeMCU_IP
    
    # Check authentication token
    auth_token = request.headers.get('X-Auth-Token')
    if not auth_token or auth_token != os.getenv('NODEMCU_AUTH_TOKEN', 'default_token'):
        logger.warning(f"Unauthorized IP registration attempt from {request.remote_addr}")
        return jsonify({"error": "Unauthorized access"}), 401
    
    try:
        data = request.get_json()
        if not data or "ip" not in data:
            return jsonify({"error": "Invalid request format"}), 400
        
        ip = data["ip"]
        if not validate_ip(ip):
            logger.warning(f"Invalid IP format in registration attempt: {ip}")
            return jsonify({"error": "Invalid IP format"}), 400
        
        nodeMCU_IP = ip
        logger.info(f"NodeMCU IP registered: {nodeMCU_IP}")
        return jsonify({"status": "IP registered successfully"}), 200
    except Exception as e:
        logger.error(f"Error in register_ip: {str(e)}")
        return jsonify({"error": "Server error"}), 500

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    """Secure login with CSRF protection and password hashing"""
    if request.method == "GET":
        # Generate CSRF token
        csrf_token = generate_csrf_token()
        return render_template("login.html", csrf_token=csrf_token)
    
    elif request.method == "POST":
        # Validate CSRF token
        token = request.form.get('csrf_token')
        if not token or token != session.get('csrf_token'):
            flash('CSRF token validation failed', 'danger')
            return redirect(url_for('login'))
        
        user_id = request.form.get("user_id")
        password = request.form.get("password")
        
        if not user_id or not password:
            flash('Please provide both username and password', 'warning')
            return redirect(url_for('login'))
        
        # Sanitize inputs (basic)
        user_id = user_id.strip()
        
        # Verify user credentials
        try:
            query = "SELECT * FROM users WHERE user_id = %s"
            user = safe_db_query(query, (user_id,), fetch_one=True)
            
            if not user:
                logger.warning(f"Failed login attempt for user: {user_id}")
                flash('Invalid credentials', 'danger')
                return redirect(url_for('login'))
            
            # Check password (assuming we've stored hashed passwords)
            stored_password = user['password']
            
            # For bcrypt hashed passwords:
            if os.getenv('USE_BCRYPT', 'True').lower() == 'true':
                # Check if password is already hashed in db
                if not stored_password.startswith('$2b$'):
                    # We need to migrate to bcrypt - this is a one-time operation per user
                    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
                    safe_db_query("UPDATE users SET password = %s WHERE user_id = %s", 
                                 (hashed.decode('utf-8'), user_id), commit=True)
                    password_valid = True
                else:
                    # Normal bcrypt check
                    password_valid = bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8'))
            else:
                # Legacy plain text comparison (not recommended!)
                password_valid = (password == stored_password)
            
            if not password_valid:
                logger.warning(f"Failed login attempt for user: {user_id}")
                flash('Invalid credentials', 'danger')
                return redirect(url_for('login'))
            
            # Set session
            session['user_id'] = user_id
            session['authenticated'] = True
            session.permanent = True
            
            # Log start time
            log_charging(user_id, start_time=datetime.now())
            
            # Redirect to success page
            return redirect(url_for("charging_station", user_id=user_id))
            
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            flash('An error occurred during login', 'danger')
            return redirect(url_for('login'))
    
    return render_template("login.html", csrf_token=generate_csrf_token())

@app.route("/charging_station/<user_id>", methods=["GET", "POST"])
@login_required
def charging_station(user_id):
    """Secure charging station page"""
    # Verify user_id matches session user
    if session.get('user_id') != user_id:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('login'))
    
    if request.method == "POST":
        # Validate CSRF token
        token = request.form.get('csrf_token')
        if not token or token != session.get('csrf_token'):
            flash('CSRF token validation failed', 'danger')
            return redirect(url_for('charging_station', user_id=user_id))
        
        # Stop charging
        stop_charging_action(user_id)
        flash('Charging has been stopped', 'info')
        return redirect(url_for("login"))
    
    # Start charging via NodeMCU
    error_message = None
    if nodeMCU_IP:
        try:
            # Add timeout and authentication
            headers = {'X-Auth-Token': os.getenv('NODEMCU_AUTH_TOKEN', 'default_token')}
            response = requests.get(f"http://{nodeMCU_IP}/relay_on", 
                                  headers=headers, 
                                  timeout=5)
            
            if response.status_code != 200:
                error_message = f"NodeMCU returned error: {response.status_code}"
                logger.error(error_message)
        except Exception as e:
            error_message = "Unable to start charging"
            logger.error(f"Error communicating with NodeMCU: {e}")
    else:
        error_message = "NodeMCU not connected"
    
    return render_template("charging_station.html", 
                          user_id=user_id, 
                          error=error_message,
                          csrf_token=generate_csrf_token())

@app.route("/status", methods=["GET"])
@login_required
def status():
    """Show charging status and logs"""
    charging_status = "Unknown"
    if nodeMCU_IP:
        try:
            # Add timeout and authentication
            headers = {'X-Auth-Token': os.getenv('NODEMCU_AUTH_TOKEN', 'default_token')}
            response = requests.get(f"http://{nodeMCU_IP}/status", 
                                  headers=headers, 
                                  timeout=5)
            
            if response.status_code == 200:
                charging_status = response.json().get("status", "Unknown")
        except Exception as e:
            logger.error(f"Error fetching status: {e}")
            charging_status = "Error connecting to device"

    # Fetch logs from MySQL - limit to most recent 50 entries
    try:
        query = """
        SELECT cl.id, cl.user_id, cl.start_time, cl.stop_time, 
               TIMESTAMPDIFF(MINUTE, cl.start_time, IFNULL(cl.stop_time, NOW())) as duration_minutes,
               u.name
        FROM charging_logs cl
        JOIN users u ON cl.user_id = u.user_id
        ORDER BY cl.start_time DESC
        LIMIT 50
        """
        logs = safe_db_query(query)
        
        if logs is None:
            logs = []
            flash('Unable to retrieve logs at this time', 'warning')
        
        return render_template("status.html", 
                              logs=logs, 
                              status=charging_status,
                              csrf_token=generate_csrf_token())
    except Exception as err:
        logger.error(f"Status page error: {err}")
        flash('An error occurred while retrieving status information', 'danger')
        return redirect(url_for('login'))

@app.route('/stop_charging/<user_id>')
@login_required
def stop_charging_endpoint(user_id):
    """Stop charging endpoint"""
    # Verify user_id matches session user
    if session.get('user_id') != user_id:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('login'))
    
    result = stop_charging_action(user_id)
    if result:
        flash('Charging stopped successfully', 'success')
    else:
        flash('Error stopping charging', 'danger')
    
    return redirect(url_for('login'))

def stop_charging_action(user_id):
    """Actual implementation of stop charging logic"""
    try:
        # Log stop time
        stop_time = datetime.now()
        log_charging(user_id, stop_time=stop_time)
        
        # Send request to NodeMCU to turn off the relay
        if nodeMCU_IP:
            try:
                headers = {'X-Auth-Token': os.getenv('NODEMCU_AUTH_TOKEN', 'default_token')}
                response = requests.get(f"http://{nodeMCU_IP}/relay_off", 
                                      headers=headers, 
                                      timeout=5)
                
                if response.status_code != 200:
                    logger.error(f"NodeMCU returned error when stopping: {response.status_code}")
                    return False
            except requests.exceptions.RequestException as e:
                logger.error(f"Error communicating with NodeMCU: {e}")
                return False
        
        # Clear session
        session.clear()
        return True
    except Exception as e:
        logger.error(f"Error in stop_charging: {e}")
        return False

@app.route('/logout')
def logout():
    """Logout and clear session"""
    user_id = session.get('user_id')
    if user_id:
        stop_charging_action(user_id)
    
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', error_code=404, message="Page not found"), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('error.html', error_code=500, message="Internal server error"), 500

if __name__ == "__main__":
    # Create .env file if it doesn't exist
    if not os.path.exists('.env'):
        with open('.env', 'w') as f:
            f.write(f"SECRET_KEY={secrets.token_hex(32)}\n")
            f.write("DB_HOST=localhost\n")
            f.write("DB_USER=root\n")
            f.write("DB_PASSWORD=\n")  # Do not store the real password here
            f.write("DB_NAME=rfid_charging\n")
            f.write("NODEMCU_AUTH_TOKEN=\n")  # Set a unique token for NodeMCU authentication
            f.write("USE_BCRYPT=True\n")
            f.write("SSL_CA_PATH=\n")  # Path to CA certificate for DB SSL
        print("Created .env file with placeholder values. Please update with real credentials.")
    
    # In production, use gunicorn or similar WSGI server
    if os.getenv('FLASK_ENV') == 'production':
        # Don't run with app.run in production
        print("In production mode - use gunicorn or similar WSGI server")
    else:
        app.run(host="0.0.0.0", port=5000, debug=False)
