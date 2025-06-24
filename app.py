import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_cors import CORS
from decouple import config
from datetime import datetime
import string
import random
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, Email, Content, MimeType

# --- Configuration ---
class Config:
    SECRET_KEY = config('SECRET_KEY')
    SENDGRID_API_KEY = config('SENDGRID_API_KEY')
    SENDGRID_SENDER_EMAIL = config('SENDGRID_SENDER_EMAIL')
    DEFAULT_SALES_MANAGER_EMAIL = config('DEFAULT_SALES_MANAGER_EMAIL', default='default.sales.manager@example.com') 
    COMPANY_NAME = config('COMPANY_NAME', default='Real Estate Company')

app = Flask(__name__)
app.config.from_object(Config)
CORS(app, supports_credentials=True) 

# --- DEBUGGING PRINTS ---
print("\n--- APP CONFIG DEBUG (FROM app.py) ---")
sendgrid_api_key_val = app.config['SENDGRID_API_KEY']
print(f"SendGrid API Key (first 20 chars): '{sendgrid_api_key_val[:20]}...'")
print(f"SendGrid API Key (last 5 chars): '...{sendgrid_api_key_val[-5:]}'")
print(f"SendGrid Sender Email: '{app.config['SENDGRID_SENDER_EMAIL']}'")
print(f"Default Sales Manager Email: '{app.config['DEFAULT_SALES_MANAGER_EMAIL']}'")
print("--- END APP CONFIG DEBUG ---\n")

sendgrid_client = SendGridAPIClient(app.config['SENDGRID_API_KEY'])

# --- Database Setup ---
DATABASE = 'database_md.db' 

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Create users table with 'manager_username' and 'is_active' columns
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            email TEXT,
            is_active BOOLEAN DEFAULT TRUE NOT NULL,
            manager_username TEXT -- Column for linking executive to admin/manager
        )
    ''')
    # Client table remains unchanged
    conn.execute('''
            CREATE TABLE IF NOT EXISTS clients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_name TEXT NOT NULL,
                mobile_number TEXT NOT NULL,
                email TEXT NOT NULL,
                scheduled_date TEXT NOT NULL,
                scheduled_time TEXT NOT NULL,
                sales_representative TEXT, 
                property_of_interest TEXT,
                additional_notes TEXT,
                unique_code TEXT UNIQUE NOT NULL,
                sales_rep_mail NOT NULL,
                is_code_used BOOLEAN DEFAULT FALSE,
                verified_at TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
    conn.commit() 
    
    # Check and add 'email' column if not exists
    cursor.execute("PRAGMA table_info(users)")
    columns = [col[1] for col in cursor.fetchall()]
    
    if 'email' not in columns:
        print("Adding 'email' column to 'users' table...")
        conn.execute("ALTER TABLE users ADD COLUMN email TEXT;")
        conn.commit()
        print("'email' column added.")

    # Check and add 'is_active' column if not exists
    if 'is_active' not in columns:
        print("Adding 'is_active' column to 'users' table...")
        conn.execute("ALTER TABLE users ADD COLUMN is_active BOOLEAN DEFAULT TRUE NOT NULL;")
        conn.commit()
        print("'is_active' column added.")
    
    # Check and add 'manager_username' column if not exists
    if 'manager_username' not in columns:
        print("Adding 'manager_username' column to 'users' table...")
        conn.execute("ALTER TABLE users ADD COLUMN manager_username TEXT;")
        conn.commit()
        print("'manager_username' column added.")

    conn.close() 
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # --- Ensure Default Users (New Hierarchy) ---
        # Superadmin
        cursor.execute("INSERT OR IGNORE INTO users (username, password, role, email) VALUES (?, ?, ?, ?)", 
                       ('superadmin', 'superadmin_pass', 'superadmin', 'superadmin@example.com'))

        # Admin
        cursor.execute("INSERT OR IGNORE INTO users (username, password, role, email) VALUES (?, ?, ?, ?)", 
                       ('admin', 'admin_pass', 'admin', 'admin@example.com')) 

        # Executive (now reports to 'admin' by default)
        cursor.execute("INSERT OR IGNORE INTO users (username, password, role, email, manager_username) VALUES (?, ?, ?, ?, ?)", 
                       ('executive', 'executive_pass', 'executive', 'executive@example.com', 'admin')) 

        # Guard
        cursor.execute("INSERT OR IGNORE INTO users (username, password, role, email) VALUES (?, ?, ?, ?)", 
                       ('guard', 'guard_pass', 'guard', 'guard@example.com'))
        
        conn.commit()
        print("Default users (superadmin, admin, executive, guard) ensured for new hierarchy.")

        # --- Clean up old user roles from previous runs ---
        users_to_delete = ('sales', 'manager', 'team_lead', 'marketing_manager', 'sales_manager', 'sales_teamlead')
        cursor.execute("DELETE FROM users WHERE role IN ({}) AND username NOT IN ('superadmin', 'admin', 'executive', 'guard')".format(','.join('?' * len(users_to_delete))), users_to_delete)
        conn.commit()
        print(f"Cleaned up users with old roles: {users_to_delete}.")

    except sqlite3.IntegrityError:
        print("Some default users might already exist.")
    except Exception as e:
        print(f"Error during default user insertion/cleanup: {e}")
    finally:
        conn.close()

with app.app_context():
    init_db()


# --- Helper Functions ---

def generate_unique_code(length=6):
    characters = string.ascii_uppercase + string.digits
    return ''.join(random.choice(characters) for i in range(length))

def send_email(to_email, subject, body):
    """
    Sends an email using SendGrid.
    """
    message = Mail(
        from_email=app.config['SENDGRID_SENDER_EMAIL'],
        to_emails=to_email,
        subject=subject,
        html_content=body
    )

    try:
        response = sendgrid_client.send(message)
        print(f"Email sent to {to_email}. Status Code: {response.status_code}")
        if response.status_code >= 200 and response.status_code < 300:
            return True
        else:
            print(f"SendGrid error response for {to_email}: Status {response.status_code}, Body: {response.body.decode('utf-8')}")
            raise Exception(f"SendGrid API responded with error: Status {response.status_code}, Body: {response.body.decode('utf-8')}")
    except Exception as e:
        print(f"Error sending email to {to_email}: {e}")
        return False


# --- Decorator for Role-Based Access Control ---
def role_required(roles):
    def decorator(f):
        def wrap(*args, **kwargs):
            if 'role' not in session or session['role'] not in roles:
                return jsonify({"message": "Unauthorized access.", "status": "error"}), 403
            return f(*args, **kwargs)
        wrap.__name__ = f.__name__
        return wrap
    return decorator


# --- Routes ---

@app.route('/')
def serve_react_app():
    return render_template('index.html') 

@app.route('/api/login', methods=['POST'])
def login_api():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE username = ? AND password = ? AND is_active = TRUE", (username, password)).fetchone()
    conn.close()

    if user:
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['role'] = user['role']
        session['email'] = user['email']
        return jsonify({
            "message": "Login successful!",
            "status": "success",
            "user": {
                "id": user['id'],
                "username": user['username'],
                "role": user['role'],
                "email": user['email']
            }
        }), 200
    else:
        conn = get_db_connection() 
        inactive_user = conn.execute("SELECT id FROM users WHERE username = ? AND password = ? AND is_active = FALSE", (username, password)).fetchone()
        conn.close()
        if inactive_user:
             return jsonify({"message": "Your account is currently inactive. Please contact support.", "status": "error"}), 401
        return jsonify({"message": "Invalid credentials. Please try again.", "status": "error"}), 401


@app.route('/api/logout', methods=['POST'])
def logout_api():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('role', None)
    session.pop('email', None)
    return jsonify({"message": "You have been logged out.", "status": "info"}), 200

@app.route('/api/check_session', methods=['GET'])
def check_session_api():
    if 'user_id' in session and session.get('username') and session.get('role'):
        return jsonify({
            "status": "success",
            "message": "Session active.",
            "user": {
                "id": session['user_id'],
                "username": session['username'],
                "role": session['role'],
                "email": session.get('email')
            }
        }), 200
    else:
        return jsonify({"status": "error", "message": "No active session."}), 401


# --- Executive Client Registration/View API Endpoint ---
@app.route('/api/executive_client_dashboard_data', methods=['GET'])
@role_required(['executive', 'superadmin', 'admin']) 
def executive_client_dashboard_data_api():
    current_username = session.get('username') 
    
    conn = get_db_connection()
    clients_rows = []

    if session['role'] in ['admin', 'superadmin']:
        clients_rows = conn.execute(
            "SELECT * FROM clients ORDER BY created_at DESC LIMIT 20"
        ).fetchall()
    else: # For 'executive' role, show only their clients
        clients_rows = conn.execute(
            "SELECT * FROM clients WHERE sales_representative = ? ORDER BY created_at DESC LIMIT 20", 
            (current_username,)
        ).fetchall()
    
    clients = [dict(row) for row in clients_rows]
    conn.close()
    return jsonify({"clients": clients, "status": "success"}), 200

@app.route('/api/register_client', methods=['POST'])
@role_required(['executive', 'superadmin']) 
def register_client_api():
    data = request.get_json()
    client_name = data.get('client_name')
    mobile_number = data.get('mobile_number') 
    email = data.get('email')
    scheduled_date = data.get('scheduled_date')
    scheduled_time = data.get('scheduled_time')
    sales_representative = session.get('username') 
    property_of_interest = data.get('property_of_interest', '')
    additional_notes = data.get('additional_notes', '')
    sales_rep_mail = data.get('sales_rep_mail','')

    if not all([client_name, mobile_number, email, scheduled_date, scheduled_time]):
        return jsonify({"message": "Please fill in all required fields.", "status": "error"}), 400

    unique_code = None
    conn = get_db_connection()
    try:
        while True:
            unique_code = generate_unique_code()
            existing_client = conn.execute("SELECT id FROM clients WHERE unique_code = ?", (unique_code,)).fetchone()
            if not existing_client:
                break

        conn.execute(
            "INSERT INTO clients (client_name, mobile_number, email, scheduled_date, scheduled_time, "
            "sales_representative, property_of_interest, additional_notes, unique_code,sales_rep_mail) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?,?)",
            (client_name, mobile_number, email, scheduled_date, scheduled_time,
             sales_representative, property_of_interest, additional_notes, unique_code,sales_rep_mail)
        )
        conn.commit()
        
        email_subject = f"Your Villa Visit Unique Code: {unique_code}"
        email_body = (
            f"<p>Dear {client_name},</p>"
            f"<p>Thank you for scheduling a visit to our property.</p>"
            f"<p>Your **unique code** to present at the gate is: <strong>{unique_code}</strong></p>"
            f"<p>Your visit is scheduled for <strong>{scheduled_date} at {scheduled_time}</strong>.</p>"
            f"<p>Sales Representative: {sales_representative if sales_representative else 'N/A'}</p>"
            f"<p>Property of Interest: {property_of_interest if property_of_interest else 'N/A'}</p>"
            f"<p>We look forward to seeing you!</p>"
            f"<p>Sincerely,<br>{app.config['COMPANY_NAME']}</p>"
        )

        email_success = send_email(email, email_subject, email_body)
        
        message = f"Client '{client_name}' registered successfully. Unique code: {unique_code}."
        if not email_success:
            message += f" Failed to send email to client."

        return jsonify({"message": message, "status": "success", "unique_code": unique_code}), 200

    except sqlite3.IntegrityError as e:
        return jsonify({"message": f"Error registering client: A client with this mobile or email might already exist. Details: {e}", "status": "error"}), 400
    except Exception as e:
        return jsonify({"message": f"An unexpected error occurred during client registration: {e}", "status": "error"}), 500
    finally:
        conn.close()


# --- Guard API Endpoints ---
verification_logs_memory = [] 

@app.route('/api/guard_verification_data', methods=['GET'])
@role_required(['guard', 'admin', 'superadmin', 'executive']) 
def guard_verification_data():
    recent_logs = verification_logs_memory[-15:] if len(verification_logs_memory) > 0 else [] 
    return jsonify({"logs": recent_logs, "status": "success"}), 200


@app.route('/api/verify_code', methods=['POST'])
@role_required(['guard', 'admin', 'superadmin']) 
def verify_code_api():
    data = request.get_json()
    unique_code = data.get('unique_code', '').strip().upper()

    conn = get_db_connection()
    client_row = conn.execute("SELECT * FROM clients WHERE unique_code = ?", (unique_code,)).fetchone()
    client = dict(client_row) if client_row else None
    conn.close()

    verification_result = {'status': 'fail', 'message': 'INVALID CODE. Please check and try again.'}
    client_name_for_log = 'N/A'

    if client:
        client_name_for_log = client['client_name']
        if client['is_code_used']:
            verification_result = {'status': 'fail', 'message': 'CODE ALREADY USED. This client has already been admitted.'}
        else:
            verification_result = {
                'status': 'success',
                'client_id': client['id'],
                'client_name': client['client_name'],
                'mobile_number': client['mobile_number'],
                'scheduled_date': client['scheduled_date'],
                'scheduled_time': client['scheduled_time'],
                'sales_representative': client['sales_representative'] if client['sales_representative'] else 'N/A',
                'property_of_interest': client['property_of_interest'] if client['property_of_interest'] else 'N/A'
            }

    status_for_log = verification_result.get('status', 'fail') 
    log_entry_data = {
        'code': unique_code,
        'client_name': client_name_for_log,
        'status': status_for_log,
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    verification_logs_memory.append(log_entry_data)

    if len(verification_logs_memory) > 15:
        verification_logs_memory.pop(0)

    return jsonify(verification_result), 200


@app.route('/api/admit_client_and_notify_manager', methods=['POST'])
@role_required(['guard', 'admin', 'superadmin']) 
def admit_client_and_notify_manager_api():
    data = request.get_json()
    client_id = data.get('client_id')

    if not client_id:
        return jsonify({"message": "Error: Client ID missing for admission/notification. Please re-verify.", "status": "error"}), 400

    conn = get_db_connection()
    client_row = conn.execute("SELECT * FROM clients WHERE id = ?", (client_id,)).fetchone()
    client = dict(client_row) if client_row else None

    if not client:
        conn.close()
        return jsonify({"message": "Error: Client not found for admission/notification.", "status": "error"}), 404

    if client['is_code_used']:
        conn.close()
        return jsonify({"message": f"Client '{client['client_name']}' has already been admitted.", "status": "info"}), 200

    try:
        conn.execute("UPDATE clients SET is_code_used = TRUE, verified_at = ? WHERE id = ?",
                     (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), client_id))
        conn.commit()
        
        manager_to_notify_email = app.config['DEFAULT_SALES_MANAGER_EMAIL'] 
        manager_username = "Admin/Manager" 
        
        if manager_to_notify_email:
            notification_subject = f"Client Admitted: {client['client_name']} ({client['unique_code']})"
            notification_body = (
                f"<p>Dear {manager_username},</p>"
                f"<p>A client has been admitted at the gate:</p>"
                f"<ul>"
                f"<li><strong>Client Name:</strong> {client['client_name']}</li>"
                f"<li><strong>Unique Code:</strong> {client['unique_code']}</li>"
                f"<li><strong>Verified At:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</li>"
                f"<li><strong>Verified By (Guard):</strong> {session.get('username', 'N/A')}</li>"
                f"<li><strong>Registered By (Executive):</strong> {client.get('sales_representative', 'N/A')}</li>" 
                f"<li><strong>Scheduled For:</strong> {client['scheduled_date']} at {client['scheduled_time']}</li>"
                f"<li><strong>Mobile:</strong> {client['mobile_number']}</li>"
                f"<li><strong>Email:</strong> {client.get('email', 'N/A')}</li>" 
                f"</ul>"
                f"<p>Thank you.</p>"
                f"<p>Regards,<br>Security Team</p>"
            )
            
            email_success = send_email(manager_to_notify_email, notification_subject, notification_body)
            if email_success:
                return jsonify({"message": f"Client '{client['client_name']}' admitted and manager ({manager_to_notify_email}) notified.", "status": "success"}), 200
            else:
                return jsonify({"message": f"Client '{client['client_name']}' admitted, but failed to send manager notification email to {manager_to_notify_email}.", "status": "warning"}), 200
        else:
            return jsonify({"message": "Client admitted, but could not determine manager to notify or no email configured for default.", "status": "warning"}), 200

    except Exception as e:
        print(f"Error in admit_client_and_notify_manager_api: {e}")
        return jsonify({"message": f"An unexpected error occurred: {e}", "status": "error"}), 500
    finally:
        conn.close()


# --- Admin Dashboard API Endpoints ---
@app.route('/api/admin_dashboard_data', methods=['GET'])
@role_required(['admin', 'superadmin'])
def admin_dashboard_data_api():
    conn = get_db_connection()
    current_user_role = session.get('role')
    current_username = session.get('username')

    all_clients = []
    if current_user_role == 'superadmin':
        all_clients_rows = conn.execute("""
            SELECT 
                c.*, 
                exec_user.manager_username AS admin_manager_username
            FROM clients c
            LEFT JOIN users exec_user ON c.sales_representative = exec_user.username
            ORDER BY c.created_at DESC
        """).fetchall()
        all_clients = [dict(row) for row in all_clients_rows]
    elif current_user_role == 'admin':
        managed_executives_rows = conn.execute(
            "SELECT username FROM users WHERE role = 'executive' AND manager_username = ?", 
            (current_username,)
        ).fetchall()
        managed_executives = [row['username'] for row in managed_executives_rows]

        if managed_executives:
            placeholders = ','.join('?' * len(managed_executives))
            all_clients_rows = conn.execute(f"""
                SELECT 
                    c.*, 
                    exec_user.manager_username AS admin_manager_username
                FROM clients c
                LEFT JOIN users exec_user ON c.sales_representative = exec_user.username
                WHERE c.sales_representative IN ({placeholders})
                ORDER BY c.created_at DESC
            """, managed_executives).fetchall()
            all_clients = [dict(row) for row in all_clients_rows]

    users_rows = conn.execute("SELECT id, username, password, role, email, is_active, manager_username FROM users ORDER BY username").fetchall() 
    users = [dict(row) for row in users_rows]
    conn.close()

    return jsonify({"clients": all_clients, "users": users, "status": "success"}), 200

# API endpoint for deactivating/activating users
@app.route('/api/user/<int:user_id>/status', methods=['PUT'])
@role_required(['admin', 'superadmin'])
def update_user_status_api(user_id):
    data = request.get_json()
    is_active = data.get('is_active')

    if is_active is None or not isinstance(is_active, bool):
        return jsonify({"message": "Invalid 'is_active' status provided.", "status": "error"}), 400

    conn = get_db_connection()
    user_to_update_row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    user_to_update = dict(user_to_update_row) if user_to_update_row else None

    if not user_to_update:
        conn.close()
        return jsonify({"message": "User not found.", "status": "error"}), 404

    if user_to_update['role'] == 'superadmin' and not is_active: 
        conn.close()
        return jsonify({"message": "Cannot deactivate a superadmin user.", "status": "error"}), 403
    elif user_to_update['id'] == session.get('user_id') and not is_active: 
        conn.close()
        return jsonify({"message": "Cannot deactivate the currently logged-in user.", "status": "error"}), 403
    
    try:
        conn.execute("UPDATE users SET is_active = ? WHERE id = ?", (is_active, user_id))
        conn.commit()
        conn.close()
        status_msg = "activated" if is_active else "deactivated"
        return jsonify({"message": f"User '{user_to_update['username']}' {status_msg} successfully.", "status": "success"}), 200
    except Exception as e:
        print(f"Error in update_user_status_api: {e}")
        return jsonify({"message": f"An error occurred while updating user status: {e}", "status": "error"}), 500

@app.route('/api/add_user', methods=['POST'])
@role_required(['admin', 'superadmin'])
def add_user_api():
    data = request.get_json()
    new_username = data.get('new_username').strip()
    new_password = data.get('new_password')
    new_role = data.get('new_role')
    new_email = data.get('new_email')
    new_manager_username = data.get('new_manager_username') 

    if not all([new_username, new_password, new_role]):
        return jsonify({"message": "Username, password, and role are required.", "status": "error"}), 400
    
    if new_role == 'executive' and not new_manager_username:
        return jsonify({"message": "Manager (Admin) is required for Executive role.", "status": "error"}), 400

    if new_email and "@" not in new_email:
        return jsonify({"message": "Please enter a valid email address.", "status": "error"}), 400

    conn = get_db_connection()
    try:
        if new_role == 'executive':
            manager_exists = conn.execute("SELECT id FROM users WHERE username = ? AND role = 'admin'", (new_manager_username,)).fetchone()
            if not manager_exists:
                conn.close()
                return jsonify({"message": f"Invalid Manager Username '{new_manager_username}'. Please select an existing Admin user.", "status": "error"}), 400
            
            conn.execute("INSERT INTO users (username, password, role, email, manager_username) VALUES (?, ?, ?, ?, ?)",
                         (new_username, new_password, new_role, new_email, new_manager_username))
        else:
            conn.execute("INSERT INTO users (username, password, role, email, manager_username) VALUES (?, ?, ?, ?, ?)",
                         (new_username, new_password, new_role, new_email, None))
        
        conn.commit()
        return jsonify({"message": f"User '{new_username}' with role '{new_role}' added successfully!", "status": "success"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"message": f"Error: Username '{new_username}' already exists. Please choose a different username.", "status": "error"}), 409
    except Exception as e:
        print(f"Error occurred while adding user: {e}")
        return jsonify({"message": f"An error occurred while adding user: {e}", "status": "error"}), 500
    finally:
        conn.close()

@app.route('/api/client/<int:client_id>', methods=['GET', 'PUT', 'DELETE'])
# IMPORTANT: Added 'executive' to role_required
@role_required(['admin', 'superadmin', 'executive'])
def client_api(client_id):
    conn = get_db_connection()
    client_row = conn.execute("SELECT * FROM clients WHERE id = ?", (client_id,)).fetchone()
    client = dict(client_row) if client_row else None

    if not client:
        conn.close()
        return jsonify({"message": "Client not found.", "status": "error"}), 404

    # Permission check for Executive role
    current_user_role = session.get('role')
    current_username = session.get('username')

    # If the user is an executive, they can only interact with clients they registered
    if current_user_role == 'executive' and client['sales_representative'] != current_username:
        conn.close()
        return jsonify({"message": "You are not authorized to modify this client.", "status": "error"}), 403


    if request.method == 'GET':
        conn.close()
        return jsonify({"client": client, "status": "success"}), 200

    elif request.method == 'PUT':
        data = request.get_json()
        client_name = data.get('client_name')
        mobile_number = data.get('mobile_number')
        email = data.get('email')
        scheduled_date = data.get('scheduled_date')
        scheduled_time = data.get('scheduled_time')
        sales_representative = data.get('sales_representative', '') 
        property_of_interest = data.get('property_of_interest', '')
        additional_notes = data.get('additional_notes', '')

        if not all([client_name, mobile_number, email, scheduled_date, scheduled_time]):
            conn.close()
            return jsonify({"message": 'All required client fields must be filled.', "status": "error"}), 400

        try:
            conn.execute(
                "UPDATE clients SET client_name=?, mobile_number=?, email=?, scheduled_date=?, scheduled_time=?, "
                "sales_representative=?, property_of_interest=?, additional_notes=? WHERE id=?",
                (client_name, mobile_number, email, scheduled_date, scheduled_time,
                 sales_representative, property_of_interest, additional_notes, client_id)
            )
            conn.commit()
            conn.close()
            return jsonify({"message": f"Client '{client_name}' updated successfully!", "status": "success"}), 200
        except Exception as e:
            conn.close()
            print(f"Error occurred while updating client: {e}")
            return jsonify({"message": f"An error occurred while updating client: {e}", "status": "error"}), 500

    elif request.method == 'DELETE':
        try:
            conn.execute("DELETE FROM clients WHERE id = ?", (client_id,))
            conn.commit()
            conn.close()
            return jsonify({"message": f"Client '{client['client_name']}' deleted successfully.", "status": "success"}), 200
        except Exception as e:
            conn.close()
            print(f"Error occurred while deleting client: {e}")
            return jsonify({"message": f"An error occurred while deleting client: {e}", "status": "error"}), 500


# --- Executive Dashboard API (aggregated view) ---
@app.route('/api/executive_dashboard_data', methods=['GET'])
@role_required(['executive', 'superadmin', 'admin']) 
def executive_dashboard_data_api():
    conn = get_db_connection()
    total_clients = conn.execute("SELECT COUNT(*) FROM clients").fetchone()[0]
    verified_clients = conn.execute("SELECT COUNT(*) FROM clients WHERE is_code_used = TRUE").fetchone()[0]
    unverified_clients = total_clients - verified_clients
    
    current_username = session.get('username') 
    
    my_registered_clients_details = []
    my_clients_total_count = 0
    total_pages = 1
    current_page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int) 

    if session['role'] == 'executive':
        my_clients_total_count_row = conn.execute(
            "SELECT COUNT(*) FROM clients WHERE sales_representative = ?", 
            (current_username,)
        ).fetchone()
        my_clients_total_count = my_clients_total_count_row[0]

        total_pages = (my_clients_total_count + per_page - 1) // per_page
        offset = (current_page - 1) * per_page

        my_registered_clients_details_rows = conn.execute(
            "SELECT * FROM clients WHERE sales_representative = ? ORDER BY created_at DESC LIMIT ? OFFSET ?", 
            (current_username, per_page, offset)
        ).fetchall()
        my_registered_clients_details = [dict(row) for row in my_registered_clients_details_rows]

    conn.close()
    return jsonify({
        "total_clients": total_clients, 
        "verified_clients": verified_clients,
        "unverified_clients": unverified_clients,
        "my_registered_clients": my_clients_total_count, 
        "my_registered_clients_details": my_registered_clients_details, 
        "my_clients_total_count": my_clients_total_count, 
        "total_pages": total_pages, 
        "current_page": current_page, 
        "per_page": per_page, 
        "status": "success"
    }), 200


# --- Main Application Execution (for local development) ---
if __name__ == '__main__':
    app.run(debug=True, port=5000)
