import flask
from flask import Flask, request, jsonify, send_from_directory, redirect, url_for, render_template, session
from flask_cors import CORS
from werkzeug.utils import secure_filename
import os
import sqlite3
from functools import wraps
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import google.generativeai as genai
import requests
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from collections import defaultdict
from datetime import datetime
from flask_socketio import SocketIO, emit, join_room, leave_room
import json 

load_dotenv()

UPLOAD_FOLDER = 'uploads'
DB_PATH = './tickets.db' 
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'def@ult-Sup3r-S3cr3t-Key-P13a5e-Chang3-M3!')
CORS(app, supports_credentials=True) 

socketio = SocketIO(app, cors_allowed_origins="*")

GEMINI_API_KEY = os.getenv('GOOGLE_API_KEY')
OTP_EMAIL_SENDER = os.getenv('EMAIL_USER')
OTP_EMAIL_PASSWORD = os.getenv('PASSWORD') 




if not GEMINI_API_KEY:
    print("CRITICAL WARNING: GOOGLE_API_KEY environment variable not set. Gemini AI calls will fail.")
else:
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        print("Gemini API Key configured successfully.")
    except Exception as e:
        print(f"Error configuring Gemini API: {e}")
        GEMINI_API_KEY = None 

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS tickets (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            title TEXT NOT NULL,
                            description TEXT,
                            remedies TEXT,
                            file_path TEXT,
                            remedy_doc_path TEXT,
                            created_by TEXT NOT NULL,
                            created_at TEXT NOT NULL,
                            status TEXT DEFAULT 'Open'
                        )''')
        conn.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT UNIQUE NOT NULL,
                            password TEXT NOT NULL, /* TODO: HASH THIS! */
                            otp TEXT,
                            verified INTEGER DEFAULT 0
                        )''')
        conn.commit()
    print(f"Database initialized/checked at {DB_PATH}")

def is_valid_email(email):
    return email and email.endswith('@cloudkeeper.com')

def send_otp_email(to_email, otp):
    if not OTP_EMAIL_SENDER or not OTP_EMAIL_PASSWORD:
        print(f"ERROR: OTP Email credentials not configured in .env. Cannot send OTP. SENDER: {OTP_EMAIL_SENDER}, PASS_CONFIGURED: {bool(OTP_EMAIL_PASSWORD)}")
        return False

    msg = MIMEMultipart('alternative')
    msg['Subject'] = 'Confirm your signup – Your OTP is inside'
    msg['From'] = f'CloudKeeper Support <{OTP_EMAIL_SENDER}>' 
    msg['To'] = to_email

    text = f"""Hi,

Thank you for signing up for CloudKeeper!

Your One-Time Password (OTP) is: {otp}

Please enter this OTP on the verification page to complete your registration.
This OTP is valid for the next 10 minutes.

If you did not initiate this request, please ignore this email.

Best regards,
The CloudKeeper Team
"""
    html = f"""
    <html>
      <body>
        <p>Hi,<br><br>
           Thank you for signing up for CloudKeeper!<br><br>
           <b>Your One-Time Password (OTP) is:</b> <span style="font-size:18px;color:#2E86C1;">{otp}</span><br><br>
           Please enter this OTP on the verification page to complete your registration.<br>
           This OTP is valid for the next 10 minutes.<br><br>
           If you did not initiate this request, please ignore this email.<br><br>
           Best regards,<br>
           The CloudKeeper Team
        </p>
      </body>
    </html>
    """
    msg.attach(MIMEText(text, 'plain'))
    msg.attach(MIMEText(html, 'html'))

    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(OTP_EMAIL_SENDER, OTP_EMAIL_PASSWORD) 
            server.sendmail(msg['From'], [msg['To']], msg.as_string())
            print(f"OTP email sent successfully to {to_email}!")
            return True
    except Exception as e:
        print(f"Failed to send OTP email to {to_email}: {e}")
        return False


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session: return redirect(url_for('form')) 
    if request.method == 'POST':
        username = request.form.get('email','').strip()
        password = request.form.get('password','') # TODO: HASH THIS!
        if not username or not password:
            return render_template('login.html', error="Email and password are required.")
        if not is_valid_email(username):
            return render_template('login.html', error="Invalid email. Must be @cloudkeeper.com.")
        
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            # TODO: HASH CHECK! This is insecure.
            cur.execute("SELECT * FROM users WHERE username = ? AND password = ? AND verified = 1", (username, password))
            user = cur.fetchone()
            if user:
                session['username'] = user['username']
                next_url = request.args.get('next')
                print(f"User '{username}' logged in successfully.")
                return redirect(next_url or url_for('form')) 
            else: 
                cur.execute("SELECT verified FROM users WHERE username = ?", (username,))
                user_exists = cur.fetchone()
                if user_exists and not user_exists['verified']:
                    error_msg = "Account not verified. Please check your email for OTP or try signing up again to resend OTP."
                    session['pending_user'] = username 
                    return redirect(url_for('verify_otp', error=error_msg))
                else:
                    error_msg = 'Invalid credentials or account not verified.'
                return render_template('login.html', error=error_msg)
    return render_template('login.html', success=request.args.get('success'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'username' in session: return redirect(url_for('form'))
    if request.method == 'POST':
        username = request.form.get('email','').strip()
        password = request.form.get('password','') # TODO: 

        if not username or not password:
            return render_template('signup.html', error="Email and password are required.")
        if not is_valid_email(username):
            return render_template('signup.html', error="Only @cloudkeeper.com emails are allowed.")
        if len(password) < 4: 
            return render_template('signup.html', error="Password must be at least 4 characters long.")

        otp = str(random.randint(100000, 999999))

        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT id, username, verified FROM users WHERE username = ?", (username,))
            existing_user = cur.fetchone()
            
            if existing_user:
                 if existing_user['verified']:
                    return render_template('signup.html', error="User already exists and is verified. Please login.")
                 else: 
                    cur.execute("UPDATE users SET password = ?, otp = ? WHERE id = ?", (password, otp, existing_user['id'])) 
                    conn.commit()
                    print(f"OTP updated for existing unverified user: {username}")
                    if send_otp_email(username, otp):
                        session['pending_user'] = username
                        return redirect(url_for('verify_otp', message='OTP has been resent to your email.'))
                    else:
                         return render_template('signup.html', error="User exists. Failed to resend OTP. Please try again later.")
            else:
                cur.execute("INSERT INTO users (username, password, otp, verified) VALUES (?, ?, ?, 0)", (username, password, otp)) 
                conn.commit()
                print(f"New user created: {username}")
                if send_otp_email(username, otp):
                    session['pending_user'] = username
                    return redirect(url_for('verify_otp'))
                else:
                    return render_template('signup.html', error="Account created, but OTP email failed. Contact support or try signing up again to resend OTP.")
    return render_template('signup.html')

@app.route('/verify', methods=['GET', 'POST'])
def verify_otp():
    pending_user_email = session.get('pending_user')
    message_from_redirect = request.args.get('message')
    error_from_redirect = request.args.get('error') 

    email_for_template = pending_user_email or request.args.get('email_to_verify_fallback', '')


    if not pending_user_email and request.method == 'GET' and not error_from_redirect :
        return redirect(url_for('signup'))

    if request.method == 'POST':
        otp_input = request.form.get('otp','').strip()

        email_to_verify_on_post = pending_user_email 

        if not email_to_verify_on_post: 
             return render_template('verify.html', error="Session expired. Please try signing up or logging in again.", email="", message=message_from_redirect)

        if not otp_input:
            return render_template('verify.html', error="OTP is required.", email=email_to_verify_on_post, message=message_from_redirect)
        
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT otp, verified FROM users WHERE username = ?", (email_to_verify_on_post,))
            user_record = cur.fetchone()

            if user_record and not user_record['verified'] and user_record['otp'] == otp_input:
                cur.execute("UPDATE users SET verified = 1, otp = NULL WHERE username = ?", (email_to_verify_on_post,))
                conn.commit()
                session.pop('pending_user', None)
                print(f"User {email_to_verify_on_post} verified successfully.")
                return redirect(url_for('login', success='Your email has been verified! Please log in.'))
            elif user_record and user_record['verified']:
                 session.pop('pending_user', None)
                 return redirect(url_for('login', success='This account is already verified. You can log in.'))
            else:
                error_msg = "Invalid OTP. Please try again."
                if not user_record:
                    error_msg = "Verification record not found. Please try signing up again."
                return render_template('verify.html', error=error_msg, email=email_to_verify_on_post, message=message_from_redirect)
                
    return render_template('verify.html', email=email_for_template, error=error_from_redirect, message=message_from_redirect)


@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('pending_user', None)
    print("User logged out.")
    return redirect(url_for('login'))

@socketio.on('connect')
def handle_socket_connect():
    if 'username' in session:
        username = session['username']
        join_room(username) 
        join_room('all_authenticated_users') 
        print(f"SocketIO Client '{username}' ({request.sid}) connected and joined rooms.")
    else:
        print(f"SocketIO Anonymous client ({request.sid}) connected.")

@socketio.on('disconnect')
def handle_socket_disconnect():
    if 'username' in session:
        username = session['username']
        leave_room(username)
        leave_room('all_authenticated_users')
        print(f"SocketIO Client '{username}' ({request.sid}) disconnected.")
    else:
        print(f"SocketIO Anonymous client ({request.sid}) disconnected.")

@app.route('/submit', methods=['POST'])
@login_required
def submit_ticket():
    current_user = session.get('username')
    new_ticket_id = None
    title = ""
    description = ""
    remedies = ""
    created_by = ""
    created_at = ""
    file_path_str = ""
    remedy_doc_path = None

    is_json_request = request.is_json 

    if is_json_request:
        data = request.get_json()
        if not data:
            app.logger.error("Submit ticket: Received non-JSON or empty payload for JSON request.")
            return jsonify({"success": False, "detail": "Invalid JSON payload"}), 400
        title = data.get('title')
        description = data.get('description')
        remedies = data.get('remedies')
        created_by = data.get('created_by', current_user) 
        created_at = data.get('created_at')
    else: 
        title = request.form.get('title')
        description = request.form.get('description')
        remedies = request.form.get('remedies', '')
        created_by = request.form.get('created_by', current_user)
        created_at = request.form.get('created_at')
        
        uploaded_files = request.files.getlist('screenshot') 
        saved_file_paths = []
        if uploaded_files:
            for file_obj in uploaded_files:
                if file_obj and file_obj.filename:
                    filename = secure_filename(file_obj.filename)
                    file_save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    try:
                        file_obj.save(file_save_path)
                        saved_file_paths.append(file_save_path)
                    except Exception as e:
                        app.logger.error(f"Failed to save uploaded file {filename}: {e}")
                        return jsonify({"success": False, "detail": f"Failed to save file {filename}."}), 500
        file_path_str = ";".join(saved_file_paths)

        remedy_doc = request.files.get('remedy_doc') 
        if remedy_doc and remedy_doc.filename:
            remedy_filename = secure_filename(remedy_doc.filename)
            remedy_doc_path = os.path.join(app.config['UPLOAD_FOLDER'], remedy_filename)
            try:
                remedy_doc.save(remedy_doc_path)
            except Exception as e:
                app.logger.error(f"Failed to save remedy doc {remedy_filename}: {e}")
                return jsonify({"success": False, "detail": f"Failed to save remedy document {remedy_filename}."}), 500

    if not all([title, created_by, created_at]):
        app.logger.warning(f"Submit ticket: Missing required fields. Title: {title}, CreatedBy: {created_by}, CreatedAt: {created_at}")
        return jsonify({"success": False, "detail": "Title, Submitted By, and Date of Occurrence are required."}), 400

    try:
        with sqlite3.connect(DB_PATH) as conn:
            cur = conn.cursor()
            cur.execute(
                'INSERT INTO tickets (title, description, remedies, file_path, remedy_doc_path, created_by, created_at, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                (title, description, remedies, file_path_str, remedy_doc_path, created_by, created_at, 'Open')
            )
            new_ticket_id = cur.lastrowid
            conn.commit()
    except sqlite3.Error as e:
        app.logger.error(f"Database error during ticket submission: {e}")
        return jsonify({"success": False, "detail": "A database error occurred while creating the ticket."}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error during ticket submission: {e}")
        return jsonify({"success": False, "detail": "An unexpected error occurred during submission."}), 500

    if new_ticket_id:
        created_at_dt_parsed = None
        created_at_display_str = created_at 
        try:
            if created_at: 
                created_at_dt_parsed = datetime.strptime(created_at, "%Y-%m-%dT%H:%M")
                created_at_display_str = created_at_dt_parsed.strftime('%Y-%m-%d %H:%M:%S') 
        except ValueError:
            app.logger.warning(f"Could not parse created_at string '{created_at}' for ticket {new_ticket_id}. Using as is for display.")
        
        print(f"Emitting new_ticket_notification for ticket {new_ticket_id}")
        socketio.emit('new_ticket_notification', {
            'id': new_ticket_id, 
            'title': title, 
            'created_by': created_by, 
            'status': 'Open',
            'created_at_display': created_at_display_str, 
            'message': f'New ticket #{new_ticket_id} ("{title}") by {created_by} has been created.'
        }, room='all_authenticated_users')
        
        return jsonify({"success": True, "message": "Ticket created successfully!", "ticket_id": new_ticket_id})
    else:
        app.logger.error("Ticket submission failed: new_ticket_id was not generated.")
        return jsonify({"success": False, "detail": "Ticket submission failed for an unknown reason after database operation."}), 500

@app.route('/form') 
@login_required
def form():
    return render_template('form.html', 
                           success_html_content="Ticket submitted successfully!" if request.args.get('success') == '1' else None,
                           error_message=request.args.get('error'),
                           username=session.get('username'))


@app.route('/tickets', methods=['GET'])
@login_required
def get_tickets():
    search = request.args.get('search', '')
    query = "SELECT id, title, description, remedies, file_path, remedy_doc_path, created_by, created_at, status FROM tickets WHERE 1=1"
    params = []
    if search:
        search_term_like = f"%{search}%"
        query += " AND (LOWER(title) LIKE LOWER(?) OR LOWER(description) LIKE LOWER(?) OR LOWER(created_by) LIKE LOWER(?) OR LOWER(created_at) LIKE LOWER(?) OR LOWER(id) LIKE LOWER(?) OR LOWER(status) LIKE LOWER(?))"
        params.extend([search_term_like] * 6)
    query += " ORDER BY datetime(created_at) DESC"
    
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute(query, params)
            tickets_raw = cur.fetchall()
            tickets = []
            for row in tickets_raw:
                ticket_dict = dict(row)
                if 'file_path' in ticket_dict and ticket_dict['file_path'] and isinstance(ticket_dict['file_path'], str):
                    ticket_dict['file_path'] = [path.strip() for path in ticket_dict['file_path'].split(';') if path.strip()]
                else:
                    ticket_dict['file_path'] = []
                tickets.append(ticket_dict)
            return jsonify(tickets)
    except Exception as e:
        app.logger.error(f"Error fetching tickets: {e}")
        return jsonify({"error": "Failed to retrieve tickets"}), 500


@app.route('/api/ticket_status_counts', methods=['GET'])
@login_required
def get_ticket_status_summary():
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row; cur = conn.cursor()
            cur.execute("SELECT status, COUNT(*) as count FROM tickets GROUP BY status")
            db_summary = {row['status']: row['count'] for row in cur.fetchall() if row['status']}
            config = {"Open": {"c":0,"color":"rgba(255,159,64,0.8)"},"In Progress":{"c":0,"color":"rgba(54,162,235,0.8)"},"Resolved":{"c":0,"color":"rgba(75,192,192,0.8)"},"Closed":{"c":0,"color":"rgba(150,150,150,0.8)"},"Pending User":{"c":0,"color":"rgba(201,203,207,0.8)"}}
            for s, d_val in config.items(): # Renamed 'data' to 'd_val'
                if s in db_summary: d_val["c"] = db_summary[s]
            return jsonify({"chart_labels": list(config.keys()), "chart_counts": [d_val["c"] for d_val in config.values()], "chart_colors": [d_val["color"] for d_val in config.values()], "open_tickets_count": config.get("Open",{}).get("c",0)})
    except Exception as e: 
        app.logger.error(f"Status summary error: {e}") 
        return jsonify({"error":"Could not get status summary"}),500


@app.route('/api/tickets_over_time_counts', methods=['GET'])
@login_required
def get_tickets_over_time_counts():
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row; cur = conn.cursor()
            cur.execute("""SELECT DATE(created_at) as creation_date, COUNT(*) as count FROM tickets WHERE DATE(created_at) >= DATE('now', '-30 days') GROUP BY DATE(created_at) ORDER BY creation_date ASC""")
            rows = cur.fetchall()
            return jsonify({"labels": [r['creation_date'] for r in rows if r['creation_date']], "counts": [r['count'] for r in rows if r['creation_date']]})
    except Exception as e: 
        app.logger.error(f"Tickets over time error: {e}") # Make sure app.logger is configured if you use it
        return jsonify({"error":"Could not get ticket trend"}),500

@app.route('/tickets/<int:ticket_id>', methods=['GET'])
@login_required
def get_ticket(ticket_id):
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT id, title, description, remedies, file_path, remedy_doc_path, created_by, created_at, status FROM tickets WHERE id=?", (ticket_id,))
            row = cur.fetchone()
            if row:
                ticket_dict = dict(row)
                if 'file_path' in ticket_dict and ticket_dict['file_path'] and isinstance(ticket_dict['file_path'], str):
                    ticket_dict['file_path'] = [path.strip() for path in ticket_dict['file_path'].split(';') if path.strip()]
                else:
                    ticket_dict['file_path'] = []
                return jsonify(ticket_dict)
            return jsonify({"error": "Ticket not found"}), 404
    except Exception as e:
        app.logger.error(f"Error fetching ticket {ticket_id}: {e}")
        return jsonify({"error": "Failed to retrieve ticket details"}), 500


@app.route('/tickets/<int:ticket_id>', methods=['PUT'])
@login_required
def update_ticket(ticket_id):
    current_user = session.get('username')
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON payload"}), 400

    title = data.get('title')
    description = data.get('description')
    remedies = data.get('remedies')
    new_status = data.get('status')

    if not title:
        return jsonify({"error": "Title is required"}), 400
    
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT created_by, status, title, created_at FROM tickets WHERE id = ?", (ticket_id,))
            original_ticket = cur.fetchone()

            if not original_ticket:
                return jsonify({"error": "Ticket not found"}), 404

            is_admin = current_user == os.getenv("ADMIN_EMAIL", "admin@cloudkeeper.com") 
            allow_edit = (original_ticket['created_by'] == current_user or is_admin)

            if not allow_edit:
                app.logger.warning(f"Forbidden PUT on ticket {ticket_id} by {current_user}")
                return jsonify({"error": "Forbidden: You can only edit your own tickets or an admin must do this."}), 403

            cur.execute('''UPDATE tickets SET title = ?, description = ?, remedies = ?, status = ? WHERE id = ?''',
                         (title, description, remedies, new_status, ticket_id))
            conn.commit()

            if cur.rowcount == 0:
                app.logger.info(f"No rows updated for ticket {ticket_id}, possibly no changes or ID mismatch on update.")
    
        msg = f'Ticket #{ticket_id} ("{title}") updated by {current_user}.'
        if new_status and new_status != original_ticket['status']:
            msg += f' Status changed: "{original_ticket["status"]}" -> "{new_status}".'
        
        created_at_obj = None
        created_at_display = original_ticket['created_at'] 
        try:
            if original_ticket['created_at']:
                created_at_obj = datetime.strptime(original_ticket['created_at'], "%Y-%m-%dT%H:%M")
                created_at_display = created_at_obj.strftime('%Y-%m-%d %H:%M:%S')
        except ValueError:
            app.logger.warning(f"Could not parse original_ticket created_at for display: {original_ticket['created_at']}")


        if original_ticket['created_by'] and original_ticket['created_by'] != current_user:
            socketio.emit('ticket_update_notification', {
                'id': ticket_id, 'title': title, 'status': new_status, 
                'message': msg, 'created_by': original_ticket['created_by'], 
                'created_at_display': created_at_display
            }, room=original_ticket['created_by'])
        
        socketio.emit('ticket_updated_globally', {
            'id': ticket_id, 'title': title, 'status': new_status, 
            'created_by': original_ticket['created_by'], 
            'created_at_display': created_at_display,
            'message': msg
        }, room='all_authenticated_users')
        
        return jsonify({'message': 'Ticket updated successfully'})

    except sqlite3.Error as e:
        app.logger.error(f"Database error during ticket update for {ticket_id}: {e}")
        return jsonify({"error": "A database error occurred."}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error during ticket update for {ticket_id}: {e}")
        return jsonify({"error": "An unexpected error occurred."}), 500

@app.route('/uploads/<path:filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(os.path.abspath(app.config['UPLOAD_FOLDER']), filename)

@app.route('/')
def home_or_main():
    if 'username' in session:
        return redirect(url_for('form')) 
    return render_template('main.html') 

@app.route('/gdoc_importer')
@login_required
def gdoc_importer_page():
    return render_template('gdoc_import.html', username=session.get('username'))

@app.route('/view')
@login_required
def view_tickets_page():
    return render_template('view.html', username=session.get('username')) 

@app.route('/user_ticket_view')
@login_required
def user_ticket_view_page():
    return render_template('users.html', username=session.get('username'))

@app.route('/counts')
@login_required
def index_counts_page():
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cur = conn.cursor()
            cur.execute('SELECT created_by, COUNT(*) as ticket_count FROM tickets GROUP BY created_by ORDER BY ticket_count DESC')
            users_data = cur.fetchall() 
        return render_template('index.html', users=users_data, username=session.get('username'))
    except Exception as e:
        app.logger.error(f"Error fetching user counts: {e}")
        return render_template('index.html', users=[], error="Could not load user counts.", username=session.get('username'))


@app.route('/users', methods=['GET'])
@login_required
def get_users_list():
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cur = conn.cursor()
            cur.execute("SELECT DISTINCT created_by FROM tickets WHERE created_by IS NOT NULL AND created_by != '' ORDER BY created_by COLLATE NOCASE")
            users = [row[0] for row in cur.fetchall()]
            return jsonify(users)
    except Exception as e:
        app.logger.error(f"Error fetching user list: {e}")
        return jsonify({"error": "Failed to retrieve user list"}), 500

@app.route('/user_tickets/<username>', methods=['GET'])
@login_required
def get_tickets_for_user_api(username):

    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT id, title, description, remedies, file_path, remedy_doc_path, created_by, created_at, status FROM tickets WHERE created_by = ? ORDER BY datetime(created_at) DESC", (username,))
            tickets_raw = cur.fetchall()
            tickets = []
            for row in tickets_raw:
                ticket_dict = dict(row)
                if 'file_path' in ticket_dict and ticket_dict['file_path'] and isinstance(ticket_dict['file_path'], str):
                    ticket_dict['file_path'] = [path.strip() for path in ticket_dict['file_path'].split(';') if path.strip()]
                else:
                    ticket_dict['file_path'] = []
                tickets.append(ticket_dict)
            return jsonify(tickets)
    except Exception as e:
        app.logger.error(f"Error fetching tickets for user {username}: {e}")
        return jsonify({"error": f"Failed to retrieve tickets for user {username}"}), 500


@app.route('/extract_gdoc_content', methods=['POST'])
@login_required
def extract_gdoc_content_route():
    data = request.get_json()
    if not data or 'gdoc_url' not in data:
        return jsonify({"success": False, "detail": "Google Doc URL is required."}), 400
    
    gdoc_url = data.get('gdoc_url').strip()
    if not gdoc_url:
        return jsonify({"success": False, "detail": "Google Doc URL cannot be empty."}), 400

    if "/pub" not in gdoc_url and "/d/" in gdoc_url and "/edit" in gdoc_url: 
        return jsonify({"success": False, "detail": "Please use a 'Published to web' link, not the editing link. (File > Share > Publish to web)"}), 400
    if "/pub" not in gdoc_url: 
         return jsonify({"success": False, "detail": "Invalid URL. Ensure it's a 'Published to web' Google Doc link (usually contains /pub or /pubhtml)."}), 400


    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        response = requests.get(gdoc_url, timeout=20, headers=headers) 
        response.raise_for_status() 
        
        soup = BeautifulSoup(response.content, 'html.parser')
        
        content_div = soup.find('div', id='contents')
        if not content_div: 
            content_div = soup.body 
            if not content_div:
                 return jsonify({"success": False, "detail": "Could not find main content area in the document."}), 400
        
        for s_or_s_tag in content_div(['script', 'style']):
            s_or_s_tag.decompose()
        

        extracted_text = content_div.get_text(separator='\n', strip=True)
        
        if not extracted_text.strip():
            return jsonify({"success": False, "detail": "No text content found in the document after cleaning."}), 400
            
        return jsonify({"success": True, "content": extracted_text})

    except requests.exceptions.Timeout:
        app.logger.error(f"Timeout fetching GDoc URL: {gdoc_url}")
        return jsonify({"success": False, "detail": "The request to Google Docs timed out. Please try again."}), 504
    except requests.exceptions.HTTPError as http_err:
        app.logger.error(f"HTTP error fetching GDoc {gdoc_url}: {http_err}")
        if http_err.response.status_code == 404:
            return jsonify({"success": False, "detail": "Document not found (404). Check the URL or publish settings."}), 404
        return jsonify({"success": False, "detail": f"Error fetching document: {http_err}"}), 500
    except requests.exceptions.RequestException as req_err:
        app.logger.error(f"Request error fetching GDoc {gdoc_url}: {req_err}")
        return jsonify({"success": False, "detail": f"Network error fetching document: {req_err}"}), 500
    except Exception as e:
        app.logger.error(f"Error parsing GDoc {gdoc_url}: {e}")
        return jsonify({"success": False, "detail": "An error occurred while parsing the document content."}), 500


@app.route('/ai-description', methods=['POST'])
@login_required
def ai_description():
    if not GEMINI_API_KEY:
        return jsonify({"error": "AI service unavailable. Key not configured."}), 503

    data = request.get_json()
    if not data:
        app.logger.error("AI Description: No JSON payload received.")
        return jsonify({"error": "Invalid payload. Expecting JSON."}), 400

    title = data.get('title', '').strip()
    description = data.get('description', '').strip()

    if not description and not title:
        return jsonify({"error": "Either a title or a description is required to generate an AI description."}), 400

    prompt_parts = ["You are an expert technical writer for a ticketing system. Your task is to refine or generate a bug/issue description."]
    if description:
        prompt_parts.append(f"Given the following user-submitted description:\n'''\n{description}\n'''")
        if title:
            prompt_parts.append(f"And the ticket title: \"{title}\"")
        prompt_parts.append("\nRewrite this into a clear, professional, and concise description suitable for a technical support ticket. Focus on clarity and completeness. If possible, infer context, potential steps to reproduce (if logical from the input), expected behavior, and actual behavior. Output only the refined description text. Do not add any preamble like 'Here is the rewritten description:'.")
    elif title: 
        prompt_parts.append(f"The ticket title is: \"{title}\".")
        prompt_parts.append("\nBased on this title, generate a detailed and professional bug/issue description. If the title is too generic, try to expand on common issues related to such a title. Include context, potential steps to reproduce, expected behavior, and actual behavior where appropriate. Output only the generated description text. Do not add any preamble.")
    
    prompt = "\n\n".join(prompt_parts)
    app.logger.info(f"AI Description Prompt (first 100 chars): {prompt[:100]}...")

    try:
        model = genai.GenerativeModel('gemini-1.5-flash-latest') 
        response = model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(
                max_output_tokens=400, 
                temperature=0.5      
            )
        )
        
        generated_text = "".join(part.text for part in response.candidates[0].content.parts).strip() if response.candidates and response.candidates[0].content.parts else ""
        
        if not generated_text:
            if response.prompt_feedback and response.prompt_feedback.block_reason:
                block_msg = response.prompt_feedback.block_reason_message or "Content generation was limited."
                app.logger.warning(f"Gemini blocked AI description generation: {block_msg}")
                return jsonify({"error": f"AI content generation was blocked: {block_msg}. Please rephrase your input or try again."}), 400
            app.logger.warning(f"Gemini returned empty content for AI description. Prompt was: {prompt[:200]}...")
            return jsonify({"generated": "AI could not generate a description for the provided input. Please try rephrasing or adding more details."})
            
        return jsonify({"generated": generated_text})

    except Exception as e:
        app.logger.error(f"Gemini API error during AI description generation: {str(e)}")
        return jsonify({"error": "An error occurred while communicating with the AI service."}), 500

DIRECT_AI_SIGNAL = "USE_DIRECT_AI_FOR_GENERAL_QUERY" 

def query_database_for_chatbot(user_message_lower):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    response_data = "Sorry, I couldn't find specific information related to your query in our ticket system. You can try asking about: 'ticket id 123', 'tickets by user@example.com', 'open tickets', 'search tickets for [keyword]', 'how many open tickets are there?', or 'show me the latest 3 tickets'."
    found_specific_query = False

    try:
        # id se ticket dhoodna
        ticket_id_phrases = ["ticket id ", "show ticket ", "details for ticket ", "ticket #", "ticket#", "ticket "]
        matched_phrase = None
        for phrase in ticket_id_phrases:
            if user_message_lower.startswith(phrase):
                matched_phrase = phrase
                break
        
        tid_str = None
        if matched_phrase:
            potential_id = user_message_lower[len(matched_phrase):].strip().split(" ")[0] 
            if potential_id.isdigit():
                tid_str = potential_id
        elif user_message_lower.split()[-1].isdigit() and \
             any(kw in user_message_lower for kw in ["ticket", "id"]): 
            tid_str = user_message_lower.split()[-1]

        if tid_str is not None:
            found_specific_query = True
            try:
                tid = int(tid_str)
                cur.execute("SELECT * FROM tickets WHERE id = ?", (tid,))
                ticket = cur.fetchone()
                if ticket:
                    text_parts = [
                        f"Ticket ID: {ticket['id']}", f"Title: {ticket['title']}", f"Status: {ticket['status']}"
                    ]
                    if ticket['description'] and ticket['description'].strip(): text_parts.append(f"Description: {ticket['description']}")
                    text_parts.append(f"Created By: {ticket['created_by']} on {ticket['created_at']}")
                    if ticket['remedies'] and ticket['remedies'].strip(): text_parts.append(f"Remedies: {ticket['remedies']}")

                    ticket_data_for_response = {
                        "type": "ticket_details", 
                        "id": ticket['id'], "title": ticket['title'], "status": ticket['status'],
                        "description": ticket['description'], "created_by": ticket['created_by'],
                        "created_at": ticket['created_at'], "remedies": ticket['remedies'],
                        "file_paths_raw": [], "remedy_doc_path_raw": None
                    }
                    if ticket['file_path'] and ticket['file_path'].strip():
                        ticket_data_for_response["file_paths_raw"] = [p.strip() for p in ticket['file_path'].split(';') if p.strip()]
                        screenshots_text = [os.path.basename(p) for p in ticket_data_for_response["file_paths_raw"]]
                        if screenshots_text: text_parts.append(f"Attached Files: {', '.join(screenshots_text)}")
                    if ticket['remedy_doc_path'] and ticket['remedy_doc_path'].strip():
                        ticket_data_for_response["remedy_doc_path_raw"] = ticket['remedy_doc_path'].strip()
                        text_parts.append(f"Remedy Document: {os.path.basename(ticket_data_for_response['remedy_doc_path_raw'])}")
                    
                    ticket_data_for_response["summary_text_for_ai"] = "\n".join(text_parts) 
                    response_data = ticket_data_for_response 
                else:
                    response_data = f"Sorry, I couldn't find any ticket with ID {tid}."
            except ValueError:
                response_data = f"The ticket ID '{tid_str}' doesn't seem to be a valid number."
                app.logger.warning(f"Chatbot: Invalid string for ticket ID: {tid_str}")
            except Exception as e:
                app.logger.error(f"Chatbot error fetching ticket ID {tid_str}: {e}")
                response_data = "I encountered an error trying to fetch the ticket details."
        
        # har user ka ticket
        elif any(user_message_lower.startswith(p) for p in ["tickets by ", "show tickets for "]):
            found_specific_query = True
            try:
                s_query = next((user_message_lower[len(p):].strip() for p in ["tickets by ", "show tickets for "] if user_message_lower.startswith(p)), None)
                if not s_query:
                    response_data = "Please specify a username or email to search for (e.g., 'tickets by user@example.com')."
                else:
                    cur.execute("SELECT id, title, status, created_at FROM tickets WHERE LOWER(created_by) LIKE LOWER(?) ORDER BY datetime(created_at) DESC LIMIT 5", (f"%{s_query}%",))
                    tickets = cur.fetchall()
                    if tickets:
                        response_data = f"Here are the latest 5 tickets for users matching '{s_query}':\n" + "\n".join([f"- ID {t['id']}: {t['title']} (Status: {t['status']}, Created: {t['created_at']})" for t in tickets])
                    else:
                        response_data = f"No tickets found for users matching '{s_query}'."
            except Exception as e:
                app.logger.error(f"Chatbot error fetching tickets by user '{s_query}': {e}")
                response_data = "I encountered an error trying to fetch user tickets."

        # status tickets ka
        elif any(keyword in user_message_lower for keyword in [" tickets", " status is "]) and \
             any(status_keyword in user_message_lower for status_keyword in ['open', 'resolved', 'closed', 'in progress', 'pending', 'pending user']): 
            found_specific_query = True
            status_to_find = None
            possible_statuses = {'open': 'Open', 'resolved': 'Resolved', 'closed': 'Closed', 'in progress': 'In Progress', 'pending user': 'Pending User', 'pending':'Pending User'} 
            for key_phrase, status_val in possible_statuses.items():
                if key_phrase in user_message_lower:
                    status_to_find = status_val
                    break
            if status_to_find:
                cur.execute("SELECT id, title, created_by FROM tickets WHERE status = ? ORDER BY datetime(created_at) DESC LIMIT 5", (status_to_find,))
                tickets = cur.fetchall()
                if tickets:
                    response_data = f"Here are the latest 5 '{status_to_find}' tickets:\n" + "\n".join([f"- ID {t['id']}: {t['title']} (By: {t['created_by']})" for t in tickets])
                else:
                    response_data = f"No '{status_to_find}' tickets found currently."
            else: 
                response_data = "Which status are you interested in (e.g., open, resolved, closed)?"

        # tickets seaching keywors k sath
        elif user_message_lower.startswith("search tickets for ") or user_message_lower.startswith("find tickets about "):
            found_specific_query = True
            search_term = user_message_lower.replace("search tickets for ", "").replace("find tickets about ","").strip()
            if search_term:
                like_term = f"%{search_term}%"
                cur.execute("SELECT id, title, status FROM tickets WHERE LOWER(title) LIKE LOWER(?) OR LOWER(description) LIKE LOWER(?) OR LOWER(remedies) LIKE LOWER(?) ORDER BY datetime(created_at) DESC LIMIT 5", 
                            (like_term,like_term,like_term))
                tickets = cur.fetchall()
                if tickets:
                    response_data = f"Found up to 5 tickets matching '{search_term}':\n" + "\n".join([f"- ID {t['id']}: {t['title']} (Status: {t['status']})" for t in tickets])
                else:
                    response_data = f"No tickets found matching '{search_term}'."
            else:
                response_data = "Please specify what you want to search for (e.g., 'search tickets for login issue')."

        # ticket count krne 
        elif user_message_lower.startswith("how many tickets are ") or user_message_lower.startswith("count of "):
            found_specific_query = True
            status_to_count = None
            possible_statuses = {'open': 'Open', 'resolved': 'Resolved', 'closed': 'Closed', 'in progress': 'In Progress', 'pending user': 'Pending User', 'pending':'Pending User'}
            for key_phrase, status_val in possible_statuses.items():
                if key_phrase in user_message_lower:
                    status_to_count = status_val
                    break
            if status_to_count:
                cur.execute("SELECT COUNT(*) FROM tickets WHERE status = ?", (status_to_count,));
                count = cur.fetchone()[0]
                response_data = f"There are {count} ticket(s) with status '{status_to_count}'."
            elif "total tickets" in user_message_lower or "all tickets" in user_message_lower: 
                cur.execute("SELECT COUNT(*) FROM tickets");
                count = cur.fetchone()[0]
                response_data = f"There are a total of {count} ticket(s) in the system."
            else:
                response_data = "Which status count are you interested in (e.g., 'how many tickets are open')?"

        # mst vali new tickets
        elif "latest " in user_message_lower and " tickets" in user_message_lower:
            found_specific_query = True
            try:
                parts = user_message_lower.split()
                num_tickets = None
                for i, part in enumerate(parts):
                    if part == "latest" and i + 1 < len(parts) and parts[i+1].isdigit():
                        num_tickets = int(parts[i+1])
                        break
                if num_tickets is not None:
                    num_tickets = min(num_tickets, 10) 
                    cur.execute("SELECT id, title, status FROM tickets ORDER BY datetime(created_at) DESC LIMIT ?", (num_tickets,))
                    tickets = cur.fetchall()
                    if tickets:
                        response_data = f"Here are the latest {len(tickets)} tickets:\n" + "\n".join([f"- ID {t['id']}: {t['title']} (Status: {t['status']})" for t in tickets])
                    else:
                        response_data = "No tickets found."
                else:
                    response_data = "Please specify how many latest tickets you want (e.g., 'latest 5 tickets')."
            except ValueError:
                response_data = "Please specify a valid number for latest tickets."
            except Exception as e:
                app.logger.error(f"Chatbot error fetching latest tickets: {e}")
                response_data = "I encountered an error trying to fetch the latest tickets."

        # kisne banai
        elif any(user_message_lower.startswith(p) for p in ["who created ticket ", "creator of ticket "]):
            found_specific_query = True
            try:
                creator_tid_str = None
                for p in ["who created ticket ", "creator of ticket "]:
                    if user_message_lower.startswith(p):
                        potential_id = user_message_lower[len(p):].strip().split(" ")[0]
                        if potential_id.isdigit():
                            creator_tid_str = potential_id
                            break
                if not creator_tid_str and user_message_lower.split()[-1].isdigit() and \
                   any(kw in user_message_lower for kw in ["ticket", "id", "creator"]):
                     creator_tid_str = user_message_lower.split()[-1]

                if not creator_tid_str:
                    response_data = "Please provide a valid ticket ID to find its creator (e.g., 'creator of ticket 123')."
                else:
                    tid = int(creator_tid_str)
                    cur.execute("SELECT created_by, title FROM tickets WHERE id = ?", (tid,));
                    ticket = cur.fetchone()
                    if ticket:
                        response_data = f"Ticket ID {tid} (\"{ticket['title']}\") was created by: {ticket['created_by']}."
                    else:
                        response_data = f"No ticket found with ID {tid}."
            except ValueError: 
                response_data = "Please provide a valid ticket ID (must be a number)."
            except Exception as e:
                app.logger.error(f"Chatbot error fetching ticket creator for ID '{creator_tid_str}': {e}")
                response_data = "I encountered an error trying to find the ticket creator."
        
        if not found_specific_query and len(user_message_lower.split()) > 1: 
            like_term = f"%{user_message_lower}%"
            cur.execute("SELECT id, title, status FROM tickets WHERE LOWER(title) LIKE LOWER(?) OR LOWER(description) LIKE LOWER(?) OR LOWER(remedies) LIKE LOWER(?) OR LOWER(created_by) LIKE LOWER(?) ORDER BY datetime(created_at) DESC LIMIT 3", 
                        (like_term, like_term, like_term, like_term))
            tickets = cur.fetchall()
            if tickets:
                response_data = f"I found these tickets that might be related to '{user_message_lower}':\n" + "\n".join([f"- ID {t['id']}: {t['title']} (Status: {t['status']})" for t in tickets])
                response_data += "\n\nCould you be more specific if this isn't what you're looking for, or ask a general question?"
                found_specific_query = True 
    
    except sqlite3.Error as sql_e:
        app.logger.error(f"Chatbot SQLite database error for user query '{user_message_lower}': {sql_e}")
        response_data = "I encountered a database problem while searching for an answer. Please try again later."
        found_specific_query = True 
    except Exception as e:
        app.logger.error(f"Chatbot unexpected error during DB query for '{user_message_lower}': {e}")
        response_data = "I encountered an unexpected issue while trying to understand your request. Please try again."
        found_specific_query = True 
    finally:
        conn.close()
    
    if not found_specific_query:
        app.logger.info(f"Chatbot: No specific DB query matched for '{user_message_lower}'. Signaling for direct AI processing.")
        return {
            "type": DIRECT_AI_SIGNAL, 
            "original_query": user_message_lower
        }
        
    return response_data

def generate_ai_chat_response(user_message, db_query_or_signal):
    if not GEMINI_API_KEY:
        app.logger.warning("Chatbot: Gemini API Key is missing. AI responses will be limited.")
        if isinstance(db_query_or_signal, dict) and db_query_or_signal.get("type") == DIRECT_AI_SIGNAL:
            return "My AI capabilities are currently unavailable for general questions. Please try asking about specific tickets."
        if isinstance(db_query_or_signal, dict) and db_query_or_signal.get("type") == "ticket_details":
            return db_query_or_signal.get("summary_text_for_ai", "Ticket information is available, but AI summarization is currently offline.")
        return str(db_query_or_signal) 

    prompt = ""
    if isinstance(db_query_or_signal, dict) and db_query_or_signal.get("type") == DIRECT_AI_SIGNAL:
        original_query = db_query_or_signal.get("original_query", user_message)
        app.logger.info(f"Chatbot: Using direct AI prompt for query: '{original_query}'")
        prompt = f"""The user asked: "{original_query}"
Please provide a helpful and general response. You do not have access to specific database information for this question.
Answer as a helpful assistant. If the question seems like a command you cannot fulfill (e.g. 'delete ticket 5'), politely explain you are an informational assistant and cannot perform actions.
If the query is vague, ask for clarification. If it's a greeting, respond politely.
Chatbot's Answer:"""
    elif isinstance(db_query_or_signal, dict) and db_query_or_signal.get("type") == "ticket_details":
        ticket_summary = db_query_or_signal.get("summary_text_for_ai", "Found details for a ticket.")
        app.logger.info(f"Chatbot: Using DB-contextualized (ticket_details) AI prompt for query: '{user_message}'")
        prompt = f"""User asked: "{user_message}"
Based *only* on this ticket information, provide a friendly and concise summary or answer related to the user's question.
Do not invent information not present in the ticket details.
Ticket Information:
{ticket_summary}

Chatbot's Answer:"""
    else: 
        app.logger.info(f"Chatbot: Using DB-contextualized (string) AI prompt for query: '{user_message}'")
        prompt = f"""User asked: "{user_message}"
Based *only* on the following database information, provide a friendly and concise answer. 
If the database info is a list of items, summarize it or list key items. 
If the database info indicates "no ticket/s found" or a similar negative result, state that politely. 
If it's an error message or a help message like "Please specify...", rephrase that helpfully for the user.
Do not add any information not present in the database result.
Database Result:
```{str(db_query_or_signal)}```
Chatbot's Answer:"""

    try:
        model = genai.GenerativeModel('gemini-1.5-flash-latest') 
        response = model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(
                max_output_tokens=400,
                temperature=0.5      
            )
        )
        
        ai_text = "".join(part.text for part in response.candidates[0].content.parts).strip() if response.candidates and response.candidates[0].content.parts else ""
        
        if not ai_text: 
            if response.prompt_feedback and response.prompt_feedback.block_reason:
                block_msg = response.prompt_feedback.block_reason_message or "Content generation was limited due to safety settings."
                app.logger.warning(f"Gemini blocked AI response: {block_msg}. Prompt: {prompt[:200]}")
                return f"My response was limited by content policy ({block_msg}). Could you please rephrase your query or ask something different?"
            
            app.logger.info(f"Chatbot AI returned empty content. Fallback based on db_query_or_signal. Prompt: {prompt[:200]}")
            if isinstance(db_query_or_signal, dict) and db_query_or_signal.get("type") == DIRECT_AI_SIGNAL:
                return "I'm sorry, I couldn't generate a specific response for that right now. Please try rephrasing your question."
            if isinstance(db_query_or_signal, dict) and db_query_or_signal.get("type") == "ticket_details":
                return db_query_or_signal.get("summary_text_for_ai", "AI could not summarize the ticket, but its details were found.")
            return "The AI assistant couldn't phrase a response. Here's the direct information I found:\n" + str(db_query_or_signal)
        
        return ai_text

    except Exception as e:
        app.logger.error(f"Gemini API call error for chatbot (prompt: {prompt[:200]}...): {str(e)}")
        if isinstance(db_query_or_signal, dict) and db_query_or_signal.get("type") == DIRECT_AI_SIGNAL:
            return "An AI service error occurred. I can't process general queries right now. Try asking about specific tickets."
        if isinstance(db_query_or_signal, dict) and db_query_or_signal.get("type") == "ticket_details":
            return db_query_or_signal.get("summary_text_for_ai", "An AI service error occurred, but ticket details were found.")
        return f"An AI service error occurred. Here's the direct information I found:\n{str(db_query_or_signal)}"


@app.route('/chat_api', methods=['POST'])
@login_required
def chat_api():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON payload"}), 400
    
    msg = data.get('message','').strip()
    mode = data.get('mode', 'ticket_assistant') 

    if not msg:
        return jsonify({"reply": "Please type a message to start the chat."})

    app.logger.info(f"Chat API: mode='{mode}', message='{msg}' from user: {session.get('username')}")

    final_reply_text = ""
    relevant_docs_list = []
    is_direct_ai_response = False 
    research_topic_suggestion = msg 

    db_result_for_ai_processing = None 

    if mode == 'general_ai':
    
        db_result_for_ai_processing = {"type": DIRECT_AI_SIGNAL, "original_query": msg}
        is_direct_ai_response = True
    else: 
        db_query_output = query_database_for_chatbot(msg.lower())

        if isinstance(db_query_output, dict):
            if db_query_output.get("type") == "ticket_details":
                ticket_info = db_query_output
                db_result_for_ai_processing = ticket_info 
                research_topic_suggestion = ticket_info.get("title", msg) 

                raw_file_paths = ticket_info.get("file_paths_raw", [])
                for raw_path in raw_file_paths:
                    if raw_path: 
                        filename = os.path.basename(raw_path)
                        try:
                            file_url = url_for('uploaded_file', filename=filename, _external=False)
                            relevant_docs_list.append({"name": filename, "url": file_url, "type": "attachment"})
                        except Exception as e:
                            app.logger.error(f"Could not generate URL for attachment {filename} in chat: {e}")
                
                raw_remedy_path = ticket_info.get("remedy_doc_path_raw")
                if raw_remedy_path:
                    remedy_filename = os.path.basename(raw_remedy_path)
                    try:
                        remedy_url = url_for('uploaded_file', filename=remedy_filename, _external=False)
                        relevant_docs_list.append({"name": remedy_filename, "url": remedy_url, "type": "remedy_document"})
                    except Exception as e:
                        app.logger.error(f"Could not generate URL for remedy doc {remedy_filename} in chat: {e}")
                is_direct_ai_response = False 
            
            elif db_query_output.get("type") == DIRECT_AI_SIGNAL: 
                db_result_for_ai_processing = db_query_output    
                is_direct_ai_response = True
            else: 
                db_result_for_ai_processing = "Error: Received an unexpected data structure from database query."
                is_direct_ai_response = False 
        else: 
            db_result_for_ai_processing = db_query_output
            is_direct_ai_response = False 

    final_reply_text = generate_ai_chat_response(msg, db_result_for_ai_processing)
    
    return jsonify({
        "reply": final_reply_text,
        "relevant_docs": relevant_docs_list,
        "is_direct_ai": is_direct_ai_response, 
        "research_topic_suggestion": research_topic_suggestion,
        "aws_docs": [] 
    })


@app.route('/aws_doc_search_api', methods=['POST'])
@login_required
def aws_doc_search_api():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON payload"}), 400
    
    research_topic = data.get('research_topic', '').strip()
    if not research_topic:
        return jsonify({"error": "Research topic is required."}), 400

    app.logger.info(f"AWS Doc Search API request for topic: '{research_topic}'")

    aws_documentation_links = []
    if not GEMINI_API_KEY:
        app.logger.warning("AWS Doc Search: Gemini API Key not configured.")
        return jsonify({"error": "AI service for AWS Doc Search is unavailable."}), 503

    try:
        aws_search_prompt = f"""
        Please find up to 3-4 highly relevant official AWS documentation links 
        related to the following topic: "{research_topic}". 
        For each link, provide a concise title (max 10 words) and the full URL.
        Focus on official AWS documentation (docs.aws.amazon.com, aws.amazon.com blogs, whitepapers, workshops.aws).
        Format your response STRICTLY as a JSON list of objects, where each object has "title" and "url" keys.
        Example:
        [
          {{"title": "Getting Started with Amazon S3", "url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/GetStartedWithS3.html"}},
          {{"title": "EC2 Instance Types Overview", "url": "https://aws.amazon.com/ec2/instance-types/"}}
        ]
        If no specific official AWS docs are found, return an empty list ([]). Do not invent links. Do not add any other text before or after the JSON list.
        """
        model = genai.GenerativeModel('gemini-1.5-flash-latest') 
        response = model.generate_content(
            aws_search_prompt,
            generation_config=genai.types.GenerationConfig(
                max_output_tokens=1500,
                temperature=0.2       
            )
        )
        
        ai_response_text = "".join(part.text for part in response.candidates[0].content.parts).strip() if response.candidates and response.candidates[0].content.parts else ""
        
        if ai_response_text:
            app.logger.debug(f"AWS Doc Search Gemini Raw Response: {ai_response_text}")
            try:
                if ai_response_text.startswith("```json"):
                    ai_response_text = ai_response_text.split("```json\n", 1)[1].rsplit("\n```", 1)[0]
                elif ai_response_text.startswith("```"): 
                     ai_response_text = ai_response_text.split("```\n", 1)[1].rsplit("\n```", 1)[0]

                parsed_links = json.loads(ai_response_text) 
                if isinstance(parsed_links, list):
                    for link_obj in parsed_links:
                        if isinstance(link_obj, dict) and "title" in link_obj and "url" in link_obj:
                            if isinstance(link_obj["url"], str) and (link_obj["url"].startswith("http://") or link_obj["url"].startswith("https://")):
                                aws_documentation_links.append({"title": str(link_obj["title"]), "url": link_obj["url"]})
                            else:
                                app.logger.warning(f"Skipping invalid URL from Gemini for AWS docs: {link_obj.get('url')}")
                        else:
                            app.logger.warning(f"Gemini returned non-dict or malformed link object for AWS docs: {link_obj}")
                else:
                    app.logger.warning(f"Gemini did not return a list for AWS docs, got: {type(parsed_links)}. Raw: {ai_response_text}")
            except json.JSONDecodeError as json_e:
                app.logger.error(f"Failed to parse Gemini JSON response for AWS docs: {json_e}. Raw response: {ai_response_text}")
        
                if "http" not in ai_response_text:
                     aws_documentation_links = []
            except Exception as e:
                 app.logger.error(f"Unexpected error processing Gemini response for AWS docs: {e}. Raw response: {ai_response_text}")
                 aws_documentation_links = [] 

        if not aws_documentation_links:
             app.logger.info(f"No valid AWS docs links extracted by AI for topic: {research_topic}")
        
        return jsonify({"aws_docs": aws_documentation_links, "message": "AWS documentation search complete." if aws_documentation_links else "No relevant AWS documentation found by AI."})

    except Exception as e:
        app.logger.error(f"Error during AWS doc search API for topic '{research_topic}': {e}")
        return jsonify({"error": "Failed to search for AWS documentation due to an internal error."}), 500



@app.route('/chatbot')
@login_required
def chatbot_page():
    return render_template('chatbot.html', username=session.get('username')) 


with app.app_context():
    print("--- Registered Endpoints (After potential changes) ---")
    endpoints_found = set()
    for rule in app.url_map.iter_rules():
        print(f"Endpoint: {rule.endpoint}, Path: {rule.rule}, Methods: {','.join(rule.methods)}")
        endpoints_found.add(rule.endpoint)
    if 'get_tickets_over_time_counts' not in endpoints_found:
        print("\nERROR: 'get_tickets_over_time_counts' IS STILL NOT REGISTERED!\n")
    if 'get_ticket_status_summary' not in endpoints_found:
        print("\nERROR: 'get_ticket_status_summary' IS STILL NOT REGISTERED!\n") # Check previous one too
    print("------------------------------------------------------")

if __name__ == '__main__':
    init_db()
    print("DB Path:", os.path.abspath(DB_PATH))
    print(f"Flask app secret key is: {'SET (length ' + str(len(app.secret_key)) + ')' if app.secret_key and app.secret_key != 'def@ult-Sup3r-S3cr3t-Key-P13a5e-Chang3-M3!' else 'NOT SET (USING DEFAULT FALLBACK - INSECURE!)'}")
    if not OTP_EMAIL_SENDER or not OTP_EMAIL_PASSWORD:
        print("WARNING: Email sending credentials (EMAIL_USER or PASSWORD in .env for OTP) are not fully configured. OTP emails will fail.")
    else:
        print(f"OTP Email sending configured with user: {OTP_EMAIL_SENDER}")
    
    print("Starting Flask-SocketIO server...")
    socketio.run(app, host='0.0.0.0', port=5001, debug=True, use_reloader=True)
    
