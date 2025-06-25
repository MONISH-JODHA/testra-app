import flask
from flask import Flask, request, redirect, url_for, render_template, session, jsonify, flash
from flask_cors import CORS
import os
import sqlite3
from functools import wraps
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
import pandas as pd
import numpy as np
import json # <<<< ADD THIS IMPORT
# ... (rest of the imports)

load_dotenv()

# --- Global Configuration ---
DB_PATH = './ec2.db'
CSV_PATH = './ec2_prices_all_regions.csv' # Path to your CSV

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'a_very_secure_default_secret_key_123!PleaseChange')
CORS(app, supports_credentials=True)

APP_EMAIL_SENDER = os.getenv('EMAIL_USER')
APP_EMAIL_PASSWORD = os.getenv('PASSWORD')

# Global DataFrame for EC2 data
ec2_df = None
unique_regions = []

def load_and_preprocess_ec2_data():
    global ec2_df, unique_regions
    try:
        df = pd.read_csv(CSV_PATH)
        
        # Preprocess Memory: Extract numeric value
        df['MemoryGiB'] = df['Memory'].str.extract(r'(\d+\.?\d*)').astype(float)
        
        # Calculate Price per vCPU and Price per GiB Memory
        # Handle cases where vCPU or MemoryGiB might be 0 to avoid division by zero
        df['PricePerVCpu'] = df.apply(lambda row: row['PricePerHourUSD'] / row['vCPU'] if row['vCPU'] > 0 else np.inf, axis=1)
        df['PricePerMemoryGiB'] = df.apply(lambda row: row['PricePerHourUSD'] / row['MemoryGiB'] if row['MemoryGiB'] > 0 else np.inf, axis=1)
        
        # Filter out rows where price is 0.0000000000 (likely placeholders or free tiers not relevant for general analysis)
        df = df[df['PricePerHourUSD'] > 0.00000001]

        ec2_df = df
        unique_regions = sorted(df['Region'].unique().tolist())
        print(f"EC2 data loaded and preprocessed successfully. {len(ec2_df)} records.")
    except FileNotFoundError:
        print(f"ERROR: CSV file not found at {CSV_PATH}")
        ec2_df = pd.DataFrame() # Empty DataFrame
    except Exception as e:
        print(f"ERROR: Failed to load or preprocess EC2 data: {e}")
        ec2_df = pd.DataFrame() # Empty DataFrame

# --- Database Initialization ---
def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT UNIQUE NOT NULL,
                            password TEXT NOT NULL, /* TODO: HASH THIS! */
                            otp TEXT,
                            verified INTEGER DEFAULT 0
                        )''')
        conn.commit()
    print(f"User database initialized/checked at {DB_PATH}")
        
def is_valid_email(email):
    return email and email.endswith('@cloudkeeper.com')

def send_otp_email(to_email, otp):
    if not APP_EMAIL_SENDER or not APP_EMAIL_PASSWORD:
        print(f"ERROR: Email credentials not configured. Cannot send OTP. SENDER: {APP_EMAIL_SENDER}, PASS_CONFIGURED: {bool(APP_EMAIL_PASSWORD)}")
        return False

    msg = MIMEMultipart('alternative')
    msg['Subject'] = 'Confirm your signup – Your OTP is inside'
    msg['From'] = f'CloudKeeper Support <{APP_EMAIL_SENDER}>'
    msg['To'] = to_email

    text = f"Hi,\n\nThank you for signing up for CloudKeeper!\n\nYour One-Time Password (OTP) is: {otp}\n\nPlease enter this OTP on the verification page to complete your registration.\nThis OTP is valid for the next 10 minutes.\n\nIf you did not initiate this request, please ignore this email.\n\nBest regards,\nThe CloudKeeper Team"
    html = f"""<html><body><p>Hi,<br><br>Thank you for signing up for CloudKeeper!<br><br><b>Your One-Time Password (OTP) is:</b> <span style="font-size:18px;color:#2E86C1;">{otp}</span><br><br>Please enter this OTP on the verification page to complete your registration.<br>This OTP is valid for the next 10 minutes.<br><br>If you did not initiate this request, please ignore this email.<br><br>Best regards,<br>The CloudKeeper Team</p></body></html>"""
    msg.attach(MIMEText(text, 'plain'))
    msg.attach(MIMEText(html, 'html'))

    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(APP_EMAIL_SENDER, APP_EMAIL_PASSWORD)
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
            flash("You need to be logged in to access this page.", "warning")
            return redirect(url_for('login', next=request.url))
        # Check if user is verified (if not already handled at login)
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT verified FROM users WHERE username = ?", (session['username'],))
            user = cur.fetchone()
            if not user or not user['verified']:
                session.pop('username', None) # Log them out
                flash("Your account is not verified. Please verify or log in again.", "danger")
                return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- Auth Routes ---
@app.route('/')
def index_route():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('email','').strip()
        password = request.form.get('password','')
        if not username or not password: return render_template('login.html', error="Email and password are required.")
        if not is_valid_email(username): return render_template('login.html', error="Invalid email. Must be @cloudkeeper.com.")
        
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password)) # INSECURE: Plain text password
            user = cur.fetchone()
            if user:
                if user['verified']:
                    session['username'] = user['username']
                    next_url = request.args.get('next')
                    print(f"User '{username}' logged in successfully.")
                    flash(f"Welcome back, {username}!", "success")
                    return redirect(next_url or url_for('dashboard'))
                else:
                    session['pending_user'] = username # To prefill email on verify page
                    flash("Your account is not verified. Please check your email for OTP.", "warning")
                    return redirect(url_for('verify_otp'))
            else: 
                error_msg = 'Invalid credentials or account does not exist.'
                return render_template('login.html', error=error_msg)
    return render_template('login.html', success=request.args.get('success'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'username' in session: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('email','').strip()
        password = request.form.get('password','') 

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
            cur.execute("SELECT id, username, password, otp, verified FROM users WHERE username = ?", (username,))
            existing_user = cur.fetchone()
            
            if existing_user:
                 if existing_user['verified']:
                    return render_template('signup.html', error="User already exists and is verified. Please login.")
                 else:
                    cur.execute("UPDATE users SET password = ?, otp = ? WHERE id = ?", (password, otp, existing_user['id'])) # INSECURE: Plain text password
                    conn.commit()
                    print(f"OTP updated for existing unverified user: {username}")
                    if send_otp_email(username, otp):
                        session['pending_user'] = username
                        return redirect(url_for('verify_otp', message='OTP has been resent to your email.'))
                    else:
                         return render_template('signup.html', error="User exists. Failed to resend OTP. Please try again later.")
            else:
                cur.execute("INSERT INTO users (username, password, otp, verified) VALUES (?, ?, ?, 0)", (username, password, otp)) # INSECURE: Plain text password
                conn.commit()
                print(f"New user created: {username}")
                if send_otp_email(username, otp):
                    session['pending_user'] = username
                    return redirect(url_for('verify_otp'))
                else:
                    return render_template('signup.html', error="Account created, but OTP email failed. You might be able to verify later or try signing up again to resend OTP.")
    return render_template('signup.html')

@app.route('/verify', methods=['GET', 'POST'])
def verify_otp():
    pending_user_email = session.get('pending_user')
    message_from_redirect = request.args.get('message')

    if not pending_user_email and request.method == 'GET': # Only redirect if it's a GET and no pending user
        flash("No pending verification. Please sign up or log in.", "info")
        return redirect(url_for('signup'))
    
    # If it's a POST, pending_user_email might be cleared but we proceed with form data
    email_to_verify = pending_user_email if pending_user_email else request.form.get('email_for_verification_fallback', '')


    if request.method == 'POST':
        otp_input = request.form.get('otp','').strip()
        if not otp_input:
            return render_template('verify.html', error="OTP is required.", email=email_to_verify, message=message_from_redirect)
        
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            # Use email_to_verify which could be from session or a hidden form field if session was lost
            cur.execute("SELECT otp, verified FROM users WHERE username = ?", (email_to_verify,))
            user_record = cur.fetchone()

            if user_record and not user_record['verified'] and user_record['otp'] == otp_input:
                cur.execute("UPDATE users SET verified = 1, otp = NULL WHERE username = ?", (email_to_verify,))
                conn.commit()
                session.pop('pending_user', None)
                print(f"User {email_to_verify} verified successfully.")
                flash("Your email has been verified! Please log in.", "success")
                return redirect(url_for('login'))
            elif user_record and user_record['verified']:
                 session.pop('pending_user', None)
                 flash("This account is already verified. You can log in.", "info")
                 return redirect(url_for('login'))
            else:
                error_msg = "Invalid OTP. Please try again."
                if not user_record:
                    error_msg = "Verification record not found for this email. Please try signing up again."
                return render_template('verify.html', error=error_msg, email=email_to_verify, message=message_from_redirect)
                
    return render_template('verify.html', email=email_to_verify, message=message_from_redirect)


@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('pending_user', None)
    print("User logged out.")
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

@app.route('/home_or_main_placeholder_route_for_logo') 
def home_or_main():
    return redirect(url_for('index_route'))

# --- EC2 Analysis Routes ---
# ... (inside server.py)

@app.route('/ec2-analysis')
@login_required
def ec2_analysis_tool():
    if ec2_df is None or ec2_df.empty:
        flash("EC2 pricing data is not available. Please check server logs.", "danger")
        return render_template('ec2_analysis.html', instances=[], regions=[], total_matched_instances=0, infinity=float('inf'))

    # Make a working copy of the full dataframe for this request
    current_view_df = ec2_df.copy()

    # Get filter parameters
    region_filter = request.args.get('region')
    instance_type_prefix = request.args.get('instance_type_prefix', '').strip().lower()
    min_vcpu = request.args.get('min_vcpu', type=int)
    min_memory = request.args.get('min_memory', type=float)
    max_price = request.args.get('max_price', type=float)
    sort_by = request.args.get('sort_by', 'PricePerHourUSD')
    limit_str = request.args.get('limit', '20')

    # --- CHART DATA PREPARATION ---
    # Chart 1: Instance Count by Region (based on the full dataset if no region filter, or just the selected region)
    chart_region_counts_data = None
    if not region_filter and not current_view_df.empty: # Only show if "All Regions" is effectively selected
        region_counts = current_view_df['Region'].value_counts().sort_index()
        chart_region_counts_data = {
            'labels': region_counts.index.tolist(),
            'data': region_counts.values.tolist(),
            'title': 'Instance Types per Region (Overall)'
        }
    elif region_filter and not current_view_df[current_view_df['Region'] == region_filter].empty:
        # If a region is filtered, show count for that region (might be less interesting, but consistent)
        # Or, you could choose to hide this chart if a region is selected. For now, let's show it.
        filtered_for_region_chart = current_view_df[current_view_df['Region'] == region_filter]
        instance_family_counts = filtered_for_region_chart['InstanceType'].apply(lambda x: x.split('.')[0]).value_counts().nlargest(15) # Top 15 families
        chart_region_counts_data = {
            'labels': instance_family_counts.index.tolist(),
            'data': instance_family_counts.values.tolist(),
            'title': f'Instance Type Families in {region_filter}'
        }


    # Apply filters to get the data for table and other charts
    filtered_df = current_view_df.copy() # Start fresh for filtering
    if region_filter:
        filtered_df = filtered_df[filtered_df['Region'] == region_filter]
    if instance_type_prefix:
        filtered_df = filtered_df[filtered_df['InstanceType'].str.lower().str.startswith(instance_type_prefix)]
    if min_vcpu is not None:
        filtered_df = filtered_df[filtered_df['vCPU'] >= min_vcpu]
    if min_memory is not None:
        filtered_df = filtered_df[filtered_df['MemoryGiB'] >= min_memory]
    if max_price is not None:
        filtered_df = filtered_df[filtered_df['PricePerHourUSD'] <= max_price]
    
    # Sorting (ensure this happens *after* all filtering)
    ascending_order = True
    sort_column_for_df = sort_by # Use this for DataFrame sorting
    if sort_by in ['vCPU', 'MemoryGiB']: 
        ascending_order = False
    
    if sort_by in ['PricePerVCpu', 'PricePerMemoryGiB']:
        # For DataFrame sorting, np.inf works.
        # For display, we'll handle np.inf in the template or when preparing chart data.
        filtered_df = filtered_df.sort_values(by=sort_column_for_df, ascending=ascending_order, na_position='last')
    else:
        filtered_df = filtered_df.sort_values(by=sort_column_for_df, ascending=ascending_order, na_position='last')

    total_matched_instances = len(filtered_df)

    # Limiting results for table display
    instances_for_table = []
    if limit_str != 'all':
        try:
            limit = int(limit_str)
            instances_for_table = filtered_df.head(limit).to_dict('records')
        except ValueError:
            instances_for_table = filtered_df.to_dict('records') 
    else:
        instances_for_table = filtered_df.to_dict('records')

    # Chart 2: Top N Instances by Selected Metric (based on filtered and sorted data)
    chart_top_n_data = None
    if instances_for_table: # Use the data prepared for the table (already sorted and limited)
        # Take top 10 from what would be displayed, or fewer if less than 10 results
        top_n_for_chart = instances_for_table[:10]
        
        metric_key = sort_by
        metric_label = sort_by # Default label
        if sort_by == "PricePerHourUSD": metric_label = "Price/Hour (USD)"
        elif sort_by == "PricePerVCpu": metric_label = "Price/vCPU (USD)"
        elif sort_by == "PricePerMemoryGiB": metric_label = "Price/GiB RAM (USD)"
        elif sort_by == "vCPU": metric_label = "vCPUs"
        elif sort_by == "MemoryGiB": metric_label = "Memory (GiB)"

        # Handle np.inf for chart data: replace with a placeholder like 0 or None for Chart.js
        # Chart.js typically skips null/undefined values in bar charts or line charts.
        # For bar chart values, ensure they are numeric.
        chart_data_values = []
        for instance in top_n_for_chart:
            val = instance.get(metric_key)
            if val == np.inf or val == -np.inf or pd.isna(val):
                chart_data_values.append(None) # Or 0, depending on how you want to represent it
            else:
                chart_data_values.append(val)
        
        chart_top_n_data = {
            'labels': [f"{instance['InstanceType']} ({instance['Region']})" for instance in top_n_for_chart],
            'data': chart_data_values,
            'metric_label': metric_label,
            'title': f'Top Instances by {metric_label}' # Dynamic title
        }

    # Chart 3: Price vs. vCPU Scatter Plot (based on *all* filtered results, before table limit)
    chart_price_vcpu_scatter_data = None
    if not filtered_df.empty:
        # Limit scatter plot points for performance if too many, e.g., max 200 points
        scatter_df = filtered_df.head(200) if len(filtered_df) > 200 else filtered_df
        
        scatter_plot_points = []
        for _, instance in scatter_df.iterrows():
            if instance['vCPU'] > 0 and instance['PricePerHourUSD'] != np.inf and not pd.isna(instance['PricePerHourUSD']):
                 scatter_plot_points.append({
                    'x': instance['vCPU'],
                    'y': instance['PricePerHourUSD'],
                    'label': f"{instance['InstanceType']} ({instance['Region']}) | Mem: {instance['MemoryGiB']:.1f}GiB" # Add more info to tooltip
                })
        
        if scatter_plot_points:
            chart_price_vcpu_scatter_data = {
                'datasets': [{
                    'label': 'Instance (vCPU vs Price/Hour)',
                    'data': scatter_plot_points,
                    'backgroundColor': 'rgba(54, 162, 235, 0.6)'
                }],
                'title': 'Price/Hour vs. vCPU (Filtered Results)'
            }
            if len(filtered_df) > 200:
                 chart_price_vcpu_scatter_data['title'] += ' (Sampled 200 points)'


    return render_template('ec2_analysis.html', 
                           instances=instances_for_table, 
                           regions=unique_regions,
                           total_matched_instances=total_matched_instances,
                           infinity=float('inf'), # Still needed for table display of N/A
                           # Pass chart data as JSON strings to be parsed by JavaScript
                           chart_region_counts_data_json=json.dumps(chart_region_counts_data) if chart_region_counts_data else None,
                           chart_top_n_data_json=json.dumps(chart_top_n_data) if chart_top_n_data else None,
                           chart_price_vcpu_scatter_data_json=json.dumps(chart_price_vcpu_scatter_data) if chart_price_vcpu_scatter_data else None
                           )

# ... (rest of your server.py code for main, etc.)


if __name__ == '__main__':
    init_db()
    load_and_preprocess_ec2_data() # Load data at startup
    print("DB Path:", os.path.abspath(DB_PATH))
    print(f"Flask app secret key is: {'SET (length ' + str(len(app.secret_key)) + ')' if app.secret_key and app.secret_key != 'a_very_secure_default_secret_key_123!PleaseChange' else 'NOT SET (USING DEFAULT FALLBACK - INSECURE!)'}")
    if not APP_EMAIL_SENDER or not APP_EMAIL_PASSWORD:
        print("WARNING: Email sending credentials (EMAIL_USER or PASSWORD in .env) are not fully configured. OTP emails will fail.")
    else:
        print(f"Email sending configured with user: {APP_EMAIL_SENDER}")
    
    app.run(host='0.0.0.0', port=5002, debug=True, use_reloader=True) # use_reloader=False if you have issues with data loading twice on startup