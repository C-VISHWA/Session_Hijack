# app.py (Flask Version - Continuous Anomaly Check - FINAL)
from flask import Flask, render_template, request, redirect, url_for, session, flash # Ensure Flask is imported
import pandas as pd
import pickle
import os
import uuid
import hashlib
from functools import wraps # Import wraps for the decorator

# --- Flask App Setup ---
app = Flask(__name__) # Ensure 'app' is the variable name
# Use Render Environment Variable for SECRET_KEY in production
app.secret_key = os.environ.get('SECRET_KEY', b'_5#y2L"F4Q8z\n\xec]/' ) # Fallback for local

# --- Global Model Variable ---
model = None

# --- Security & Model Functions ---
def hash_password(password):
    """Hashes a password."""
    return hashlib.sha256(str.encode(password)).hexdigest()

def load_anomaly_model():
    """Loads the model from the expected path."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(base_dir, 'model', 'rf_pipeline_model.pkl')
    print(f"Attempting to load model from: {model_path}")
    if not os.path.exists(model_path):
        print(f"--- ERROR --- Model file NOT FOUND at {model_path}.")
        print("Ensure the build script ran successfully and created the file in the 'model' directory.")
        return None
    try:
        with open(model_path, 'rb') as f:
            loaded_model = pickle.load(f)
        print("✅ Anomaly detection model loaded successfully.")
        return loaded_model
    except Exception as e:
        print(f"--- ERROR --- Error loading model from {model_path}: {e}")
        return None

# --- Function to get SIMULATED METADATA for LOGIN ATTEMPT ---
def get_simulated_login_metadata(simulated_user_type):
    """Generates metadata based on the dropdown simulation choice for the initial login check."""
    if simulated_user_type == "Normal User (NY)":
        metadata = {
            "request_type": "POST",
            "status_code": 200,
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36",
            "location": "New York"
        }
    elif simulated_user_type == "Normal User (London)":
        metadata = {
            "request_type": "POST",
            "status_code": 200,
            "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15",
            "location": "London"
        }
    elif simulated_user_type == "Anomalous Bot (404)": # Suspicious
        metadata = {
            "request_type": "GET",
            "status_code": 404,
            "user_agent": "SuspiciousBot/1.0 (Scraping)",
            "location": "Moscow"
        }
    else: # "Anomalous POST" - Suspicious
        metadata = {
            "request_type": "POST",
            "status_code": 200,
            "user_agent": "python-requests/2.25.1",
            "location": "New York"
        }
    return metadata

# --- Function to get METADATA FOR THE *CURRENT* REQUEST (for subsequent checks) ---
def get_current_request_metadata():
    """Extracts metadata relevant to the model from the current live request."""
    user_agent = request.headers.get('User-Agent', 'Unknown')
    # Using session's login location as a fallback proxy for current location
    location = session.get('login_location', 'Unknown') # Default if not logged in
    request_type = request.method
    status_code = 200 # Assume okay status for check on existing session

    metadata = {
        "request_type": request_type,
        "status_code": status_code,
        "user_agent": user_agent,
        "location": location
    }
    return metadata

# --- Check function for ANOMALOUS LOGIN ATTEMPT ---
def check_anomaly_on_login(loaded_model, metadata_dict):
    """Checks the simulated metadata during a login attempt."""
    global model
    if model is None:
        print("--- WARNING --- Anomaly model not loaded during login check. Skipping (FAIL OPEN).")
        return False
    data = pd.DataFrame([metadata_dict])
    print(f"--- DEBUG: Data sent to model (Login Attempt) --- \n{data}")
    try:
        prediction = model.predict(data)
        print(f"--- DEBUG: Raw model prediction (Login Attempt): {prediction}")
        is_anomalous = (prediction[0] == 1)
        print(f"--- DEBUG: Is login attempt anomalous? {is_anomalous}")
        return is_anomalous
    except Exception as e:
        print(f"--- ERROR --- Error during login anomaly prediction: {e}")
        return False

# --- Check function for ANOMALY ON SUBSEQUENT REQUESTS (ML Model part) ---
def check_anomaly_on_request_ml(loaded_model):
    """Checks the current live request's metadata against the ML model."""
    global model
    if model is None:
        print("--- WARNING --- Anomaly model not loaded during request check. Skipping ML check.")
        return False # Skip ML check if model isn't loaded

    current_metadata = get_current_request_metadata()
    data = pd.DataFrame([current_metadata])
    print(f"--- DEBUG: Data for subsequent ML check ---\n{data}")
    try:
        prediction = model.predict(data)
        print(f"--- DEBUG: Subsequent request ML prediction: {prediction}")
        is_anomalous = (prediction[0] == 1)
        print(f"--- DEBUG: Subsequent request ML anomalous? {is_anomalous}")
        return is_anomalous
    except Exception as e:
        print(f"--- ERROR --- Error during subsequent ML anomaly prediction: {e}")
        return False # Fail safe

# --- Decorator for Protected Routes ---
def login_required_and_check(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 1. Basic Login Check (is user_id in session?)
        if 'user_id' not in session:
            flash("Please log in to access this page.", "error")
            return redirect(url_for('login'))

        # --- 2. HEURISTIC CHECK: User-Agent comparison ---
        login_ua = session.get('login_user_agent')
        current_ua = request.headers.get('User-Agent', 'Unknown')
        ua_mismatch = False
        if login_ua and login_ua != current_ua:
             ua_mismatch = True
             print(f"--- DEBUG: User-Agent MISMATCH detected! Login: '{login_ua}' vs Current: '{current_ua}' ---")

        if ua_mismatch:
             flash("Session anomaly detected (context change). Please log in again.", "error")
             session.clear() # Log out fully
             return redirect(url_for('login'))

        # --- 3. Optional: ML Anomaly Check on Current Request ---
        # Uncomment this block if you want the ML model to *also* check
        # if the current request itself looks like a bot, even if the UA matches.
        # if check_anomaly_on_request_ml(model):
        #      flash("Suspicious activity detected in your session (ML Model). Please log in again.", "error")
        #      session.clear()
        #      return redirect(url_for('login'))

        # If all checks pass, proceed
        print("--- DEBUG: All session checks passed. ---")
        return f(*args, **kwargs)
    return decorated_function

# --- Load Model at Startup ---
with app.app_context():
    if model is None:
        print("Attempting initial model load...")
        model = load_anomaly_model()

# --- Routes ---
@app.route('/', methods=['GET', 'POST'])
def login():
    # Handle simulation type change
    if request.method == 'POST' and request.form.get('simulation_change') == 'true':
        session['simulated_user_type'] = request.form.get('simulated_user_type', 'Normal User (NY)')
        return render_template('login.html', simulated_user_type=session['simulated_user_type'])

    simulated_user_type = session.get('simulated_user_type', 'Normal User (NY)')

    # Handle login submission
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        current_sim_type = request.form.get('simulated_user_type', simulated_user_type)

        demo_users = {
            "admin": hash_password("password123"),
            "user": hash_password("streamlit")
        }

        # --- Initial Login Anomaly Check ---
        login_metadata = get_simulated_login_metadata(current_sim_type)
        print(f"Checking Initial Login anomaly for simulated type: {current_sim_type}")
        is_anomalous_login = check_anomaly_on_login(model, login_metadata)

        if is_anomalous_login:
            flash("Access Denied: Suspicious Activity Detected by Model during login.", "error")
            session.clear()
            return render_template('login.html', simulated_user_type=current_sim_type)
        else:
            # --- Check Credentials ---
            if username in demo_users and demo_users[username] == hash_password(password):
                # --- SUCCESS: Set session, store baseline, redirect ---
                session.clear() # Clear old session data before setting new
                session['username'] = username
                session['user_id'] = str(uuid.uuid4())
                # Store baseline User-Agent from this successful login attempt's metadata
                session['login_user_agent'] = login_metadata.get('user_agent', 'Unknown_Login_UA')
                # Store baseline Location
                session['login_location'] = login_metadata.get('location', 'Unknown_Login_Loc')
                print(f"--- INFO: Stored baseline UA: {session['login_user_agent'][:30]}..., Loc: {session['login_location']} ---")

                flash("Login Successful!", "success")
                return redirect(url_for('dashboard'))
            else:
                flash("Invalid username or password.", "error")
                return render_template('login.html', simulated_user_type=current_sim_type)

    # --- Handle GET Request ---
    # If user is already logged in (e.g., has a valid session cookie), redirect to dashboard
    # The decorator on dashboard will handle checks
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    # Otherwise, show the login page
    return render_template('login.html', simulated_user_type=simulated_user_type)


@app.route('/dashboard')
@login_required_and_check # Apply the security decorator
def dashboard():
    # If code reaches here, decorator checks passed
    return render_template(
        'dashboard.html',
        username=session['username'],
        session_id_display=session['user_id']
    )

@app.route('/logout')
def logout():
    session.clear() # Clear all session data
    flash("You have been logged out.", "success")
    return redirect(url_for('login'))

# --- Run the App ---
if __name__ == '__main__':
    if model is None:
       # Log a critical error if the model didn't load during startup
       print("\n--- CRITICAL STARTUP ERROR ---")
       print("Model was not loaded. Application cannot run securely.")
       print("Check build logs and file paths.")
       print("---")
       # Optionally exit:
       # import sys
       # sys.exit(1)

    # Get port from environment variable, default to 5000
    port = int(os.environ.get('PORT', 5000))
    # host='0.0.0.0' is essential for Render
    print(f"--- Starting Flask App on host 0.0.0.0 port {port} ---")
    # Render uses Gunicorn via Procfile, app.run() is for local testing mostly
    app.run(host='0.0.0.0', port=port)