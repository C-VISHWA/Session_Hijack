# app.py (Flask Version - Heuristic UA Check Added)
# ... (Keep all imports and other functions the same) ...

# --- Decorator for Protected Routes (MODIFIED) ---
from functools import wraps

def login_required_and_check(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 1. Basic Login Check (is user_id in session?)
        if 'user_id' not in session:
            flash("Please log in to access this page.", "error")
            return redirect(url_for('login'))

        # --- NEW HEURISTIC CHECK FOR DEMONSTRATION ---
        # Compare current User-Agent with the one stored during login
        login_ua = session.get('login_user_agent')
        current_ua = request.headers.get('User-Agent', 'Unknown')

        print(f"--- DEBUG: UA Check ---")
        print(f"Login UA: {login_ua}")
        print(f"Current UA: {current_ua}")

        # Basic check: If login UA exists and doesn't match current UA, flag it.
        # Allow if login_ua wasn't stored (e.g., older session) or matches.
        ua_mismatch = False
        if login_ua and login_ua != current_ua:
             ua_mismatch = True
             print("--- DEBUG: User-Agent MISMATCH detected! ---")

        if ua_mismatch:
             # User-Agent changed - potential hijacking attempt
             flash("Session anomaly detected (context change). Please log in again.", "error")
             # Log the user out
             session.clear() # Clear all session data
             return redirect(url_for('login'))
        # --- END NEW HEURISTIC CHECK ---

        # 3. Optional: Perform ML Anomaly Check on Current Request (as secondary check)
        #    This checks if the current request itself looks like a bot, etc.
        #    You can comment this out if you ONLY want the UA check to block reuse.
        # if check_anomaly_on_request(model): # Pass the globally loaded model
        #      flash("Suspicious activity detected in your session (ML Model). Please log in again.", "error")
        #      session.clear()
        #      return redirect(url_for('login'))

        # If all checks pass, proceed to the original route function
        print("--- DEBUG: All session checks passed. ---")
        return f(*args, **kwargs)
    return decorated_function

# ... (Rest of your app.py, including routes, load_model, etc., remains the same) ...

# --- Make sure the check_anomaly_on_request function still exists ---
# (even if commented out in the decorator, it might be called elsewhere or needed later)
def check_anomaly_on_request(loaded_model):
    """Checks the current live request's metadata against the model."""
    global model
    if model is None:
        print("--- WARNING --- Anomaly model not loaded during request check. Skipping.")
        return False

    current_metadata = get_current_request_metadata()
    data = pd.DataFrame([current_metadata])
    print(f"--- DEBUG: Data for subsequent check ---\n{data}")
    try:
        prediction = model.predict(data)
        print(f"--- DEBUG: Subsequent request prediction: {prediction}")
        is_anomalous = (prediction[0] == 1)
        print(f"--- DEBUG: Subsequent request anomalous? {is_anomalous}")
        return is_anomalous
    except Exception as e:
        print(f"--- ERROR --- Error during subsequent anomaly prediction: {e}")
        return False

# ... (The rest of your app.py, including get_current_request_metadata, login, dashboard, logout, if __name__ == '__main__': block) ...