from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import webauthn
import webauthn.helpers.structs as webauthn_structs
import os
import base64
import json
from webauthn.helpers import (
    options_to_json, 
    parse_registration_credential_json, 
    parse_authentication_credential_json
)

app = Flask(__name__)
# A secret key is required for sessions (to track login status)
app.config['SECRET_KEY'] = 'high_security_secret_key_98765'

# --- WebAuthn Server Configuration ---
# We'll start with localhost. We can change this for Render later.
RP_ID = 'localhost'
RP_NAME = 'High Security Biometric App'
EXPECTED_ORIGIN = 'http://localhost:8090'

# --- In-Memory Database ---
# This new DB is designed to hold both face and fingerprint data
# It will reset every time the server restarts!
db = {
    "users": {},  # Stores user info by username
    "credentials": {}  # Stores credentials by user_id
}
# Example user:
# db["users"]["victor"] = {
#     "id": b"some_random_bytes", 
#     "username": "victor", 
#     "face_descriptor": [0.1, 0.2, ...] 
# }
# db["credentials"][b"some_random_bytes"] = [ ...credential_object... ]

# === Routes for Standard Pages ===

@app.route('/')
@app.route('/register')
def register():
    """Renders the single registration page."""
    return render_template('register.html')


@app.route('/login')
def login():
    """Renders the single login page."""
    return render_template('login.html')


@app.route('/success')
def success():
    """Renders the success page after a successful login."""
    if not session.get('logged_in'):
        return redirect(url_for('login'))
        
    return render_template('success.html')

# === 1. HIGH-SECURITY REGISTRATION ===

@app.route('/register-begin', methods=['POST'])
def register_begin():
    """
    Called by JavaScript *after* a successful face scan.
    Receives face data and sends back a fingerprint challenge.
    """
    data = request.json
    username = data.get('username')
    face_descriptor = data.get('face_descriptor') # The 128 numbers from the AI

    if not username or not face_descriptor:
        return jsonify({"error": "Username and face descriptor are required"}), 400

    if username in db['users']:
        return jsonify({"error": "User already exists"}), 400

    # Create new user and save their face data
    user_id = os.urandom(32)
    db['users'][username] = {
        "id": user_id,
        "username": username,
        "face_descriptor": face_descriptor 
    }
    # Create an empty list for their credentials
    db['credentials'][user_id] = []
    
    # Store ID and challenge for the next step
    session['registration_user_id'] = base64.b64encode(user_id).decode('utf-8')
    session['registration_username'] = username

    # Now, generate the fingerprint challenge
    options = webauthn.generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=user_id,
        user_name=username,
    )

    session['challenge'] = options.challenge
    
    # Send the fingerprint challenge back to the JavaScript
    return app.response_class(
        response=options_to_json(options),
        mimetype="application/json"
    )


@app.route('/register-complete', methods=['POST'])
def register_complete():
    """
    Called by JavaScript *after* a successful fingerprint scan.
    Receives and verifies the fingerprint credential.
    """
    data = request.json # This is the fingerprint credential
    challenge = session.get('challenge')
    user_id_b64 = session.get('registration_user_id')

    if not challenge or not user_id_b64:
        return jsonify({"error": "Session expired. Please try registering again."}), 400

    user_id = base64.b64decode(user_id_b64)

    try:
        credential = parse_registration_credential_json(data)
        
        registration_verification = webauthn.verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_origin=EXPECTED_ORIGIN,
            expected_rp_id=RP_ID,
        )
    except Exception as e:
        # If fingerprint fails, delete the user we just created
        username = session.get('registration_username')
        if username and username in db['users']:
            del db['users'][username]
            del db['credentials'][user_id]
        return jsonify({"error": f"Fingerprint registration failed: {e}. Please start over."}), 400

    # Fingerprint was good! Save it to the database.
    db['credentials'][user_id].append(registration_verification)
    
    # Clear session and return success
    session.pop('registration_user_id', None)
    session.pop('registration_username', None)
    session.pop('challenge', None)
    
    return jsonify({"success": True, "message": "Registration successful! Both face and fingerprint are saved."})


# === 2. HIGH-SECURITY LOGIN ===

@app.route('/login-begin', methods=['POST'])
def login_begin():
    """
    Called by JavaScript *after* a successful face scan.
    Verifies the user exists, sends back their saved face data,
    and sends a new fingerprint challenge.
    """
    data = request.json
    username = data.get('username')

    if not username:
        return jsonify({"error": "Username is required"}), 400

    user = db['users'].get(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Get the user's saved data
    user_id = user['id']
    saved_face_descriptor = user.get('face_descriptor')
    saved_fingerprint_credentials = db['credentials'].get(user_id, [])

    if not saved_face_descriptor or not saved_fingerprint_credentials:
        return jsonify({"error": "This account is not fully registered with both face and fingerprint."}), 400

    # Create the descriptors for the fingerprint challenge
    descriptors = []
    for cred in saved_fingerprint_credentials:
        descriptors.append(
            webauthn_structs.PublicKeyCredentialDescriptor(
                id=cred.credential_id,
                type=webauthn_structs.PublicKeyCredentialType.PUBLIC_KEY
            )
        )

    # Generate the fingerprint challenge
    options = webauthn.generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=descriptors,
    )

    # Save challenge and user ID for the final step
    session['challenge'] = options.challenge
    session['login_user_id'] = base64.b64encode(user_id).decode('utf-8')
    
    # Send *both* the saved face data AND the new fingerprint challenge
    return jsonify({
        "face_descriptor": saved_face_descriptor,
        "fingerprint_options": json.loads(options_to_json(options)) # Send as a JSON object
    })


@app.route('/login-complete', methods=['POST'])
def login_complete():
    """
    Called by JavaScript *after* a successful fingerprint scan.
    Receives and verifies the fingerprint credential.
    (The face was already verified by the JavaScript)
    """
    data = request.json # This is the fingerprint credential
    challenge = session.get('challenge')
    user_id_b64 = session.get('login_user_id')

    if not challenge or not user_id_b64:
        return jsonify({"error": "Session expired. Please try logging in again."}), 400

    user_id = base64.b64decode(user_id_b64)
    user_credentials = db['credentials'].get(user_id, [])

    try:
        raw_id_from_login = data.get('rawId')
        if not raw_id_from_login:
            return jsonify({"error": "Login data was missing rawId"}), 400
            
        matching_cred = None
        for cred in user_credentials:
            saved_id_b64 = base64.urlsafe_b64encode(cred.credential_id).decode('utf-8').rstrip('=')
            if saved_id_b64 == raw_id_from_login:
                matching_cred = cred
                break
        
        if not matching_cred:
            return jsonify({"error": "Fingerprint credential not recognized."}), 400

        credential = parse_authentication_credential_json(data)

        # Verify the fingerprint
        verification = webauthn.verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_origin=EXPECTED_ORIGIN,
            expected_rp_id=RP_ID,
            credential_public_key=matching_cred.credential_public_key,
            credential_current_sign_count=matching_cred.sign_count,
        )
        
        # Update the signature count
        matching_cred.sign_count = verification.new_sign_count

    except Exception as e:
        return jsonify({"error": f"Fingerprint login failed: {e}"}), 400

    # Both face (in JS) and fingerprint (here) have succeeded!
    session.pop('login_user_id', None)
    session.pop('challenge', None)
    session['logged_in'] = True

    return jsonify({"success": True, "message": "Login successful!"})


# === Run the Application ===

if __name__ == '__main__':
    app.run(debug=True, port=8090)