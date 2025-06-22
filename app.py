import os
from flask import (
    Flask,
    request,
    redirect,
    url_for,
    session,
    render_template,
    jsonify,
    send_from_directory,
)
from functools import wraps
from models import db, User, OAuth2Client
from oauth_server import config_oauth, authorization_server as oauth
from authlib.integrations.flask_oauth2 import current_token

# --- Flask App Setup ---
app = Flask(__name__)
app.secret_key = os.urandom(24)

db.init_app(app)

@app.before_request
def log_request_info():
    app.logger.info('Headers: %s', request.headers)
    app.logger.info('Body: %s', request.get_data())
    app.logger.info(f'Request to {request.path}')

# --- Static file serving for public client ---
@app.route('/public/<path:path>')
def send_public_file(path):
    return send_from_directory('oauth-clients/public', path)


# --- User Session Management ---
def current_user():
    if 'id' in session:
        uid = session['id']
        return User.query_by_id(uid)
    return None

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        print(f"Checking login for user: {current_user()}")
        if not current_user():
            print("User not found, redirecting to login.")
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


# --- Main Application Routes ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    '''Resource Owner Password Credentials Grant.'''
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query_by_username(username)
        print(username, password, f'User: {user}')
        # In a real app, use hashed passwords and proper validation
        if user and user.password == password:
            session['id'] = user.id
            # Redirect to the URL they were trying to access before login
            next_url = request.args.get('next')
            if next_url:
                return redirect(next_url)
            return redirect('/')
        # If login fails, you would show an error message
    return render_template('login.html')

@app.route('/logout')
def logout():
    del session['id']
    return redirect('/')

@app.route('/')
@login_required
def home():
    return render_template('home.html')

# --- OAuth 2.1 Provider Endpoints ---
# This configures all the /oauth/* routes
require_oauth = config_oauth(app)

@app.route('/oauth/authorize', methods=['GET', 'POST'])
@login_required
def authorize():
    '''
    The endpoint for the resource owner to grant consent to a client.
    '''
    user = current_user()
    if request.method == 'GET':
        try:
            # Let Authlib validate the authorization request
            grant = oauth.get_consent_grant(end_user=user)
            client = grant.client
            return render_template('consent.html', client=client, scopes=client.get_allowed_scope(grant.request.payload.scope), user=user)
        except Exception as e:
            app.logger.error(f'Authorization error: {e}')
            return jsonify({'error': 'invalid_request', 'error_description': str(e)}), 400

    if request.form['confirm']:
        # User has granted consent
        grant_user = user
    else:
        # User has denied consent
        grant_user = None
    
    return oauth.create_authorization_response(grant_user=grant_user)

@app.route('/oauth/token', methods=['POST'])
def issue_token():
    '''The token endpoint, where clients exchange codes/credentials for tokens.'''
    return oauth.create_token_response()

@app.route('/oauth/revoke', methods=['POST'])
def revoke_token():
    '''The token revocation endpoint.'''
    return oauth.create_endpoint_response('revocation')

@app.route('/oauth/introspect', methods=['POST'])
def introspect_token():
    '''The token introspection endpoint for resource servers to validate tokens.'''
    return oauth.create_endpoint_response('introspection')

@app.route('/oauth/register', methods=['POST'])
def register_client():
    '''
    Dynamic Client Registration endpoint.
    In a real app, this endpoint MUST be protected.
    '''
    client_meta = request.get_json()
    client = OAuth2Client.create_dynamic_client(client_meta)
    
    if not client:
        return jsonify({'error': 'invalid_client_metadata'}), 400
        
    client_info = client.get_client_info()
    return jsonify(client_info), 201


# --- Resource Server ---
@app.route('/api/profile')
@require_oauth('profile')
def api_profile():
    '''
    A protected resource endpoint.
    The `require_oauth` decorator ensures a valid token with the 'profile' scope.
    '''
    user = User.query_by_id(current_token.user_id)
    return jsonify(
        id=user.id,
        username=user.username,
        message='This is your protected profile information.'
    )


# --- Main Entry Point ---
if __name__ == '__main__':
    # Initialize the 'database' with some sample data
    app.run(host='0.0.0.0', port=5001, debug=True)
