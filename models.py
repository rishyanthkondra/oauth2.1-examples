import time
from authlib.oauth2.rfc6749 import (
    AuthorizationCodeMixin,
    TokenMixin,
    ClientMixin
)
from werkzeug.security import gen_salt

# In-memory 'database'
# In a real application, you would replace this with a proper database like PostgreSQL or MySQL
# and use a library like SQLAlchemy.
DB_DATA = {
    'users': {},
    'clients': {},
    'tokens': {},
    'codes': {},
}

class Database:
    def __init__(self):
        self._data = DB_DATA

    def init_app(self, app):
        '''Initializes the database with sample data.'''
        # A sample user
        user = User(id=1, username='testuser')
        user.password = 'testpass' # In production, hash this!
        self.save_user(user)

        # A confidential client with a pre-shared secret
        confidential_client = OAuth2Client(
            client_id='confidential-client',
            client_secret='confidential-secret',
            client_name='My Confidential App',
            grant_types=['authorization_code', 'refresh_token', 'client_credentials'],
            response_types=['code'],
            scope='profile openid',
            redirect_uris=['http://localhost:5001/callback'],
            token_endpoint_auth_method='client_secret_post'
        )
        self.save_client(confidential_client)

        # A public client that uses PKCE (no secret)
        public_client = OAuth2Client(
            client_id='public-client',
            client_secret=None, # Public clients have no secret
            client_name='My Public SPA',
            grant_types=['authorization_code', 'refresh_token'],
            response_types=['code'],
            scope='profile',
            redirect_uris=['http://localhost:5001/public/callback.html'],
            token_endpoint_auth_method='none' # PKCE is enforced by the server grant
        )
        self.save_client(public_client)

        # A client for private_key_jwt authentication
        # You need to generate private.pem and public.pem
        try:
            with open('public.pem', 'r') as f:
                public_key = f.read()
            
            jwt_client = OAuth2Client(
                client_id='jwt-client',
                client_secret=None,
                client_name='My JWT-Authenticated App',
                grant_types=['client_credentials', 'refresh_token'],
                response_types=[],
                scope='profile',
                redirect_uris=[],
                token_endpoint_auth_method='private_key_jwt',
                jwks={'keys': [{'kty': 'RSA', 'use': 'sig', 'alg': 'RS256', 'n': '...', 'e': 'AQAB', 'key_ops': ['verify'], 'value': public_key}]}
            )
            self.save_client(jwt_client)
        except FileNotFoundError:
            print('WARNING: public.pem not found. JWT client not created.')


    # --- User Methods ---
    def get_user(self, user_id):
        return self._data['users'].get(user_id)
    def save_user(self, user):
        self._data['users'][user.id] = user
    def query_user_by_name(self, username):
        for user in self._data['users'].values():
            if user.username == username:
                return user
        return None

    # --- Client Methods ---
    def get_client(self, client_id):
        return self._data['clients'].get(client_id)
    def save_client(self, client):
        self._data['clients'][client.client_id] = client

    # --- Token Methods ---
    def get_token(self, access_token=None, refresh_token=None):
        if access_token:
            key = f'access_{access_token}'
        elif refresh_token:
            key = f'refresh_{refresh_token}'
        else:
            return None
        return self._data['tokens'].get(key)

    def save_token(self, token):
        access_key = f'access_{token.access_token}'
        self._data['tokens'][access_key] = token
        if token.refresh_token:
            refresh_key = f'refresh_{token.refresh_token}'
            self._data['tokens'][refresh_key] = token

    def delete_token(self, access_token):
        key = f'access_{access_token}'
        if key in self._data['tokens']:
            token = self._data['tokens'].pop(key)
            if token.refresh_token and f'refresh_{token.refresh_token}' in self._data['tokens']:
                del self._data['tokens'][f'refresh_{token.refresh_token}']

    # --- Auth Code Methods ---
    def get_code(self, code):
        return self._data['codes'].get(code)
    def save_code(self, code, auth_code):
        self._data['codes'][code] = auth_code
    def delete_code(self, code):
        if code in self._data['codes']:
            del self._data['codes'][code]


db = Database()


# --- Data Model Classes ---
class User:
    def __init__(self, id, username):
        self.id = id
        self.username = username
        self.password = None # Should be a hash

    def get_user_id(self):
        return self.id
    
    @staticmethod
    def query_by_id(user_id):
        return db.get_user(user_id)
    
    @staticmethod
    def query_by_username(username):
        return db.query_user_by_name(username)


class OAuth2Client(ClientMixin):
    def __init__(self, client_id, client_secret, **kwargs):
        self.client_id = client_id
        self.client_secret = client_secret
        self.client_name = kwargs.get('client_name')
        self.grant_types = kwargs.get('grant_types', [])
        self.response_types = kwargs.get('response_types', [])
        self.scope = kwargs.get('scope', '')
        self.redirect_uris = kwargs.get('redirect_uris', [])
        self.token_endpoint_auth_method = kwargs.get('token_endpoint_auth_method', 'client_secret_post')
        self.jwks = kwargs.get('jwks')

    def get_client_id(self):
        return self.client_id

    def get_default_redirect_uri(self):
        if self.redirect_uris:
            return self.redirect_uris[0]
        return None
    
    def get_allowed_scope(self, scope):
        if not scope:
            return self.scope
        allowed = set(self.scope.split())
        req = set(scope.split())
        return ' '.join(allowed.intersection(req))

    def check_redirect_uri(self, redirect_uri):
        return redirect_uri in self.redirect_uris
    
    def check_client_secret(self, client_secret):
        return self.client_secret == client_secret

    def check_grant_type(self, grant_type):
        return grant_type in self.grant_types

    def check_response_type(self, response_type):
        return response_type in self.response_types
    
    def check_endpoint_auth_method(self, method, endpoint):
        if endpoint == 'token':
            return self.token_endpoint_auth_method == method
        # Can add checks for other endpoints if needed
        return True
        
    def has_client_secret(self):
        return bool(self.client_secret)
        
    def get_client_info(self):
        return {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'client_name': self.client_name,
            'redirect_uris': self.redirect_uris,
            'scope': self.scope,
            'token_endpoint_auth_method': self.token_endpoint_auth_method,
        }
    
    @staticmethod
    def get_by_client_id(client_id):
        return db.get_client(client_id)

    @staticmethod
    def create_dynamic_client(metadata):
        '''Creates a new client from dynamic registration metadata.'''
        client_id = gen_salt(24)
        is_confidential = 'client_secret' in metadata.get('token_endpoint_auth_method', '')
        client_secret = gen_salt(48) if is_confidential else None
        
        client = OAuth2Client(
            client_id=client_id,
            client_secret=client_secret,
            client_name=metadata.get('client_name'),
            grant_types=metadata.get('grant_types', ['authorization_code']),
            response_types=metadata.get('response_types', ['code']),
            scope=metadata.get('scope', 'profile'),
            redirect_uris=metadata.get('redirect_uris', []),
            token_endpoint_auth_method=metadata.get('token_endpoint_auth_method', 'client_secret_post')
        )
        db.save_client(client)
        return client

class OAuth2AuthorizationCode(AuthorizationCodeMixin):
    def __init__(self, code, client_id, redirect_uri, scope, user_id, **kwargs):
        self.code = code
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.scope = scope
        self.user_id = user_id
        self.code_challenge = kwargs.get('code_challenge')
        self.code_challenge_method = kwargs.get('code_challenge_method')
        self.created_at = int(time.time())
    
    def is_expired(self):
        return self.created_at + 300 < time.time() # 5 minute expiry

    def get_redirect_uri(self):
        return self.redirect_uri

    def get_scope(self):
        return self.scope or ''
        
    def get_auth_time(self):
        return self.created_at

class OAuth2Token(TokenMixin):
    def __init__(self, client_id, user_id, scope, **kwargs):
        self.client_id = client_id
        self.user_id = user_id
        self.scope = scope
        self.access_token = kwargs.get('access_token')
        self.refresh_token = kwargs.get('refresh_token')
        self.token_type = kwargs.get('token_type', 'Bearer')
        self.expires_in = kwargs.get('expires_in', 3600)
        self.issued_at = kwargs.get('issued_at', int(time.time()))

    def get_client_id(self):
        return self.client_id

    def get_scope(self):
        return self.scope

    def get_user_id(self):
        return self.user_id
        
    def is_access_token_expired(self):
        return self.issued_at + self.expires_in < time.time()
        
    def is_expired(self):
        return self.is_access_token_expired()
    
    def is_revoked(self):
        return False
