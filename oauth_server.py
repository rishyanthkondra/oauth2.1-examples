from authlib.integrations.flask_oauth2 import (
    AuthorizationServer,
    ResourceProtector,
)
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
    ClientCredentialsGrant,
    RefreshTokenGrant,
)
from authlib.oauth2.rfc6750 import BearerTokenValidator
from authlib.oauth2.rfc7636 import CodeChallenge
from authlib.oauth2.rfc7009 import RevocationEndpoint
from authlib.oauth2.rfc7662 import IntrospectionEndpoint

from models import db, User, OAuth2Client, OAuth2AuthorizationCode, OAuth2Token

# --- Custom Grant Types ---

class AuthorizationCodeGrant(_AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ['client_secret_basic', 'client_secret_post', 'none']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.code_challenge_service = CodeChallenge()

    def save_authorization_code(self, code, request):
        code_challenge = request.payload.data.get('code_challenge')
        code_challenge_method = request.payload.data.get('code_challenge_method')
        auth_code = OAuth2AuthorizationCode(
            code=code,
            client_id=request.client.client_id,
            redirect_uri=request.payload.redirect_uri,
            scope=request.payload.scope,
            user_id=request.user.get_user_id(),
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )
        db.save_code(code, auth_code)
        return auth_code

    def query_authorization_code(self, code, client):
        auth_code = db.get_code(code)
        if auth_code and auth_code.client_id == client.client_id:
            return auth_code
        return None

    def delete_authorization_code(self, authorization_code):
        db.delete_code(authorization_code.code)

    def authenticate_user(self, authorization_code):
        return User.query_by_id(authorization_code.user_id)
    
    def exists_nonce(self, nonce, request):
        # Implement nonce storage to prevent replay attacks if using OpenID Connect
        return False
        
    def get_jwt_config(self, grant):
        return {
            'key': 'secret-key', # Replace with a proper key management solution
            'alg': 'HS256',
            'iss': 'https://localhost:5000',
            'exp': 3600
        }

# --- Validator Classes ---
class MyBearerTokenValidator(BearerTokenValidator):
    def authenticate_token(self, token_string):
        return db.get_token(access_token=token_string)

    def request_invalid(self, request):
        return False

    def token_revoked(self, token):
        # A simple check; in a real app, you might have a revocation list.
        return not db.get_token(access_token=token.access_token)


# --- Server Configuration ---
authorization_server = AuthorizationServer()
require_oauth = ResourceProtector()

def config_oauth(app):
    '''Initializes and configures the AuthorizationServer.'''

    def query_client(client_id):
        return OAuth2Client.get_by_client_id(client_id)

    def save_token(token_data, request):
        if request.user:
            user_id = request.user.get_user_id()
        else:
            # For client_credentials grant, user is None
            user_id = None
        
        token = OAuth2Token(
            client_id=request.client.client_id,
            user_id=user_id,
            **token_data
        )
        db.save_token(token)
        return token

    authorization_server.init_app(
        app,
        query_client=query_client,
        save_token=save_token
    )

    # Register Grant Types
    authorization_server.register_grant(AuthorizationCodeGrant)
    authorization_server.register_grant(ClientCredentialsGrant)
    authorization_server.register_grant(RefreshTokenGrant)

    # Register Endpoint Handlers
    authorization_server.register_endpoint(RevocationEndpoint)
    authorization_server.register_endpoint(IntrospectionEndpoint)
    
    # Configure Resource Protector
    require_oauth.register_token_validator(MyBearerTokenValidator())

    return require_oauth
