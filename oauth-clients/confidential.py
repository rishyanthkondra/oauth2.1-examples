import time
import requests
from authlib.jose import jwt

# --- Configuration ---
OAUTH_SERVER_URL = 'http://localhost:5001'
TOKEN_URL = f'{OAUTH_SERVER_URL}/oauth/token'
API_URL = f'{OAUTH_SERVER_URL}/api/profile'
CLIENT_ID = 'jwt-client'
PRIVATE_KEY_PATH = '../private.pem' # Adjust path as needed

def create_client_assertion(private_key):
    '''Creates a JWT signed with the client's private key.'''
    header = {'alg': 'RS256'}
    payload = {
        'iss': CLIENT_ID,
        'sub': CLIENT_ID,
        'aud': TOKEN_URL,
        'iat': int(time.time()),
        'exp': int(time.time()) + 300, # 5 minute expiry
        'jti': str(time.time()) # A unique identifier for the token
    }
    return jwt.encode(header, payload, private_key)

def main():
    '''
    Demonstrates the private_key_jwt client credentials flow.
    '''
    print('--- Confidential Client (private_key_jwt) Demo ---')

    # 1. Load the private key
    try:
        with open(PRIVATE_KEY_PATH, 'r') as f:
            private_key = f.read()
        print('✓ Private key loaded.')
    except FileNotFoundError:
        print(f'✗ ERROR: Private key not found at {PRIVATE_KEY_PATH}')
        return

    # 2. Create the signed JWT client assertion
    client_assertion = create_client_assertion(private_key)
    print('✓ Client assertion JWT created.')

    # 3. Request an access token from the token endpoint
    token_request_data = {
        'grant_type': 'client_credentials',
        'scope': 'profile',
        'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        'client_assertion': client_assertion,
    }

    print('\n> Requesting access token...')
    try:
        response = requests.post(TOKEN_URL, data=token_request_data)
        response.raise_for_status() # Raise an exception for bad status codes
        token_data = response.json()
        access_token = token_data.get('access_token')
        print(f'✓ Access token received: {access_token[:15]}...')
    except requests.exceptions.RequestException as e:
        print(f'✗ ERROR fetching token: {e}')
        if e.response:
            print('Response:', e.response.json())
        return

    # 4. Use the access token to call the protected API
    headers = {'Authorization': f'Bearer {access_token}'}
    print('\n> Accessing protected resource (/api/profile)...')
    try:
        api_response = requests.get(API_URL, headers=headers)
        api_response.raise_for_status()
        profile_data = api_response.json()
        print('✓ Successfully accessed API.')
        print('--- Profile Data ---')
        print(profile_data)
        print('--------------------')
    except requests.exceptions.RequestException as e:
        print(f'✗ ERROR accessing API: {e}')
        if e.response:
            print('Response:', e.response.json())

if __name__ == '__main__':
    main()

