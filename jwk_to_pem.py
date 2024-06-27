import base64
import json
from Crypto.PublicKey import RSA

def jwk_to_pem(jwk):
    e = base64.urlsafe_b64decode(jwk['e'] + '==')
    n = base64.urlsafe_b64decode(jwk['n'] + '==')

    pub_key = RSA.construct((int.from_bytes(n, 'big'), int.from_bytes(e, 'big')))
    return pub_key.export_key().decode('utf-8')

# Load JWKS JSON file
with open('jwks.json') as f:
    jwks = json.load(f)

# Extract the first key (adjust if necessary)
jwk = jwks['keys'][0]

# Convert to PEM
pem = jwk_to_pem(jwk)

# Save to a file
with open('public_key.pem', 'w') as f:
    f.write(pem)

print('PEM certificate saved to public_key.pem')

