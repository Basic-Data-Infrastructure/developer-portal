---
title: Handle call without pre-authorization
category: A. Cookbook
order: 3
---

### Provider is called without pre-authorization

As Service Provider, handle an authenticated call by a Data Consumer which does not include pre-authorization. The provider will need to perform authorization manually, or contact an Authorization Registry.

### TODO Handle token call

In order to perform a /parties call in the testing environment at dilsat1-mw.pg.bdinetwork.org, first one needs to post a client assertion to the /connect/token endpoint. To create a client assertion, we use the [`python-ishare`](https://github.com/iSHAREScheme/python-ishare) library. Install it with `pip install python-ishare`

You will need a private key, a certificate, and an EORI client id.

Then run the following script, taking care to set the correct values for your client id and the locations of the private key and the certificate.

```
from pathlib import Path

from cryptography.x509 import load_pem_x509_certificates, Certificate
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from python_ishare import create_jwt

YOUR_EORI = ... # TODO
THEIR_EORI = "EU.EORI.NLDILSATTEST1"

pk_path = Path(r"my_private_key.pem") # TODO
# Load your RSA key to an RSAPrivateKey
with pk_path.open("rb") as file:
    private_key: RSAPrivateKey = load_pem_private_key(file.read(), password=None)

cert_path = Path(r"my_certificate.crt") # TODO
with cert_path.open("rb") as file:
    chain: list[Certificate] = load_pem_x509_certificates(file.read())

# Create the actual token
client_assertion = create_jwt(
    payload={ "iss": YOUR_EORI, "sub": YOUR_EORI, "aud": THEIR_EORI },
    private_key=private_key,
    x5c_certificate_chain=chain
)

print(client_assertion)
```

The next step is to call the `/connect/token` endpoint, and post the client assertion.

```
import requests

url = "https://dilsat1-mw.pg.bdinetwork.org/connect/token"
headers = {
    "accept": "application/json",
    "Content-Type": "application/x-www-form-urlencoded"
}
data = {
    "grant_type": "client_credentials",
    "scope": "iSHARE",
    "client_id": "EU.EORI.NLFLEXTRANS",
    "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    "client_assertion": client_assertion
}

response = requests.post(url, headers=headers, data=data)

print(response.status_code)
print(response.json())

access_token = response.json()['access_token']
```

### TODO Handle API call
### TODO Generate Delegation Mask
### TODO Fetch token from AR
### TODO Fetch delegation evidence from AR
### TODO Check delegation evidence
### TODO Execute call
