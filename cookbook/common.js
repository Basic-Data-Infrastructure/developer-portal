// requires
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const crypto = require('crypto');
const axios = require('axios');
const forge = require('node-forge');

// file paths

const privateKeyPath = process.env.HOME + '/.ssh/EU.EORI.NLFLEXTRANS.pem'; // NOTE: Example definition, adjust as needed
const certKeyPath = process.env.HOME + '/.ssh/EU.EORI.NLFLEXTRANS.crt'; // NOTE: Example definition, adjust as needed

// constants

const YOUR_CLIENT_EORI = "EU.EORI.NLFLEXTRANS"; // NOTE: Example definition, adjust as needed
const YOUR_SP_EORI = "EU.EORI.NLFLEXTRANS"; // NOTE: Example definition, adjust as needed
const ASSOC_EORI = "EU.EORI.NLDILSATTEST1"; // NOTE: Example definition, adjust as needed
const SP_EORI = "EU.EORI.NL809023854"; // NOTE: Example definition, adjust as needed
const AR_EORI = 'EU.EORI.NL000000004'; // NOTE: Example definition, adjust as needed

// credentials

const pemData = fs.readFileSync(privateKeyPath, 'utf8');
const publicKey = crypto.createPublicKey(pemData);
const certificateChainData = fs.readFileSync(certKeyPath, 'utf8');
// Split the certificate chain into individual certificates
const certificates = certificateChainData.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g);
// Convert each certificate to DER format and then base64 encode it
const x5c = certificates.map(cert => {
  return cert.replace(/-----\w+ CERTIFICATE-----/g, '').replace(/\s+/g, '');
});

let tokenList = {};

// URLs

const assocUrlRoot = "https://dilsat1-mw.pg.bdinetwork.org"; // NOTE: Example definition, adjust as needed
const tokenUrlAssoc = assocUrlRoot + "/connect/token";
const partiesUrlAssoc = assocUrlRoot + "/parties";
const trustedUrlAssoc = assocUrlRoot + "/trusted_list";
// const tokenArUrl = "https://ar.isharetest.net/connect/token"; // NOTE: Example definition, adjust as needed
// const delegationArUrl = "https://ar.isharetest.net/delegation"; // NOTE: Example definition, adjust as needed

// create client assertion with default values
function createClientAssertion(token) {
  return new URLSearchParams({
    "grant_type": "client_credentials",
    "scope": "iSHARE",
    "client_id": YOUR_CLIENT_EORI,
    "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    "client_assertion": token
  })
};

// sign JWT payload with default settings
function signJwt(payload) {
  const header = {
    alg: 'RS256',
    typ: 'JWT',
    x5c: x5c
  };
  return jwt.sign(payload, pemData, { algorithm: 'RS256', expiresIn: "30s", header: header });
}

// Check whether a jwt, split in parts, has been signed correctly (with the certificate in the x5c field in the header)
function verifySignature(parts) {
  // Step 1: Extract the header
  const header = JSON.parse(Buffer.from(parts[0].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));

  // Step 2: Extract x5c from header
  const x5c = header.x5c;  // This is an array of Base64-encoded certificates

  // Step 3: Convert the x5c certificate to PEM format
  const cert = `-----BEGIN CERTIFICATE-----\n${x5c[0].match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----`;

  // Step 4: Convert certificate to public key
  const publicKey = crypto.createPublicKey(cert);

  // Step 5: Create the signed text (header and payload, joined by a dot)
  const signedText = parts[0] + '.' + parts[1];

  // Step 6: Convert signature from base64url to base64
  const signature = Buffer.from(parts[2].replace(/-/g, '+').replace(/_/g, '/'), 'base64');

  // Step 7: Verify the signature using the public key
  const isValid = crypto.verify(
    'sha256',                                  // Algorithm for RS256 is SHA-256
    Buffer.from(signedText),                   // Data to verify (header and payload)
    publicKey,                                 // Public key
    signature                                  // Signature to verify
  );

  if (isValid) {
    console.log("Signature OK")
  } else {
    throw new Error("Signature does not match");
  }
}

// Call /token endpoint and return access_token
async function accessToken(eori, tokenUrl, yourEori) {
  let payload = { "iss": yourEori, "sub": yourEori, "aud": eori, "jti": uuidv4() }
  const token = signJwt(payload);
  let response = await axios.post(tokenUrl, createClientAssertion(token), { "accept": "application/json", "Content-Type": "application/x-www-form-urlencoded" })
  return response.data['access_token'];
}

// Decode a base64 encoded JWT fragment (header or payload)
function decodeJWTFragment(fragment) {
  // Replace URL-safe Base64 characters with standard Base64 characters
  const base64 = fragment.replace(/-/g, '+').replace(/_/g, '/');

  // Decode the Base64 string and parse it as a UTF-8 string
  const jsonString = Buffer.from(base64, 'base64').toString('utf8');

  // Parse and return the JSON object
  return JSON.parse(jsonString);
}

// decode JWT with signature verification
function decodeJWT(token) {
  // Split the JWT into its three parts: header, payload, and signature
  const parts = token.split('.');
  if (parts.length !== 3) {
      throw new Error('Invalid JWT');
  }

  // Decode the Base64Url encoded payload (second part)
  const header = decodeJWTFragment(parts[0]);
  const payload = decodeJWTFragment(parts[1]);
  console.log("header");
  console.log(header);
  verifySignature(parts);
  return { header, payload };
}

// Lookup party in Association Register
async function lookupParty(eori, yourEori) {
  let bearerToken = await accessToken(ASSOC_EORI, tokenUrlAssoc, yourEori);

  const headersParties = {
    "accept": "application/json",
    "Authorization": "Bearer " + bearerToken
  };

  // association registry /parties
  response = await axios.get(partiesUrlAssoc + '/' + eori, { headers: headersParties, params: {} })
  let partyToken = response.data.party_token;

  const decodedPayload = decodeJWT(partyToken).payload;
  let party = decodedPayload["party_info"];
  return party;
}

// Take party object of Service Provider, and return object with arEori, tokenArUrl and delegationArUrl for
// matching authorization register in party object
function extractAuthRegisterFromParty(party) {
  let ar = party["authregistery"][0];
  let arEori = ar.authorizationRegistryID;
  let arUrlRoot = ar.authorizationRegistryUrl;
  let tokenArUrl = arUrlRoot + 'connect/token';
  let delegationArUrl = arUrlRoot + 'delegation';
  return {arEori, tokenArUrl, delegationArUrl}
}

// fetch delegation evidence based on delegation request
async function fetchDelegationEvidence(delegationArUrl, delegationRequest) {
  const arHeaders = { "Content-Type": "application/json",
                      "Authorization": "Bearer " + bearerToken }
  let body = JSON.stringify({"delegationRequest": delegationRequest})
  // authorization registry /delegation
  response = await axios.post(delegationArUrl, body, { headers: arHeaders });
  return response.data.delegationToken;
}

// check if party is still adherent according to association register
function checkAdherence(adh) {
  if (adh['status'] !== 'Active') {
    throw new Error("Status is not Active");
  }
  let now = new Date();
  if (new Date(adh['start_date']) > now) {
    throw new Error("Start date is set in future");
  }
  if (new Date(adh['end_date']) < now) {
    throw new Error("End date is set in past");
  }
}

// Convert base64 encoded certificate to pem format.
function x5cToPem(x5cCert) {
  const certDer = Buffer.from(x5cCert, 'base64');
  const certAsn1 = forge.asn1.fromDer(certDer.toString('binary'));
  const certPki = forge.pki.certificateFromAsn1(certAsn1);
  return forge.pki.certificateToPem(certPki);
}

// Return hex (upcase) fingerprint for certificate
function fingerprint(base64Cert) {
  // Step 1: Decode base64
  const derBuffer = Buffer.from(base64Cert, 'base64');

  // Step 2: Compute the SHA-256 hash of the DER-encoded certificate, and convert the hash to uppercase
  return crypto.createHash('sha256').update(derBuffer).digest('hex').toUpperCase();
}

// check if root certificate is included in trusted list
function checkTrust(trustedList, certificate) {
  let certFingerprint = fingerprint(certificate);
  for(let i=0; i < trustedList.length; i++) {
    let c = trustedList[i];
    if(c.certificate_fingerprint == certFingerprint) {
      console.log(c);
      return true;
    }
  }
  return false;
}

// Verify whether the certificate chain is secure
function validateCertificateChain(trustedList, x5c) {
  // validate the certificate chain (is it a chain? is the CA in our list of accepted associations?)
  const certificates = x5c.map(certBase64 => {
    const certDer = forge.util.decode64(certBase64);
    const asn1Obj = forge.asn1.fromDer(certDer);
    return forge.pki.certificateFromAsn1(asn1Obj);
  });

  try {
    for (let i = 0; i < certificates.length - 1; i++) {
      const subjectCert = certificates[i];
      const issuerCert = certificates[i + 1];

      // Create a CA store with just the issuer certificate
      const caStore = forge.pki.createCaStore([issuerCert]);

      // Verify the current certificate against the issuer
      const isValid = forge.pki.verifyCertificateChain(caStore, [subjectCert]);
      if (!isValid) {
        console.error(`Certificate ${i} failed to validate against its issuer.`);
        return false;
      }
    }

    // Optionally, verify that the root certificate is self-signed
    const rootCert = certificates[certificates.length - 1];
    if (!rootCert.verify(rootCert)) {
      console.error('Root certificate is not self-signed.');
      return false;
    }

    let rootCertX5c = x5c[x5c.length-1];
    return checkTrust(trustedList, rootCertX5c);
  } catch (err) {
    console.error('Error during certificate chain validation:', err.message);
    return false;
  }
}

// Check if single use token is known, and then delete it.
function checkToken(token, tokenList) {
  let tokenData = tokenList[token];
  if(tokenData) {
    delete tokenList[token];
    if(tokenData.expiresAt >=  new Date()) {
      return tokenData.clientId;
    }
  }
  throw new Error("")
}
