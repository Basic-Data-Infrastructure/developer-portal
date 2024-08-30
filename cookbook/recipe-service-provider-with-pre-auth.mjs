// requires
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const crypto = require('crypto');
const axios = require('axios');
const forge = require('node-forge');

// file paths

const privateKeyPath = process.env.HOME + '/.ssh/EU.EORI.NLFLEXTRANS.pem';
const certKeyPath = process.env.HOME + '/.ssh/EU.EORI.NLFLEXTRANS.crt';

// constants

const tokenUrlAssoc = "https://dilsat1-mw.pg.bdinetwork.org/connect/token";
const trustedUrlAssoc = "https://dilsat1-mw.pg.bdinetwork.org/trusted_list";
const partiesUrlAssoc = "https://dilsat1-mw.pg.bdinetwork.org/parties";
const YOUR_EORI = "EU.EORI.NLFLEXTRANS";
const ASSOC_EORI = "EU.EORI.NLDILSATTEST1";
const pemData = fs.readFileSync(privateKeyPath, 'utf8');
const certificateChainData = fs.readFileSync(certKeyPath, 'utf8');
// Split the certificate chain into individual certificates
const certificates = certificateChainData.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g);
// Convert each certificate to DER format and then base64 encode it
const x5c = certificates.map(cert => {
  return cert.replace(/-----\w+ CERTIFICATE-----/g, '').replace(/\s+/g, '');
});

let tokenList = {};

// create client assertion with default values
function createClientAssertion(token) {
  return new URLSearchParams({
    "grant_type": "client_credentials",
    "scope": "iSHARE",
    "client_id": YOUR_EORI,
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

// Call /token endpoint and return access_token
async function accessToken(eori, tokenUrl) {
  let payload = { "iss": YOUR_EORI, "sub": YOUR_EORI, "aud": eori, "jti": uuidv4() }
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

// decode JWT without signature verification
function decodeJWT(token) {
  // Split the JWT into its three parts: header, payload, and signature
  const parts = token.split('.');
  if (parts.length !== 3) {
      throw new Error('Invalid JWT');
  }

  // Decode the Base64Url encoded payload (second part)
  const header = decodeJWTFragment(parts[0]);
  const payload = decodeJWTFragment(parts[1]);
  return { header, payload };
}

// Convert base64 encoded certificate to pem format.
function x5cToPem(x5cCert) {
  const certDer = Buffer.from(x5cCert, 'base64');
  const certAsn1 = forge.asn1.fromDer(certDer.toString('binary'));
  const certPki = forge.pki.certificateFromAsn1(certAsn1);
  return forge.pki.certificateToPem(certPki);
}

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
// Return hex (upcase) fingerprint for certificate
function fingerprint(base64Cert) {
  // Step 1: Decode base64
  const derBuffer = Buffer.from(base64Cert, 'base64');

  // Step 2: Compute the SHA-256 hash of the DER-encoded certificate, and convert the hash to uppercase
  return crypto.createHash('sha256').update(derBuffer).digest('hex').toUpperCase();
}

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

// After a user has made a http request for the token, extract the client assertion and call this function.
// This function will either return a bearer authorization token that can be used once
// within the configured expiration date, or throw an error.
async function token(clientAssertionJWT) {
  // decode JWT
  const decodedJWT = decodeJWT(clientAssertionJWT);
  const header = decodedJWT['header'];
  const payload = decodedJWT['payload'];
  const x5c = header["x5c"];
  const clientId = payload["iss"];

  // validate the client assertion (is it addressed to us? it is not expired?)
  const audience = payload["aud"];
  const jwtCreatedAt = new Date(1000 * payload["iat"]);
  const jwtExpiresAt = new Date(1000 * payload["exp"]);
  const now = new Date();
  if (jwtCreatedAt > now) {
    throw new Error("iat value set in future");
  }
  if (jwtExpiresAt < now) {
    throw new Error("JWT is expired");
  }

  if (audience !== YOUR_EORI) {
    throw new Error('Wrong audience');
  }

  // validate the signature (we check with the first certificate in the x5c chain)
  jwt.verify(clientAssertionJWT, x5cToPem(x5c[0]));

  // validate the certificate chain (is it a chain? is the CA in our list of accepted associations?)
  let bearerToken = await accessToken(ASSOC_EORI, tokenUrlAssoc);
  const authenticatedHeader = {
    "accept": "application/json",
    "Authorization": "Bearer " + bearerToken
  };

  let response = await axios.get(trustedUrlAssoc, { headers: authenticatedHeader, params: {} });
  const trustedList = decodeJWT(response.data.trusted_list_token).trusted_list;

  if (!validateCertificateChain(trustedList, x5c)) {
    throw new Error("Certificate chain invalid");
  }

  // contact the association register to see if the client is still in good standing

  // first, get a token
  bearerToken = await accessToken(ASSOC_EORI, tokenUrlAssoc);

  // then, make the parties call

  const headersParties = { "accept": "application/json", "Authorization": "Bearer " + bearerToken };

  let partiesResponse = await axios.get(partiesUrlAssoc + '/' + clientId, { headers: headersParties, params: {} });
  let partyToken = partiesResponse.data['party_token'];
  const decodedPayload = decodeJWT(partyToken);
  let party = decodedPayload["payload"]["party_info"];
  // check adherence of client
  checkAdherence(party["adherence"]);

  // generate a token and store it with the expiration date and the client id
  let uuid = uuidv4();
  let expiresAt = new Date(new Date().getTime() + 30000);
  tokenList[uuid] = { clientId: clientId, expiresAt: expiresAt };

  // return the token
  return uuid;
}

function checkToken(token) {
  let tokenData = tokenList[token];
  if(tokenData) {
    delete tokenList[token];
    if(tokenData.expiresAt >=  new Date()) {
      return tokenData.clientId;
    }
  }
  throw new Error("")
}

function callApi(token, delegationToken, request) {
  checkToken(token);
  checkDelegationEvidence(delegationToken, request);
  checkDelegationToken(delegationToken);
  performApiCall(request);
}
