// requires
const jwt = require('jsonwebtoken');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const axios = require('axios');

// constants

const tokenUrlAssoc = "https://dilsat1-mw.pg.bdinetwork.org/connect/token";
const partiesUrlAssoc = "https://dilsat1-mw.pg.bdinetwork.org/parties";
const YOUR_EORI = "EU.EORI.NLFLEXTRANS";
const ASSOC_EORI = "EU.EORI.NLDILSATTEST1";
const headersTokenCall = { "accept": "application/json", "Content-Type": "application/x-www-form-urlencoded" };

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

// Call /token endpoint and return access_token
async function accessToken(eori, tokenUrl) {
  let payload = { "iss": YOUR_EORI, "sub": YOUR_EORI, "aud": eori, "jti": uuidv4() }
  const token = jwt.sign(payload, pemData, { algorithm: 'RS256', expiresIn: "30s", header: header });
  response = await axios.post(tokenUrl, createClientAssertion(token), { "accept": "application/json", "Content-Type": "application/x-www-form-urlencoded" })
  return response.data['access_token'];
}

// Decode a base64 encoded JWT fragment (header or payload)
function decodeJWTFragment(fragment) {
  const base64 = fragment.replace(/-/g, '+').replace(/_/g, '/');
  const data = decodeURIComponent(atob(base64).split('').map(function(c) {
      return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
  }).join(''));

  return JSON.parse(data);
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

function validateCertificateChain(certificates) {
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

    let serialNumber = rootCert.serialNumber;
    let trustedCertificatesSN = ["04b536719019a8b1"];
    for(i=0; i<trustedCertificatesSN.length; i++) {
      if(serialNumber === trustedCertificatesSN[i]) {
        return true;
      }
    }
    return false;
  } catch (err) {
    console.error('Error during certificate chain validation:', err.message);
    return false;
  }
}

try {
  const isValid = validateCertificateChain(certificates);
  if (isValid) {
    console.log('Certificate chain is valid.');
  } else {
    console.error('Certificate chain validation failed.');
  }
} catch (err) {
  console.error('Error during validation:', err.message);
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
  jwt.verify(token, x5cToPem(x5c[0]));

  // validate the certificate chain (is it a chain? is the CA in our list of accepted associations?)
  const certs = x5c.map(certBase64 => {
    const certDer = forge.util.decode64(certBase64);
    const asn1Obj = forge.asn1.fromDer(certDer);
    return forge.pki.certificateFromAsn1(asn1Obj);
  });

  if (!validateCertificateChain(certs)) {
    throw new Error("Certificate chain invalid");
  }

  // contact the association register to see if the client is still in good standing

  // first, get a token
  let bearerToken = accessToken(ASSOC_EORI, tokenUrlAssoc);

  // then, make the parties call

  const headersParties = { "accept": "application/json", "Authorization": "Bearer " + bearerToken };
  // TODO just get the party for the client id
  const params = {
    "active_only": "true",
    "certified_only": "false",
    "adherenceStatus": "Active",
    "framework": "iSHARE",
    "publiclyPublishable": "false",
    "page": "1"
  };

  let partiesResponse = await axios.get(partiesUrlAssoc + '/' + clientId, { headers: headersParties, params: params });
  let partyToken = partiesResponse.data['party_token'];
  const decodedPayload = decodeJWT(partyToken);
  let party = decodedPayload["payload"]["party_info"];
  // check adherence of client
  checkAdherence(party["adherence"]);

  // generate a token and store it with the expiration date and the client id
  let token = uuidv4();
  let expiresAt = new Date(new Date().getTime() + 30000);
  tokenList[token] = { clientId: clientId, expiresAt: expiresAt };

  // return the token
  return token;
}

function callApi(token, request) {
  let clientId = checkToken(token);
  let delegationMask = createDelegationMask(request);
  let delegationToken = callDelegation(delegationMask);
  checkDelegationToken(delegationToken);
  performApiCall(request);
}
