// imports
import jwt from 'jsonwebtoken';
import fs from 'fs';
import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';
import axios from 'axios';

// file paths

const privateKeyPath = process.env.HOME + '/.ssh/EU.EORI.NLFLEXTRANS.pem';
const certKeyPath = process.env.HOME + '/.ssh/EU.EORI.NLFLEXTRANS.crt';

// credentials

const YOUR_EORI = "EU.EORI.NLFLEXTRANS";
const ASSOC_EORI = "EU.EORI.NLDILSATTEST1";
const SP_EORI = "EU.EORI.NL809023854";
const AR_EORI = 'EU.EORI.NL000000004';
const pemData = fs.readFileSync(privateKeyPath, 'utf8');
const publicKey = crypto.createPublicKey(pemData);
const certificateChainData = fs.readFileSync(certKeyPath, 'utf8');
// Split the certificate chain into individual certificates
const certificates = certificateChainData.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g);
// Convert each certificate to DER format and then base64 encode it
const x5c = certificates.map(cert => {
  const der = Buffer.from(cert.replace(/-----\w+ CERTIFICATE-----/g, ''), 'base64');
  return der.toString('base64');
});

// URLs
const tokenUrlAssoc = "https://dilsat1-mw.pg.bdinetwork.org/connect/token";
const tokenArUrl = "https://ar.isharetest.net/connect/token";
const delegationArUrl = "https://ar.isharetest.net/delegation";
const partiesUrlAssoc = "https://dilsat1-mw.pg.bdinetwork.org/parties";

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

// sign JWT payload with default settings
function signJwt(payload) {
  const header = {
    alg: 'RS256',
    typ: 'JWT',
    x5c: x5c
  };
  return jwt.sign(payload, pemData, { algorithm: 'RS256', expiresIn: "30s", header: header });
}

// decode JWT without signature verification
function decodeJWT(token) {
  // Split the JWT into its three parts: header, payload, and signature
  const parts = token.split('.');
  if (parts.length !== 3) {
      throw new Error('Invalid JWT');
  }

  // Decode the Base64Url encoded payload (second part)
  const base64Url = parts[1];
  const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
  const payload = decodeURIComponent(atob(base64).split('').map(function(c) {
      return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
  }).join(''));

  // Parse the JSON payload
  return JSON.parse(payload);
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

let bearerToken = accessToken(ASSOC_EORI, tokenUrlAssoc);
const headersParties = {
  "accept": "application/json",
  "Authorization": "Bearer " + bearerToken
};

const params = {
  "active_only": "true",
  "certified_only": "false",
  "adherenceStatus": "Active",
  "framework": "iSHARE",
  "publiclyPublishable": "false",
  "page": "1"
};

// association registry /parties
response = await axios.get(partiesUrlAssoc + '/' + SP_EORI, { headers: headersParties, params: params })
let partyToken = response.data['party_token'];

const decodedPayload = decodeJWT(partyToken);
console.log(decodedPayload);
let party = decodedPayload["party_info"];
console.log(party);
checkAdherence(party);
let ar = party["authregistery"][0];
console.log(ar);

bearerToken = accessToken(AR_EORI, tokenArUrl);
const headersApi = {
  "accept": "application/json",
  "Authorization": "Bearer " + bearerToken
};

// Make actual API request without delegation token
response = await axios.post(spApiUrl, body, headersApi);
