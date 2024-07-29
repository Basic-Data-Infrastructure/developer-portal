---
title: Handle call without authorization
category: B. Cookbook Javascript
order: 5
---

### WORK IN PROGRESS!

### Provider is called without external authorization

As Service Provider, handle an authenticated call by a Service Consumer which does not include pre-authorization. The provider must perform authorization manually.

#### Check client assertion

Decode jwt
Validate signature

### TODO Handle API call
### TODO Check authorization in-app
### TODO Execute call


```
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


// After a user has made a http request for the token, extract the client assertion and call this function.
// This function will either return a bearer authorization token that can be used once
// within the configured expiration date, or throw an error.
async function token(clientAssertionJWT) {
  // decode JWT
  const decodedJWT = decodeJWT(clientAssertionJWT);
  const header = decodedJWT['header'];
  const payload = decodedJWT['payload'];
  const x5c = header["x5c"];
  const issuer = payload["iss"];


  // validate the signature (we check with the first certificate in the x5c chain)
  // validate the client assertion (is it addressed to us? it is not expired?)
  // validate the certificate chain (is it a chain? is the CA in our list of accepted associations?)

  // contact the association register to see if the client is still in good standing

  // first, get a token
  let payloadAssoc = { "iss": YOUR_EORI, "sub": YOUR_EORI, "aud": ASSOC_EORI, "jti": uuidv4() }
  let response = await axios.post(tokenUrlAssoc, createClientAssertion(signJwt(payloadAssoc)), { headers: headersTokenCall });
  let accessToken = response.data['access_token'];

  // then, make the parties call

  const headersParties = { "accept": "application/json", "Authorization": "Bearer " + accessToken };
  // TODO just get the party for the client id
  const params = {
    "active_only": "true",
    "certified_only": "false",
    "adherenceStatus": "Active",
    "framework": "iSHARE",
    "publiclyPublishable": "false",
    "page": "1"
  };

  let partiesResponse = await axios.get(partiesUrlAssoc, { headers: headersParties, params: params });
  let partiesToken = partiesResponse.data['parties_token'];
  const decodedPayload = decodeJWT(partiesToken);
  let party = decodedPayload["payload"]["parties_info"]["data"][1];
  // TODO determine if client in good standing

  // generate a token and store it with the expiration date and the client id
  let token = uuidv4();
  let expiresAt = new Date(new Date().getTime() + 30000);
  tokenList[token] = { clientId: clientId, expiresAt: expiresAt };

  // return the token
  return token;

}
```
