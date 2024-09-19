
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

  if (audience !== YOUR_SP_EORI) {
    throw new Error('Wrong audience');
  }

  // validate the signature (we check with the first certificate in the x5c chain)
  jwt.verify(clientAssertionJWT, x5cToPem(x5c[0]));

  // validate the certificate chain (is it a chain? is the CA in our list of accepted associations?)
  let bearerToken = await accessToken(ASSOC_EORI, tokenUrlAssoc, YOUR_SP_EORI);
  const authenticatedHeader = {
    "accept": "application/json",
    "Authorization": "Bearer " + bearerToken
  };

  let response = await axios.get(trustedUrlAssoc, { headers: authenticatedHeader, params: {} });
  const trustedList = decodeJWT(response.data.trusted_list_token).payload.trusted_list;

  if (!validateCertificateChain(trustedList, x5c)) {
    throw new Error("Certificate chain invalid");
  }

  // contact the association register to see if the client is still in good standing

  // first, get a token
  bearerToken = await accessToken(ASSOC_EORI, tokenUrlAssoc, YOUR_SP_EORI);

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

function callApi(token, request) {
  let clientId = checkToken(token, tokenList);
  // possibility to check if client is allowed to perform request in an ad hoc way.
  // checkAuthorization(clientId, request);
  performApiCall(request);
}
