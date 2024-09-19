let party = lookupParty(SP_EORI, YOUR_CLIENT_EORI);
checkAdherence(party);
const {arEori, tokenArUrl, delegationArUrl} = extractAuthRegisterFromParty(party);
bearerToken = await accessToken(arEori, tokenArUrl, YOUR_CLIENT_EORI);
const policy = {
  "target": {
    "resource": {
      "type": "text",
      "identifiers": [ "text" ],
      "attributes": [ "text" ]
    },
    "actions": [ "text" ]
  },
  "rules": [ { "effect": "text" } ]
};
let delegationRequest = {
  "policyIssuer": "text",
  "target": { "accessSubject": "text" },
  "policySets": [ { "policies": [ policy ] } ]
}

let delegationToken = fetchDelegationEvidence(delegationArUrl, delegationRequest, bearerToken);

let tokenSpUrl = ''; // NOTE define the url of the Service Provider's /connect/token endpoint here

bearerToken = await accessToken(SP_EORI, tokenSpUrl, YOUR_CLIENT_EORI);
const headersApi = {
  "accept": "application/json",
  "Authorization": "Bearer " + bearerToken,
  "DelegationEvidence": delegationToken
};

// Make actual API call with delegation evidence token
let spApiUrl = 'https://service-provider/api'; // Example definition, adjust as needed
response = await axios.post(spApiUrl, body, { headers: headersApi });
