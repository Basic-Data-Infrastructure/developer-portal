let party = lookupParty(SP_EORI, YOUR_CLIENT_EORI);
checkAdherence(party);

let tokenSpUrl = ''; // NOTE define the url of the Service Provider's /connect/token endpoint here

bearerToken = await accessToken(SP_EORI, tokenSpUrl, YOUR_CLIENT_EORI);
const headersApi = {
  "accept": "application/json",
  "Authorization": "Bearer " + bearerToken
};

// Make actual API request without delegation token

let spApiUrl = 'https://service-provider/api'; // NOTE: Example definition, adjust as needed
let body = {}; // or the correct body data as per your API requirement
response = await axios.post(spApiUrl, body, headersApi);
