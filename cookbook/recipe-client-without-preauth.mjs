let bearerToken = await accessToken(ASSOC_EORI, tokenUrlAssoc);
const headersParties = {
  "accept": "application/json",
  "Authorization": "Bearer " + bearerToken
};

// association registry /parties
response = await axios.get(partiesUrlAssoc + '/' + SP_EORI, { headers: headersParties, params: {} })
let partyToken = response.data['party_token'];

const decodedPayload = decodeJWT(partyToken);
let party = decodedPayload["party_info"];
checkAdherence(party);

let tokenSpUrl = ''; // NOTE define the url of the Service Provider's /connect/token endpoint here

bearerToken = await accessToken(SP_EORI, tokenSpUrl);
const headersApi = {
  "accept": "application/json",
  "Authorization": "Bearer " + bearerToken
};

// Make actual API request without delegation token

let spApiUrl = 'https://service-provider/api'; // NOTE: Example definition, adjust as needed
let body = {}; // or the correct body data as per your API requirement
response = await axios.post(spApiUrl, body, headersApi);
