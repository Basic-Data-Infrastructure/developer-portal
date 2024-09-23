---
title: Writing a service
category: 7. Writing a service
order: 1
---

## Designing the API -- existing standards

When designing a new API in the Logistics sector, we recommend using existing standards for entities from the world of logistics, such as vehicle, route, location, trip and transport order.

[Open Trip Model](https://www.sutc.nl/en_US/open-trip-model) has standardized logistics entities and [documented](https://otm5.opentripmodel.org) them, so that anyone may use them and data exchange will become much more simple.

[EPCIS](https://www.gs1.org/standards/epcis) is a data-sharing standard for enabling visibility, within organizations as well as across an entire supply chain of trading partners and other stakeholders. It helps provide the "what, when, where, why and how" of products and other assets, enabling the capture and sharing of interoperable information about status, location, movement, and chain of custody.

More information can be found in the [Developing Semantics for Supply Chain, Transport and Logistics](https://bdinetwork.org/wp-content/uploads/2024/01/2024-BDI-Developing-Semantics-for-Supply-Chain-Transport-Logistics.pdf) white paper.

## BDI Enabling

To extend a service provider API and make it BDI compatible, at minimum you will need to provide the `/connect/token` endpoint to provide access tokens for use in further API calls. The `/connect/token` endpoint will first check whether the client assertion in the request is valid and addressed to the server. You will obtain a token from the Association Registry, and then use it to perform a /party call there to look up information on the client based on the client ID included in the client assertion. If the party information shows that the client is compliant, then you can return a token to the client.

Also, you'll have to extend all API calls with a check to see whether they include a valid token in the header and check to see if they include a delegation evidence JWT. That JWT should be valid (right sender and recipient, and signed correctly) and the policies in its payload should allow access to the current API call.

If all that is correct, the API call may proceed.

## Non-HTTP Services

The BDI generally assumes that a service is implemented as a online HTTP API. If the service uses another online protocol, it may be useful to translate parts of the protocols and/or "bridge" service with HTTP components. For instance, a service can provide an HTTP `/connect/token` endpoint for authentication, returning an access token as usual. The Data Consumer can then use the access token as a credential in some other protocol.

If the Service does not implement online API at all, the basic service looks a lot like a Data Consumer from the point of view of the BDI architecture; for an example, see the [DIL - Demo Vertrouwde Goederenafgifte](https://github.com/Basic-Data-Infrastructure/demo-vertrouwde-goederenafgifte/blob/master/doc/architecture/architecture-description.md) architecture. Here, parties authorize (using Authorization Registers) physical access to consignments at a distribution center.

