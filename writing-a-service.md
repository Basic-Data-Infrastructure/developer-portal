---
title: Writing a service
category: 7. Writing a service
order: 1
---

## Designing the API -- existing standards

When designing a new API in the Logistics sector, we recommend using existing standards for entities from the world of logistics, such as vehicle, route, location, trip and transport order.

[Open Trip Model](https://www.sutc.nl/en_US/open-trip-model) has standardized logistics entities and [documented](https://otm5.opentripmodel.org) them, so that anyone may use them and data exchange will become much more simple.

[EPCIS](https://www.gs1.org/standards/epcis) is a data sharing standard for enabling visibility, within organisations as well as across an entire supply chain of trading partners and other stakeholders. It helps provide the “what, when, where, why and how” of products and other assets, enabling the capture and sharing of interoperable information about status, location, movement and chain of custody.

More information can be found in the [Developing Semantics for Supply Chain, Transport and Logistics](https://bdinetwork.org/wp-content/uploads/2024/01/2024-BDI-Developing-Semantics-for-Supply-Chain-Transport-Logistics.pdf) white paper.

## BDI Enabling

To extend a service provider API and make it BDI compatible, at minimum you will need to provide the `/connect/token` endpoint to provide access tokens for use in further API calls. The `/connect/token` endpoint which will first check whether the client assertion in the request is valid and addressed to the server. You will perform get a token from the Association Registry, and then use it to perform a /party call there to lookup information on the client based on the client id included in the client assertion. If the party information shows that the client is compliant, then you can return a token to the client.

Also, you'll have to extend all API calls with a check to see whether they include a valid token in the header, and check to see if they include a delegation evidence JWT. That JWT should be valid (right sender and recipient, and signed correctly) and the policies in its payload should allow access to the current API call.

If all that is correct, the API call may proceed.
