---
title: Service Provider
category: 4. Components
order: 4
---

There are two different flows for the Service Provider.

In the full flow, the Data Consumer makes a request that includes delegation evidence. In the minimal flow, the request of the consumer does not contain delegation evidence.

## Full Flow

In this flow, BDI capabilities can be added to an existing API by implementing three extensions:

1. First, any protected call must check if there is a valid Bearer Token in the header. All calls with invalid or missing tokens are refused.
2. Second, there should be an endpoint to distribute tokens based on [Client Assertions](glossary#client-assertion). All callers with a valid client assertion get a token which grants access for a specified period of time.
3. Finally, any protected call must also check the delegation evidence JWT in the request header. Any calls with missing or invalid JWTs are refused. In addition, the permissions granted in the JWT must grant access to the actual request being made. It is the responsibility of the Service Provider to implement this check, which will be different for every Service Provider, and to implement a mapping between the policies in the JWT and the shape of their own API.

## Minimal Flow

In this flow, BDI capabilities can be added to an existing API by implementing a larger set of extensions.

1. First, any protected call must check if there is a valid Bearer Token in the header. All calls with invalid or missing tokens are refused.
2. Second, there should be an endpoint to distribute tokens based on [Client Assertions](glossary#client-assertion). All callers with a valid client assertion get a token which grants access for a specified period of time.
3. Now, the Service Provider is responsible for acquiring a Delegation Evidence JWT, in much the same way as the Data Consumer was in the Full Flow, with the important difference that the Service Provider is now responsible for creating the Delegation Mask, and must take care to build one that requests the necessary permissions to execute the actual request by the consumer.
