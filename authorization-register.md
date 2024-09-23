---
title: Authorization Register
category: 4. Components
order: 3
---

Within a Data Space, the Authorization Register manages and enforces access control policies. Its core functions revolve around ensuring that data access is granted based on predefined rules and that only authorized participants can access specific data or services.

The Basic Data Infrastructure separates the roles of Service Provider and Authorization Register, but it's possible to implement a service-specific Authorization Register or to integrate the authorization mechanisms in the service (especially when adding BDI functionality to existing services).

#### Core Functions of the Authorization Register

##### Access Control Policy Management:

- Policy Definition: Allows administrators to define access control policies that specify who can access what data and under what conditions.
- Policy Storage: Securely stores these policies to ensure they are enforced consistently across the Data Space.

##### Authorization Decision Making:

- Request Evaluation: Evaluates access requests against the stored policies to determine whether to grant or deny access.
- Contextual Analysis: Takes into account contextual information such as the time of request, location, and other relevant factors to make nuanced authorization decisions.

##### Delegation of Rights:

- Delegation Support: Allows data owners to delegate access rights to other participants. This delegation can be temporary or conditional, based on specific criteria.
- Chaining of Permissions: Supports the chaining of permissions where rights can be delegated through multiple levels of participants.

##### Interoperability and Standards:

- Standard Protocols: Uses standard protocols (e.g., OAuth, XACML) for authorization to ensure interoperability between different systems and services within the Data Space.
- Integration Support: Facilitates integration with other components such as Association Registries, identity providers, and data services.

#### Main API Call

The main API call of the Authorization Register is [the `/delegation` call](https://dev.ishare.eu/authorisation-registry-role/delegation-endpoint). It is used to pass a delegation mask, or delegation request, to the AR, and to receive a Delegation Evidence, a JWT, in response. A Delegation Mask contains an issuer and a target, and a set of policies. Each policy contains (desired) rules (e.g., "Effect: permit"), and a target. The target contains a resource, an environment, and a list of actions (e.g., create, read, update, delete). Together, the policies represent the right to take specified actions on a specified set of resources.

The Delegation Evidence is very similar to the Delegation Mask. It also contains an issuer, a target, and a set of policies, and in addition, it contains a time frame in which the Delegation Evidence is valid, and a few other values, such as the license for the target, and a maximum delegation depth.

Since the Delegation Evidence is a JWT, it is signed and can be used as a credential when accessing a resource. It is the responsibility of the resource to check whether the resource request is covered by the Delegation Evidence. This is not part of the specification and can be implemented in an ad-hoc way by each Service Provider.
