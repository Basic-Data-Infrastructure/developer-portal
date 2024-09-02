---
title: BDI Developer Portal Introduction
category: 1. Introduction
order: 1
---

#### Overview of BDI

BDI is an architecture that enables services to allow unknown clients to access their APIs if these clients are known to, authenticated by, and authorized by other BDI services. This allows networks of organizations, such as those in the logistics sector, to share data securely and efficiently without the need for an overarching organization to coordinate it all. BDI allows loose coupling of services, using standards where possible, but without requiring them. Even within this loose structure, BDI allows for secure and efficient access to APIs.

#### Key Concepts and Components

The core services in a BDI architecture are the API consumer, the Service Provider, Association Register, and the Authorization Register.

##### Data Owner

Party who is entitled to have control over data and access to data, and controls decision on data sovereignty and trust sovereignty. It is responsible for authorization policies kept in an Authorization Register.

##### Service Provider

The Service Provider exposes an API that is accessible to authenticated and authorized clients. Only the authentication and authorization are standardized - BDI does not mandate any standards for the API itself. Some standards are recommended (Open Trip Model), but the API may provide any kind of data in any format, whether that's JSON, XML, CSV or a custom binary format.

##### Service Consumer

The Service Consumer is able to request authentication and authorization via the BDI services, and must then call the API of the Service Provider. Since no mandatory standards for data exchange exist, it is the responsibility of the Service Consumer to know how to interact with the Service Provider and to parse its data format.

##### Association Register

The Association Register is a register of all known participants in the system. There is no single global system; instead, there are many BDI compatible systems, and therefore many Association Registers. For every participant, they store its id, current compliance status, legal agreements, etc. They also have a list of Authorization Registers for each participant. The purpose of Association Registers is to provide up-to-date information about all participants.

##### Authorization Register

The Authorization Register acts as an information point on authorizations to data belonging to a Data Owner. The register can follow any logic required by the Data Owner (role-based, permission based, etc). A Service Consumer can give it a request for what resource you would like to access, via what API call, and in what way (read, create, update) and it will give out a digital permission slip, if the Service Consumer indeed has access to that resource. This permission slip, known as “delegation evidence,” can then be passed to the Service Provider. The Service Provider can use the Delegation Evidence in its authorization logic.

#### Developer’s Role in BDI

The main way in which developers participate in BDI is by writing Service Consumers and Service Providers. It is important to understand the role and purpose of all components involved, in order to maintain the security of the services. The largest part of working in a BDI architecture is managing credentials, calling the Association Register and Authorization Register services, and checking the output of these services. Skipping steps, such as not verifying the signature of a JSON Web Token, will compromise the security of the service you are implementing.

#### Technical Overview

All services provide a `/connect/token` endpoint used to get a Bearer Token, which is needed to access other calls on the service. The Association Register has a [`/parties`](https://dev.ishare.eu/ishare-satellite-role/single-party) endpoint which is used to retrieve information about specific participants. It also has a [`/trusted_list`](https://dev.ishare.eu/ishare-satellite-role/trusted-list) which lists all Certificate Authorities that are trusted.
The Authorization Register has a [`/delegation`](https://dev.ishare.eu/authorisation-registry-role/delegation-endpoint) endpoint which you can use to obtain a Delegation Evidence JWT.
The Service Provider may have any number of API calls, which are accessible with authentication in the form of a Bearer Token, and authorization in the form of Delegation Evidence.
