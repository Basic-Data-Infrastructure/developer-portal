---
title: Association Register
category: 4. Components
order: 2
---

The Association Register, unlike the Authorization Register, is a register run by a central authority. It maintains the set of trusted participants in a Data Space. For each participant, it stores their current compliance status, the time frame during which that status applies, their endpoint, and a list of Authorization Registers that manage access to the participants. It also contains additional information, including legal details such as agreements.

To interact with an Association Register, clients first need to obtain a token by sending a message containing their ID, among other details, and signing it with their private key. This message is called a Client Assertion. The Association Register will use the supplied ID to look up the client's public key. With the public key, it will verify the signature. If the signature is valid and the client's current status is active, the register will generate a token, store it internally along with an expiration date, and send it to the client.

With this token, clients may use the API of the Association Register. Using the [single party API-call](https://dev.ishare.eu/ishare-satellite-role/single-party), clients may access data of a specific party, specified by their [EORI-id](glossary.md#EORI).

Service providers will use this call to authenticate requests from Data Consumers and can use the party info to evaluate the trust status of the consumer.

Note that Data Consumers do not need to interact with the Association Register directly, though they need to make sure their record is up-to-date with the Association.

##### Core Functions of the Association Register

###### Compliance Status Management

Compliance Status: Tracks whether a participant meets the required standards and protocols set by iSHARE.

Validity Period: Indicates the time frame during which the compliance status is valid. This helps ensure that participants are regularly reviewed and re-validated.

###### Participant Endpoints

Stores the endpoint information of each participant, enabling other participants to discover and interact with them directly.

###### Authorization Register References

Lists the Authorization Registries associated with each participant. These registries manage detailed access control policies and permissions for data sharing.

###### Legal and Contractual Information

Contains agreements and legal documents that outline the terms of participation and data sharing. This ensures transparency and legal compliance among participants.

###### Trust Roots

The BDI framework makes extensive use of public-key cryptography. The Association Register provides a "Trusted List" of Certificate Authorities (Root CAs) that are trusted to provide certificates for registered parties.
