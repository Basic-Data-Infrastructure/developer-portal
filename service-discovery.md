---
title: Service discovery
category: 6. Writing a client
order: 2
---

In a federated system like the BDI, it's sometimes necessary to contact services that are new to the data consumer. For instance, it's possible to configure an Authorization Register per Data Owner, even when the data is all provider by a single Service Provider. In any case the Data Owner can choose where to host services.

In the BDI, the discovery process is recommended for enabling connections between data providers and consumers. Unlike traditional data marketplaces, where the primary focus is on matching providers with potential consumers to establish new data-sharing relationships, BDI focuses on optimizing existing data exchanges. These exchanges often support operational logistics in the supply chain, where different parties are already connected but require more efficient methods for data exchange.

The BDI supports two methods of service discovery:

- Discovery by defining a standard based on the Domain Name System (DNS)
- Discovery based on the Association Register and standardised endpoints of Service Providers

## DNS based Service Discovery

1. Well-Known Subdomain: A predictable subdomain, such as _bdi.acme-corp.com, serves as a central point for service discovery. This subdomain is used to organize DNS records related to BDI services, making it easy for data consumers to find relevant endpoints. 
2. SRV Records: SRV records are used to locate the actual endpoints where services are hosted. These records specify the hostname or IP address, port number, protocol, and other parameters necessary to connect to the service.
3. Key Fields: target (hostname/IP), port (service port number), priority and weight (used to select the best service endpoint if multiple are available). 
4. TXT Records: TXT records provide descriptive information about the services offered by a data provider. These records can include lists of services available under a specific subdomain, details about the protocols used, and any additional attributes required for service access. 
5. DNSSEC: DNSSEC provides security for DNS by enabling the validation of DNS responses. This is crucial for preventing attacks like cache poisoning, ensuring that data consumers receive accurate and trustworthy information during the discovery process. 

More information is available in [DNS Service Discovery proposal](2024_DIL_BDI-DNS-Service-Discovery-Proposal.pdf)

## Association Register and endpoints-based Service Discovery

BDI provides a framework for discovery based on specifications in the iSHARE Trust Framework. There are three aspects to discovery:

- Associations. Associations (called Data Spaces in iSHARE) are (if they choose to) discoverable through the [/dataspaces endpoint](https://dev.ishare.eu/ishare-satellite-role/dataspaces) of any Association Register (in iSHARE: iSHARE Satellite).
- Members of an Association (called in iSHARE Participants of a Data Space). Participants of an association (in iSHARE: data space) are (if they choose to) discoverable through the [/parties endpoint](https://dev.ishare.eu/ishare-satellite-role/parties) of any Association Register (in iSHARE: iSHARE Satellite).
- (Data) Services. All participants providing services must provide a [/capabilities endpoint](https://dev.ishare.eu/authorisation-registry-role/capabilities). This endpoint provides information on the available BDI supported service offerings.

### Discovery of the Authorization Registry of a Data Owner

To discovery the Authorization Register that is chosen by the Data Owner (optionally for a specific Data Space or Service), the party details can be retrieved using the [/parties endpoint](https://dev.ishare.eu/ishare-satellite-role/parties) or the the ["Single Party" endpoint](https://dev.ishare.eu/ishare-satellite-role/single-party). The information is available in the `auth_registries` attribute.
