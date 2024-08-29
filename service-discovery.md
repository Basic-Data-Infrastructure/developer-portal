---
title: Service discovery
category: 6. Writing a client
order: 2
---

In a federated system like the BDI, it's sometimes necessary to contact services that are new to the data consumer. For instance, it's possible to configure an Authorization Register per Data Owner, even when the data is all provider by a single Service Provider. In any case the Data Owner can choose where to host services.

In the BDI, the discovery process is recommended for enabling connections between data providers and consumers. Unlike traditional data marketplaces, where the primary focus is on matching providers with potential consumers to establish new data-sharing relationships, BDI focuses on optimizing existing data exchanges. These exchanges often support operational logistics in the supply chain, where different parties are already connected but require more efficient methods for data exchange. 

The BDI supports two methods of service discovery: one based on the Domain Name System (DNS), and the other based on entries in the Association Register.

# DNS based Service Discovery

1. Well-Known Subdomain: A predictable subdomain, such as _bdi.acme-corp.com, serves as a central point for service discovery. This subdomain is used to organize DNS records related to BDI services, making it easy for data consumers to find relevant endpoints. 
2. SRV Records: SRV records are used to locate the actual endpoints where services are hosted. These records specify the hostname or IP address, port number, protocol, and other parameters necessary to connect to the service.
3. Key Fields: target (hostname/IP), port (service port number), priority and weight (used to select the best service endpoint if multiple are available). 
4. TXT Records: TXT records provide descriptive information about the services offered by a data provider. These records can include lists of services available under a specific subdomain, details about the protocols used, and any additional attributes required for service access. 
5. DNSSEC: DNSSEC provides security for DNS by enabling the validation of DNS responses. This is crucial for preventing attacks like cache poisoning, ensuring that data consumers receive accurate and trustworthy information during the discovery process. 

More information is available in [DNS Service Discovery proposal](2024_DIL_BDI-DNS-Service-Discovery-Proposal.pdf)

# Association Register based Service Discovery

The Data Owner amends its record in the Assocation Register to include references to its data services. When using an iSHARE Assocation Registry, this method is used to specify the Autorization Register for a particular Data Space. See `auth_registries` attribute in [the "Single Party" endpoint](https://dev.ishare.eu/ishare-satellite-role/single-party).
