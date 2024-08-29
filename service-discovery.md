---
title: Service discovery
category: 6. Writing a client
order: 2
---

TODO: Include references to two ways of service discovery: 1. via Association Register party info, 2. via DNS (pdf document)

Service discovery in the context of Basic Data Infrastructure (BDI) is a crucial mechanism that helps participants locate and access various services within a vast and interconnected digital network. Imagine it as an advanced directory system that knows where all the services, such as data storage, analytics tools, and application interfaces, are located. This directory system ensures that participants can easily find and use these services without needing to know their specific locations or endpoints in advance.

Instead of being a single central directory, BDI employs a network of federated directories. These directories share information with each other, maintaining an updated map of available services across different regions and domains. When a participant needs a particular service, they can query the directory, which then provides the necessary information on where to find and how to access that service. This decentralized approach enhances the system’s resilience and scalability, allowing it to efficiently handle the addition of new services and participants.

Security and trust are fundamental in the service discovery process within BDI. Participants must authenticate themselves and verify the integrity of the services they discover. This is typically done using digital certificates and cryptographic techniques, ensuring that only authorized entities can publish and access services. Additionally, service discovery in BDI supports dynamic and context-aware searches, enabling participants to locate services based on specific criteria, such as type, geographic proximity, or current network conditions. This dynamic capability ensures efficient and effective data sharing and collaboration, making BDI a robust foundation for diverse digital ecosystems.
