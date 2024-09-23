---
title: Available Components
category: 2. Getting Started
order: 1
---

## Components

Several components are available for BDI implementations.

### [FIWARE iSHARE Satellite](https://github.com/FIWARE/ishare-satellite)

A simple implementation of an iSHARE satellite trust anchor / BDI Association Register.

The FIWARE iSHARE Satellite is based on Python Flask using Gunicorn and runs completely stateless. It is configured with a static configuration file.

_This implementation of the iSHARE Satellite is only meant for testing and demonstration purposes. It is not possible to change participants or trusted CAs in a running instance. It is not recommended to be used in production environments._

### [Poort8 Dataspace Noodle Bar](https://github.com/POORT8/Poort8.Dataspace.NoodleBar)

The Noodle Bar project falls under the Basic Data Infrastructure (BDI) umbrella, pending its ongoing development.

Noodle Bar facilitates setting up dataspaces that follow certain principles, serving as an initial platform for data providers, apps, and data consumers.

**Roles**

 - Data Providers: Organizations that either offer a data source with raw data or an app with processed data. In all cases, access conditions are set by the data owner.
 - App Providers: Organizations that act as intermediaries, adding value to raw data. They act as a Data Consumer on behalf of their end users, and as a Data Provider for their end users.
 - Data Consumers: Organizations that use data via Service Providers or directly.
 - Dataspace Initiators: Organizations that set up and manage the dataspace.

### [iSHARE .NET Client](https://github.com/iSHAREScheme/iSHARE.NET)

This is the official iSHARE library, which provides core functionality for service consumers. In other words, it encapsulates HTTP request calls towards iSHARE endpoints, JWT response validation, and mapping business logic.

### [Postman Collections](https://dev.ishare.eu/demo-and-testing/postman.html)

This link provides access to a set of tools called Postman collections, which are used to manually test how iSHARE APIs work within the BDI architecture. Postman is a popular API development and collaboration platform that allows developers and teams to design, test, document, and share APIs efficiently. It provides an intuitive interface for sending HTTP requests, examining responses, and automating API workflows through collections. In the collections provided here, you'll be pretending to be a company called "ABC Trucking" using a special digital key that allows you to interact with the system as if you were that company. This is a safe way to try out the APIs and see how they work.

### [iSHARE Authorization Registry](https://github.com/iSHAREScheme/AuthorizationRegistry)

_The Authorization Register code that is in this repository is not a 'production-ready' Authorization Register, meaning it has a limited set of functionalities. It can be used in proof of concepts or pilots to showcase the iSHARE Authorization protocol, however many functionalities can be improved. Furthermore, it should be noted that only the request and return made to the /delegation endpoint (as described on our Developer Portal) is specified within the iSHARE standards. How an authorization registry registers policies and translates these into delegation evidence is up to the authorization registry. This code only provides one of the options to do so._

### [iSHARE Satellite](https://github.com/iSHAREScheme/iSHARESatellite)

This is the iSHARE equivalent of a BDI Association Register.

The iSHARE Satellite is an application that safeguards trust in a dataspace. It functions as a register of participants. Participants can call the Satellite API to verify each other. When you verify that a participant is registered in the Satellite, you know that this participant has signed which agreements and the participant is indeed a part of a dataspace, also on a "legal level".
