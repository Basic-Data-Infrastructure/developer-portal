---
title: Getting Started with BDI
category: 2. Getting Started
order: 2
---

To get started with BDI, there are a few things you need to acquire or install.

First, whether you are developing a Data Consumer or a Service Provider, you will need to be registered by an Association Register in the Data Space where you want to work. You will need an EORI number and credentials, including a private key and a certificate. You will also need to know the endpoint of the Association Register. If you are building a Data Consumer, you will also need to know the EORI numbers and endpoints of all Service Providers you plan to use.

We have provided cookbook recipes for several common scenarios. These are written in JavaScript. You can find links to them in the sidebar on the left.

If you prefer to use another language, that is possible too. The cryptography used in BDI, such as parsing certificate chains and verifying them is standard and will have implementations in practically every language, and even the JWT standard has been so widely accepted as to have implementations in [nearly 40 languages](https://jwt.io/libraries).

To implement a Data Consumer is to make a series of HTTP calls. Implementing a Service Provider requires writing an HTTP server with two endpoints, which perform a series of HTTP calls.
