---
title: Writing a client
category: 6. Writing a client
order: 1
---

What is needed to write a client?

A client will need to make a series of HTTP calls. They might need a certificate and/or a form of credentials.

They will need the following information:

- The URL and ID of the association registry
- A certificate chain plus a private key
- Knowledge of the API of the resource you want to access and the ability to create a resource request

If you have all that, then you're ready to make the calls. In total, you'll need to make 6 calls: two to the association registry, two to the authorization registry, and two to the resource provider.

The first call to each entity is always to request a token. To request a token, you will need an ID and a URL for each service. You'll pass in a client assertion, which is a JWT token, containing your own ID, the ID of the target, the certificate chain, and you'll sign it with your private key. In return, you'll get a token which you can use for the second call to the service.

The second call to the association registry will fetch information about the parties that you're interested in, including name, ID, status (whether they're active), the URL, and also a list of authorization registries with similar information. You should pass in your token and the ID of the resource you're interested in.

After you've received the party information, it's time to talk to the second entity, the authorization registry. You can extract its ID and URL from the party data object. First, you'll request a token, but now with a client assertion with the authorization registry as its audience. With the token, you can now call it again to request the delegation evidence, but you'll also need to pass in the delegation mask, which is a description in JSON format of the permissions you'll need to make the resource request. You'll receive a delegation evidence JWT object in return, which contains a JSON object.

Finally, it's time to address the service provider. First, request a token with the ID of the service provider as its audience, which was included in the party information, then use that token and the delegation evidence in the HTTP header to make the actual resource request. This will allow you to do the actual request that you intended, with the service provider knowing that you were authenticated and authorized for that request, but without them knowing who you are.
