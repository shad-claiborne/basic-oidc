# This package is not intended for production environments.
```ts
const issuer = 'https://id.some-idp.com';
const provider:IdentityProvider = await createIdentityProvider(issuer);
const clientId = 'client-id';
const clientSecret = 'client-secret';
const client:Client = provider.createClient(clientId, clientSecret);
const codeChallenge = 'test123';
const authRequest:AuthorizationRequest = client.newAuthorizationRequest()
        .setRedirectUri('https://this-app.com/basic-oidc/callback')
        .setResponseMode('fragment')
        .setResponseType('code id_token')
        .setScope(['email', 'profile'])
        .setCodeChallenge(codeChallenge)
        .setState('data');
const authURL = authRequest.toURL();
const window.location.replace(authURL.href);
// IdP redirects back to https://this-app.com/basic-oidc/callback - 
// i.e. A user has granted us authorization
const authResponseParams = 
        new URLSearchParams(window.location.hash.substring(1));
const authResponse = 
        Object.fromEntries(authResponseParams) as AuthorizationResponse;
const tokenSet:TokenSet = 
        await client.requestAccess(authResponse, { codeVerifier: codeChallenge });
const id:Identity = await provider.getIdentity(tokenSet);
// await client.revokeAccess(tokenSet);
```