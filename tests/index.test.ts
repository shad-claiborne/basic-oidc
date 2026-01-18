import { describe, expect, test } from 'vitest';
import { IdentityProvider, AuthorizationResponse, Client, createIdentityProvider } from '../src';
import axios from 'axios';

describe("Core logic", async () => {
    test('Identity', async () => {
        const provider = await createIdentityProvider('http://localhost');
        expect(provider).toBeInstanceOf(IdentityProvider);

        const client = provider.createClient('client-id', 'client-secret');
        expect(client).toBeInstanceOf(Client);

        const authzRequest =
            client.newAuthorizationRequest()
                .setResponseType('code id_token')
                .setScope(['email', 'profile'])
                .setCodeChallenge('test')
                .setState('base64');

        const authzURL = authzRequest.toURL();
        expect(authzURL).toBeInstanceOf(URL);
        let res = await axios.get(authzURL.toString());
        const authResponse = res.data as AuthorizationResponse;
        expect(authResponse.code).toBeDefined();
        expect(authResponse.id_token).toBeDefined();
        expect(authResponse.state).toBeDefined();
        expect(authResponse.state).toEqual('base64');

        let tokenSet = await client.requestAccess(authResponse, { codeVerifier: 'test' });
        expect(tokenSet).toBeDefined();

        tokenSet = await client.refreshAccess(tokenSet);
        expect(tokenSet).toBeDefined();

        const id = await provider.getIdentity(tokenSet);
        expect(id).not.toBeNull();

        await client.revokeAccess(tokenSet);
    });
});