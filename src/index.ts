import sha256 from 'crypto-js/sha256';
import Base64url from 'crypto-js/enc-base64url';
import axios from 'axios';
import { jwtVerify, createRemoteJWKSet } from 'jose';

export interface IdentityProviderConfiguration {
    issuer: string;
    authorization_endpoint: string;
    token_endpoint: string;
    userinfo_endpoint: string;
    registration_endpoint: string;
    jwks_uri: string;
    response_types_supported: string[];
    response_modes_supported: string[];
    grant_types_supported: string[];
    subject_types_supported: string[];
    id_token_signing_alg_values_supported: string[];
    scopes_supported: string[];
    token_endpoint_auth_methods_supported: string[];
    claims_supported: string[];
    code_challenge_methods_supported: string[];
    introspection_endpoint: string;
    introspection_endpoint_auth_methods_supported: string[];
    revocation_endpoint: string;
    revocation_endpoint_auth_methods_supported: string[];
    end_session_endpoint: string;
    request_parameter_supported: boolean;
    request_object_signing_alg_values_supported: string[];
    device_authorization_endpoint: string;
    pushed_authorization_request_endpoint: string;
    backchannel_token_delivery_modes_supported: string[];
    backchannel_authentication_request_signing_alg_values_supported: string[];
    dpop_signing_alg_values_supported: string[];
}

export interface AuthorizationResponse {
    code?: string;
    id_token?: string;
    state?: string;
}

export interface TokenSet {
    token_type: string;
    access_token: string;
    expires_in: number;
    refresh_token: string;
    id_token?: string;
}

export interface Identity {
    sub: string;
    name?: string;
    email?: string;
}

/**
 * class AuthorizationRequest
 */
export class AuthorizationRequest {
    private client: Client;
    private responseType: string | undefined;
    private responseMode: string | undefined;
    private redirectUri: string | undefined;
    private scope: string[] | undefined;
    private state: string | undefined;
    private codeChallenge: string | undefined;
    private codeChallengeMethod: string | undefined;

    /**
     * constructor
     * @param client Client
     */
    constructor(client: Client) {
        this.client = client;
    }

    /**
     * setRedirectUri
     * @param uri string
     */
    public setRedirectUri(uri: string): AuthorizationRequest {
        this.redirectUri = uri;
        return this;
    }

    /**
     * setState
     * @param state string
     */
    public setState(state: string): AuthorizationRequest {
        this.state = state;
        return this;
    }

    /**
     * setResponseMode
     * @param mode string
     */
    public setResponseMode(mode: string): AuthorizationRequest {
        if (this.client.getProvider().isResponseModeSupported(mode)) {
            this.responseMode = mode;
        } else
            throw new Error('invalid or unsupported response mode');
        return this;
    }

    /**
     * setResponseType
     * @param type string[]
     */
    public setResponseType(type: string): AuthorizationRequest {
        if (this.client.getProvider().isResponseTypeSupported(type)) {
            this.responseType = type;
        } else
            throw new Error('invalid or unsupported response type');
        return this;
    }

    /**
     * setScope
     * @param scope string[]
     */
    public setScope(scope: string[]): AuthorizationRequest {
        if (this.client.getProvider().isScopeSupported(scope)) {
            this.scope = ['openid', ...scope];
        } else
            throw new Error('invalid or unsupported scope');
        return this;
    }

    /**
     * setCodeChallenge
     * @param challenge string
     * @param method string
     */
    public setCodeChallenge(challenge: string, method: string = 'S256'): AuthorizationRequest {
        if (this.client.getProvider().isChallengeMethodSupported(method)) {
            if (method === 'plain') {
                this.codeChallenge = challenge;
            }
            else if (method === 'S256') {
                this.codeChallenge = Base64url.stringify(sha256(challenge));
            } else
                throw new Error('code challenge method not yet implemented');
            this.codeChallengeMethod = method;
        } else
            throw new Error('invalid or unsupported code challenge method');
        return this;
    }

    /**
     * toURLSearchParams
     * @returns URLSearchParams
     */
    public toURLSearchParams(): URLSearchParams {
        const params = new URLSearchParams();
        params.append('client_id', this.client.getClientId());

        if (this.responseType === undefined)
            throw new Error('response type is required');
        params.append('response_type', this.responseType);

        if (this.responseMode)
            params.append('response_mode', this.responseMode);

        if (this.redirectUri)
            params.append('redirect_uri', this.redirectUri);

        if (this.scope === undefined)
            throw new Error('scope is required');
        params.append('scope', this.scope.join(' '));

        if (this.state)
            params.append('state', this.state);

        const isCodeResponseTypeIncluded = this.responseType.includes('code');

        if (this.codeChallenge === undefined) {
            if (isCodeResponseTypeIncluded)
                throw new Error("code challenge required for 'code' response type");
        } else
            params.append('code_challenge', this.codeChallenge);

        if (this.codeChallengeMethod === undefined) {
            if (isCodeResponseTypeIncluded)
                throw new Error("code challenge method required for 'code' response type");
        } else
            params.append('code_challenge_method', this.codeChallengeMethod);
        return params;
    }

    /**
     * toURL
     * @returns URL
     */
    public toURL(): URL {
        const endpointUrl = new URL(this.client.getProvider().getAuthorizationEndpoint());
        endpointUrl.search = this.toURLSearchParams().toString();
        return endpointUrl;
    }
}

/**
 * class TokenRequest
 */
export class TokenRequest {
    private client: Client;
    private code: string | undefined;
    private codeVerifier: string | undefined;
    private redirectUri: string | undefined;
    private grantType: string | undefined;
    private refreshToken: string | undefined;

    /**
     * constructor
     * @param client Client
     */
    constructor(client: Client) {
        this.client = client;
    }

    /**
     * setCode
     * @param code string
     */
    public setCode(code: string): TokenRequest {
        this.code = code;
        return this;
    }

    /**
     * setRedirectUri
     * @param uri string
     */
    public setRedirectUri(uri: string): TokenRequest {
        this.redirectUri = uri;
        return this;
    }

    /**
     * setCodeVerifier
     * @param verifier string
     */
    public setCodeVerifier(verifier: string): TokenRequest {
        this.codeVerifier = verifier;
        return this;
    }

    /**
     * setGrantType
     * @param type string
     */
    public setGrantType(type: string): TokenRequest {
        if (this.client.getProvider().isGrantTypeSupported(type)) {
            this.grantType = type;
        } else
            throw new Error('grant type not supported');
        return this;
    }

    /**
     * setRefreshToken
     * @param token string
     */
    public setRefreshToken(token: string): TokenRequest {
        this.refreshToken = token;
        return this;
    }

    /**
     * toURLSearchParams
     * @returns URLSearchParams
     */
    public toURLSearchParams(): URLSearchParams {
        const params = new URLSearchParams();
        params.append('client_id', this.client.getClientId());
        params.append('client_secret', this.client.getClientSecret());

        if (this.grantType === undefined)
            throw new Error('grant type is required');
        params.append('grant_type', this.grantType);

        if (this.grantType === 'authorization_code') {
            if (this.code === undefined)
                throw new Error('code is required for authorization code flow');
            params.append('code', this.code);

            if (this.codeVerifier)
                params.append('code_verifier', this.codeVerifier);
            if (this.redirectUri)
                params.append('redirect_uri', this.redirectUri);
        }
        else if (this.grantType === 'refresh_token') {
            if (this.refreshToken === undefined)
                throw new Error('refresh token required for grant type');
            params.append('refresh_token', this.refreshToken);
        }

        return params;
    }
}

/**
 * class IdentityProvider
 */
export class IdentityProvider {
    private config: IdentityProviderConfiguration;

    /**
     * constructor
     * @param config IdentityProviderConfiguration
     */
    constructor(config: IdentityProviderConfiguration) {
        this.config = config;
    }

    /**
     * getAuthorizationEndpoint
     * @returns string
     */
    public getAuthorizationEndpoint(): string {
        return this.config.authorization_endpoint;
    }

    /**
     * getTokenEndpoint
     * @returns string
     */
    public getTokenEndpoint(): string {
        return this.config.token_endpoint;
    }

    /**
     * getUserinfoEndpoint
     * @returns string
     */
    public getUserinfoEndpoint(): string {
        return this.config.userinfo_endpoint;
    }

    /**
     * getRevocationEndpoint
     * @returns string
     */
    public getRevocationEndpoint(): string {
        return this.config.revocation_endpoint;
    }

    /**
     * isResponseModeSupported
     * @param mode string
     * @returns boolean
     */
    public isResponseModeSupported(mode: string): boolean {
        return this.config.response_modes_supported.includes(mode);
    }

    /**
     * isResponseTypeSupported
     * @param type string[]
     * @returns boolean
     */
    public isResponseTypeSupported(type: string): boolean {
        return this.config.response_types_supported.includes(type);
    }

    /**
     * isScopeSupported
     * @param scope string[]
     * @returns boolean
     */
    public isScopeSupported(scope: string[]): boolean {
        return scope.length === scope.filter(s => this.config.scopes_supported.includes(s)).length;
    }

    /**
     * isChallengeMethodSupported
     * @param method string
     * @returns boolean
     */
    public isChallengeMethodSupported(method: string): boolean {
        return this.config.code_challenge_methods_supported.includes(method);
    }

    /**
     * isGrantTypeSupported
     * @param method string
     * @returns boolean
     */
    public isGrantTypeSupported(type: string): boolean {
        return this.config.grant_types_supported.includes(type);
    }

    /**
     * createClient
     * @returns Client
     */
    public createClient(id: string, secret: string): Client {
        const client = new Client(this, id, secret);
        return client;
    }

    /**
     * getIdentity
     * @param client Client
     * @param tokenSet TokenSet
     * @returns Promise<Identity | null>
     */
    public async getIdentity(client: Client, tokenSet: TokenSet): Promise<Identity | null> {
        let id: Identity | null = null;

        if (tokenSet.id_token) {
            const jwks = createRemoteJWKSet(new URL(this.config.jwks_uri));
            const { payload } = await jwtVerify(tokenSet.id_token, jwks, { issuer: this.config.issuer });
            id = payload as Identity;
        }
        else {
            const api = new IdentityProviderApi(this, tokenSet);
            id = await api.fetchUserinfo();
        }
        return id;
    }
}

/**
 * class IdentityProviderApi
 */
class IdentityProviderApi {
    private provider: IdentityProvider;
    private tokenSet: TokenSet;

    /**
     * constructor
     * @param provider IdentityProvider
     * @param client Client
     */
    constructor(provider: IdentityProvider, tokenSet: TokenSet) {
        this.provider = provider;
        this.tokenSet = tokenSet;
    }

    /**
     * setTokenSet
     * @param tokenSet TokenSet
     */
    public setTokenSet(tokenSet: TokenSet) {
        this.tokenSet = tokenSet;
    }

    /**
     * fetchUserinfo
     * @returns Promise<Identity>
     */
    public async fetchUserinfo(): Promise<Identity> {
        const res = await axios.get(this.provider.getUserinfoEndpoint(), {
            headers: {
                'Authorization': `Bearer ${this.tokenSet.access_token}`
            }
        });
        return res.data as Identity;
    }
}

/**
 * class Client
 */
export class Client {
    private provider: IdentityProvider;
    private clientId: string;
    private clientSecret: string;

    /**
     * constructor
     * @param provider IdentityProvider
     * @param id string
     * @param secret string
     */
    constructor(provider: IdentityProvider, id: string, secret: string) {
        this.provider = provider;
        this.clientId = id;
        this.clientSecret = secret;
    }

    /**
     * getProvider
     * @returns IdentityProvider
     */
    public getProvider(): IdentityProvider {
        return this.provider;
    }

    /**
     * getClientId
     * @returns string
     */
    public getClientId(): string {
        return this.clientId;
    }

    /**
     * getClientSecret
     * @returns string
     */
    public getClientSecret(): string {
        return this.clientSecret;
    }

    /**
     * newAuthorizationRequest
     * @returns AuthorizationRequest
     */
    public newAuthorizationRequest(): AuthorizationRequest {
        const req = new AuthorizationRequest(this);
        return req;
    }

    /**
     * requestAccess
     * @param authResponse AuthorizationResponse
     * @param codeVerifier string
     * @returns Promise<TokenSet>
     */
    public async requestAccess(authResponse: AuthorizationResponse, codeVerifier?: string): Promise<TokenSet> {
        const tokenRequest = new TokenRequest(this);

        if (authResponse.code === undefined)
            throw new Error('authorization response did not include a code');
        tokenRequest.setCode(authResponse.code)
            .setGrantType('authorization_code');

        if (codeVerifier)
            tokenRequest.setCodeVerifier(codeVerifier);
        const res = await axios.post(this.provider.getTokenEndpoint(), tokenRequest.toURLSearchParams());
        return res.data as TokenSet;
    }

    /**
     * refreshAccess
     * @param tokenSet TokenSet
     * @returns Promise<TokenSet>
     */
    public async refreshAccess(tokenSet: TokenSet): Promise<TokenSet> {
        const tokenRequest = new TokenRequest(this)
            .setRefreshToken(tokenSet.refresh_token)
            .setGrantType('refresh_token');
        const res = await axios.post(this.provider.getTokenEndpoint(), tokenRequest.toURLSearchParams());
        return res.data as TokenSet;
    }

    /**
     * revokeAccess
     * @param tokenSet TokenSet
     * @returns Promise<void>
     */
    public async revokeAccess(tokenSet: TokenSet): Promise<void> {
        const params = new URLSearchParams();
        params.append('client_id', this.clientId);
        params.append('client_secret', this.clientSecret);
        params.append('token', tokenSet.access_token);
        params.append('token_type_hint', 'access_token');
        await axios.post(this.provider.getRevocationEndpoint(), params);
    }
}

/**
 * createIdentityProvider
 * @param issuer string
 * @returns IdentityProvider
 */
export const createIdentityProvider = async (issuer: string): Promise<IdentityProvider> => {
    const discoveryUrl = `${issuer}/.well-known/openid-configuration`;
    const res = await axios.get(discoveryUrl);
    const config = res.data as IdentityProviderConfiguration;
    const provider = new IdentityProvider(config);
    return provider;
}