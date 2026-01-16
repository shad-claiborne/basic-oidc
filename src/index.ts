import axios from "axios";
import { IdentityProvider, IdentityProviderConfiguration } from "./identity-provider"

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