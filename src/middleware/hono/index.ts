import { getCookie, setCookie } from "hono/cookie";
import { createMiddleware } from "hono/factory";
import { createIdentityProvider } from "../..";

export const withIdentity = createMiddleware(async (c, next) => {
    const { env } = c;
    const identityProvider = await createIdentityProvider("https://id.shadclaiborne.com");
    const accessToken = getCookie(c, env.SOI_ACCESS_TOKEN_COOKIE_NAME);

    if (accessToken === undefined) {
        const refreshToken = getCookie(c, env.SOI_REFRESH_TOKEN_COOKIE_NAME);

        if (refreshToken === undefined) {
            const authorizationRequest = identityProvider.newAuthorizationRequest();
        } else {
        }
    }
    await next();
});