# Portal OAuth reference notes

Google, GitHub and Microsoft sign-in are distinct from optional cloud-service credentials. Signing in must not automatically authorize scans, fetch a visitor's cloud accounts or expose cloud credentials to the decoy. Each external provider needs a registered OAuth application and an exact callback URL. No provider credentials have been supplied for this portal yet.

Google web-server authentication uses a registered client ID, client secret, exact redirect URI, state and nonce. The code exchange happens server-side; request only identity scopes (`openid email profile`). Validate identity tokens, issuer, audience and nonce before creating an application session. Source: https://developers.google.com/identity/openid-connect/openid-connect

GitHub's OAuth web application flow redirects to `https://github.com/login/oauth/authorize`, exchanges the authorization code server-side, and revalidates the returned identity with `https://api.github.com/user`. A registered OAuth application supplies the client ID and secret; use state and PKCE where supported. Login scopes must not include repository administration. Source: https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps

Microsoft recommends a supported authentication library for authorization-code flow with PKCE and OIDC. A confidential server-based web app needs an application registration, matching redirect URI and client secret or certificate. Tenant selection controls the sign-in audience. Source: https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow

The operator portal must validate browser-bound, single-use state/nonce, use fixed in-app return paths, HttpOnly secure application sessions, CSRF/origin protection on changes, per-user ownership and no development authentication bypass. OAuth credentials stay server-side. Provider setup status must be reported honestly instead of using simulated sign-in buttons.

The reusable shield-check branding icon is from Lucide, released under the ISC license. Source: https://lucide.dev/icons/shield-check and https://lucide.dev/license . Image-search catalogs were reviewed; no decorative imagery is necessary for this operator dashboard.
