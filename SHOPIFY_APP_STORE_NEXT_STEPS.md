# Shopify App Store next steps

## Current status

The app has the core building blocks for a public hosted Shopify app: OAuth install, hosted session handling, webhook validation, and compliance endpoints. The repo is not yet a complete submission package, but it is close enough to proceed methodically.

## Immediate next milestone

### 1. Production deployment handoff

- [ ] Set the real production `HOST` value to the public HTTPS app URL
- [ ] Set `SHOPIFY_API_KEY` and `SHOPIFY_API_SECRET` from the production app in the Shopify Partner Dashboard
- [ ] Generate a strong `SESSION_SECRET` and never reuse the Shopify secret
- [ ] Set `PACKSCAN_ENV=production`
- [ ] Set `PORT` to the platform-provided port for Render, Railway, Fly, etc.
- [ ] Confirm the app serves correctly over HTTPS and not just localhost

### 2. Real-store validation

- [ ] Install the app on a Shopify development store
- [ ] Confirm the OAuth redirect succeeds and lands on the shop home screen
- [ ] Confirm the session cookie is stored and reads correctly after refresh
- [ ] Verify the app can read the required order and fulfillment data
- [ ] Verify the cookie still works in embedded Shopify contexts

### 3. Compliance validation

- [ ] Trigger each required compliance webhook against the production host
- [ ] Confirm the HMAC check passes for valid requests and rejects invalid ones
- [ ] Validate that `shop/redact` removes stored shop token data
- [ ] Validate that `app/uninstalled` removes the stored shop token
- [ ] Confirm compliance logs are retained only as needed and do not expose secrets

### 4. Listing readiness

- [ ] Publish the final privacy policy URL
- [ ] Add support and contact information
- [ ] Provide final app screenshots and feature previews
- [ ] Write the final App Store description and pricing plan
- [ ] Configure your public app listing in Partner Dashboard

### 5. Review pass

- [ ] Submit the app for review
- [ ] Run partner dashboard automated checks
- [ ] Fix any issues returned by Shopify
- [ ] Confirm the app is installable without developer-side custom setup

## Risk watchlist

- Browser cookie handling in embedded Shopify contexts
- Local JSON storage for merchant tokens and logs
- Host-based data persistence on ephemeral platforms
- Final privacy/public compliance messaging

## Recommended target order

1. Production deployment
2. Real-store install testing
3. Compliance webhook testing
4. App listing assets and privacy policy
5. Shopify review submission

This sequence reduces the likelihood of shipping a public app that technically runs locally but fails review or fails in production.
