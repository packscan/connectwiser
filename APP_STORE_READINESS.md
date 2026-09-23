# PackScan App Store readiness checklist

This document tracks what is already in place for a Shopify public app and what still needs to be completed before a Shopify App Store submission.

## Status summary

- OAuth install flow: Ready
- Hosted server configuration: Ready with deployment variables
- Required compliance webhooks: Ready
- Privacy policy: Ready in principle, but should be reviewed for final publication
- App Store listing metadata: Not yet finalized
- Screenshots: Not yet prepared
- Production validation: Pending on a real test store and HTTPS host

## Required checklist

### 1. App configuration

- [x] App name and public app identity are defined in the repo
- [x] OAuth flow is implemented in the server
- [x] Redirect URL and app URL are documented
- [x] `shopify.app.toml` includes compliance webhook declarations
- [x] README documents deployment env vars

### 2. Compliance and privacy

- [x] `/webhooks/customers/data_request` handling exists
- [x] `/webhooks/customers/redact` handling exists
- [x] `/webhooks/shop/redact` handling exists
- [x] `app/uninstalled` cleanup exists
- [x] HMAC validation is implemented for webhooks
- [x] Privacy page exists at `/privacy` and `/privacy.html`
- [ ] Final privacy policy is reviewed and approved for public publishing
- [ ] Privacy policy URL is configured in Shopify Partner dashboard

### 3. Production launch requirements

- [x] `HOST` is documented in `.env.example`
- [x] `SHOPIFY_API_KEY` and `SHOPIFY_API_SECRET` are documented
- [x] `SESSION_SECRET` is documented as required in production
- [x] `PACKSCAN_ENV=production` is documented
- [ ] Production host is live and serving HTTPS
- [ ] Real OAuth install is tested on a development store

### 4. App Store listing content

- [ ] Final app title and subtitle are set
- [ ] App category is selected
- [ ] App description is written
- [ ] Pricing is configured in Shopify Partner Dashboard
- [ ] Privacy policy URL is published and reachable
- [ ] Contact/support URL is published
- [ ] Screenshots are prepared for the listing
- [ ] Demo videos or additional assets are prepared if needed

### 5. Review / validation

- [ ] App is tested on a real Shopify development store
- [ ] Install flow works end-to-end
- [ ] Store owner can sign in and load the app
- [ ] Webhooks respond with the expected HMAC verification behavior
- [ ] App handles uninstall and data-deletion requirements
- [ ] Final review checklist is passed in Partner Dashboard

## Current assessment

The app has the main technical foundation needed for a public Shopify app, but it is not yet complete as a final App Store submission package. The repo already covers installation, OAuth, compliance webhooks, and privacy messaging, but the listing and review deliverables still need to be finalized in the Shopify Partner Dashboard.

## Recommended next milestone

Before submitting to the App Store, complete the following items in order:

1. Finalize the public privacy policy and support/contact links
2. Validate the app on a real development store under HTTPS
3. Prepare screenshots and final listing text
4. Configure pricing and listing metadata in Shopify Partner Dashboard
5. Run the automated App Store checks and fix any review issues
