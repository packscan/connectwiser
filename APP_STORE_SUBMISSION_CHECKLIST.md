# Shopify App Store submission checklist

## Core technical requirements

- [x] App is hosted on HTTPS
- [x] Shopify OAuth install flow is implemented
- [x] Redirect URI is configured for the server host
- [x] App scopes are documented and justified
- [x] Compliance webhooks are configured
- [x] Webhooks validate HMAC signatures
- [x] Uninstall cleanup is implemented
- [x] Session cookie handling works for app access

## Privacy and compliance

- [x] Privacy page exists
- [x] Privacy policy includes Shopify data handling details
- [ ] Privacy policy URL is publicly reachable
- [ ] Merchant data deletion flow is validated
- [ ] App review privacy requirements are confirmed by Shopify

## Listing and commerce

- [ ] App title and subtitle are chosen
- [ ] App description is finalized
- [ ] Pricing is configured
- [ ] App category is selected
- [ ] Screenshots are added
- [ ] Contact/support URL is published

## Validation

- [ ] Install flow is tested on a development store
- [ ] App loads correctly in embedded Shopify contexts
- [ ] App does not crash on shop launch or install callback
- [ ] Webhooks are tested with real payloads
- [ ] App handles exceptions and returns safe errors

## Final pass before release

- [ ] App is live on production HTTPS
- [ ] Developer has reviewed the app for Shopify compliance guidelines
- [ ] App store listing is complete
- [ ] Partner Dashboard automated checks pass
- [ ] Final review approves the listing
