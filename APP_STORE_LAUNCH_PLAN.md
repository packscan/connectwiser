# Shopify App Store launch plan

## Goal

Ship a review-ready, hosted PackScan app that can be installed from the Shopify App Store and used by merchants without requiring custom developer setup.

## Phase 1: production hardening

1. Configure production environment variables on the host
   - `HOST`
   - `SHOPIFY_API_KEY`
   - `SHOPIFY_API_SECRET`
   - `SESSION_SECRET`
   - `PACKSCAN_ENV=production`
   - `PORT`
2. Deploy app to a real HTTPS host
3. Verify OAuth install / callback route works on a development store
4. Confirm embedded cookie behavior works in a real browser
5. Validate the app logs in and reads shop state correctly

## Phase 2: compliance and privacy

1. Publish the privacy policy URL
2. Confirm compliance webhooks are reachable on the production host
3. Validate HMAC verification with Shopify test payloads
4. Confirm uninstall removes the stored shop token
5. Confirm compliance logs are retained only as required

## Phase 3: listing and review

1. Prepare store listing title, subtitle, and description
2. Create a privacy policy page and support contact
3. Create screenshots showing the warehouse flow
4. Set pricing and merchant support details in Partner Dashboard
5. Submit for review and fix any issues raised by Shopify

## Phase 4: launch

1. Promote the app to a dev store for real-world testing
2. Collect merchant feedback on flow and UX
3. Resolve bugs and edge cases before public release
4. Publish the app to the App Store and monitor install issues

## Risk items to monitor

- Cookie compatibility in embedded Shopify contexts
- Session expiry and re-authentication behavior
- Local file storage of shop tokens and metadata
- Production webhook endpoint reachability
- Merchant support and privacy policy clarity
