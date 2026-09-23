# PackScan — hosted Shopify app

Same pick/pack station, installed from Shopify Admin. Merchants do not paste Client secrets. You host one server; each shop gets an OAuth token stored on the server.

Carrier keys (FedEx / UPS / USPS) still stay in the merchant’s browser Settings.

## 1. Partner Dashboard app

1. [partners.shopify.com](https://partners.shopify.com) → Apps → **Create app** → Create app manually.
2. App URL: `https://YOUR-HOST/`
3. Allowed redirection URL(s): `https://YOUR-HOST/auth/callback`
4. Scopes:
   `read_orders,read_products,read_locations,read_merchant_managed_fulfillment_orders,write_merchant_managed_fulfillment_orders`
5. Copy **Client ID** and **Client secret**.
6. Distribution: Public app when you want the App Store. Use a custom distribution / test store first.

## 2. Host on Render (simplest)

1. Push this `packscan-cloud` folder to a GitHub repo.
2. [render.com](https://render.com) → New Web Service → that repo.
3. Build: leave empty / `true`. Start: `python server.py`.
4. Configure the following environment variables. Use a unique high-entropy value for `SESSION_SECRET`; it is required in hosted production and must not be the Shopify API secret.

   | Key | Value |
   |---|---|
   | `HOST` | `https://your-service.onrender.com` (no trailing slash) |
   | `SHOPIFY_API_KEY` | Client ID |
   | `SHOPIFY_API_SECRET` | Client secret |
   | `SESSION_SECRET` | unique high-entropy session-signing value |
   | `SESSION_TTL_SECONDS` | optional session lifetime in seconds (default: 2592000 = 30 days) |
   | `PACKSCAN_ENV` | `production` |
   | `BIND` | `0.0.0.0` |

5. Deploy. Open the Render URL — you should see PackScan.
6. In Partner Dashboard set App URL + redirect to that same host.
7. Install: `https://YOUR-HOST/auth?shop=your-store.myshopify.com`  
   or Apps → PackScan → Install on a development store.

After install you land on `/` with a 30-day session cookie by default. Refresh loads that shop’s orders until the session expires, then the merchant must sign back in.

## 3. Mandatory privacy webhooks (App Store listing)

Shopify will reject the listing until these three HTTPS URLs are set and they return **401** on a bad HMAC.

In **Dev Dashboard / Partner Dashboard → your PackScan app → Versions / App setup → Compliance webhooks** (or `shopify app deploy` with `shopify.app.toml`):

| Topic | URL |
|---|---|
| customers/data_request | `https://YOUR-HOST/webhooks/customers/data_request` |
| customers/redact | `https://YOUR-HOST/webhooks/customers/redact` |
| shop/redact | `https://YOUR-HOST/webhooks/shop/redact` |

You can also point all three at `https://YOUR-HOST/webhooks`. The server reads `X-Shopify-Topic`.

HMAC is checked against `SHOPIFY_API_SECRET`. Invalid signature → HTTP 401. Valid → HTTP 200.

PackScan does not keep customer profiles on the server. `shop/redact` and `app/uninstalled` delete that shop’s stored OAuth token.

Redeploy Render after pushing `server.py`, then click **Run** on the App Store automated checks.

Fly.io / Railway / Cloud Run work the same: run `python server.py`, set `PORT` (they inject it), `HOST`, API key/secret.

## 3. Monthly fee (App Store)

Do **not** bill with Stripe for App Store installs.

Partner Dashboard → your app → **Pricing** (Shopify App Pricing):

- e.g. $29 every 30 days
- optional trial

Shopify invoices the merchant and pays you. Submit the listing when the install + pack flow works on a test shop.

Privacy policy URL, GDPR webhooks, and screenshots are required for review. Webhooks can wait until you submit; installs work without them.

## 4. What stays local vs hosted

| Local PackScan (`proxy.py`) | Hosted app |
|---|---|
| You paste Client ID/Secret | Merchant clicks Install |
| One PC | Any browser, any station |
| Good for your warehouse only | Sell or share with other shops |

Keep using the local zip in the warehouse if you want. Hosted is the public version.

## 5. Data

Installed shop tokens are stored in `data/shops.json` on the server. Compliance logs are also stored under `data/`. The server only serves an allowlist of application HTML, CSS, and logo assets, so neither directory is web-accessible. On Render’s free/starter disk these files can reset on redeploy — use a persistent disk or later swap in Postgres. Treat the directory as secret.

## Local test of the hosted server

```bash
export HOST=http://localhost:8787
export SHOPIFY_API_KEY=...
export SHOPIFY_API_SECRET=...
export PACKSCAN_ENV=development
python server.py
```

For local development without `SESSION_SECRET`, the server generates a random process-local secret and invalidates sessions on restart. OAuth redirect URLs must be HTTPS for real shops. Use a tunnel (`cloudflared` / ngrok) pointing at localhost:8787, set `HOST` to the https tunnel URL, and keep `PACKSCAN_ENV=development` only for that local process.
