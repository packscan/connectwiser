import hashlib
import hmac
import unittest
import urllib.parse
from unittest import mock

import server


def signed_query(shop, timestamp):
    params = {
        "host": "YWRtaW4uc2hvcGlmeS5jb20vc3RvcmUvY2hpbGQtdG8tY2hlcmlzaA",
        "shop": shop,
        "timestamp": str(timestamp),
    }
    message = "&".join(f"{key}={params[key]}" for key in sorted(params))
    params["hmac"] = hmac.new(server.API_SECRET.encode(), message.encode(), hashlib.sha256).hexdigest()
    return urllib.parse.urlencode(params)


class ShopifyLaunchTests(unittest.TestCase):
    def setUp(self):
        self.secret = mock.patch.object(server, "API_SECRET", "test-secret")
        self.secret.start()
        self.addCleanup(self.secret.stop)
        self.shops = mock.patch.object(server, "load_shops", return_value={
            "child-to-cherish.myshopify.com": {"access_token": "token"}
        })
        self.shops.start()
        self.addCleanup(self.shops.stop)

    def test_accepts_recent_signed_launch_for_installed_shop(self):
        query = signed_query("child-to-cherish.myshopify.com", 1_700_000_000)
        self.assertEqual(
            server.verify_shopify_launch(query, now=1_700_000_100),
            "child-to-cherish.myshopify.com",
        )

    def test_rejects_expired_or_tampered_launch(self):
        query = signed_query("child-to-cherish.myshopify.com", 1_700_000_000)
        self.assertIsNone(server.verify_shopify_launch(query, now=1_700_000_301))
        self.assertIsNone(server.verify_shopify_launch(query.replace("child-to-cherish", "other"), now=1_700_000_100))

    def test_https_cookie_supports_shopify_embedded_context(self):
        handler = object.__new__(server.Handler)
        with mock.patch.object(server, "HOST", "https://packscan.example"):
            cookie = handler._cookie_value("packscan_session", "signed", 300)
        self.assertIn("SameSite=None", cookie)
        self.assertIn("Secure", cookie)
        self.assertIn("Partitioned", cookie)


if __name__ == "__main__":
    unittest.main()
