=== Jacker Login Guard ===
Contributors: jackerteo
Tags: security, login protection, hide login, anti-brute-force, wp-admin protection
Requires at least: 6.1
Tested up to: 6.7
Stable tag: 1.0.0
Requires PHP: 7.4
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Protect your WordPress login with a hidden URL, signed access tokens, IP controls, and comprehensive security hardening.

== Description ==

**Built after hackers installed a backdoor on my WordPress site. Now it's finally quiet.**

Jacker Login Guard protects your WordPress login by hiding the entry point, enforcing short-lived HMAC-SHA256 signed access tokens, and blocking unauthorized access attempts.

= Why Choose This Plugin? =

* **True Security:** It does not just change the URL. It enforces a short-lived, HMAC-SHA256 signed cookie. Even if a bot guesses your secret URL, it cannot access the login page without a valid token.
* **Zero Bloat:** No heavy JavaScript, no external API calls on the frontend. Pure, optimized PHP.
* **Cloudflare Aware:** Securely detects real visitor IPs behind Cloudflare proxies.

= Core Features =

* **Hidden Entry URL:** Hides wp-login.php and wp-admin from public view.
* **Signed Access Tokens:** Generates a 5-minute, cryptographically signed cookie.
* **Smart Blocking:** Returns 404 or 403 to unauthorized scanners.
* **IP Controls:** Manual Whitelist and Blacklist with full IPv4/IPv6, CIDR, and IP range (A-B) support.
* **Passkey & 2FA Friendly:** Compatible with WordPress 6.3+ Passkeys and popular 2FA plugins.
* **Anti-Enumeration:** Blocks XML-RPC, REST API user enumeration, and author scanning.
* **Attack Detection:** Detects malicious requests, scanners, and encoded or plain-text attacks in the URI and POST body.
* **Failed Login Auto-Block:** Automatically blocks IPs after a configurable number of failed login attempts within 24 hours.
* **Auto-Block:** Suspicious IPs are automatically blocked after a configurable number of attacks.
* **Auto-Unblock:** Auto-blocks expire after a configurable duration.
* **Escalation:** Repeatedly blocked IPs are escalated to the permanent blacklist.
* **Trusted IP Window:** Recently authenticated IPs are protected from accidental blocking.
* **Three Logging Systems:** Login Events, Access Log, Auto Block List.
* **Admin Operation Audit:** Logs state-changing admin actions with 15-minute deduplication.
* **IP Country Detection:** Displays country flags for each IP address in logs.
* **Bulk Actions:** Whitelist, Blacklist, or Remove multiple entries at once.
* **Security Headers:** Adds X-Content-Type-Options, X-Frame-Options, and more.
* **Import/Export Settings:** Backup and restore plugin configuration.
* **Dashboard:** Real-time stats showing online users, admin online, last login, and blocked counts.

== External Services ==

This plugin connects to external services for IP geolocation and Cloudflare IP detection.

= 1. Cloudflare API =

The plugin connects to the Cloudflare API (https://api.cloudflare.com/client/v4/ips) to fetch official Cloudflare IP ranges. This allows the plugin to correctly identify real visitor IP addresses when your site is behind Cloudflare CDN.

What data is sent:
- No personal data or site-specific data is sent.
- A standard HTTPS GET request to the Cloudflare IP ranges endpoint.

When it happens:
- When a visitor IP address needs to be checked and Cloudflare is detected.
- The IP list is cached for 7 days to minimize API calls.

Service Provider:
Cloudflare, Inc.
- Terms of Service: https://www.cloudflare.com/terms/
- Privacy Policy: https://www.cloudflare.com/privacypolicy/

= 2. IP Geolocation API =

The plugin uses IP-API.com to detect the country of IP addresses for display in the logs. An HTTPS endpoint is used when an API key is provided via the `jacklogu_ipapi_key` filter; otherwise the free HTTP endpoint is used.

What data is sent:
- The visitor IP address.
- No personal or site-specific data is sent.

When it happens:
- When an IP address is displayed in the admin logs (batch request, cached for 7 days).

Service Provider:
IP-API.com
- Terms of Service: https://ip-api.com/legal

== Installation ==

1. Upload the jacker-login-guard folder to the /wp-content/plugins/ directory.
2. Activate the plugin through the Plugins menu in WordPress.
3. Go to Settings > Login Guard to configure your Secret Entry URL.
4. Important: Bookmark your new Secret Entry URL immediately.
5. (Optional) If you encounter a 404 on first use, go to Settings > Permalinks and click Save Changes.

== Frequently Asked Questions ==

= What happens if I forget my Secret Entry URL? =

If you have access to your hosting file manager or FTP, you can rename the plugin folder to temporarily disable it and log in via the standard wp-login.php.

= Does this plugin support Passkeys and 2FA? =

Yes. The signed cookie mechanism is compatible with WordPress 6.3+ Passkeys and popular 2FA plugins. Authentication extensions that submit binary or structured data are handled correctly.

= Will this slow down my website? =

No. The plugin uses lightweight PHP hooks and object caching.

= Does this plugin support multisite? =

Yes. Settings are managed per-site, not network-wide.

= How does the Attack Detection work? =

The plugin detects suspicious User-Agent strings, empty or short User-Agent, encoded and plain malicious content (SQL injection, XSS, command injection) in the URI and POST body, invalid request methods, and high-frequency requests.

To preserve compatibility with passkey, WebAuthn, and 2FA extensions, payload inspection is skipped for wp-login.php, wp-cron.php, and admin-ajax.php.

= How does the Failed Login Auto-Block work? =

After a configurable number of failed login attempts from the same IP within 24 hours, the IP is auto-blocked. This applies even when a valid access token is present. Set the threshold to 0 to disable.

= How does auto-unblock work? =

Auto-blocks expire after the configured duration. Once expired, the IP is automatically unbanned.

= How does escalation work? =

Every auto-block cycle is counted. When the count reaches the configured threshold, the IP is added to the permanent blacklist.

= What is the Trusted IP Window? =

After a successful login, the same IP is protected from auto-blocking for a configurable number of days.

= What is the API Whitelist for? =

By default, all REST API endpoints are blocked. If you use plugins like Jetpack, WooCommerce, or custom APIs, add their endpoint paths to the whitelist.

Example:
/wp-json/jetpack/v4/
/wp-json/woocommerce/v1/
/wp-json/custom/v1/

= What is the Access Log? =

The Access Log records requests to sensitive resources, including login page attempts, wp-admin access attempts, REST API calls, XML-RPC requests, and configuration file access attempts.

= Which IP formats are supported? =

* Single IPv4: 192.168.1.100
* Single IPv6: 2001:db8::1
* IPv4 CIDR: 192.168.1.0/24
* IPv6 CIDR: 2001:db8::/32
* IPv4 range: 192.168.1.10-192.168.1.50
* IPv6 range: 2001:db8::1-2001:db8::ffff
* Inline comment: 192.168.1.100 # My Office

== Screenshots ==

1. The Dashboard showing real-time statistics.
2. The Settings page.
3. The Login Events log.
4. The Access Log.
5. The Auto Block List.

== Changelog ==

= 1.0.0 =
* Initial public release.
* Hidden login URL with HMAC-SHA256 signed access cookies.
* Protection against direct wp-login.php and wp-admin access.
* IP Whitelist and Blacklist with IPv4/IPv6, CIDR, and A-B range support.
* Cloudflare-aware IP detection with 5-minute failure fallback cache.
* Blocks XML-RPC and REST API user enumeration.
* Three logging systems: Login Events, Access Log, Auto Block List.
* Automatic attack detection (encoded and plain) in URI and POST body.
* Payload inspection skipped for wp-login.php, wp-cron.php, and admin-ajax.php to preserve passkey / WebAuthn / 2FA compatibility.
* Configurable failed-login auto-block threshold (default 5 within 24 hours).
* Configurable auto-block trigger threshold (rolling 24-hour window).
* Configurable auto-block duration with automatic unblock.
* Configurable escalation to permanent blacklist.
* Trusted IP window after successful login.
* Admin operation audit with 15-minute deduplication.
* Bulk actions (Whitelist, Blacklist, Remove) on all logs.
* Access Log records referer information and supports status filter.
* IP country detection with flag emojis.
* Dashboard with real-time statistics.
* Log retention limit setting.
* Security headers.
* Import/Export settings.

== Upgrade Notice ==

= 1.0.0 =
Initial release.