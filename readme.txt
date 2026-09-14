=== Jacker Login Guard ===
Contributors: jackerteo
Tags: security, login protection, hide login, anti-brute-force, wp-admin protection
Requires at least: 6.1
Tested up to: 7.1
Stable tag: 1.0.0
Requires PHP: 7.4
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Protect your WordPress login with hidden URL, signed access tokens, IP controls, and comprehensive security hardening.

== Description ==

Jacker Login Guard provides comprehensive login security by hiding your WordPress login page, protecting it with short-lived signed cookies, and blocking unauthorized access attempts.

Core Features:

* Hidden Entry URL: Completely hide wp-login.php and wp-admin from public view.
* One-Time Signed Access: HMAC-SHA256 signed cookie for login page access.
* Smart Interception: Blocks sensitive paths, XML-RPC, and REST API user enumeration.
* IP Controls: Whitelist and Blacklist with IPv4/IPv6 and CIDR support.
* API Whitelist: Allow specific REST API endpoints to bypass restrictions.
* Path Whitelist: Allow specific paths to bypass login protection.
* Attack Detection: Automatically detects malicious requests, scanners, and encoded attacks.
* Auto-blocking: Suspicious IPs are automatically blocked after a configurable number of attacks.
* Auto-Unblock: Auto-blocks expire after a configurable duration.
* Escalation: Repeatedly blocked IPs are escalated to the permanent blacklist.
* Trusted IP Window: Recently authenticated IPs are protected from accidental blocking.
* Cloudflare Aware: Detects real visitor IPs behind Cloudflare.
* Compatibility Mode: Supports WordPress password reset and registration flows.
* Three Logging Systems:
  - Login Events: Tracks admin login attempts with IP and timestamp.
  - Access Log: Records requests to sensitive resources (login, wp-admin, REST API, XML-RPC, config files) with referer and status.
  - Auto Block List: Shows automatically blocked IPs with reason, block time, and expiry.
* IP Country Detection: Displays country flags for each IP address in logs.
* Bulk Actions: Whitelist, Blacklist, or Remove multiple entries at once.
* Security Headers: Adds X-Content-Type-Options, X-Frame-Options, and more.
* Import/Export Settings: Backup and restore plugin configuration.
* Dashboard: Real-time stats showing online users, admin online, last login, and blocked counts.
* Zero Bloat: No heavy scripts or stylesheets on frontend pages.

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

The plugin uses IP-API.com (http://ip-api.com) to detect the country of IP addresses for display in the logs.

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
4. Important: Bookmark your new Secret Entry URL immediately!
5. (Optional) If you encounter a 404 on first use, go to Settings > Permalinks and click Save Changes.

== Frequently Asked Questions ==

= What happens if I forget my Secret Entry URL? =

If you have access to your hosting file manager or FTP, rename the plugin folder (e.g., to jacker-login-guard-disabled) to temporarily disable it and log in via wp-login.php. Once logged in, reactivate the plugin and check the settings.

= Does this plugin support Passkeys and 2FA? =

Yes. The signed cookie mechanism is fully compatible with WordPress 6.3+ Passkeys and popular 2FA plugins.

= Will this slow down my website? =

No. The plugin uses lightweight PHP hooks and object caching. No heavy scripts or stylesheets are loaded on frontend pages.

= Does this plugin support multisite? =

Yes. However, settings are managed per-site, not network-wide.

= How does the Attack Detection work? =

The plugin automatically detects:
- Suspicious User-Agent strings
- Empty or short User-Agent
- Encoded malicious content (SQL injection, XSS, command injection)
- Invalid request methods
- High-frequency requests (120+ per minute)

Detected attacks are counted. After the configured number of attempts, the IP is auto-blocked.

= How does auto-unblock work? =

Auto-blocks expire after the configured duration. Once expired, the IP is automatically unbanned.

= How does escalation work? =

Every auto-block cycle is counted. When the count reaches the configured threshold, the IP is added to the permanent blacklist, which never expires unless manually removed.

= What is the Trusted IP Window? =

After a successful login, the same IP is protected from auto-blocking for a configurable number of days. This prevents the admin from accidentally blocking themselves when their session expires.

= What is the API Whitelist for? =

By default, all REST API endpoints are blocked. If you use plugins like Jetpack, WooCommerce, or custom APIs, you can add their endpoint paths to the whitelist.

Example:
/wp-json/jetpack/v4/
/wp-json/woocommerce/v1/
/wp-json/custom/v1/

= What is the Access Log? =

The Access Log records requests to sensitive resources, including:
- Login page attempts (allowed and blocked)
- wp-admin access attempts
- REST API calls (whitelisted endpoints)
- XML-RPC requests
- Configuration file access attempts

Each entry shows the target path, the referer (where the request came from), and whether it was allowed or blocked.

Normal page views (homepage, posts, categories) are NOT logged.

== Screenshots ==

1. The Dashboard showing real-time statistics.
2. The Settings page with all configuration options.
3. The Login Events log.
4. The Access Log with referer information and status filter.
5. The Auto Block List with block reason, block time, and expiry.

== Changelog ==

= 1.0.0 =
* Initial public release.
* Hidden login URL with HMAC-SHA256 signed access cookies.
* Protection against direct wp-login.php and wp-admin access.
* IP Whitelist and Blacklist with IPv4/IPv6 and CIDR support.
* Cloudflare-aware IP detection.
* Blocks XML-RPC and REST API user enumeration.
* Three logging systems: Login Events, Access Log, Auto Block List.
* Automatic attack detection and blocking.
* Configurable auto-block trigger threshold.
* Configurable auto-block duration with automatic unblock.
* Configurable escalation to permanent blacklist.
* Trusted IP window after successful login.
* Bulk actions (Whitelist, Blacklist, Remove) on all logs.
* Access Log records referer information and supports status filter.
* IP country detection with flag emojis.
* Dashboard with real-time statistics.
* Log retention limit setting.
* Security headers.
* Import/Export settings.

== Upgrade Notice ==

= 1.0.0 =
Initial release. Protect your WordPress login with hidden URL, signed access tokens, and IP controls.