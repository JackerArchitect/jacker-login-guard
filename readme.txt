=== Hide Login Secure ===
Contributors: jackerteo
Tags: hide login, wp-login, security, brute force, passkey, 2fa, hide admin, login protection, xmlrpc
Requires at least: 5.8
Tested up to: 7.1
Stable tag: 1.0.0
Requires PHP: 7.4
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Hide and protect your WordPress login page with a custom URL, short-lived signed access tokens, and smart IP controls. Reduces brute-force exposure without slowing down your site.

== Description ==

Most "hide login" plugins only change the URL. **Hide Login Secure** goes further. It hides your login page, protects it with short-lived signed cookies, and blocks unauthorized access attempts intelligently. 

It is designed to be **extremely lightweight**, ensuring your website speed is never compromised by heavy security scripts.

**Core Features (Free):**
* **Hidden Entry URL:** Completely hide `wp-login.php` and `wp-admin` from public view and HTML source code.
* **One-Time Signed Access:** Generates a short-lived, HMAC-SHA256 signed cookie to access the login page. Prevents direct access and automated scanners.
* **Smart Interception:** Blocks sensitive paths (`/login`, `/admin`), XML-RPC, and REST API user enumeration.
* **IP Controls:** Manual Whitelist and Blacklist with full IPv4/IPv6 and CIDR support.
* **Cloudflare Aware:** Securely detects real visitor IPs behind Cloudflare without spoofing risks.
* **Compatibility Mode:** Allows standard WordPress password reset and registration flows to work seamlessly.
* **Zero Bloat:** No heavy JavaScript, no external API calls on the frontend. Just pure, fast PHP security.

**Why choose this over other plugins?**
1. **Passkey & 2FA Friendly:** Unlike older plugins that break modern authentication, our signed cookie mechanism ensures Passkeys and 2FA plugins work perfectly.
2. **No Redirect Loops:** Uses a robust direct-render and cookie verification system to prevent the infamous "ERR_TOO_MANY_REDIRECTS" errors.
3. **True Security:** We don't just hide the door; we verify who is knocking.

== Installation ==

1. Upload the `hide-login-secure` folder to the `/wp-content/plugins/` directory.
2. Activate the plugin through the 'Plugins' menu in WordPress.
3. Go to **Settings > Hide Login** to configure your Secret Entry URL.
4. **Important:** Bookmark your new Secret Entry URL immediately! You will need it to log in.
5. (Optional) If you encounter a 404 on first use, go to **Settings > Permalinks** and click "Save Changes" to refresh rewrite rules.

== Frequently Asked Questions ==

= What happens if I forget my Secret Entry URL? =
If you have access to your hosting file manager or FTP, you can rename the plugin folder (e.g., to `hide-login-secure-disabled`) to temporarily disable it and log in via the standard `wp-login.php`. Once logged in, reactivate the plugin and check the settings.

= Does this plugin support Passkeys and 2FA? =
Yes! Our signed cookie mechanism is designed to be fully compatible with WordPress 6.3+ Passkeys and popular 2FA plugins. It does not interfere with the authentication flow.

= Will this slow down my website? =
No. The plugin uses extremely lightweight PHP hooks and object caching. It does not load any heavy scripts or stylesheets on your frontend pages.

= How does the "Return 403 Forbidden" option work? =
When enabled, unauthorized requests (like bots scanning for `wp-login.php`) are immediately rejected with a 403 Forbidden error. This acts as a honeypot, wasting the scanner's resources and reducing server load.

== Screenshots ==

1. The Settings page showing the Secret Entry URL and protection modes.
2. The Login Events log showing blocked and successful attempts.

== Changelog ==

= 1.0.0 =
* Initial public release.
* Hidden login URL with HMAC-SHA256 signed access cookies.
* Protection against direct `wp-login.php` and `wp-admin` access.
* IP Whitelist/Blacklist with IPv6 and CIDR support.
* Cloudflare-aware IP detection.
* Blocks XML-RPC and REST API user enumeration.
* Lightweight Login Events logging (auto-cleans to 300 entries).
* Compatibility and Strict login protection modes.

== Support & Development ==

This plugin is built, maintained, and supported by an independent developer. 

* **Official Website:** [https://jackerteo.com/plugin](https://jackerteo.com/plugin)
* **Source Code (GitHub):** [https://github.com/JackerArchitect/hide-login-secure](https://github.com/JackerArchitect/hide-login-secure)
* **Support Email:** [support@jackerteo.com](mailto:support@jackerteo.com)

If you find this plugin helpful, please consider [leaving a review](https://wordpress.org/support/plugin/hide-login-secure/reviews/) or supporting future development!
