# Jacker Login Guard

[![GitHub](https://img.shields.io/badge/GitHub-Repository-blue)](https://github.com/JackerArchitect/jacker-login-guard)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-orange.svg)](https://www.gnu.org/licenses/gpl-2.0.html)
[![PHP Version](https://img.shields.io/badge/PHP-7.4%2B-purple)](https://php.net/)
[![WordPress](https://img.shields.io/badge/WordPress-6.1%2B-blue)](https://wordpress.org/)

> 🛡️ **Built after hackers installed a backdoor on my WordPress site. Now it's finally quiet.**

---

## 📖 The Origin Story

My journey with WordPress security started out of pure frustration. My site was repeatedly targeted:

1. Hackers kept resetting my admin and user passwords.
2. They escalated to mass-creating fake admin accounts.
3. Finally, they crossed the line by installing a malicious backdoor plugin to steal my data.

I was stuck in an endless loop of cleaning up the mess. Existing security plugins were either too bloated, destroyed my site's performance, or broke modern features like Passkeys.

So, I analyzed the attack vectors myself and built **Jacker Login Guard** from scratch. Now that my site is secure, I'm open-sourcing it to help other WordPress site owners fight back against these attacks without the bloat.

---

## 🛡️ Why Choose This Plugin?

Most security plugins are heavy, slow down your site, and break modern authentication features. **Jacker Login Guard** is built differently:

- **True Security:** It doesn't just change the URL; it enforces a short-lived, HMAC-SHA256 signed cookie. Even if a bot guesses your secret URL, it cannot access the login page without a valid token.
- **Zero Bloat:** No heavy JavaScript, no external API calls on the frontend. Pure, optimized PHP that respects your Core Web Vitals.
- **Cloudflare Aware:** Securely detects real visitor IPs behind Cloudflare proxies without spoofing vulnerabilities.

---

## ✨ Features

### Core Protection (Free)

- **Hidden Entry URL:** Completely removes `wp-login.php` and `wp-admin` from public view.
- **Signed Access Tokens:** Generates a 5-minute, cryptographically signed cookie to access the login page.
- **Smart Blocking:** Returns 404 or 403 to unauthorized scanners, effectively hiding your site's existence and acting as a honeypot to waste their resources.
- **IP Controls:** Manual Whitelist and Blacklist with full **IPv4 / IPv6 / CIDR / IP Range (A-B)** support.
- **Passkey & 2FA Friendly:** Fully compatible with WordPress 6.3+ Passkeys and popular 2FA plugins.
- **Anti-Enumeration:** Blocks XML-RPC, REST API user enumeration, and author scanning.
- **Attack Detection:** Automatically detects malicious requests, scanners, and encoded attacks (SQLi / XSS / CMD).
- **Auto-Block:** Suspicious IPs are automatically blocked after a configurable number of attacks.
- **Auto-Unblock:** Auto-blocks expire after a configurable duration.
- **Escalation:** Repeatedly blocked IPs are escalated to the permanent blacklist.
- **Trusted IP Window:** Recently authenticated IPs are protected from accidental blocking.
- **Admin Operation Audit:** Logs state-changing admin actions (edit, save, delete, import, export, etc.) with 15-minute deduplication.
- **Three Logging Systems:**
  - **Login Events:** Tracks admin login attempts with IP and timestamp.
  - **Access Log:** Records requests to sensitive resources (login, wp-admin, REST API, XML-RPC, config files) with referer and status.
  - **Auto Block List:** Shows automatically blocked IPs with reason, block time, and expiry.
- **IP Country Detection:** Displays country flags for each IP address in logs.
- **Bulk Actions:** Whitelist, Blacklist, or Remove multiple entries at once.
- **Security Headers:** Adds `X-Content-Type-Options`, `X-Frame-Options`, and more.
- **Import / Export Settings:** Backup and restore plugin configuration.
- **Dashboard:** Real-time stats showing online users, admin online, last login, and blocked counts.

### 🚀 Pro Version (Coming Soon)

*Based on community feedback, the following features are in development:*

- **Smart Auto-Ban:** Automatically block IPs after X failed login attempts.
- **Forced 2FA / Passkey:** Disable password login for Administrators entirely.
- **Country Blocking:** Block login attempts from specific countries using GeoIP.
- **Real-time Alerts:** Email notifications for suspicious login attempts.
- **Emergency Recovery:** Master recovery system for locked-out administrators.

---

## 📥 Installation

1. Upload the `jacker-login-guard` folder to the `/wp-content/plugins/` directory.
2. Activate the plugin through the **Plugins** menu in WordPress.
3. Go to **Settings → Login Guard** to configure your **Secret Entry URL**.
4. **Important:** Bookmark your new Secret Entry URL immediately! You will need it to log in.
5. *(Optional)* If you encounter a 404 on first use, go to **Settings → Permalinks** and click **Save Changes** to refresh rewrite rules.

---

## ❓ Frequently Asked Questions

### What happens if I forget my Secret Entry URL?

If you have access to your hosting file manager or FTP, you can rename the plugin folder (e.g., to `jacker-login-guard-disabled`) to temporarily disable it and log in via the standard `wp-login.php`. Once logged in, reactivate the plugin and check the settings.

### Does this plugin support Passkeys and 2FA?

Yes! Our signed cookie mechanism is designed to be fully compatible with WordPress 6.3+ Passkeys and popular 2FA plugins. It does not interfere with the authentication flow.

### Will this slow down my website?

No. The plugin uses extremely lightweight PHP hooks and object caching. It does not load any heavy scripts or stylesheets on your frontend pages.

### Does this plugin support multisite?

Yes. However, settings are managed per-site, not network-wide.

### How does the Attack Detection work?

The plugin automatically detects:

- Suspicious User-Agent strings
- Empty or short User-Agent
- Encoded malicious content (SQL injection, XSS, command injection)
- Invalid request methods
- High-frequency requests (120+ per minute)

Detected attacks are counted. After the configured number of attempts, the IP is auto-blocked.

### How does auto-unblock work?

Auto-blocks expire after the configured duration. Once expired, the IP is automatically unbanned.

### How does escalation work?

Every auto-block cycle is counted. When the count reaches the configured threshold, the IP is added to the permanent blacklist, which never expires unless manually removed.

### What is the Trusted IP Window?

After a successful login, the same IP is protected from auto-blocking for a configurable number of days. This prevents the admin from accidentally blocking themselves when their session expires.

### What is the API Whitelist for?

By default, all REST API endpoints are blocked. If you use plugins like Jetpack, WooCommerce, or custom APIs, you can add their endpoint paths to the whitelist.

**Example:**

```text
/wp-json/jetpack/v4/
/wp-json/woocommerce/v1/
/wp-json/custom/v1/
```

### What is the Access Log?

The Access Log records requests to sensitive resources, including:

- Login page attempts (allowed and blocked)
- wp-admin access attempts
- REST API calls (whitelisted endpoints)
- XML-RPC requests
- Configuration file access attempts

Each entry shows the target path, the referer (where the request came from), and whether it was allowed or blocked.

**Normal page views (homepage, posts, categories) are NOT logged.**

### Which IP formats are supported?

Whitelist and Blacklist accept one entry per line:

| Format | Example |
|--------|---------|
| Single IPv4 | `192.168.1.100` |
| Single IPv6 | `2001:db8::1` |
| IPv4 CIDR | `192.168.1.0/24` |
| IPv6 CIDR | `2001:db8::/32` |
| IPv4 range | `192.168.1.10-192.168.1.50` |
| IPv6 range | `2001:db8::1-2001:db8::ffff` |
| With comment | `192.168.1.100 # My Office` |

---

## 🔒 External Services

This plugin connects to two external services. Both are optional and cached to minimize requests.

### 1. Cloudflare API

Fetches official Cloudflare IP ranges from `https://api.cloudflare.com/client/v4/ips` to correctly detect real visitor IPs behind Cloudflare CDN.

- **Data sent:** None (just a standard HTTPS GET request)
- **Cached:** 7 days
- [Terms of Service](https://www.cloudflare.com/terms/) · [Privacy Policy](https://www.cloudflare.com/privacypolicy/)

### 2. IP Geolocation API (IP-API.com)

Uses `http://ip-api.com` to detect the country of IP addresses shown in the admin logs.

- **Data sent:** The visitor IP address
- **Cached:** 7 days
- [Terms of Service](https://ip-api.com/legal)

---

## 🖼️ Screenshots

1. The Dashboard showing real-time statistics.
2. The Settings page with all configuration options.
3. The Login Events log.
4. The Access Log with referer information and status filter.
5. The Auto Block List with block reason, block time, and expiry.

---

## 📄 Changelog

### 1.0.0

- Initial public release.
- Hidden login URL with HMAC-SHA256 signed access cookies.
- Protection against direct `wp-login.php` and `wp-admin` access.
- IP Whitelist and Blacklist with IPv4 / IPv6 / CIDR / Range support.
- Cloudflare-aware IP detection.
- Blocks XML-RPC and REST API user enumeration.
- Three logging systems: Login Events, Access Log, Auto Block List.
- Automatic attack detection and blocking.
- Configurable auto-block trigger threshold.
- Configurable auto-block duration with automatic unblock.
- Configurable escalation to permanent blacklist.
- Trusted IP window after successful login.
- Admin operation audit with 15-minute deduplication.
- Bulk actions (Whitelist, Blacklist, Remove) on all logs.
- Access Log records referer information and supports status filter.
- IP country detection with flag emojis.
- Dashboard with real-time statistics.
- Log retention limit setting.
- Security headers.
- Import / Export settings.

---

## 🔗 Links

- **WordPress.org:** https://wordpress.org/plugins/jacker-login-guard/
- **Source Code (GitHub):** https://github.com/JackerArchitect/jacker-login-guard
- **Support Email:** support@jackerteo.com
- **Website:** https://jackerteo.com/plugin

---

## ☕ Support Development

This plugin is built, maintained, and supported by an independent developer. There are no premium upsells, no tracking, and no bloat in the free version.

If this plugin has saved your website from attacks or saved you hours of debugging, consider supporting the development:

- **Solana (SOL) Mainnet:**  
  `EHHPsci6pKbfL71t73KNCXrtanM1TWPrWYJZ1ik1b5FH`

---

## 📄 License

This plugin is licensed under the **GNU General Public License v2.0 (GPLv2)**.  
See the [LICENSE](LICENSE) file for more details.

---

**Built with ❤️ by [Jacker Architect](https://github.com/JackerArchitect)**
