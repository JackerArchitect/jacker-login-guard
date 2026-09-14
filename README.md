
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
