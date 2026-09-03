# Hide Login Secure

[![WordPress Plugin](https://img.shields.io/badge/WordPress-Plugin-blue)](https://wordpress.org/plugins/hide-login-secure/)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-orange.svg)](https://www.gnu.org/licenses/gpl-2.0.html)
[![PHP Version](https://img.shields.io/badge/PHP-7.4%2B-purple)](https://php.net/)

> 🛡️ **Built after hackers installed a backdoor on my WordPress site.** Now it's finally quiet.

---

## 📖 The Origin Story

My journey with WordPress security started out of pure frustration. My site was repeatedly targeted:
1. Hackers kept resetting my admin and user passwords.
2. They escalated to mass-creating fake admin accounts.
3. Finally, they crossed the line by installing a malicious backdoor plugin to steal my data.

I was stuck in an endless loop of cleaning up the mess. Existing security plugins were either too bloated, destroyed my site's performance, or broke modern features like Passkeys. 

So, I analyzed the attack vectors myself and built **Hide Login Secure** from scratch. Now that my site is secure, I’m open-sourcing it to help other WordPress site owners fight back against these attacks without the bloat.

---

## 🛡️ Why Choose This Plugin?

Most security plugins are heavy, slow down your site, and break modern authentication features. **Hide Login Secure** is built differently:

- **True Security:** It doesn't just change the URL; it enforces a short-lived, HMAC-SHA256 signed cookie. Even if a bot guesses your secret URL, it cannot access the login page without a valid token.
- **Zero Bloat:** No heavy JavaScript, no external API calls on the frontend. Pure, optimized PHP that respects your Core Web Vitals.
- **Cloudflare Aware:** Securely detects real visitor IPs behind Cloudflare proxies without spoofing vulnerabilities.

## ✨ Features

### Core Protection (Free)
- **Hidden Entry URL:** Completely removes `wp-login.php` and `wp-admin` from public view.
- **Signed Access Tokens:** Generates a 5-minute, cryptographically signed cookie to access the login page.
- **Smart Blocking:** Returns 404 or 403 to unauthorized scanners, effectively hiding your site's existence and acting as a honeypot to waste their resources.
- **IP Controls:** Manual Whitelist and Blacklist with full IPv4/IPv6 and CIDR support.
- **Passkey & 2FA Friendly:** Fully compatible with WordPress 6.3+ Passkeys and popular 2FA plugins.
- **Anti-Enumeration:** Blocks XML-RPC, REST API user enumeration, and author scanning.
- **Login Events Log:** Keeps a lightweight log of the last 300 successful logins.

### 🚀 Pro Version (Coming Soon)
*Based on community feedback, the following features are in development:*
- **Smart Auto-Ban:** Automatically block IPs after X failed login attempts.
- **Forced 2FA/Passkey:** Disable password login for Administrators entirely.
- **Country Blocking:** Block login attempts from specific countries using GeoIP.
- **Real-time Alerts:** Email notifications for suspicious login attempts.
- **Emergency Recovery:** Master recovery system for locked-out administrators.

---

## 📥 Installation

1. Upload the `hide-login-secure` folder to the `/wp-content/plugins/` directory.
2. Activate the plugin through the 'Plugins' menu in WordPress.
3. Go to **Settings > Hide Login** to configure your Secret Entry URL.
4. **Important:** Bookmark your new Secret Entry URL immediately! You will need it to log in.
5. *(Optional)* If you encounter a 404 on first use, go to **Settings > Permalinks** and click "Save Changes" to refresh rewrite rules.

---

## ❓ Frequently Asked Questions

**What happens if I forget my Secret Entry URL?**
If you have access to your hosting file manager or FTP, you can rename the plugin folder (e.g., to `hide-login-secure-disabled`) to temporarily disable it and log in via the standard `wp-login.php`. Once logged in, reactivate the plugin and check the settings.

**Does this plugin support Passkeys and 2FA?**
Yes! Our signed cookie mechanism is designed to be fully compatible with WordPress 6.3+ Passkeys and popular 2FA plugins. It does not interfere with the authentication flow.

**Will this slow down my website?**
No. The plugin uses extremely lightweight PHP hooks and object caching. It does not load any heavy scripts or stylesheets on your frontend pages.

---

## ☕ Support Development

This plugin is built, maintained, and supported by an independent developer. There are no premium upsells, no tracking, and no bloat in the free version.

If this plugin has saved your website from attacks or saved you hours of debugging, consider supporting the development:

- **Solana (SOL) Mainnet:**  
  `EHHPsci6pKbfL71t73KNCXrtanM1TWPrWYJZ1ik1b5FH`

- **Contact:** [support@jackerteo.com](mailto:support@jackerteo.com)
- **Website:** [jackerteo.com/plugin](https://jackerteo.com/plugin)

---

## 📄 License

This plugin is licensed under the **GNU General Public License v2.0 (GPLv2)**.  
See the [LICENSE](LICENSE) file for more details.

---

**Built with ❤️ by [Jacker Architect](https://github.com/JackerArchitect)**
