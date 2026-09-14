<?php
/**
 * Plugin Name:       Jacker Login Guard
 * Plugin URI:        https://jackerteo.com/plugin
 * Description:       Protect your WordPress login with hidden URL, signed access tokens, IP controls, and comprehensive security hardening.
 * Version:           1.0.0
 * Requires at least: 6.1
 * Requires PHP:      7.4
 * Author:            Jacker Architect
 * Author URI:        https://github.com/JackerArchitect
 * License:           GPL v2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       jacker-login-guard
 *
 * @package   JackerLoginGuard
 * @author    Jacker Architect
 * @copyright 2026 Jacker Architect
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

namespace JackerArchitect\JackerLoginGuard;

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/*
|--------------------------------------------------------------------------
| Plugin constants.
|--------------------------------------------------------------------------
*/

/**
 * Plugin version.
 *
 * @since 1.0.0
 * @var   string
 */
define( 'JACKLOGU_VERSION', '1.0.0' );

/**
 * Absolute path to the main plugin file.
 *
 * @since 1.0.0
 * @var   string
 */
define( 'JACKLOGU_FILE', __FILE__ );

/**
 * Absolute path to the plugin directory (with trailing slash).
 *
 * @since 1.0.0
 * @var   string
 */
define( 'JACKLOGU_DIR', plugin_dir_path( __FILE__ ) );

/**
 * Public URL to the plugin directory (with trailing slash).
 *
 * @since 1.0.0
 * @var   string
 */
define( 'JACKLOGU_URL', plugin_dir_url( __FILE__ ) );

/**
 * Option key that stores all plugin settings.
 *
 * @since 1.0.0
 * @var   string
 */
define( 'JACKLOGU_OPTION_KEY', 'jacklogu_settings' );

/**
 * Legacy option key (pre-1.0.0 development builds).
 *
 * @since 1.0.0
 * @var   string
 */
define( 'JACKLOGU_OLD_OPTION_KEY', 'jlg_settings' );

/**
 * Default login gate slug.
 *
 * @since 1.0.0
 * @var   string
 */
define( 'JACKLOGU_DEFAULT_SLUG', 'my-login' );

/**
 * Name of the temporary auth cookie issued at the hidden login gate.
 *
 * @since 1.0.0
 * @var   string
 */
define( 'JACKLOGU_AUTH_COOKIE', 'jacklogu_gate' );

/**
 * Login events table suffix.
 *
 * @since 1.0.0
 * @var   string
 */
define( 'JACKLOGU_LOGIN_TABLE', 'jacklogu_login_events' );

/**
 * Access log table suffix.
 *
 * @since 1.0.0
 * @var   string
 */
define( 'JACKLOGU_ACCESS_TABLE', 'jacklogu_access_events' );

/**
 * Auto-block table suffix.
 *
 * @since 1.0.0
 * @var   string
 */
define( 'JACKLOGU_AUTO_BLOCK_TABLE', 'jacklogu_auto_blocks' );

/*
|--------------------------------------------------------------------------
| Load plugin classes.
|--------------------------------------------------------------------------
*/

require_once JACKLOGU_DIR . 'includes/class-tables.php';
require_once JACKLOGU_DIR . 'includes/class-ip-utils.php';
require_once JACKLOGU_DIR . 'includes/class-settings.php';
require_once JACKLOGU_DIR . 'includes/class-logger.php';
require_once JACKLOGU_DIR . 'includes/class-detector.php';
require_once JACKLOGU_DIR . 'includes/class-session-tracker.php';
require_once JACKLOGU_DIR . 'includes/class-access-control.php';
require_once JACKLOGU_DIR . 'includes/class-admin.php';
require_once JACKLOGU_DIR . 'includes/class-plugin.php';

/*
|--------------------------------------------------------------------------
| Activation / deactivation hooks.
|--------------------------------------------------------------------------
*/

/**
 * Plugin activation handler.
 *
 * Creates the plugin's custom database tables, seeds default settings,
 * and flushes rewrite rules so the hidden login slug resolves properly.
 *
 * @since 1.0.0
 * @return void
 */
function jacklogu_activate() {
	Tables::create();
	Settings::get_instance()->set_defaults();
	flush_rewrite_rules();
}
register_activation_hook( __FILE__, __NAMESPACE__ . '\\jacklogu_activate' );

/**
 * Plugin deactivation handler.
 *
 * Flushes rewrite rules and clears any plugin-owned transients so the site
 * falls back to WordPress defaults while the plugin is inactive.
 *
 * @since 1.0.0
 * @return void
 */
function jacklogu_deactivate() {
	flush_rewrite_rules();
	delete_transient( 'jacklogu_cloudflare_ips' );
}
register_deactivation_hook( __FILE__, __NAMESPACE__ . '\\jacklogu_deactivate' );

/*
|--------------------------------------------------------------------------
| Bootstrap.
|--------------------------------------------------------------------------
*/

/**
 * Bootstrap the plugin.
 *
 * Runs on `plugins_loaded` so that classes can register their `init` hooks
 * (priority 1 and 20) before WordPress fires the `init` action.
 *
 * @since 1.0.0
 * @return void
 */
function jacklogu_bootstrap() {
	// Run the DB schema upgrade check on every load (cheap option read).
	Tables::maybe_upgrade();

	Plugin::get_instance();
}
add_action( 'plugins_loaded', __NAMESPACE__ . '\\jacklogu_bootstrap' );