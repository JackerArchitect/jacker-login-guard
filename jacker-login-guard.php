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
 * Domain Path:       /languages
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

define( 'JACKLOGU_VERSION', '1.0.0' );
define( 'JACKLOGU_FILE', __FILE__ );
define( 'JACKLOGU_DIR', plugin_dir_path( __FILE__ ) );
define( 'JACKLOGU_URL', plugin_dir_url( __FILE__ ) );
define( 'JACKLOGU_BASENAME', plugin_basename( __FILE__ ) );

define( 'JACKLOGU_OPTION_KEY', 'jacklogu_settings' );
define( 'JACKLOGU_OLD_OPTION_KEY', 'jlg_settings' );
define( 'JACKLOGU_DEFAULT_SLUG', 'my-login' );
define( 'JACKLOGU_AUTH_COOKIE', 'jacklogu_gate' );

define( 'JACKLOGU_LOGIN_TABLE', 'jacklogu_login_events' );
define( 'JACKLOGU_ACCESS_TABLE', 'jacklogu_access_events' );
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
 * @since 1.0.0
 * @return void
 */
function jacklogu_deactivate() {
	flush_rewrite_rules();

	// Clear plugin-owned transients.
	delete_transient( 'jacklogu_cloudflare_ips' );

	global $wpdb;
	// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
	$wpdb->query(
		$wpdb->prepare(
			"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s",
			$wpdb->esc_like( '_transient_jacklogu_' ) . '%',
			$wpdb->esc_like( '_transient_timeout_jacklogu_' ) . '%'
		)
	);
	// phpcs:enable

	if ( function_exists( 'wp_cache_flush_group' ) ) {
		wp_cache_flush_group( 'jackerloginguard' );
	}
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
 * @since 1.0.0
 * @return void
 */
function jacklogu_bootstrap() {
	// Load translations.
	load_plugin_textdomain( 'jacker-login-guard', false, dirname( JACKLOGU_BASENAME ) . '/languages' );

	// Run the DB schema upgrade check on every load.
	Tables::maybe_upgrade();

	Plugin::get_instance();
}
add_action( 'plugins_loaded', __NAMESPACE__ . '\\jacklogu_bootstrap' );