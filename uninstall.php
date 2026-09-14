<?php
/**
 * Uninstall handler.
 *
 * Runs when the plugin is deleted via the WordPress admin. Data is only
 * removed if the site owner explicitly opted in from the settings page.
 *
 * @package   JackerLoginGuard
 * @author    Jacker Architect
 * @copyright 2026 Jacker Architect
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

// Exit if uninstall is not called by WordPress.
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

// Respect the site owner's data retention choice.
$jacklogu_settings = get_option( 'jacklogu_settings', array() );

if ( empty( $jacklogu_settings['uninstall_remove_data'] ) ) {
	return;
}

global $wpdb;

/*
|--------------------------------------------------------------------------
| 1. Delete plugin options.
|--------------------------------------------------------------------------
*/
delete_option( 'jacklogu_settings' );
delete_option( 'jlg_settings' );
delete_option( 'jacklogu_db_version' );

/*
|--------------------------------------------------------------------------
| 2. Delete plugin transients (current + timeout rows).
|--------------------------------------------------------------------------
*/
// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
$wpdb->query(
	$wpdb->prepare(
		"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s",
		$wpdb->esc_like( '_transient_jacklogu_' ) . '%',
		$wpdb->esc_like( '_transient_timeout_jacklogu_' ) . '%'
	)
);
$wpdb->query(
	$wpdb->prepare(
		"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s",
		$wpdb->esc_like( '_transient_jlg_' ) . '%',
		$wpdb->esc_like( '_transient_timeout_jlg_' ) . '%'
	)
);
// phpcs:enable

/*
|--------------------------------------------------------------------------
| 3. Delete plugin user meta.
|--------------------------------------------------------------------------
*/
// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
$wpdb->query(
	$wpdb->prepare(
		"DELETE FROM {$wpdb->usermeta} WHERE meta_key IN (%s, %s)",
		'jacklogu_last_activity',
		'jacklogu_activity_lock'
	)
);
// phpcs:enable

/*
|--------------------------------------------------------------------------
| 4. Drop plugin tables.
|--------------------------------------------------------------------------
*/
$jacklogu_tables = array(
	$wpdb->prefix . 'jacklogu_login_events',
	$wpdb->prefix . 'jacklogu_access_events',
	$wpdb->prefix . 'jacklogu_auto_blocks',
);

foreach ( $jacklogu_tables as $jacklogu_table ) {
	// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
	$wpdb->query( "DROP TABLE IF EXISTS {$jacklogu_table}" );
	// phpcs:enable
}

/*
|--------------------------------------------------------------------------
| 5. Clear plugin object-cache entries.
|--------------------------------------------------------------------------
*/
wp_cache_delete( 'jacklogu_cloudflare_ips' );

if ( function_exists( 'wp_cache_flush_group' ) ) {
	wp_cache_flush_group( 'jackerloginguard' );
} else {
	$jacklogu_slugs = array( 'my-login', 'login', 'admin' );

	foreach ( $jacklogu_slugs as $jacklogu_slug ) {
		wp_cache_delete( 'jacklogu_page_check_' . md5( $jacklogu_slug ), 'jackerloginguard' );
	}
}