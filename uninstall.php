<?php
/**
 * Uninstall script for Hide Login Secure
 * 
 * This file is automatically executed by WordPress when the user deletes 
 * the plugin from the Plugins screen.
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
$hls_settings = get_option( 'hls_settings', [] );

if ( empty( $hls_settings['uninstall_remove_data'] ) ) {
	return;
}

delete_option( 'hls_settings' );
delete_transient( 'hls_cloudflare_ips' );

global $wpdb;
// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
$hls_table_name = $wpdb->prefix . 'hls_login_events';

// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
$wpdb->query( "DROP TABLE IF EXISTS {$hls_table_name}" );
