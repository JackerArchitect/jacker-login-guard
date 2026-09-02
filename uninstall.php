<?php
/**
 * Uninstall script for Hide Login – Secure Admin & Login Protection.
 * 
 * This file runs when the plugin is deleted via the WordPress admin.
 * It cleans up all database tables, options, and transients created by the plugin.
 *
 * @package HideLoginSecure
 */

// Exit if not called by WordPress uninstall process
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
    exit;
}

global $wpdb;

// 1. Drop the custom database table
$table_name = $wpdb->prefix . 'hls_login_events';
$wpdb->query( "DROP TABLE IF EXISTS $table_name" );

// 2. Delete plugin options
delete_option( 'hls_settings' );

// 3. Delete transients (cached data)
delete_transient( 'hls_cloudflare_ips' );

// 4. Flush rewrite rules to ensure no leftover routing conflicts
flush_rewrite_rules();