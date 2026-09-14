<?php
/**
 * Database schema management.
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

/**
 * Class Tables
 *
 * @since 1.0.0
 */
class Tables {

	/**
	 * Current database schema version.
	 *
	 * @since 1.0.0
	 * @var   string
	 */
	const DB_VERSION = '1.0.0';

	/**
	 * Option key storing the installed database schema version.
	 *
	 * @since 1.0.0
	 * @var   string
	 */
	const DB_VERSION_OPTION = 'jacklogu_db_version';

	/**
	 * Create or upgrade all plugin tables.
	 *
	 * @since 1.0.0
	 * @return void
	 */
	public static function create() {
		global $wpdb;

		self::migrate_old_tables();

		$charset_collate = $wpdb->get_charset_collate();

		$sql_login = "CREATE TABLE {$wpdb->prefix}" . JACKLOGU_LOGIN_TABLE . " (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			username varchar(255) NOT NULL,
			login_time datetime NOT NULL,
			user_ip varchar(45) NOT NULL,
			status varchar(20) NOT NULL DEFAULT 'success',
			PRIMARY KEY  (id),
			KEY idx_time (login_time),
			KEY idx_ip (user_ip),
			KEY idx_status (status),
			KEY idx_ip_status_time (user_ip, status, login_time)
		) {$charset_collate};";

		$sql_access = "CREATE TABLE {$wpdb->prefix}" . JACKLOGU_ACCESS_TABLE . " (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			event_time datetime NOT NULL,
			user_ip varchar(45) NOT NULL,
			user_agent text,
			request_method varchar(10) NOT NULL,
			request_url text NOT NULL,
			request_path varchar(255) NOT NULL,
			referer varchar(255) NOT NULL DEFAULT '',
			reason varchar(255) NOT NULL DEFAULT '',
			status varchar(20) NOT NULL DEFAULT 'allowed',
			PRIMARY KEY  (id),
			KEY idx_ip (user_ip),
			KEY idx_time (event_time),
			KEY idx_ip_time (user_ip, event_time),
			KEY idx_path (request_path(191)),
			KEY idx_status (status)
		) {$charset_collate};";

		$sql_auto_block = "CREATE TABLE {$wpdb->prefix}" . JACKLOGU_AUTO_BLOCK_TABLE . " (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			user_ip varchar(45) NOT NULL,
			reason varchar(255) NOT NULL,
			block_time datetime NOT NULL,
			expire_at datetime DEFAULT NULL,
			is_active tinyint(1) NOT NULL DEFAULT 1,
			PRIMARY KEY  (id),
			KEY idx_ip (user_ip),
			KEY idx_time (block_time),
			KEY idx_expire (expire_at),
			KEY idx_active (is_active),
			KEY idx_ip_active (user_ip, is_active)
		) {$charset_collate};";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql_login );
		dbDelta( $sql_access );
		dbDelta( $sql_auto_block );

		update_option( self::DB_VERSION_OPTION, self::DB_VERSION );
	}

	/**
	 * Run the schema upgrade routine when the stored version is older.
	 *
	 * @since 1.0.0
	 * @return void
	 */
	public static function maybe_upgrade() {
		$installed = get_option( self::DB_VERSION_OPTION, '0' );

		if ( version_compare( $installed, self::DB_VERSION, '<' ) ) {
			self::create();
		}
	}

	/**
	 * Rename legacy tables to the current names.
	 *
	 * @since 1.0.0
	 * @return void
	 */
	private static function migrate_old_tables() {
		global $wpdb;

		$migrations = array(
			$wpdb->prefix . 'jlg_login_events'  => $wpdb->prefix . JACKLOGU_LOGIN_TABLE,
			$wpdb->prefix . 'jlg_access_events' => $wpdb->prefix . JACKLOGU_ACCESS_TABLE,
			$wpdb->prefix . 'jlg_auto_blocks'   => $wpdb->prefix . JACKLOGU_AUTO_BLOCK_TABLE,
		);

		foreach ( $migrations as $old => $new ) {
			// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$old_exists = $wpdb->get_var(
				$wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $old ) )
			);
			$new_exists = $wpdb->get_var(
				$wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $new ) )
			);

			if ( $old_exists && ! $new_exists ) {
				$wpdb->query( "RENAME TABLE {$old} TO {$new}" );
			}
			// phpcs:enable
		}
	}

	/**
	 * Drop all plugin tables.
	 *
	 * @since 1.0.0
	 * @return void
	 */
	public static function drop() {
		global $wpdb;

		$tables = array(
			$wpdb->prefix . JACKLOGU_LOGIN_TABLE,
			$wpdb->prefix . JACKLOGU_ACCESS_TABLE,
			$wpdb->prefix . JACKLOGU_AUTO_BLOCK_TABLE,
			$wpdb->prefix . 'jlg_login_events',
			$wpdb->prefix . 'jlg_access_events',
			$wpdb->prefix . 'jlg_auto_blocks',
		);

		foreach ( $tables as $table ) {
			// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$wpdb->query( "DROP TABLE IF EXISTS {$table}" );
			// phpcs:enable
		}

		delete_option( self::DB_VERSION_OPTION );
	}

	/**
	 * Return the fully-prefixed name of a plugin table.
	 *
	 * @since 1.0.0
	 * @param string $table Short table name.
	 * @return string Full table name.
	 */
	public static function get( $table ) {
		global $wpdb;
		return $wpdb->prefix . $table;
	}
}