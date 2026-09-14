<?php
/**
 * Event logging and auto-block management.
 *
 * Records login events and access events, maintains log retention limits,
 * auto-blocks attackers, and escalates repeat offenders to the permanent
 * blacklist.
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
 * Class Logger
 *
 * @since 1.0.0
 */
class Logger {

	/**
	 * Settings instance.
	 *
	 * @since 1.0.0
	 * @var   Settings
	 */
	private $settings;

	/**
	 * Constructor.
	 *
	 * @since 1.0.0
	 */
	public function __construct() {
		$this->settings = Settings::get_instance();
	}

	/**
	 * Register the WordPress hooks used by this class.
	 *
	 * @since 1.0.0
	 * @return void
	 */
	public function register_hooks() {
		add_action( 'wp_login', array( $this, 'log_successful_login' ), 10, 2 );
		add_action( 'wp_login_failed', array( $this, 'log_failed_login' ), 10, 1 );
	}

	/**
	 * Log a successful login.
	 *
	 * @since 1.0.0
	 * @param string   $user_login User login name.
	 * @param \WP_User $user       The authenticated user object.
	 * @return void
	 */
	public function log_successful_login( $user_login, $user ) {
		if ( ! $this->settings->get( 'enable_logging' ) ) {
			return;
		}

		$this->insert_login_event( $user_login, 'success' );
	}

	/**
	 * Log a failed login attempt.
	 *
	 * @since 1.0.0
	 * @param string $username Attempted username.
	 * @return void
	 */
	public function log_failed_login( $username ) {
		if ( ! $this->settings->get( 'enable_logging' ) ) {
			return;
		}

		$this->insert_login_event( $username, 'failed' );
	}

	/**
	 * Insert a login event row.
	 *
	 * @since 1.0.0
	 * @param string $username Username.
	 * @param string $status   Either `success` or `failed`.
	 * @return void
	 */
	private function insert_login_event( $username, $status ) {
		global $wpdb;
		$table = Tables::get( JACKLOGU_LOGIN_TABLE );

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->insert(
			$table,
			array(
				'username'   => sanitize_user( $username, true ),
				'login_time' => current_time( 'mysql' ),
				'user_ip'    => IpUtils::get_client_ip(),
				'status'     => $status,
			),
			array( '%s', '%s', '%s', '%s' )
		);
		// phpcs:enable

		$this->maintain_limit( $table );
	}

	/**
	 * Insert an access log row.
	 *
	 * @since 1.0.0
	 * @param string $target Path or label for the event.
	 * @param string $status Either `allowed` or `blocked`.
	 * @param string $reason Human-readable reason.
	 * @return void
	 */
	public function log_access_event( $target, $status = 'allowed', $reason = '' ) {
		if ( ! $this->settings->get( 'enable_logging' ) ) {
			return;
		}

		global $wpdb;
		$table = Tables::get( JACKLOGU_ACCESS_TABLE );

		// phpcs:disable WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash
		$user_agent     = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		$request_method = isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : 'GET';
		$request_url    = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		$referer        = isset( $_SERVER['HTTP_REFERER'] ) ? esc_url_raw( wp_unslash( $_SERVER['HTTP_REFERER'] ) ) : '';
		// phpcs:enable

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->insert(
			$table,
			array(
				'event_time'     => current_time( 'mysql' ),
				'user_ip'        => IpUtils::get_client_ip(),
				'user_agent'     => $user_agent,
				'request_method' => $request_method,
				'request_url'    => $request_url,
				'request_path'   => $target,
				'referer'        => $referer,
				'reason'         => $reason,
				'status'         => $status,
			),
			array( '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s' )
		);
		// phpcs:enable

		$this->maintain_limit( $table );
	}

	/**
	 * Check whether an IP has recently completed a successful login.
	 *
	 * The window is controlled by the `trusted_ip_window_days` setting.
	 * Trusted IPs are excluded from auto-blocking.
	 *
	 * @since 1.0.0
	 * @param string $ip IP address.
	 * @return bool
	 */
	public static function is_trusted_ip( $ip ) {
		if ( empty( $ip ) || ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return false;
		}

		$window = Settings::get_instance()->get_trusted_ip_window_seconds();

		if ( $window <= 0 ) {
			return false;
		}

		if ( AccessControl::is_whitelisted( $ip ) ) {
			return true;
		}

		global $wpdb;
		$table = Tables::get( JACKLOGU_LOGIN_TABLE );
		$since = gmdate( 'Y-m-d H:i:s', time() - $window );

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$exists = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT id FROM {$table} WHERE user_ip = %s AND status = %s AND login_time > %s LIMIT 1",
				$ip,
				'success',
				$since
			)
		);
		// phpcs:enable

		return ! empty( $exists );
	}

	/**
	 * Count how many times an IP has been auto-blocked, all-time.
	 *
	 * @since 1.0.0
	 * @param string $ip IP address.
	 * @return int
	 */
	private function count_block_cycles( $ip ) {
		global $wpdb;
		$table = Tables::get( JACKLOGU_AUTO_BLOCK_TABLE );

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$count = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$table} WHERE user_ip = %s",
				$ip
			)
		);
		// phpcs:enable

		return $count;
	}

	/**
	 * Count blocked requests for an IP from the access log.
	 *
	 * @since 1.0.0
	 * @param string $ip IP address.
	 * @return int
	 */
	private function count_blocked_requests( $ip ) {
		global $wpdb;
		$table = Tables::get( JACKLOGU_ACCESS_TABLE );

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$count = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$table} WHERE user_ip = %s AND status = %s",
				$ip,
				'blocked'
			)
		);
		// phpcs:enable

		return $count;
	}

	/**
	 * Retrieve the most recent auto-block record for an IP.
	 *
	 * @since 1.0.0
	 * @param string $ip IP address.
	 * @return object|null Row object, or null when none exists.
	 */
	private function get_last_block( $ip ) {
		global $wpdb;
		$table = Tables::get( JACKLOGU_AUTO_BLOCK_TABLE );

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$row = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM {$table} WHERE user_ip = %s ORDER BY id DESC LIMIT 1",
				$ip
			)
		);
		// phpcs:enable

		return $row ? $row : null;
	}

	/**
	 * Auto-block an IP when it crosses the configured attack threshold.
	 *
	 * Whitelisted IPs, logged-in users, and IPs with a recent successful
	 * login are never auto-blocked. This method is also responsible for
	 * escalating repeat offenders to the permanent blacklist.
	 *
	 * @since 1.0.0
	 * @param string $ip     IP address.
	 * @param string $reason Reason for the block attempt.
	 * @return void
	 */
	public function auto_block_ip( $ip, $reason ) {
		if ( ! $this->settings->get( 'auto_block_attacks' ) ) {
			return;
		}

		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return;
		}

		if ( AccessControl::is_whitelisted( $ip ) ) {
			return;
		}

		if ( is_user_logged_in() ) {
			return;
		}

		if ( self::is_trusted_ip( $ip ) ) {
			return;
		}

		global $wpdb;
		$auto_block_table = Tables::get( JACKLOGU_AUTO_BLOCK_TABLE );

		// Already blocked (active, unexpired)? Nothing to do.
		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$active = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT id FROM {$auto_block_table} WHERE user_ip = %s AND is_active = 1 LIMIT 1",
				$ip
			)
		);
		// phpcs:enable

		if ( $active ) {
			return;
		}

		$trigger_count = $this->settings->get_auto_block_trigger_threshold();
		$last_block    = $this->get_last_block( $ip );

		if ( $last_block ) {
			$since_ts  = ! empty( $last_block->expire_at )
				? strtotime( $last_block->expire_at )
				: strtotime( $last_block->block_time );
			$since_str = gmdate( 'Y-m-d H:i:s', $since_ts );

			$access_table = Tables::get( JACKLOGU_ACCESS_TABLE );

			// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$attacks_since = (int) $wpdb->get_var(
				$wpdb->prepare(
					"SELECT COUNT(*) FROM {$access_table} WHERE user_ip = %s AND status = %s AND event_time > %s",
					$ip,
					'blocked',
					$since_str
				)
			);
			// phpcs:enable
		} else {
			$attacks_since = $this->count_blocked_requests( $ip );
		}

		if ( $attacks_since < $trigger_count ) {
			return;
		}

		$duration = $this->settings->get_auto_block_duration_seconds();
		$now      = time();

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->insert(
			$auto_block_table,
			array(
				'user_ip'    => $ip,
				'reason'     => $reason,
				'block_time' => current_time( 'mysql' ),
				'expire_at'  => gmdate( 'Y-m-d H:i:s', $now + $duration ),
				'is_active'  => 1,
			),
			array( '%s', '%s', '%s', '%s', '%d' )
		);
		// phpcs:enable

		$this->maintain_limit( $auto_block_table );

		$this->maybe_escalate_to_blacklist( $ip );
	}

	/**
	 * Deactivate auto-blocks whose expiry has passed.
	 *
	 * Cheap thanks to the `idx_expire` index. Runs on every request.
	 *
	 * @since 1.0.0
	 * @return void
	 */
	public static function expire_stale_blocks() {
		global $wpdb;
		$table = Tables::get( JACKLOGU_AUTO_BLOCK_TABLE );
		$now   = current_time( 'mysql' );

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$wpdb->query(
			$wpdb->prepare(
				"UPDATE {$table} SET is_active = 0 WHERE is_active = 1 AND expire_at IS NOT NULL AND expire_at <= %s",
				$now
			)
		);
		// phpcs:enable
	}

	/**
	 * Escalate an IP to the permanent blacklist when its block-cycle
	 * count reaches the configured threshold.
	 *
	 * @since 1.0.0
	 * @param string $ip IP address.
	 * @return void
	 */
	private function maybe_escalate_to_blacklist( $ip ) {
		$threshold = $this->settings->get_auto_block_to_blacklist_threshold();

		if ( $threshold <= 0 ) {
			return;
		}

		if ( AccessControl::is_whitelisted( $ip ) ) {
			return;
		}

		if ( $this->is_already_blacklisted( $ip ) ) {
			return;
		}

		$cycles = $this->count_block_cycles( $ip );

		if ( $cycles < $threshold ) {
			return;
		}

		$this->add_ip_to_blacklist( $ip );
	}

	/**
	 * Check whether an IP is already on the manual blacklist.
	 *
	 * @since 1.0.0
	 * @param string $ip IP address.
	 * @return bool
	 */
	private function is_already_blacklisted( $ip ) {
		$current = $this->settings->get( 'blacklist_ips', '' );
		$lines   = array_filter( array_map( 'trim', explode( "\n", $current ) ) );

		foreach ( $lines as $line ) {
			$parts   = explode( ' #', $line, 2 );
			$ip_part = trim( $parts[0] );

			if ( $ip_part === $ip ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Add an IP to the manual blacklist and remove it from the whitelist.
	 *
	 * @since 1.0.0
	 * @param string $ip IP address.
	 * @return void
	 */
	private function add_ip_to_blacklist( $ip ) {
		$current = $this->settings->get( 'blacklist_ips', '' );
		$lines   = array_filter( array_map( 'trim', explode( "\n", $current ) ) );

		$existing = array();
		foreach ( $lines as $line ) {
			$parts      = explode( ' #', $line, 2 );
			$existing[] = trim( $parts[0] );
		}

		if ( in_array( $ip, $existing, true ) ) {
			return;
		}

		$lines[] = $ip;

		$this->remove_ip_from_whitelist( $ip );

		$this->settings->update( 'blacklist_ips', implode( "\n", $lines ) );
	}

	/**
	 * Remove an IP from the whitelist.
	 *
	 * @since 1.0.0
	 * @param string $ip IP address.
	 * @return void
	 */
	private function remove_ip_from_whitelist( $ip ) {
		$current = $this->settings->get( 'whitelist_ips', '' );
		$lines   = array_filter( array_map( 'trim', explode( "\n", $current ) ) );
		$new     = array();

		foreach ( $lines as $line ) {
			$parts = explode( ' #', $line, 2 );

			if ( trim( $parts[0] ) !== $ip ) {
				$new[] = $line;
			}
		}

		$this->settings->update( 'whitelist_ips', implode( "\n", $new ) );
	}

	/**
	 * Trim a log table down to its configured row limit.
	 *
	 * @since 1.0.0
	 * @param string $table Fully-prefixed table name.
	 * @return void
	 */
	private function maintain_limit( $table ) {
		global $wpdb;
		$limit = intval( $this->settings->get_log_limit() );

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$table} WHERE id NOT IN (SELECT id FROM (SELECT id FROM {$table} ORDER BY id DESC LIMIT %d) AS temp)",
				$limit
			)
		);
		// phpcs:enable
	}
}