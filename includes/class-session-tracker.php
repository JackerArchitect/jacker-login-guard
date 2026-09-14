<?php
/**
 * Session activity tracking.
 *
 * Records the last-activity timestamp for every logged-in user and enforces
 * the optional session lifetime. The display timestamp and the enforcement
 * timestamp use independent transients so they never interfere with each
 * other.
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
 * Class SessionTracker
 *
 * @since 1.0.0
 */
class SessionTracker {

	/**
	 * How long a user remains visible in the "Current Login" list (seconds).
	 *
	 * @since 1.0.0
	 * @var   int
	 */
	const ONLINE_TTL = 1800; // 30 minutes.

	/**
	 * Minimum seconds between last-activity writes (anti-flood).
	 *
	 * The heartbeat AJAX endpoint bypasses this throttle.
	 *
	 * @since 1.0.0
	 * @var   int
	 */
	const WRITE_THROTTLE = 5;

	/**
	 * User meta key storing the last-activity timestamp.
	 *
	 * @since 1.0.0
	 * @var   string
	 */
	const META_KEY = 'jacklogu_last_activity';

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
		add_action( 'init', array( $this, 'update_activity' ), 20 );
		add_action( 'wp_ajax_jacklogu_heartbeat', array( $this, 'ajax_heartbeat' ) );
	}

	/**
	 * Update the current user's last-activity marker.
	 *
	 * Two independent mechanisms run here:
	 *
	 * 1. Session lifetime — an activity transient refreshed on every page
	 *    request. When the transient expires, the user is force-logged out.
	 *    This is fully independent from the "Current Login" list.
	 *
	 * 2. Last activity — a user meta timestamp feeding the "Current Login"
	 *    list. Updated with a small throttle to reduce database writes.
	 *
	 * @since 1.0.0
	 * @return void
	 */
	public function update_activity() {
		if ( ! is_user_logged_in() ) {
			return;
		}

		$user_id = get_current_user_id();

		if ( $user_id <= 0 ) {
			return;
		}

		$now = time();

		// 1) Session lifetime (force logout).
		$lifetime = $this->settings->get_session_lifetime();

		if ( $lifetime > 0 ) {
			$token = $this->get_current_token();

			if ( ! empty( $token ) ) {
				$token_hash = hash( 'sha256', $token );
				$activity   = get_transient( 'jacklogu_activity_' . $token_hash );

				if ( false === $activity ) {
					set_transient( 'jacklogu_activity_' . $token_hash, $now, $lifetime );
				} else {
					$elapsed = $now - (int) $activity;

					if ( $elapsed >= 60 ) {
						set_transient( 'jacklogu_activity_' . $token_hash, $now, $lifetime );
					}
				}
			}
		}

		// 2) Last activity (Current Login list).
		$this->write_last_activity( $user_id, $now );
	}

	/**
	 * Write the last-activity timestamp with optional throttling.
	 *
	 * @since 1.0.0
	 * @param int  $user_id User ID.
	 * @param int  $now     Current Unix timestamp.
	 * @param bool $force   When true, bypass the throttle.
	 * @return void
	 */
	private function write_last_activity( $user_id, $now, $force = false ) {
		$last = (int) get_user_meta( $user_id, self::META_KEY, true );

		if ( $force || ( $now - $last ) >= self::WRITE_THROTTLE ) {
			update_user_meta( $user_id, self::META_KEY, $now );
		}
	}

	/**
	 * AJAX heartbeat handler.
	 *
	 * Refreshes the last-activity timestamp while the user keeps a tab open.
	 *
	 * @since 1.0.0
	 * @return void
	 */
	public function ajax_heartbeat() {
		check_ajax_referer( 'jacklogu_heartbeat', 'nonce' );

		if ( ! is_user_logged_in() ) {
			wp_send_json_error( array( 'message' => 'not_logged_in' ), 401 );
		}

		$user_id = get_current_user_id();

		if ( $user_id <= 0 ) {
			wp_send_json_error( array( 'message' => 'no_user' ), 401 );
		}

		$now = time();
		$this->write_last_activity( $user_id, $now, true );

		wp_send_json_success( array( 'ts' => $now ) );
	}

	/**
	 * Extract the current session token from the logged-in cookie.
	 *
	 * Cookie format: `username|expiration|token|hmac`.
	 *
	 * @since 1.0.0
	 * @return string Token, or empty string when unavailable.
	 */
	private function get_current_token() {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash
		$cookie = isset( $_COOKIE[ LOGGED_IN_COOKIE ] ) ? wp_unslash( $_COOKIE[ LOGGED_IN_COOKIE ] ) : '';

		if ( empty( $cookie ) ) {
			return '';
		}

		$parts = explode( '|', $cookie );

		if ( count( $parts ) < 3 ) {
			return '';
		}

		return $parts[2];
	}

	/**
	 * Return a user's last-activity timestamp.
	 *
	 * @since 1.0.0
	 * @param int $user_id User ID.
	 * @return int Timestamp, or 0 when none was recorded.
	 */
	public static function get_last_activity( $user_id ) {
		$user_id = (int) $user_id;

		if ( $user_id <= 0 ) {
			return 0;
		}

		return (int) get_user_meta( $user_id, self::META_KEY, true );
	}

	/**
	 * Whether a user is currently considered "online".
	 *
	 * @since 1.0.0
	 * @param int $user_id User ID.
	 * @return bool
	 */
	public static function is_online( $user_id ) {
		$last = self::get_last_activity( $user_id );

		if ( $last <= 0 ) {
			return false;
		}

		return ( time() - $last ) <= self::ONLINE_TTL;
	}

	/**
	 * Force-logout every session belonging to a user and clear their
	 * activity markers.
	 *
	 * @since 1.0.0
	 * @param int $user_id User ID.
	 * @return bool True on success, false when the user ID is invalid.
	 */
	public static function force_logout_user( $user_id ) {
		$user_id = intval( $user_id );

		if ( $user_id <= 0 ) {
			return false;
		}

		$sessions = \WP_Session_Tokens::get_instance( $user_id );
		$all      = $sessions->get_all();

		foreach ( $all as $token => $data ) {
			$token_hash = hash( 'sha256', $token );
			delete_transient( 'jacklogu_activity_' . $token_hash );
		}

		$sessions->destroy_all();

		delete_user_meta( $user_id, self::META_KEY );

		return true;
	}
}