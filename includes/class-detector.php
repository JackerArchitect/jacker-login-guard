<?php
/**
 * Attack detection engine.
 *
 * Inspects incoming requests for suspicious user agents, encoded malicious
 * payloads, unusual HTTP methods, and high-frequency floods.
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
 * Class Detector
 *
 * @since 1.0.0
 */
class Detector {

	/**
	 * User agents that reliably indicate a scanning or exploitation tool.
	 *
	 * @since 1.0.0
	 * @var   string[]
	 */
	private static $suspicious_agents = array(
		'nmap',
		'nikto',
		'sqlmap',
		'dirbuster',
		'wpscan',
		'zmap',
		'masscan',
		'awvs',
		'nessus',
		'openvas',
		'metasploit',
	);

	/**
	 * SQL injection signatures (regex).
	 *
	 * @since 1.0.0
	 * @var   string[]
	 */
	private static $sql_signatures = array(
		'/\bUNION\b\s+\bSELECT\b/i',
		'/\bSELECT\b.+\bFROM\b/i',
		'/\bDROP\b\s+\bTABLE\b/i',
		'/\bINSERT\b\s+\bINTO\b/i',
		'/\bDELETE\b\s+\bFROM\b/i',
		'/\bUPDATE\b.+\bSET\b/i',
		'/\bALTER\b\s+\bTABLE\b/i',
		"/'\s*OR\s*'1'\s*=\s*'1/i",
		'/\bOR\b\s+1\s*=\s*1/i',
		'/--\s*$/m',
		'/;\s*DROP\b/i',
	);

	/**
	 * Command injection signatures (regex).
	 *
	 * @since 1.0.0
	 * @var   string[]
	 */
	private static $cmd_signatures = array(
		'/\b(?:exec|system|passthru|shell_exec|popen|proc_open)\s*\(/i',
		'/\|\s*(?:nc|netcat|bash|sh)\b/i',
		'/`[^`]+`/',
		'/\$\([^)]+\)/',
	);

	/**
	 * XSS signatures (regex).
	 *
	 * @since 1.0.0
	 * @var   string[]
	 */
	private static $xss_signatures = array(
		'/<script\b[^>]*>/i',
		'/javascript\s*:/i',
		'/onerror\s*=/i',
		'/onload\s*=/i',
		'/<iframe\b[^>]*>/i',
		'/<img\b[^>]*\bon\w+\s*=/i',
	);

	/**
	 * Run all detection checks against the current request.
	 *
	 * @since 1.0.0
	 * @return array{is_invalid: bool, reason: string, status_code: int} Detection result.
	 */
	public function detect() {
		$result = array(
			'is_invalid'  => false,
			'reason'      => '',
			'status_code' => 200,
		);

		// Whitelisted IPs are trusted.
		if ( AccessControl::is_whitelisted( IpUtils::get_client_ip() ) ) {
			return $result;
		}

		// Logged-in users are trusted.
		if ( is_user_logged_in() ) {
			return $result;
		}

		// phpcs:disable WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash
		$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		$user_agent  = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		$method      = isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : 'GET';
		// phpcs:enable

		// 1) Suspicious user agent.
		$agent_result = $this->check_user_agent( $user_agent );

		if ( $agent_result ) {
			return $agent_result;
		}

		// 2) Empty or short user agent.
		if ( empty( $user_agent ) || strlen( $user_agent ) < 10 ) {
			$result['is_invalid']  = true;
			$result['reason']      = __( 'Request with no browser identity', 'jacker-login-guard' );
			$result['status_code'] = 403;
			return $result;
		}

		// 3) Encoded malicious payload.
		$encoded_result = $this->check_encoded_attack( $request_uri );

		if ( $encoded_result ) {
			return $encoded_result;
		}

		// 4) Unusual HTTP method.
		$allowed_methods = array( 'GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'PATCH', 'OPTIONS' );

		if ( ! in_array( $method, $allowed_methods, true ) ) {
			$result['is_invalid']  = true;
			$result['reason']      = __( 'Unusual HTTP method used', 'jacker-login-guard' );
			$result['status_code'] = 405;
			return $result;
		}

		// 5) High-frequency flood.
		$freq_result = $this->check_high_frequency();

		if ( $freq_result ) {
			return $freq_result;
		}

		return $result;
	}

	/**
	 * Check the request against the suspicious user-agent list.
	 *
	 * @since 1.0.0
	 * @param string $user_agent User agent string.
	 * @return array{is_invalid: bool, reason: string, status_code: int}|false Match, or false.
	 */
	private function check_user_agent( $user_agent ) {
		foreach ( self::$suspicious_agents as $agent ) {
			if ( stripos( $user_agent, $agent ) !== false ) {
				return array(
					'is_invalid'  => true,
					'reason'      => $this->get_agent_reason( $agent ),
					'status_code' => 403,
				);
			}
		}

		return false;
	}

	/**
	 * Check the URL-decoded request URI against known attack signatures.
	 *
	 * @since 1.0.0
	 * @param string $request_uri Raw request URI.
	 * @return array{is_invalid: bool, reason: string, status_code: int}|false Match, or false.
	 */
	private function check_encoded_attack( $request_uri ) {
		if ( ! preg_match( '/%[0-9A-Fa-f]{2}/', $request_uri ) ) {
			return false;
		}

		$decoded = urldecode( $request_uri );

		if ( $decoded === $request_uri ) {
			return false;
		}

		foreach ( self::$sql_signatures as $pattern ) {
			if ( preg_match( $pattern, $decoded ) ) {
				return array(
					'is_invalid'  => true,
					'reason'      => __( 'SQL injection attempt', 'jacker-login-guard' ),
					'status_code' => 403,
				);
			}
		}

		foreach ( self::$cmd_signatures as $pattern ) {
			if ( preg_match( $pattern, $decoded ) ) {
				return array(
					'is_invalid'  => true,
					'reason'      => __( 'Malicious code execution attempt', 'jacker-login-guard' ),
					'status_code' => 403,
				);
			}
		}

		foreach ( self::$xss_signatures as $pattern ) {
			if ( preg_match( $pattern, $decoded ) ) {
				return array(
					'is_invalid'  => true,
					'reason'      => __( 'Cross-site scripting attempt', 'jacker-login-guard' ),
					'status_code' => 403,
				);
			}
		}

		return false;
	}

	/**
	 * Check whether the current IP has made too many requests recently.
	 *
	 * Results are cached for 10 seconds to avoid hammering the database.
	 *
	 * @since 1.0.0
	 * @return array{is_invalid: bool, reason: string, status_code: int}|false Match, or false.
	 */
	private function check_high_frequency() {
		if ( AccessControl::is_whitelisted( IpUtils::get_client_ip() ) ) {
			return false;
		}

		if ( is_user_logged_in() ) {
			return false;
		}

		$ip = IpUtils::get_client_ip();

		if ( '0.0.0.0' === $ip ) {
			return false;
		}

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';

		foreach ( array( 'admin-ajax.php', 'wp-cron.php', 'wp-login.php' ) as $safe_path ) {
			if ( strpos( $uri, $safe_path ) !== false ) {
				return false;
			}
		}

		$cache_key = 'jacklogu_freq_' . md5( $ip );
		$count     = get_transient( $cache_key );

		if ( false === $count ) {
			global $wpdb;
			$table = Tables::get( JACKLOGU_ACCESS_TABLE );
			$time  = gmdate( 'Y-m-d H:i:s', time() - 60 );

			// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$count = (int) $wpdb->get_var(
				$wpdb->prepare(
					"SELECT COUNT(*) FROM {$table} WHERE user_ip = %s AND event_time > %s",
					$ip,
					$time
				)
			);
			// phpcs:enable

			set_transient( $cache_key, $count, 10 );
		}

		if ( $count > 120 ) {
			return array(
				'is_invalid'  => true,
				/* translators: %d: number of requests in the last minute. */
				'reason'      => sprintf( __( 'Too many requests (%d in 1 minute)', 'jacker-login-guard' ), $count ),
				'status_code' => 429,
			);
		}

		return false;
	}

	/**
	 * Translate a suspicious user-agent keyword into a human-readable reason.
	 *
	 * @since 1.0.0
	 * @param string $agent Lowercase agent keyword.
	 * @return string Localized reason.
	 */
	private function get_agent_reason( $agent ) {
		$agent = strtolower( $agent );

		$map = array(
			'sqlmap'     => __( 'SQL injection tool detected', 'jacker-login-guard' ),
			'nikto'      => __( 'Vulnerability scanner detected', 'jacker-login-guard' ),
			'dirbuster'  => __( 'Vulnerability scanner detected', 'jacker-login-guard' ),
			'wpscan'     => __( 'Vulnerability scanner detected', 'jacker-login-guard' ),
			'nmap'       => __( 'Network scanner detected', 'jacker-login-guard' ),
			'masscan'    => __( 'Network scanner detected', 'jacker-login-guard' ),
			'zmap'       => __( 'Network scanner detected', 'jacker-login-guard' ),
			'metasploit' => __( 'Exploitation tool detected', 'jacker-login-guard' ),
			'awvs'       => __( 'Security scanner detected', 'jacker-login-guard' ),
			'nessus'     => __( 'Security scanner detected', 'jacker-login-guard' ),
			'openvas'    => __( 'Security scanner detected', 'jacker-login-guard' ),
		);

		return isset( $map[ $agent ] ) ? $map[ $agent ] : __( 'Suspicious software detected', 'jacker-login-guard' );
	}
}