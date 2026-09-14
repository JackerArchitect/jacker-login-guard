<?php
/**
 * Access control gate.
 *
 * Decides whether an incoming request is allowed to reach WordPress. Every
 * request passes through one of the checks in a strict priority order.
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
 * Class AccessControl
 *
 * @since 1.0.0
 */
class AccessControl {

	/**
	 * Settings instance.
	 *
	 * @since 1.0.0
	 * @var   Settings
	 */
	private $settings;

	/**
	 * Logger instance.
	 *
	 * @since 1.0.0
	 * @var   Logger
	 */
	private $logger;

	/**
	 * Detector instance.
	 *
	 * @since 1.0.0
	 * @var   Detector
	 */
	private $detector;

	/**
	 * Paths that should never be reachable without an authenticated session.
	 *
	 * @since 1.0.0
	 * @var   string[]
	 */
	private static $sensitive_paths = array( 'login', 'admin', 'signin', 'sign-in', 'log-in', 'wp-json', 'xmlrpc' );

	/**
	 * Files whose public access is always blocked.
	 *
	 * @since 1.0.0
	 * @var   string[]
	 */
	private static $sensitive_files = array( 'wp-config.php', '.htaccess', 'install.php', 'upgrade.php' );

	/**
	 * Admin AJAX actions that are never audited (read-only UI polling).
	 *
	 * @since 1.0.0
	 * @var   string[]
	 */
	private static $safe_admin_actions = array(
		'heartbeat',
		'autosave',
		'query-attachments',
		'fetch-list',
		'get-users',
		'get-comments',
		'get-replies',
		'inline-save',
		'dashboard-widgets',
		'dashboard_primary',
		'menu-quick-search',
		'meta-box-order',
		'wp-check-locked-posts',
		'wp-remove-post-lock',
	);

	/**
	 * Action slugs that are read-only when combined with a GET request.
	 *
	 * @since 1.0.0
	 * @var   string[]
	 */
	private static $view_only_actions = array(
		'edit',
		'editpost',
		'edit-comments',
		'edit-comment',
		'edit-tags',
		'edit-tag',
		'add',
		'add-new',
		'new',
		'view',
		'preview',
	);

	/**
	 * Substrings that mark an action as a state-changing operation.
	 *
	 * @since 1.0.0
	 * @var   string[]
	 */
	private static $dangerous_action_keywords = array(
		'save',
		'update',
		'create',
		'insert',
		'publish',
		'unpublish',
		'switch',
		'toggle',
		'delete',
		'remove',
		'trash',
		'import',
		'export',
		'install',
		'activate',
		'deactivate',
		'upload',
		'reset',
		'clear',
		'grant',
		'revoke',
		'promote',
		'demote',
	);

	/**
	 * Admin scripts always audited on POST, even without an action.
	 *
	 * @since 1.0.0
	 * @var   string[]
	 */
	private static $always_log_scripts = array(
		'options.php',
		'options-general.php',
		'options-writing.php',
		'options-reading.php',
		'options-discussion.php',
		'options-media.php',
		'options-permalink.php',
		'user-new.php',
		'user-edit.php',
		'profile.php',
		'plugins.php',
		'themes.php',
		'widgets.php',
		'nav-menus.php',
		'export.php',
		'import.php',
		'tools.php',
		'site-health.php',
	);

	/**
	 * Deduplication window for admin audit entries (seconds).
	 *
	 * @since 1.0.0
	 * @var   int
	 */
	const ADMIN_AUDIT_DEDUP_TTL = 900; // 15 minutes.

	/**
	 * Constructor.
	 *
	 * @since 1.0.0
	 */
	public function __construct() {
		$this->settings = Settings::get_instance();
		$this->logger   = new Logger();
		$this->detector = new Detector();
	}

	/**
	 * Register the WordPress hooks used by this class.
	 *
	 * @since 1.0.0
	 * @return void
	 */
	public function register_hooks() {
		add_action( 'init', array( $this, 'check_access' ), 5 );
		add_action( 'template_redirect', array( $this, 'block_sensitive_paths' ), 1 );
		add_action( 'template_redirect', array( $this, 'block_user_enumeration' ), 1 );
	}

	/**
	 * Main access check.
	 *
	 * @since 1.0.0
	 * @return void
	 */
	public function check_access() {
		if ( defined( 'WP_INSTALLING' ) && WP_INSTALLING ) {
			return;
		}

		Logger::expire_stale_blocks();

		$client_ip = IpUtils::get_client_ip();

		// 1) Whitelisted IPs — never blocked, but still routed through the
		//    login gate so /<slug>/ issues a token instead of 404.
		if ( self::is_whitelisted( $client_ip ) ) {
			if ( $this->is_login_gate_request() ) {
				$this->logger->log_access_event(
					$this->get_clean_path(),
					'allowed',
					__( 'Login gate opened (whitelisted IP)', 'jacker-login-guard' )
				);
				$this->generate_auth_cookie( $client_ip );
				return;
			}

			return;
		}

		// 2) Custom login gate.
		if ( $this->is_login_gate_request() ) {
			$this->logger->log_access_event(
				$this->get_clean_path(),
				'allowed',
				__( 'Login gate opened (auth cookie issued)', 'jacker-login-guard' )
			);
			$this->generate_auth_cookie( $client_ip );
			return;
		}

		// 3) Logged-in users — audited.
		if ( is_user_logged_in() ) {
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash
			$script = isset( $_SERVER['SCRIPT_NAME'] ) ? basename( sanitize_text_field( wp_unslash( $_SERVER['SCRIPT_NAME'] ) ) ) : '';

			if ( 'wp-login.php' === $script ) {
				$this->log_allowed_deduped(
					'wp-login.php',
					__( 'Logged-in user accessed wp-login.php', 'jacker-login-guard' )
				);
			} else {
				$this->maybe_log_admin_operation();
			}
			return;
		}

		// 4) Manual blacklist — silently rejected.
		if ( self::is_manual_blacklisted( $client_ip ) ) {
			$this->deny_response( 'manual_blacklist' );
			exit;
		}

		// 5) Active auto-block — silently rejected.
		if ( self::is_auto_blocked( $client_ip ) ) {
			$this->deny_response( 'auto_blocked' );
			exit;
		}

		// 6) Attack detection.
		$result = $this->detector->detect();

		if ( $result['is_invalid'] ) {
			$this->logger->log_access_event( $this->get_request_path(), 'blocked', $result['reason'] );
			$this->logger->auto_block_ip( $client_ip, $result['reason'] );

			if ( in_array( $result['status_code'], array( 403, 429 ), true ) ) {
				$this->deny_response( $result['reason'] );
				exit;
			}
		}

		// 7) Login-page rules.
		$this->handle_login_access( $client_ip );
	}

	/**
	 * Whether the current request targets the custom login gate slug.
	 *
	 * @since 1.0.0
	 * @return bool
	 */
	private function is_login_gate_request() {
		$slug = trim( $this->settings->get( 'slug', JACKLOGU_DEFAULT_SLUG ), '/' );

		if ( empty( $slug ) ) {
			return false;
		}

		$candidates = array();

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		$candidates[] = trim( strtok( $uri, '?' ), '/' );

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET['pagename'] ) ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$candidates[] = trim( sanitize_text_field( wp_unslash( $_GET['pagename'] ) ), '/' );
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET['name'] ) ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$candidates[] = trim( sanitize_text_field( wp_unslash( $_GET['name'] ) ), '/' );
		}

		foreach ( $candidates as $candidate ) {
			if ( $candidate === $slug ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Log admin operations performed by a logged-in user.
	 *
	 * @since 1.0.0
	 * @return void
	 */
	private function maybe_log_admin_operation() {
		if ( ! $this->settings->get( 'enable_logging' ) ) {
			return;
		}

		if ( ! is_admin() ) {
			return;
		}

		// phpcs:disable WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.NonceVerification.Recommended, WordPress.Security.NonceVerification.Missing
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : 'GET';
		$script = isset( $_SERVER['SCRIPT_NAME'] ) ? basename( sanitize_text_field( wp_unslash( $_SERVER['SCRIPT_NAME'] ) ) ) : '';
		$action = '';

		if ( isset( $_GET['action'] ) ) {
			$action = sanitize_key( wp_unslash( $_GET['action'] ) );
		} elseif ( isset( $_POST['action'] ) ) {
			$action = sanitize_key( wp_unslash( $_POST['action'] ) );
		}
		// phpcs:enable

		if ( empty( $script ) ) {
			return;
		}

		if ( ! empty( $action ) && strpos( $action, 'jacklogu_' ) === 0 ) {
			return;
		}

		if ( ! empty( $action ) && in_array( $action, self::$safe_admin_actions, true ) ) {
			return;
		}

		$is_get = ( 'GET' === $method );

		if ( $is_get && ! empty( $action ) && in_array( $action, self::$view_only_actions, true ) ) {
			return;
		}

		$is_dangerous_action = ( ! empty( $action ) && self::action_has_dangerous_keyword( $action ) );
		$is_write_to_script  = ( ! $is_get && in_array( $script, self::$always_log_scripts, true ) );

		if ( ! $is_dangerous_action && ! $is_write_to_script ) {
			return;
		}

		$user_id = get_current_user_id();

		if ( $user_id <= 0 ) {
			return;
		}

		$target    = $script . ( $action ? '?action=' . $action : '' );
		$dedup_key = 'jacklogu_admin_op_' . md5( $user_id . '|' . $method . '|' . $target );

		if ( false !== get_transient( $dedup_key ) ) {
			return;
		}

		set_transient( $dedup_key, 1, self::ADMIN_AUDIT_DEDUP_TTL );

		$reason = sprintf(
			/* translators: 1: HTTP method, 2: admin target, 3: user ID, 4: action slug or "no-action". */
			__( 'Admin operation: %1$s %2$s (user #%3$d, %4$s)', 'jacker-login-guard' ),
			$method,
			$target,
			$user_id,
			$action ? $action : 'no-action'
		);

		$this->logger->log_access_event( $target, 'allowed', $reason );
	}

	/**
	 * Whether an action slug contains one of the dangerous keywords.
	 *
	 * @since 1.0.0
	 * @param string $action Action slug.
	 * @return bool
	 */
	private static function action_has_dangerous_keyword( $action ) {
		$action = strtolower( $action );

		foreach ( self::$dangerous_action_keywords as $keyword ) {
			if ( strpos( $action, $keyword ) !== false ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Handle access to wp-login.php, XML-RPC, REST, and the admin area.
	 *
	 * @since 1.0.0
	 * @param string $client_ip Client IP address.
	 * @return void
	 */
	private function handle_login_access( $client_ip ) {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash
		$script_name = isset( $_SERVER['SCRIPT_NAME'] ) ? sanitize_text_field( wp_unslash( $_SERVER['SCRIPT_NAME'] ) ) : '';

		// wp-login.php.
		if ( 'wp-login.php' === basename( $script_name ) ) {
			if ( $this->verify_auth_cookie( $client_ip ) ) {
				$this->logger->log_access_event(
					'wp-login.php',
					'allowed',
					__( 'Login page accessed via valid auth cookie', 'jacker-login-guard' )
				);
				return;
			}

			if ( $this->is_allowed_login_action() ) {
				$this->logger->log_access_event(
					'wp-login.php',
					'allowed',
					__( 'Allowed login action (compatibility mode)', 'jacker-login-guard' )
				);
				return;
			}

			$this->logger->log_access_event( 'wp-login.php', 'blocked', __( 'Direct login access attempt', 'jacker-login-guard' ) );
			$this->logger->auto_block_ip( $client_ip, __( 'Direct login access attempt', 'jacker-login-guard' ) );
			$this->deny_response( 'direct_login' );
			exit;
		}

		// XML-RPC.
		if ( 'xmlrpc.php' === basename( $script_name ) ) {
			if ( $this->settings->get( 'block_xmlrpc' ) ) {
				$this->logger->log_access_event( 'xmlrpc.php', 'blocked', __( 'XML-RPC access blocked', 'jacker-login-guard' ) );
				$this->logger->auto_block_ip( $client_ip, __( 'XML-RPC access blocked', 'jacker-login-guard' ) );
				$this->deny_response( 'xmlrpc' );
				exit;
			}

			$this->logger->log_access_event( 'xmlrpc.php', 'allowed', __( 'XML-RPC access allowed', 'jacker-login-guard' ) );
			return;
		}

		// API whitelist.
		if ( $this->is_api_whitelisted() ) {
			$this->log_allowed_deduped(
				$this->get_request_path(),
				__( 'REST API endpoint whitelisted', 'jacker-login-guard' )
			);
			return;
		}

		// REST enumeration.
		if ( $this->is_rest_enumeration() ) {
			$this->logger->log_access_event( $this->get_request_path(), 'blocked', __( 'User enumeration attempt', 'jacker-login-guard' ) );
			$this->logger->auto_block_ip( $client_ip, __( 'User enumeration attempt', 'jacker-login-guard' ) );
			$this->deny_response( 'rest_enum' );
			exit;
		}

		// Path whitelist.
		if ( $this->is_path_whitelisted() ) {
			$this->log_allowed_deduped(
				$this->get_request_path(),
				__( 'Path whitelisted', 'jacker-login-guard' )
			);
			return;
		}

		// Sensitive files.
		if ( in_array( basename( $script_name ), self::$sensitive_files, true ) ) {
			$this->logger->log_access_event( $this->get_request_path(), 'blocked', __( 'Sensitive file access attempt', 'jacker-login-guard' ) );
			$this->logger->auto_block_ip( $client_ip, __( 'Sensitive file access attempt', 'jacker-login-guard' ) );
			$this->deny_response( 'sensitive_file' );
			exit;
		}

		// Unauthenticated admin access (excluding admin-ajax.php).
		$request_uri = $this->get_clean_path();

		if ( $this->is_admin_request( $request_uri ) && strpos( $request_uri, 'admin-ajax.php' ) === false ) {
			$this->logger->log_access_event( $this->get_request_path(), 'blocked', __( 'Unauthorized admin access', 'jacker-login-guard' ) );
			$this->logger->auto_block_ip( $client_ip, __( 'Unauthorized admin access', 'jacker-login-guard' ) );
			$this->deny_response( 'admin_access' );
			exit;
		}
	}

	/**
	 * Log an "allowed" event, deduplicated within a 60-second window.
	 *
	 * @since 1.0.0
	 * @param string $target Path or label.
	 * @param string $reason Human-readable reason.
	 * @return void
	 */
	private function log_allowed_deduped( $target, $reason ) {
		$ip  = IpUtils::get_client_ip();
		$key = 'jacklogu_log_dedup_' . md5( $ip . '|' . $target );

		if ( false !== get_transient( $key ) ) {
			return;
		}

		set_transient( $key, 1, 60 );

		$this->logger->log_access_event( $target, 'allowed', $reason );
	}

	/**
	 * Block access to sensitive paths on template_redirect.
	 *
	 * @since 1.0.0
	 * @return void
	 */
	public function block_sensitive_paths() {
		if ( self::is_whitelisted( IpUtils::get_client_ip() ) ) {
			return;
		}

		if ( is_user_logged_in() ) {
			return;
		}

		if ( $this->is_login_gate_request() ) {
			return;
		}

		$request_path = $this->get_request_path();

		if ( empty( $request_path ) ) {
			return;
		}

		$slug = trim( $this->settings->get( 'slug', JACKLOGU_DEFAULT_SLUG ), '/' );

		if ( $request_path === $slug ) {
			return;
		}

		if ( ! in_array( $request_path, self::$sensitive_paths, true ) ) {
			return;
		}

		if ( $this->real_page_exists( $request_path ) ) {
			return;
		}

		$this->logger->log_access_event(
			$request_path,
			'blocked',
			__( 'Sensitive path access attempt', 'jacker-login-guard' )
		);
		$this->logger->auto_block_ip( IpUtils::get_client_ip(), __( 'Sensitive path access attempt', 'jacker-login-guard' ) );

		$this->deny_response( 'sensitive_path' );
		exit;
	}

	/**
	 * Block author and REST enumeration on template_redirect.
	 *
	 * @since 1.0.0
	 * @return void
	 */
	public function block_user_enumeration() {
		if ( self::is_whitelisted( IpUtils::get_client_ip() ) ) {
			return;
		}

		if ( is_user_logged_in() ) {
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( $this->settings->get( 'block_author_enum' ) && isset( $_GET['author'] ) && is_numeric( $_GET['author'] ) ) {
			$this->logger->log_access_event( $this->get_request_path(), 'blocked', __( 'Author enumeration attempt', 'jacker-login-guard' ) );
			$this->logger->auto_block_ip( IpUtils::get_client_ip(), __( 'Author enumeration attempt', 'jacker-login-guard' ) );
			$this->deny_response( 'author_enum' );
			exit;
		}

		if ( $this->is_rest_enumeration() ) {
			$this->logger->log_access_event( $this->get_request_path(), 'blocked', __( 'REST API user enumeration attempt', 'jacker-login-guard' ) );
			$this->logger->auto_block_ip( IpUtils::get_client_ip(), __( 'REST API user enumeration attempt', 'jacker-login-guard' ) );
			$this->deny_response( 'rest_enum' );
			exit;
		}
	}

	/**
	 * Whether an IP is on the whitelist.
	 *
	 * @since 1.0.0
	 * @param string $ip IP address.
	 * @return bool
	 */
	public static function is_whitelisted( $ip ) {
		$settings = Settings::get_instance();
		$list     = array_filter( array_map( 'trim', explode( "\n", $settings->get( 'whitelist_ips', '' ) ) ) );

		foreach ( $list as $range ) {
			if ( $ip === $range || ( strpos( $range, '/' ) !== false && IpUtils::ip_in_range( $ip, $range ) ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Whether an IP is on the manual blacklist.
	 *
	 * @since 1.0.0
	 * @param string $ip IP address.
	 * @return bool
	 */
	private static function is_manual_blacklisted( $ip ) {
		$settings = Settings::get_instance();
		$list     = array_filter( array_map( 'trim', explode( "\n", $settings->get( 'blacklist_ips', '' ) ) ) );

		foreach ( $list as $line ) {
			$parts   = explode( ' #', $line, 2 );
			$ip_part = trim( $parts[0] );

			if ( $ip === $ip_part || ( strpos( $ip_part, '/' ) !== false && IpUtils::ip_in_range( $ip, $ip_part ) ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Whether an IP has an active, unexpired auto-block.
	 *
	 * @since 1.0.0
	 * @param string $ip IP address.
	 * @return bool
	 */
	private static function is_auto_blocked( $ip ) {
		global $wpdb;
		$table = Tables::get( JACKLOGU_AUTO_BLOCK_TABLE );
		$now   = current_time( 'mysql' );

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$exists = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT id FROM {$table} WHERE user_ip = %s AND is_active = 1 AND (expire_at IS NULL OR expire_at > %s) LIMIT 1",
				$ip,
				$now
			)
		);
		// phpcs:enable

		return ! empty( $exists );
	}

	/**
	 * Issue the temporary auth cookie and redirect to wp-login.php.
	 *
	 * @since 1.0.0
	 * @param string $client_ip Client IP address.
	 * @return void
	 */
	private function generate_auth_cookie( $client_ip ) {
		$time    = time();
		$rand    = wp_rand( 100000, 999999 );
		$payload = $time . '|' . $rand;

		if ( $this->settings->get( 'bind_ip_to_cookie' ) ) {
			$payload .= '|' . hash( 'sha256', $client_ip );
		}

		$sig = hash_hmac( 'sha256', $payload, wp_salt( 'auth' ) );
		$val = base64_encode( $payload . '|' . $sig );

		$params = array(
			'expires'  => time() + 5 * MINUTE_IN_SECONDS,
			'path'     => COOKIEPATH ? COOKIEPATH : '/',
			'domain'   => defined( 'COOKIE_DOMAIN' ) && COOKIE_DOMAIN ? COOKIE_DOMAIN : '',
			'secure'   => is_ssl(),
			'httponly' => true,
			'samesite' => 'Lax',
		);

		if ( PHP_VERSION_ID >= 70300 ) {
			setcookie( JACKLOGU_AUTH_COOKIE, $val, $params );
		} else {
			setcookie(
				JACKLOGU_AUTH_COOKIE,
				$val,
				$params['expires'],
				$params['path'] . '; SameSite=Lax',
				$params['domain'],
				$params['secure'],
				$params['httponly']
			);
		}

		wp_safe_redirect( site_url( 'wp-login.php' ), 302 );
		exit;
	}

	/**
	 * Verify the temporary auth cookie.
	 *
	 * @since 1.0.0
	 * @param string $current_ip Client IP address.
	 * @return bool
	 */
	private function verify_auth_cookie( $current_ip ) {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash
		$raw = isset( $_COOKIE[ JACKLOGU_AUTH_COOKIE ] ) ? wp_unslash( $_COOKIE[ JACKLOGU_AUTH_COOKIE ] ) : '';

		if ( empty( $raw ) ) {
			return false;
		}

		$decoded = base64_decode( $raw );

		if ( ! $decoded ) {
			return false;
		}

		$parts          = explode( '|', $decoded );
		$bind           = $this->settings->get( 'bind_ip_to_cookie' );
		$expected_parts = $bind ? 4 : 3;

		if ( count( $parts ) !== $expected_parts ) {
			return false;
		}

		$time    = $parts[0];
		$rand    = $parts[1];
		$sig     = end( $parts );
		$payload = $time . '|' . $rand;

		if ( $bind ) {
			$payload .= '|' . $parts[2];
		}

		$expected_sig = hash_hmac( 'sha256', $payload, wp_salt( 'auth' ) );

		if ( ! hash_equals( $expected_sig, $sig ) ) {
			return false;
		}

		if ( ( time() - (int) $time ) > 5 * MINUTE_IN_SECONDS ) {
			return false;
		}

		if ( $bind && $parts[2] !== hash( 'sha256', $current_ip ) ) {
			return false;
		}

		return true;
	}

	/**
	 * Whether the current request is an allowed wp-login action.
	 *
	 * @since 1.0.0
	 * @return bool
	 */
	private function is_allowed_login_action() {
		if ( 'strict' === $this->settings->get( 'login_protection_mode' ) ) {
			return false;
		}

		// phpcs:disable WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash
		$action = isset( $_GET['action'] ) ? sanitize_key( wp_unslash( $_GET['action'] ) ) : '';
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : 'GET';
		// phpcs:enable

		if ( 'GET' !== $method ) {
			return false;
		}

		$allowed = array( 'logout', 'lostpassword', 'rp', 'resetpass', 'register', 'postpass', 'confirm_admin_email' );

		return in_array( $action, $allowed, true );
	}

	/**
	 * Whether the current URI is covered by the API whitelist.
	 *
	 * @since 1.0.0
	 * @return bool
	 */
	private function is_api_whitelisted() {
		$whitelist = $this->settings->get( 'api_whitelist', '' );

		if ( empty( $whitelist ) ) {
			return false;
		}

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? wp_parse_url( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ), PHP_URL_PATH ) : '';

		if ( empty( $uri ) || strpos( $uri, '/wp-json/' ) !== 0 ) {
			return false;
		}

		$allowed = array_filter( array_map( 'trim', explode( "\n", $whitelist ) ) );

		foreach ( $allowed as $api ) {
			if ( strpos( $uri, $api ) === 0 ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Whether the current URI is covered by the path whitelist.
	 *
	 * @since 1.0.0
	 * @return bool
	 */
	private function is_path_whitelisted() {
		$whitelist = $this->settings->get( 'path_whitelist', '' );

		if ( empty( $whitelist ) ) {
			return false;
		}

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? wp_parse_url( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ), PHP_URL_PATH ) : '';

		if ( empty( $uri ) ) {
			return false;
		}

		$allowed = array_filter( array_map( 'trim', explode( "\n", $whitelist ) ) );

		foreach ( $allowed as $path ) {
			if ( strpos( $uri, $path ) === 0 ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Whether the current request targets a REST enumeration route.
	 *
	 * @since 1.0.0
	 * @return bool
	 */
	private function is_rest_enumeration() {
		if ( ! $this->settings->get( 'block_rest_api_users' ) ) {
			return false;
		}

		$is_rest = defined( 'REST_REQUEST' ) && REST_REQUEST;

		if ( ! $is_rest ) {
			$path = $this->get_request_path();

			if ( strpos( $path, 'wp-json/' ) === 0 ) {
				$is_rest = true;
			}
		}

		if ( ! $is_rest ) {
			return false;
		}

		$route = '';

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET['rest_route'] ) ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$route = sanitize_text_field( wp_unslash( $_GET['rest_route'] ) );
		} else {
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash
			$uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';

			if ( preg_match( '#/wp-json/([^?]+)#', $uri, $m ) ) {
				$route = '/' . $m[1];
			}
		}

		foreach ( array( '#^/wp/v2/users#', '#^/wp/v2/users/\d+#', '#^/oembed/1.0/proxy#' ) as $pattern ) {
			if ( preg_match( $pattern, $route ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Whether the given path targets the WordPress admin area.
	 *
	 * @since 1.0.0
	 * @param string $path Request path.
	 * @return bool
	 */
	private function is_admin_request( $path ) {
		$admin = trim( wp_parse_url( admin_url(), PHP_URL_PATH ) ?: '', '/' );

		return ! empty( $admin ) && ( $path === $admin || strpos( $path, $admin . '/' ) === 0 );
	}

	/**
	 * Whether a real frontend page exists at the given slug.
	 *
	 * @since 1.0.0
	 * @param string $slug Page slug.
	 * @return bool
	 */
	private function real_page_exists( $slug ) {
		$key    = 'jacklogu_page_check_' . md5( $slug );
		$cached = wp_cache_get( $key, 'jackerloginguard' );

		if ( false !== $cached ) {
			return (bool) $cached;
		}

		$query = new \WP_Query(
			array(
				'name'           => $slug,
				'post_type'      => get_post_types( array( 'public' => true ) ),
				'post_status'    => 'publish',
				'posts_per_page' => 1,
				'fields'         => 'ids',
				'no_found_rows'  => true,
			)
		);

		$exists = $query->have_posts();
		wp_cache_set( $key, $exists ? 1 : 0, 'jackerloginguard', HOUR_IN_SECONDS );

		return $exists;
	}

	/**
	 * Return the current request path (no query string, no leading/trailing slash).
	 *
	 * @since 1.0.0
	 * @return string
	 */
	private function get_clean_path() {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';

		return trim( strtok( $uri, '?' ), '/' );
	}

	/**
	 * Return the current request path.
	 *
	 * @since 1.0.0
	 * @return string
	 */
	private function get_request_path() {
		return $this->get_clean_path();
	}

	/**
	 * Terminate the request with the configured unauthorized response.
	 *
	 * @since 1.0.0
	 * @param string $reason Reason for the denial (used for logging only).
	 * @return void
	 */
	private function deny_response( $reason = '' ) {
		$mode = $this->settings->get( 'unauthorized_response', '0.0.0.0' );

		switch ( $mode ) {
			case '0.0.0.0':
				status_header( 200 );
				header( 'Content-Type: text/html; charset=utf-8' );
				// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				echo '0.0.0.0';
				exit;

			case '403':
				status_header( 403 );
				wp_die(
					esc_html__( 'Access Denied', 'jacker-login-guard' ),
					esc_html__( '403 - Forbidden', 'jacker-login-guard' ),
					array( 'response' => 403 )
				);
				exit;

			case 'homepage':
				wp_safe_redirect( home_url() );
				exit;

			case '404':
			default:
				$this->send_404();
		}
	}

	/**
	 * Emit a 404 response using the active theme's template when available.
	 *
	 * @since 1.0.0
	 * @return void
	 */
	private function send_404() {
		global $wp_query;

		if ( isset( $wp_query ) ) {
			$wp_query->set_404();
		}

		status_header( 404 );
		nocache_headers();

		$template = get_stylesheet_directory() . '/404.php';

		if ( file_exists( $template ) ) {
			include $template;
		} else {
			wp_die(
				esc_html__( 'Page not found', 'jacker-login-guard' ),
				esc_html__( '404 - Not Found', 'jacker-login-guard' ),
				array( 'response' => 404 )
			);
		}

		exit;
	}
}