<?php
/**
 * Main plugin bootstrap and common hooks.
 *
 * Instantiates every class and registers the hooks that apply to both the
 * frontend and the admin area.
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
 * Class Plugin
 *
 * @since 1.0.0
 */
class Plugin {

	/**
	 * Singleton instance.
	 *
	 * @since 1.0.0
	 * @var   Plugin|null
	 */
	private static $instance = null;

	/**
	 * Access-control instance.
	 *
	 * @since 1.0.0
	 * @var   AccessControl
	 */
	private $access_control;

	/**
	 * Admin instance (only created inside wp-admin).
	 *
	 * @since 1.0.0
	 * @var   Admin|null
	 */
	private $admin;

	/**
	 * Logger instance.
	 *
	 * @since 1.0.0
	 * @var   Logger
	 */
	private $logger;

	/**
	 * Session tracker instance.
	 *
	 * @since 1.0.0
	 * @var   SessionTracker
	 */
	private $session_tracker;

	/**
	 * Get the singleton instance.
	 *
	 * @since 1.0.0
	 * @return Plugin
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Constructor. Wires up every plugin class and its hooks.
	 *
	 * @since 1.0.0
	 */
	private function __construct() {
		$this->logger          = new Logger();
		$this->access_control  = new AccessControl();
		$this->session_tracker = new SessionTracker();

		$this->logger->register_hooks();
		$this->access_control->register_hooks();
		$this->session_tracker->register_hooks();

		$this->register_common_hooks();

		if ( is_admin() ) {
			$this->admin = new Admin();
			$this->admin->register_hooks();
		}
	}

	/**
	 * Register hooks that must fire on both frontend and admin.
	 *
	 * @since 1.0.0
	 * @return void
	 */
	private function register_common_hooks() {
		add_filter( 'body_class', array( $this, 'remove_author_body_class' ) );
		add_filter( 'the_author', array( $this, 'hide_author_in_feed' ) );
		add_filter( 'get_the_author', array( $this, 'hide_author_in_feed' ) );
		add_filter( 'login_errors', array( $this, 'custom_login_error' ) );
		add_filter( 'author_link', array( $this, 'filter_author_link' ), 10, 3 );
		add_filter( 'robots_txt', array( $this, 'filter_robots' ), 10, 2 );
		add_action( 'send_headers', array( $this, 'add_security_headers' ) );
		add_action( 'wp_footer', array( $this, 'output_heartbeat_script' ), 99 );
		add_action( 'wp_logout', array( $this, 'clear_gate_cookie_on_logout' ) );
		add_filter( 'logout_redirect', array( $this, 'redirect_after_logout' ), 10, 3 );
	}

	/**
	 * Redirect the user to the custom login gate after logout.
	 *
	 * WordPress otherwise sends them to `wp-login.php?loggedout=true`,
	 * which is intercepted by the access gate (the user is now logged out
	 * and has no valid token). Sending them to the hidden login gate is a
	 * clean experience and keeps the single-entry rule intact.
	 *
	 * @since 1.0.0
	 * @param string       $redirect_to           Default redirect URL.
	 * @param string       $requested_redirect_to Requested redirect URL.
	 * @param \WP_User|int $user                  Logged-out user or user ID.
	 * @return string Filtered redirect URL.
	 */
	public function redirect_after_logout( $redirect_to, $requested_redirect_to, $user ) {
		if ( ! empty( $requested_redirect_to ) ) {
			return $redirect_to;
		}

		$slug = trim( Settings::get_instance()->get( 'slug', JACKLOGU_DEFAULT_SLUG ), '/' );

		if ( empty( $slug ) ) {
			return home_url( '/' );
		}

		return home_url( '/' . $slug . '/' );
	}

	/**
	 * Output the heartbeat script on frontend pages.
	 *
	 * @since 1.0.0
	 * @return void
	 */
	public function output_heartbeat_script() {
		if ( ! is_user_logged_in() ) {
			return;
		}

		if ( is_admin() ) {
			return;
		}

		$nonce    = wp_create_nonce( 'jacklogu_heartbeat' );
		$ajax_url = admin_url( 'admin-ajax.php' );
		?>
		<script>
		(function() {
			var AJAX_URL = <?php echo wp_json_encode( $ajax_url ); ?>;
			var NONCE    = <?php echo wp_json_encode( $nonce ); ?>;
			var INTERVAL = 5 * 60 * 1000;

			function beat() {
				if (document.visibilityState !== 'visible') { return; }

				var xhr = new XMLHttpRequest();
				xhr.open('POST', AJAX_URL, true);
				xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8');
				xhr.send('action=jacklogu_heartbeat&nonce=' + encodeURIComponent(NONCE));
			}

			beat();
			setInterval(beat, INTERVAL);

			document.addEventListener('visibilitychange', function() {
				if (document.visibilityState === 'visible') { beat(); }
			});
		})();
		</script>
		<?php
	}

	/**
	 * Clear the temporary login-gate cookie on logout.
	 *
	 * @since 1.0.0
	 * @return void
	 */
	public function clear_gate_cookie_on_logout() {
		if ( ! isset( $_COOKIE[ JACKLOGU_AUTH_COOKIE ] ) ) {
			return;
		}

		$params = array(
			'expires'  => time() - HOUR_IN_SECONDS,
			'path'     => COOKIEPATH ? COOKIEPATH : '/',
			'domain'   => defined( 'COOKIE_DOMAIN' ) && COOKIE_DOMAIN ? COOKIE_DOMAIN : '',
			'secure'   => is_ssl(),
			'httponly' => true,
			'samesite' => 'Lax',
		);

		if ( PHP_VERSION_ID >= 70300 ) {
			setcookie( JACKLOGU_AUTH_COOKIE, '', $params );
		} else {
			setcookie(
				JACKLOGU_AUTH_COOKIE,
				'',
				$params['expires'],
				$params['path'] . '; SameSite=Lax',
				$params['domain'],
				$params['secure'],
				$params['httponly']
			);
		}

		unset( $_COOKIE[ JACKLOGU_AUTH_COOKIE ] );
	}

	/**
	 * Remove `author-*` classes from the body element.
	 *
	 * @since 1.0.0
	 * @param string[] $classes Body classes.
	 * @return string[] Filtered classes.
	 */
	public function remove_author_body_class( $classes ) {
		if ( ! Settings::get_instance()->get( 'remove_author_body_class' ) ) {
			return $classes;
		}

		foreach ( $classes as $key => $class ) {
			if ( strpos( $class, 'author-' ) === 0 ) {
				unset( $classes[ $key ] );
			}
		}

		return array_values( $classes );
	}

	/**
	 * Replace the author name with the site name inside feeds.
	 *
	 * @since 1.0.0
	 * @param string $name Author display name.
	 * @return string Filtered name.
	 */
	public function hide_author_in_feed( $name ) {
		if ( Settings::get_instance()->get( 'hide_author_in_feed' ) && is_feed() ) {
			return get_bloginfo( 'name' );
		}
		return $name;
	}

	/**
	 * Replace verbose login errors with a single generic message.
	 *
	 * @since 1.0.0
	 * @param string $error Original error HTML.
	 * @return string Filtered error HTML.
	 */
	public function custom_login_error( $error ) {
		if ( ! Settings::get_instance()->get( 'unify_login_errors' ) ) {
			return $error;
		}

		$patterns = array(
			'The password you entered for the username',
			'Invalid username',
			'The email could not be sent',
			'Unknown email address',
			'There is no user registered with that email',
		);

		foreach ( $patterns as $pattern ) {
			if ( strpos( $error, $pattern ) !== false ) {
				return '<strong>' . esc_html__( 'ERROR', 'jacker-login-guard' ) . '</strong>: ' . esc_html__( 'Invalid username or password.', 'jacker-login-guard' );
			}
		}

		return $error;
	}

	/**
	 * Redirect author links to the homepage when author enumeration is blocked.
	 *
	 * @since 1.0.0
	 * @param string $link            Author archive URL.
	 * @param int    $author_id       Author user ID.
	 * @param string $author_nicename Author nicename.
	 * @return string Filtered URL.
	 */
	public function filter_author_link( $link, $author_id, $author_nicename ) {
		if ( Settings::get_instance()->get( 'block_author_enum' ) && ! is_user_logged_in() ) {
			return home_url( '/' );
		}
		return $link;
	}

	/**
	 * Append Disallow rules to robots.txt.
	 *
	 * @since 1.0.0
	 * @param string $output The generated robots.txt content.
	 * @param bool   $public Whether the site is publicly visible.
	 * @return string Filtered robots.txt content.
	 */
	public function filter_robots( $output, $public ) {
		if ( ! $public ) {
			return $output;
		}

		$output .= "Disallow: /wp-login.php\n";
		$output .= "Disallow: /wp-admin/\n";
		$output .= "Disallow: /wp-json/\n";
		$output .= "Disallow: /xmlrpc.php\n";
		$output .= "Disallow: /*?author=\n";

		return $output;
	}

	/**
	 * Send basic security headers.
	 *
	 * @since 1.0.0
	 * @return void
	 */
	public function add_security_headers() {
		if ( ! Settings::get_instance()->get( 'enable_security_headers' ) || headers_sent() ) {
			return;
		}

		remove_action( 'wp_head', 'wp_generator' );

		header( 'X-Content-Type-Options: nosniff' );
		header( 'X-Frame-Options: SAMEORIGIN' );
		header( 'Referrer-Policy: strict-origin-when-cross-origin' );
		header( 'Permissions-Policy: geolocation=(), microphone=(), camera=()' );

		if ( is_ssl() ) {
			header( 'Strict-Transport-Security: max-age=31536000; includeSubDomains' );
		}

		header_remove( 'X-Powered-By' );
	}
}