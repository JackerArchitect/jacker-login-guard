<?php
/**
 * Admin interface.
 *
 * Renders the plugin settings page, tab navigation, log viewers, current
 * login list, and handles every admin action (bulk actions, IP list edits,
 * settings import/export).
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
 * Class Admin
 *
 * @since 1.0.0
 */
class Admin {

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
		add_action( 'admin_menu', array( $this, 'add_menu' ) );
		add_action( 'admin_init', array( $this->settings, 'register' ) );
		add_action( 'admin_init', array( $this, 'handle_actions' ) );
		add_action( 'admin_init', array( $this, 'handle_reset' ) );
		add_action( 'admin_init', array( $this, 'handle_import_export' ) );
		add_action( 'admin_notices', array( $this, 'show_reset_notice' ) );
		add_action( 'admin_notices', array( $this, 'show_settings_errors' ) );
		add_filter( 'plugin_action_links', array( $this, 'action_links' ), 10, 2 );

		add_action( 'wp_ajax_jacklogu_get_current_logins', array( $this, 'ajax_get_current_logins' ) );
		add_action( 'wp_ajax_jacklogu_geo_lookup', array( $this, 'ajax_geo_lookup' ) );
	}

	/**
	 * Register the plugin's options page.
	 *
	 * @since 1.0.0
	 * @return void
	 */
	public function add_menu() {
		add_options_page(
			__( 'Jacker Login Guard', 'jacker-login-guard' ),
			__( 'Login Guard', 'jacker-login-guard' ),
			'manage_options',
			'jacker-login-guard',
			array( $this, 'render_page' )
		);
	}

	/**
	 * Render the main admin page.
	 *
	 * @since 1.0.0
	 * @return void
	 */
	public function render_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$tab  = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : 'dashboard';
		$tabs = array(
			'dashboard'     => __( 'Dashboard', 'jacker-login-guard' ),
			'settings'      => __( 'Settings', 'jacker-login-guard' ),
			'login-events'  => __( 'Login Events', 'jacker-login-guard' ),
			'current-login' => __( 'Current Login', 'jacker-login-guard' ),
			'access-log'    => __( 'Access Log', 'jacker-login-guard' ),
			'auto-block'    => __( 'Auto Block List', 'jacker-login-guard' ),
		);
		?>
		<div class="wrap">
			<h1><?php echo esc_html( get_admin_page_title() ); ?></h1>

			<h2 class="nav-tab-wrapper">
				<?php foreach ( $tabs as $key => $label ) : ?>
					<a href="?page=jacker-login-guard&tab=<?php echo esc_attr( $key ); ?>"
					   class="nav-tab <?php echo $tab === $key ? 'nav-tab-active' : ''; ?>">
						<?php echo esc_html( $label ); ?>
					</a>
				<?php endforeach; ?>
			</h2>

			<?php
			switch ( $tab ) {
				case 'settings':
					$this->render_settings();
					break;
				case 'login-events':
					$this->render_login_events();
					break;
				case 'current-login':
					$this->render_current_login();
					break;
				case 'access-log':
					$this->render_access_log();
					break;
				case 'auto-block':
					$this->render_auto_block();
					break;
				default:
					$this->render_dashboard();
			}

			$this->render_heartbeat_script();
			$this->render_geo_flag_script();
			$this->render_table_scripts();
			?>
		</div>
		<?php
	}

	/**
	 * Output the shared JS used by every log table.
	 *
	 * Handles the "select all" master checkbox. Runs on every admin page
	 * load, independent of pagination, so it also works when a log has
	 * fewer than one page of entries.
	 *
	 * @since 1.0.0
	 * @return void
	 */
	private function render_table_scripts() {
		?>
		<script>
		document.addEventListener('DOMContentLoaded', function() {
			document.querySelectorAll('.jacklogu-select-all').forEach(function(master) {
				master.addEventListener('change', function() {
					var table = master.closest('table');
					if (!table) { return; }

					table.querySelectorAll('.jacklogu-bulk-select').forEach(function(cb) {
						cb.checked = master.checked;
					});
				});
			});
		});
		</script>
		<?php
	}

	/**
	 * Output the heartbeat script used by the Current Login tab.
	 *
	 * @since 1.0.0
	 * @return void
	 */
	private function render_heartbeat_script() {
		if ( ! is_user_logged_in() ) {
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
	 * Output the JS that batch-fills country flags via AJAX.
	 *
	 * @since 1.0.0
	 * @return void
	 */
	private function render_geo_flag_script() {
		$nonce    = wp_create_nonce( 'jacklogu_geo_lookup' );
		$ajax_url = admin_url( 'admin-ajax.php' );
		?>
		<script>
		(function() {
			var AJAX_URL = <?php echo wp_json_encode( $ajax_url ); ?>;
			var NONCE    = <?php echo wp_json_encode( $nonce ); ?>;

			function collectIps() {
				var seen = {};
				var ips  = [];
				document.querySelectorAll('.jacklogu-flag-placeholder').forEach(function(el) {
					var ip = el.getAttribute('data-ip');
					if (!ip || seen[ip]) { return; }
					seen[ip] = true;
					ips.push(ip);
				});
				return ips;
			}

			function applyFlags(flags) {
				document.querySelectorAll('.jacklogu-flag-placeholder').forEach(function(el) {
					var ip = el.getAttribute('data-ip');
					if (flags[ip]) {
						el.outerHTML = flags[ip];
					} else {
						el.outerHTML = '';
					}
				});
			}

			function fetchFlags() {
				var ips = collectIps();
				if (ips.length === 0) { return; }

				var body = 'action=jacklogu_geo_lookup&nonce=' + encodeURIComponent(NONCE);
				ips.forEach(function(ip) {
					body += '&ips[]=' + encodeURIComponent(ip);
				});

				var xhr = new XMLHttpRequest();
				xhr.open('POST', AJAX_URL, true);
				xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8');
				xhr.onload = function() {
					if (xhr.status !== 200) { return; }
					try {
						var resp = JSON.parse(xhr.responseText);
						if (resp.success && resp.data.flags) {
							applyFlags(resp.data.flags);
						}
					} catch (e) {}
				};
				xhr.send(body);
			}

			window.jackloguFetchFlags = fetchFlags;

			if (document.readyState === 'loading') {
				document.addEventListener('DOMContentLoaded', fetchFlags);
			} else {
				fetchFlags();
			}
		})();
		</script>
		<?php
	}

	/**
	 * Render the Dashboard tab.
	 *
	 * @since 1.0.0
	 * @return void
	 */
	private function render_dashboard() {
		global $wpdb;

		$login_table      = Tables::get( JACKLOGU_LOGIN_TABLE );
		$access_table     = Tables::get( JACKLOGU_ACCESS_TABLE );
		$auto_block_table = Tables::get( JACKLOGU_AUTO_BLOCK_TABLE );

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$last_login = $wpdb->get_var( "SELECT login_time FROM {$login_table} WHERE status = 'success' ORDER BY id DESC LIMIT 1" );

		$blocked_24h = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$access_table} WHERE event_time > %s AND status = %s",
				gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS ),
				'blocked'
			)
		);

		$total_blocked_requests = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$access_table} WHERE status = %s",
				'blocked'
			)
		);

		$total_auto_blocked_ips = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$auto_block_table} WHERE is_active = 1" );

		$total_sessions = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$wpdb->usermeta} WHERE meta_key = %s",
				'session_tokens'
			)
		);
		// phpcs:enable

		$logins = $this->get_current_logins();

		$online_count = 0;
		$admin_online = 0;

		foreach ( $logins as $login ) {
			$online_count++;

			if ( 'administrator' === $login['role'] ) {
				$admin_online++;
			}
		}
		?>
		<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:15px;margin:20px 0;">
			<div style="background:#fff;padding:18px 20px;border-radius:6px;border-left:4px solid #46b450;">
				<div style="font-size:12px;color:#888;text-transform:uppercase;"><?php esc_html_e( 'Last Login', 'jacker-login-guard' ); ?></div>
				<div style="font-size:18px;font-weight:600;color:#1d2327;margin-top:4px;"><?php echo esc_html( $last_login ? $last_login : __( 'Never', 'jacker-login-guard' ) ); ?></div>
			</div>
			<div style="background:#fff;padding:18px 20px;border-radius:6px;border-left:4px solid #2271b1;">
				<div style="font-size:12px;color:#888;text-transform:uppercase;"><?php esc_html_e( 'Admin Online', 'jacker-login-guard' ); ?></div>
				<div style="font-size:24px;font-weight:700;color:#1d2327;margin-top:4px;"><?php echo esc_html( $admin_online ); ?></div>
			</div>
			<div style="background:#fff;padding:18px 20px;border-radius:6px;border-left:4px solid #46b450;">
				<div style="font-size:12px;color:#888;text-transform:uppercase;"><?php esc_html_e( 'All Online Users', 'jacker-login-guard' ); ?></div>
				<div style="font-size:24px;font-weight:700;color:#46b450;margin-top:4px;"><?php echo esc_html( $online_count ); ?></div>
			</div>
			<div style="background:#fff;padding:18px 20px;border-radius:6px;border-left:4px solid #9b59b6;">
				<div style="font-size:12px;color:#888;text-transform:uppercase;"><?php esc_html_e( 'Total Sessions', 'jacker-login-guard' ); ?></div>
				<div style="font-size:24px;font-weight:700;color:#1d2327;margin-top:4px;"><?php echo esc_html( $total_sessions ); ?></div>
			</div>
			<div style="background:#fff;padding:18px 20px;border-radius:6px;border-left:4px solid #dc3232;">
				<div style="font-size:12px;color:#888;text-transform:uppercase;"><?php esc_html_e( 'Blocked (24h)', 'jacker-login-guard' ); ?></div>
				<div style="font-size:24px;font-weight:700;color:#dc3232;margin-top:4px;"><?php echo esc_html( $blocked_24h ); ?></div>
			</div>
			<div style="background:#fff;padding:18px 20px;border-radius:6px;border-left:4px solid #d63638;">
				<div style="font-size:12px;color:#888;text-transform:uppercase;"><?php esc_html_e( 'Total Blocked', 'jacker-login-guard' ); ?></div>
				<div style="font-size:24px;font-weight:700;color:#d63638;margin-top:4px;"><?php echo esc_html( number_format_i18n( $total_blocked_requests ) ); ?></div>
			</div>
			<div style="background:#fff;padding:18px 20px;border-radius:6px;border-left:4px solid #8b0000;">
				<div style="font-size:12px;color:#888;text-transform:uppercase;"><?php esc_html_e( 'Auto-Blocked IPs', 'jacker-login-guard' ); ?></div>
				<div style="font-size:24px;font-weight:700;color:#8b0000;margin-top:4px;"><?php echo esc_html( number_format_i18n( $total_auto_blocked_ips ) ); ?></div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the Settings tab.
	 *
	 * @since 1.0.0
	 * @return void
	 */
	private function render_settings() {
		$slug      = trim( $this->settings->get( 'slug', JACKLOGU_DEFAULT_SLUG ), '/' );
		$log_limit = $this->settings->get_log_limit();
		$data      = $this->settings->get_all();
		?>
		<div class="notice notice-info inline" style="margin:15px 0;padding:10px 15px;">
			<p>
				<strong><?php esc_html_e( 'Hidden Entry URL:', 'jacker-login-guard' ); ?></strong>
				<code id="jacklogu-url"><?php echo esc_html( home_url( '/' . $slug . '/' ) ); ?></code>
				<button type="button" class="button button-small" onclick="navigator.clipboard.writeText(document.getElementById('jacklogu-url').textContent);this.textContent='<?php echo esc_js( __( 'Copied!', 'jacker-login-guard' ) ); ?>';">
					<?php esc_html_e( 'Copy', 'jacker-login-guard' ); ?>
				</button>
			</p>
			<p style="color:#666;font-size:13px;margin-top:10px;">
				<?php esc_html_e( 'Note: If you encounter a 404 error on first use, please visit Settings > Permalinks and click "Save Changes".', 'jacker-login-guard' ); ?>
			</p>
		</div>

		<form method="post" action="options.php">
			<?php settings_fields( 'jacklogu_settings_group' ); ?>
			<table class="form-table">
				<tr>
					<th scope="row"><?php esc_html_e( 'Login Slug', 'jacker-login-guard' ); ?></th>
					<td>
						<input type="text" name="<?php echo esc_attr( JACKLOGU_OPTION_KEY ); ?>[slug]" value="<?php echo esc_attr( $data['slug'] ); ?>" class="regular-text" />
						<p class="description"><?php esc_html_e( 'Single URL slug (lowercase letters, numbers, hyphens). Example: my-login', 'jacker-login-guard' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Login Protection Mode', 'jacker-login-guard' ); ?></th>
					<td>
						<label>
							<input type="radio" name="<?php echo esc_attr( JACKLOGU_OPTION_KEY ); ?>[login_protection_mode]" value="compatibility" <?php checked( $data['login_protection_mode'], 'compatibility' ); ?> />
							<strong><?php esc_html_e( 'Compatibility Mode (Recommended)', 'jacker-login-guard' ); ?></strong>
						</label>
						<br><br>
						<label>
							<input type="radio" name="<?php echo esc_attr( JACKLOGU_OPTION_KEY ); ?>[login_protection_mode]" value="strict" <?php checked( $data['login_protection_mode'], 'strict' ); ?> />
							<strong><?php esc_html_e( 'Strict Mode', 'jacker-login-guard' ); ?></strong>
						</label>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Unauthorized Response', 'jacker-login-guard' ); ?></th>
					<td>
						<?php
						$responses = array(
							'0.0.0.0'  => __( 'Return 0.0.0.0 (Recommended)', 'jacker-login-guard' ),
							'404'      => __( 'Return 404 Not Found', 'jacker-login-guard' ),
							'403'      => __( 'Return 403 Forbidden', 'jacker-login-guard' ),
							'homepage' => __( 'Redirect to homepage', 'jacker-login-guard' ),
						);
						foreach ( $responses as $value => $label ) :
							?>
							<label style="display:block;margin-bottom:6px;">
								<input type="radio" name="<?php echo esc_attr( JACKLOGU_OPTION_KEY ); ?>[unauthorized_response]" value="<?php echo esc_attr( $value ); ?>" <?php checked( $data['unauthorized_response'], $value ); ?> />
								<?php echo esc_html( $label ); ?>
							</label>
						<?php endforeach; ?>
					</td>
				</tr>

				<tr>
					<th scope="row"><?php esc_html_e( 'Whitelist IPs', 'jacker-login-guard' ); ?></th>
					<td>
						<textarea name="<?php echo esc_attr( JACKLOGU_OPTION_KEY ); ?>[whitelist_ips]" rows="6" class="large-text code" placeholder="192.168.1.100
10.0.0.0/8
2001:db8::1
203.0.113.0/24"><?php echo esc_textarea( $data['whitelist_ips'] ); ?></textarea>
						<p class="description">
							<strong><?php esc_html_e( 'One IP or CIDR range per line.', 'jacker-login-guard' ); ?></strong><br>
							<?php esc_html_e( 'Formats supported:', 'jacker-login-guard' ); ?>
						</p>
						<ul style="margin:6px 0 0 20px;font-size:13px;color:#555;">
							<li><code>192.168.1.100</code> — <?php esc_html_e( 'single IPv4 address', 'jacker-login-guard' ); ?></li>
							<li><code>10.0.0.0/8</code> — <?php esc_html_e( 'IPv4 CIDR range (10.0.0.0 to 10.255.255.255)', 'jacker-login-guard' ); ?></li>
							<li><code>203.0.113.0/24</code> — <?php esc_html_e( 'IPv4 CIDR range (203.0.113.0 to 203.0.113.255)', 'jacker-login-guard' ); ?></li>
							<li><code>2001:db8::1</code> — <?php esc_html_e( 'single IPv6 address', 'jacker-login-guard' ); ?></li>
							<li><code>2001:db8::/32</code> — <?php esc_html_e( 'IPv6 CIDR range', 'jacker-login-guard' ); ?></li>
							<li><code>192.168.1.100 # My Office</code> — <?php esc_html_e( 'with a comment after # (optional, for your reference)', 'jacker-login-guard' ); ?></li>
						</ul>
						<p class="description" style="color:#2271b1;">
							<?php esc_html_e( 'Whitelisted IPs bypass ALL protection rules and are never blocked, blacklisted, or auto-blocked.', 'jacker-login-guard' ); ?>
						</p>
					</td>
				</tr>

				<tr>
					<th scope="row"><?php esc_html_e( 'Blacklist IPs', 'jacker-login-guard' ); ?></th>
					<td>
						<textarea name="<?php echo esc_attr( JACKLOGU_OPTION_KEY ); ?>[blacklist_ips]" rows="6" class="large-text code" placeholder="203.0.113.55
198.51.100.0/24
2001:db8:bad::/48
192.0.2.10 # Spam bot"><?php echo esc_textarea( $data['blacklist_ips'] ); ?></textarea>
						<p class="description">
							<strong><?php esc_html_e( 'One IP or CIDR range per line.', 'jacker-login-guard' ); ?></strong><br>
							<?php esc_html_e( 'Same format as Whitelist:', 'jacker-login-guard' ); ?>
						</p>
						<ul style="margin:6px 0 0 20px;font-size:13px;color:#555;">
							<li><code>203.0.113.55</code> — <?php esc_html_e( 'block a single IPv4 address', 'jacker-login-guard' ); ?></li>
							<li><code>198.51.100.0/24</code> — <?php esc_html_e( 'block an entire IPv4 subnet', 'jacker-login-guard' ); ?></li>
							<li><code>2001:db8:bad::/48</code> — <?php esc_html_e( 'block an IPv6 range', 'jacker-login-guard' ); ?></li>
							<li><code>192.0.2.10 # Spam bot</code> — <?php esc_html_e( 'with a comment (optional, after #)', 'jacker-login-guard' ); ?></li>
						</ul>
						<p class="description" style="color:#d63638;">
							<strong><?php esc_html_e( 'Blacklist always takes priority over Whitelist.', 'jacker-login-guard' ); ?></strong><br>
							<?php esc_html_e( 'Blacklisted IPs are permanently denied. If an IP appears on both lists, it will be blocked.', 'jacker-login-guard' ); ?>
						</p>
					</td>
				</tr>

				<tr>
					<th scope="row"><?php esc_html_e( 'API Whitelist', 'jacker-login-guard' ); ?></th>
					<td>
						<textarea name="<?php echo esc_attr( JACKLOGU_OPTION_KEY ); ?>[api_whitelist]" rows="5" class="large-text code" placeholder="/wp-json/jetpack/v4/
/wp-json/woocommerce/v1/"><?php echo esc_textarea( $data['api_whitelist'] ); ?></textarea>
						<p class="description"><?php esc_html_e( 'One endpoint per line. Use full path starting with /wp-json/', 'jacker-login-guard' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Path Whitelist', 'jacker-login-guard' ); ?></th>
					<td>
						<textarea name="<?php echo esc_attr( JACKLOGU_OPTION_KEY ); ?>[path_whitelist]" rows="5" class="large-text code" placeholder="/wp-admin/admin-ajax.php
/wp-cron.php"><?php echo esc_textarea( $data['path_whitelist'] ); ?></textarea>
						<p class="description"><?php esc_html_e( 'One path per line. Paths starting with /', 'jacker-login-guard' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Log Retention Limit', 'jacker-login-guard' ); ?></th>
					<td>
						<input type="number" name="<?php echo esc_attr( JACKLOGU_OPTION_KEY ); ?>[log_retention_limit]" value="<?php echo esc_attr( $log_limit ); ?>" min="10" max="5000" class="small-text" />
						<p class="description"><?php esc_html_e( 'Recommended: 300 entries per log table. Lower saves space, higher keeps more history.', 'jacker-login-guard' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Session Lifetime', 'jacker-login-guard' ); ?></th>
					<td>
						<input type="number" name="<?php echo esc_attr( JACKLOGU_OPTION_KEY ); ?>[session_lifetime]" value="<?php echo esc_attr( isset( $data['session_lifetime'] ) ? $data['session_lifetime'] : 0 ); ?>" min="0" max="10080" step="1" class="small-text" />
						<span><?php esc_html_e( 'minutes', 'jacker-login-guard' ); ?></span>
						<p class="description">
							<?php esc_html_e( 'Auto-logout users after this many minutes of inactivity. Set to 0 to use WordPress default (2 days). Range: 0-10080 (7 days).', 'jacker-login-guard' ); ?>
							<br>
							<strong style="color:#d63638;">
								<?php esc_html_e( 'Note: Timer resets on every action. Users are only logged out after complete inactivity.', 'jacker-login-guard' ); ?>
							</strong>
						</p>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Auto-Block Trigger', 'jacker-login-guard' ); ?></th>
					<td>
						<input type="number"
							   name="<?php echo esc_attr( JACKLOGU_OPTION_KEY ); ?>[auto_block_trigger_threshold]"
							   value="<?php echo esc_attr( $this->settings->get_auto_block_trigger_threshold() ); ?>"
							   min="1" max="100" step="1" class="small-text" />
						<span><?php esc_html_e( 'attacks', 'jacker-login-guard' ); ?></span>
						<p class="description">
							<?php esc_html_e( 'An IP is blocked only after this many attack attempts. Recommended: 3.', 'jacker-login-guard' ); ?>
						</p>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Auto-Block Duration', 'jacker-login-guard' ); ?></th>
					<td>
						<input type="number"
							   name="<?php echo esc_attr( JACKLOGU_OPTION_KEY ); ?>[auto_block_duration_hours]"
							   value="<?php echo esc_attr( intval( $this->settings->get( 'auto_block_duration_hours', 24 ) ) ); ?>"
							   min="1" max="8760" step="1" class="small-text" />
						<span><?php esc_html_e( 'hours', 'jacker-login-guard' ); ?></span>
						<p class="description">
							<?php esc_html_e( 'How long the block lasts before the IP is automatically unblocked. Recommended: 24 hours.', 'jacker-login-guard' ); ?>
						</p>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Auto-Block Escalation', 'jacker-login-guard' ); ?></th>
					<td>
						<input type="number"
							   name="<?php echo esc_attr( JACKLOGU_OPTION_KEY ); ?>[auto_block_to_blacklist_threshold]"
							   value="<?php echo esc_attr( $this->settings->get_auto_block_to_blacklist_threshold() ); ?>"
							   min="0" max="100" step="1" class="small-text" />
						<span><?php esc_html_e( 'times', 'jacker-login-guard' ); ?></span>
						<p class="description">
							<?php esc_html_e( 'When the same IP is blocked this many times, it is automatically added to the permanent Blacklist.', 'jacker-login-guard' ); ?>
							<br>
							<?php esc_html_e( 'Set to 0 to disable auto-escalation. Recommended: 3.', 'jacker-login-guard' ); ?>
						</p>
						<p class="description" style="color:#666;">
							<strong><?php esc_html_e( 'How it works:', 'jacker-login-guard' ); ?></strong>
							<?php esc_html_e( 'Every time an IP is auto-blocked counts as one cycle. Once an IP reaches this many block cycles, it is added to Blacklist IPs above, where it stays permanently until manually removed.', 'jacker-login-guard' ); ?>
						</p>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Trusted IP Window', 'jacker-login-guard' ); ?></th>
					<td>
						<input type="number"
							   name="<?php echo esc_attr( JACKLOGU_OPTION_KEY ); ?>[trusted_ip_window_days]"
							   value="<?php echo esc_attr( intval( $this->settings->get( 'trusted_ip_window_days', 7 ) ) ); ?>"
							   min="0" max="365" step="1" class="small-text" />
						<span><?php esc_html_e( 'days', 'jacker-login-guard' ); ?></span>
						<p class="description">
							<?php esc_html_e( 'After a successful login, the same IP is protected from auto-blocking for this many days. Set to 0 to disable.', 'jacker-login-guard' ); ?>
						</p>
						<p class="description" style="color:#2271b1;">
							<?php esc_html_e( 'This prevents the admin from accidentally blocking themselves when their session expires. Recommended: 7 days.', 'jacker-login-guard' ); ?>
						</p>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Security Options', 'jacker-login-guard' ); ?></th>
					<td>
						<?php
						$checkboxes = array(
							'enable_security_headers'  => __( 'Add basic Security Headers', 'jacker-login-guard' ),
							'enable_logging'           => __( 'Enable Event Logging', 'jacker-login-guard' ),
							'block_xmlrpc'             => __( 'Block XML-RPC', 'jacker-login-guard' ),
							'block_author_enum'        => __( 'Block Author Enumeration', 'jacker-login-guard' ),
							'block_rest_api_users'     => __( 'Protect REST API User Enumeration', 'jacker-login-guard' ),
							'remove_author_body_class' => __( 'Remove Username from Body Class', 'jacker-login-guard' ),
							'hide_author_in_feed'      => __( 'Hide Author Name in RSS Feed', 'jacker-login-guard' ),
							'unify_login_errors'       => __( 'Unify Login Error Messages', 'jacker-login-guard' ),
							'auto_block_attacks'       => __( 'Auto-block malicious attacks', 'jacker-login-guard' ),
						);
						foreach ( $checkboxes as $key => $label ) :
							?>
							<label style="display:block;margin-bottom:6px;">
								<input type="hidden" name="<?php echo esc_attr( JACKLOGU_OPTION_KEY ); ?>[<?php echo esc_attr( $key ); ?>]" value="0" />
								<input type="checkbox" name="<?php echo esc_attr( JACKLOGU_OPTION_KEY ); ?>[<?php echo esc_attr( $key ); ?>]" value="1" <?php checked( ! empty( $data[ $key ] ) ); ?> />
								<?php echo esc_html( $label ); ?>
							</label>
						<?php endforeach; ?>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Advanced Options', 'jacker-login-guard' ); ?></th>
					<td>
						<label style="display:block;margin-bottom:6px;">
							<input type="hidden" name="<?php echo esc_attr( JACKLOGU_OPTION_KEY ); ?>[bind_ip_to_cookie]" value="0" />
							<input type="checkbox" name="<?php echo esc_attr( JACKLOGU_OPTION_KEY ); ?>[bind_ip_to_cookie]" value="1" <?php checked( ! empty( $data['bind_ip_to_cookie'] ) ); ?> />
							<?php esc_html_e( 'Bind login access cookie to client IP address (stricter)', 'jacker-login-guard' ); ?>
						</label>
						<p class="description"><?php esc_html_e( 'When enabled, the one-time login access cookie is only valid for the same IP. Not recommended for mobile users with changing IPs.', 'jacker-login-guard' ); ?></p>
					</td>
				</tr>
			</table>
			<?php submit_button(); ?>
		</form>

		<hr />
		<h2><?php esc_html_e( 'Danger Zone', 'jacker-login-guard' ); ?></h2>

		<form method="post">
			<?php wp_nonce_field( 'jacklogu_reset_action', 'jacklogu_reset_nonce' ); ?>
			<input type="hidden" name="jacklogu_action" value="reset_settings_post" />
			<button type="submit" class="button" style="color:#dc3232;border-color:#dc3232;"
					onclick="return confirm('<?php echo esc_js( __( 'Are you sure? This will reset all settings.', 'jacker-login-guard' ) ); ?>');">
				<?php esc_html_e( 'Reset All Settings to Default', 'jacker-login-guard' ); ?>
			</button>
		</form>

		<h3><?php esc_html_e( 'Data Retention on Plugin Deletion', 'jacker-login-guard' ); ?></h3>
		<form method="post" action="options.php">
			<?php settings_fields( 'jacklogu_settings_group' ); ?>
			<input type="hidden" name="<?php echo esc_attr( JACKLOGU_OPTION_KEY ); ?>[uninstall_remove_data]" value="0" />
			<label style="display:block;margin:8px 0;">
				<input type="checkbox" name="<?php echo esc_attr( JACKLOGU_OPTION_KEY ); ?>[uninstall_remove_data]" value="1" <?php checked( ! empty( $data['uninstall_remove_data'] ) ); ?> />
				<?php esc_html_e( 'Remove ALL plugin data when deleting the plugin', 'jacker-login-guard' ); ?>
			</label>
			<p class="description" style="color:#d63638;">
				<?php esc_html_e( 'Warning: When checked, uninstalling the plugin will permanently delete all settings, logs, and custom tables. This cannot be undone.', 'jacker-login-guard' ); ?>
			</p>
			<?php submit_button( __( 'Save Retention Setting', 'jacker-login-guard' ), 'secondary' ); ?>
		</form>

		<h3><?php esc_html_e( 'Import / Export', 'jacker-login-guard' ); ?></h3>
		<form method="post" style="display:inline-block;">
			<?php wp_nonce_field( 'jacklogu_export_action', 'jacklogu_export_nonce' ); ?>
			<input type="hidden" name="jacklogu_action" value="export_settings" />
			<button type="submit" class="button"><?php esc_html_e( 'Download Settings', 'jacker-login-guard' ); ?></button>
		</form>
		<form method="post" enctype="multipart/form-data" style="display:inline-block;margin-left:10px;">
			<?php wp_nonce_field( 'jacklogu_import_action', 'jacklogu_import_nonce' ); ?>
			<input type="hidden" name="jacklogu_action" value="import_settings" />
			<input type="file" name="jacklogu_settings_file" accept=".json" required />
			<button type="submit" class="button" onclick="return confirm('<?php echo esc_js( __( 'Overwrite current settings?', 'jacker-login-guard' ) ); ?>');">
				<?php esc_html_e( 'Import', 'jacker-login-guard' ); ?>
			</button>
		</form>
		<?php
	}

	/**
	 * Render the Login Events tab.
	 *
	 * @since 1.0.0
	 * @return void
	 */
	private function render_login_events() {
		global $wpdb;

		$table = Tables::get( JACKLOGU_LOGIN_TABLE );
		$limit = $this->settings->get_log_limit();
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$page = isset( $_GET['paged'] ) ? max( 1, intval( $_GET['paged'] ) ) : 1;
		$per  = 30;
		$off  = ( $page - 1 ) * $per;

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$total = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" );

		$rows = $wpdb->get_results(
			$wpdb->prepare( "SELECT * FROM {$table} ORDER BY id DESC LIMIT %d OFFSET %d", $per, $off )
		);
		// phpcs:enable
		?>
		<form method="post">
			<?php wp_nonce_field( 'jacklogu_event_action', 'jacklogu_nonce' ); ?>
			<input type="hidden" name="jacklogu_action" value="bulk_login_action" />
			<input type="hidden" name="jacklogu_tab" value="login-events" />

			<h2>
				<?php
				/* translators: 1: limit, 2: total */
				printf( esc_html__( 'Login Events — Last %1$s Entries (%2$s total)', 'jacker-login-guard' ), number_format( $limit ), number_format( $total ) );
				?>
			</h2>

			<div style="margin:10px 0;">
				<select name="bulk_action">
					<option value=""><?php esc_html_e( 'Bulk Action', 'jacker-login-guard' ); ?></option>
					<option value="whitelist"><?php esc_html_e( 'Whitelist', 'jacker-login-guard' ); ?></option>
					<option value="blacklist"><?php esc_html_e( 'Blacklist', 'jacker-login-guard' ); ?></option>
					<option value="remove"><?php esc_html_e( 'Remove', 'jacker-login-guard' ); ?></option>
				</select>
				<button type="submit" class="button"><?php esc_html_e( 'Apply', 'jacker-login-guard' ); ?></button>
				<button type="submit" name="clear_all" value="1" class="button" style="float:right;color:#dc3232;border-color:#dc3232;"
						onclick="return confirm('<?php echo esc_js( __( 'Delete all login events?', 'jacker-login-guard' ) ); ?>');">
					<?php esc_html_e( 'Clear All', 'jacker-login-guard' ); ?>
				</button>
			</div>

			<table class="wp-list-table widefat fixed striped">
				<thead>
					<tr>
						<th style="width:30px;"><input type="checkbox" class="jacklogu-select-all" /></th>
						<th style="width:50px;">ID</th>
						<th><?php esc_html_e( 'Username', 'jacker-login-guard' ); ?></th>
						<th><?php esc_html_e( 'Time', 'jacker-login-guard' ); ?></th>
						<th><?php esc_html_e( 'IP', 'jacker-login-guard' ); ?></th>
						<th style="width:90px;"><?php esc_html_e( 'Status', 'jacker-login-guard' ); ?></th>
						<th style="width:250px;"><?php esc_html_e( 'Actions', 'jacker-login-guard' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php if ( empty( $rows ) ) : ?>
						<tr><td colspan="7"><?php esc_html_e( 'No events.', 'jacker-login-guard' ); ?></td></tr>
					<?php else : ?>
						<?php foreach ( $rows as $row ) : ?>
							<tr>
								<td><input type="checkbox" class="jacklogu-bulk-select" name="selected_ids[]" value="<?php echo esc_attr( $row->id ); ?>" /></td>
								<td><?php echo esc_html( $row->id ); ?></td>
								<td><strong><?php echo esc_html( $row->username ); ?></strong></td>
								<td><?php echo esc_html( $row->login_time ); ?></td>
								<td>
									<code><?php echo esc_html( $row->user_ip ); ?></code>
									<?php
									// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
									echo IpUtils::get_country_flag_html( $row->user_ip );
									?>
								</td>
								<td>
									<?php if ( 'success' === $row->status ) : ?>
										<span style="color:#46b450;">✅ <?php esc_html_e( 'Success', 'jacker-login-guard' ); ?></span>
									<?php else : ?>
										<span style="color:#dc3232;">❌ <?php esc_html_e( 'Failed', 'jacker-login-guard' ); ?></span>
									<?php endif; ?>
								</td>
								<td><?php $this->render_row_actions( $row->user_ip, $row->id, 'login-events' ); ?></td>
							</tr>
						<?php endforeach; ?>
					<?php endif; ?>
				</tbody>
			</table>

			<?php $this->render_pagination( $total, $per, $page ); ?>
		</form>
		<?php
	}

	/**
	 * Return the list of currently online sessions.
	 *
	 * @since 1.0.0
	 * @return array<int, array<string, mixed>>
	 */
	private function get_current_logins() {
		global $wpdb;

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$metas = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT user_id, meta_value FROM {$wpdb->usermeta} WHERE meta_key = %s",
				'session_tokens'
			)
		);
		// phpcs:enable

		if ( empty( $metas ) ) {
			return array();
		}

		$now    = time();
		$logins = array();

		foreach ( $metas as $meta ) {
			$user_id = (int) $meta->user_id;

			$last_activity = SessionTracker::get_last_activity( $user_id );

			if ( $last_activity <= 0 || ( $now - $last_activity ) > SessionTracker::ONLINE_TTL ) {
				continue;
			}

			$sessions = maybe_unserialize( $meta->meta_value );

			if ( ! is_array( $sessions ) || empty( $sessions ) ) {
				continue;
			}

			$user = get_userdata( $user_id );

			if ( ! $user ) {
				continue;
			}

			$role = ! empty( $user->roles ) ? reset( $user->roles ) : 'unknown';

			$picked = null;

			foreach ( $sessions as $token => $data ) {
				if ( ! isset( $data['expiration'] ) || $data['expiration'] < $now ) {
					continue;
				}

				$login_ts = isset( $data['login'] ) ? (int) $data['login'] : 0;

				if ( null === $picked || $login_ts > $picked['login_ts'] ) {
					$picked = array(
						'token'    => $token,
						'data'     => $data,
						'login_ts' => $login_ts,
					);
				}
			}

			if ( null === $picked ) {
				continue;
			}

			$data       = $picked['data'];
			$ip         = isset( $data['ip'] ) ? $data['ip'] : '';
			$ua         = isset( $data['ua'] ) ? $data['ua'] : '';
			$login_time = $picked['login_ts'];

			$logins[] = array(
				'user_id'          => $user_id,
				'username'         => $user->user_login,
				'display_name'     => $user->display_name,
				'role'             => $role,
				'role_weight'      => $this->get_role_weight( $role ),
				'ip'               => $ip,
				'user_agent'       => $ua,
				'login_time'       => $login_time ? gmdate( 'Y-m-d H:i:s', $login_time ) : '',
				'last_activity'    => gmdate( 'Y-m-d H:i:s', $last_activity ),
				'last_activity_ts' => $last_activity,
				'session_token'    => $picked['token'],
			);
		}

		usort(
			$logins,
			function ( $a, $b ) {
				if ( $a['role_weight'] !== $b['role_weight'] ) {
					return $a['role_weight'] - $b['role_weight'];
				}
				return $b['last_activity_ts'] - $a['last_activity_ts'];
			}
		);

		return $logins;
	}

	/**
	 * Return the sort weight of a role (lower = shown first).
	 *
	 * @since 1.0.0
	 * @param string $role Role slug.
	 * @return int
	 */
	private function get_role_weight( $role ) {
		$weights = array(
			'administrator' => 1,
			'editor'        => 2,
			'author'        => 3,
			'contributor'   => 4,
			'subscriber'    => 5,
			'customer'      => 6,
			'shop_manager'  => 7,
		);

		return isset( $weights[ $role ] ) ? $weights[ $role ] : 100;
	}

	/**
	 * AJAX handler: return the list of currently online sessions.
	 *
	 * @since 1.0.0
	 * @return void
	 */
	public function ajax_get_current_logins() {
		check_ajax_referer( 'jacklogu_current_login', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => 'Permission denied.' ), 403 );
		}

		$logins = $this->get_current_logins();

		wp_send_json_success(
			array(
				'logins' => $logins,
				'count'  => count( $logins ),
				'time'   => current_time( 'mysql' ),
			)
		);
	}

	/**
	 * AJAX handler: resolve country flags for a batch of IPs.
	 *
	 * @since 1.0.0
	 * @return void
	 */
	public function ajax_geo_lookup() {
		check_ajax_referer( 'jacklogu_geo_lookup', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => 'Permission denied.' ), 403 );
		}

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash
		$raw = isset( $_POST['ips'] ) ? (array) wp_unslash( $_POST['ips'] ) : array();
		$ips = array();

		foreach ( $raw as $ip ) {
			$ip = sanitize_text_field( $ip );

			if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
				$ips[] = $ip;
			}
		}

		if ( empty( $ips ) ) {
			wp_send_json_success( array( 'flags' => array() ) );
		}

		$flags = IpUtils::get_country_flags_batch( array_unique( $ips ) );

		wp_send_json_success( array( 'flags' => $flags ) );
	}

	/**
	 * Render the Current Login tab.
	 *
	 * @since 1.0.0
	 * @return void
	 */
	private function render_current_login() {
		$nonce           = wp_create_nonce( 'jacklogu_current_login' );
		$ajax_url        = admin_url( 'admin-ajax.php' );
		$logins          = $this->get_current_logins();
		$current_user_id = get_current_user_id();

		$action_base  = admin_url( 'admin.php?page=jacker-login-guard&tab=current-login' );
		$action_nonce = wp_create_nonce( 'jacklogu_event_action' );
		?>
		<h2>
			<?php
			printf(
				/* translators: %s: total count */
				esc_html__( 'Current Login — %s online sessions', 'jacker-login-guard' ),
				'<span id="jacklogu-total-count">' . esc_html( number_format( count( $logins ) ) ) . '</span>'
			);
			?>
		</h2>
		<p class="description">
			<?php esc_html_e( 'Shows users active within the last 30 minutes. Auto-refreshes every 5 minutes.', 'jacker-login-guard' ); ?>
			<span id="jacklogu-last-refresh"></span>
		</p>

		<div id="jacklogu-loading" style="display:none;padding:10px;color:#666;">
			<span class="spinner is-active" style="float:none;margin:0 8px 0 0;"></span>
			<?php esc_html_e( 'Refreshing...', 'jacker-login-guard' ); ?>
		</div>

		<form method="post" id="jacklogu-current-form">
			<?php wp_nonce_field( 'jacklogu_event_action', 'jacklogu_nonce' ); ?>
			<input type="hidden" name="jacklogu_action" value="bulk_current_login_action" />
			<input type="hidden" name="jacklogu_tab" value="current-login" />

			<div style="margin:10px 0;">
				<select name="bulk_action">
					<option value=""><?php esc_html_e( 'Bulk Action', 'jacker-login-guard' ); ?></option>
					<option value="logout"><?php esc_html_e( 'Force Logout', 'jacker-login-guard' ); ?></option>
					<option value="whitelist"><?php esc_html_e( 'Whitelist IP', 'jacker-login-guard' ); ?></option>
					<option value="blacklist"><?php esc_html_e( 'Blacklist IP', 'jacker-login-guard' ); ?></option>
				</select>
				<button type="submit" class="button"><?php esc_html_e( 'Apply', 'jacker-login-guard' ); ?></button>
			</div>

			<table class="wp-list-table widefat fixed striped" id="jacklogu-logins-table">
				<thead>
					<tr>
						<th style="width:30px;"><input type="checkbox" class="jacklogu-select-all" /></th>
						<th style="width:50px;">#</th>
						<th><?php esc_html_e( 'Username', 'jacker-login-guard' ); ?></th>
						<th><?php esc_html_e( 'Display Name', 'jacker-login-guard' ); ?></th>
						<th style="width:130px;"><?php esc_html_e( 'Role', 'jacker-login-guard' ); ?></th>
						<th style="width:150px;"><?php esc_html_e( 'IP', 'jacker-login-guard' ); ?></th>
						<th style="width:150px;"><?php esc_html_e( 'Last Activity', 'jacker-login-guard' ); ?></th>
						<th style="width:100px;"><?php esc_html_e( 'Status', 'jacker-login-guard' ); ?></th>
						<th style="width:250px;"><?php esc_html_e( 'Actions', 'jacker-login-guard' ); ?></th>
					</tr>
				</thead>
				<tbody id="jacklogu-logins-body">
					<?php $this->render_login_rows( $logins, $current_user_id ); ?>
				</tbody>
			</table>
		</form>

		<script>
		(function() {
			var AJAX_URL         = <?php echo wp_json_encode( $ajax_url ); ?>;
			var NONCE            = <?php echo wp_json_encode( $nonce ); ?>;
			var CURRENT_USER_ID  = <?php echo (int) $current_user_id; ?>;
			var ACTION_BASE      = <?php echo wp_json_encode( $action_base ); ?>;
			var ACTION_NONCE     = <?php echo wp_json_encode( $action_nonce ); ?>;
			var LANG = {
				ago:     <?php echo wp_json_encode( __( 'ago', 'jacker-login-guard' ) ); ?>,
				logout:  <?php echo wp_json_encode( __( 'Logout', 'jacker-login-guard' ) ); ?>,
				white:   <?php echo wp_json_encode( __( 'Whitelist', 'jacker-login-guard' ) ); ?>,
				black:   <?php echo wp_json_encode( __( 'Blacklist', 'jacker-login-guard' ) ); ?>,
				online:  <?php echo wp_json_encode( __( 'Online', 'jacker-login-guard' ) ); ?>,
				none:    <?php echo wp_json_encode( __( 'No online sessions.', 'jacker-login-guard' ) ); ?>,
				confirm: <?php echo wp_json_encode( __( 'Force this user to log out?', 'jacker-login-guard' ) ); ?>
			};
			var REFRESH_INTERVAL = 5 * 60 * 1000;
			var TICK_INTERVAL    = 1000;
			var timer;
			var tickTimer;

			function buildActionUrl( action, params ) {
				var url = ACTION_BASE + '&jacklogu_action=' + encodeURIComponent(action);
				if (params) {
					for (var key in params) {
						if (params.hasOwnProperty(key)) {
							url += '&' + encodeURIComponent(key) + '=' + encodeURIComponent(params[key]);
						}
					}
				}
				url += '&jacklogu_nonce=' + encodeURIComponent(ACTION_NONCE);
				return url;
			}

			function formatElapsed(seconds) {
				if (seconds < 0) { seconds = 0; }
				if (seconds < 60) { return seconds + 's'; }
				if (seconds < 3600) {
					var m = Math.floor(seconds / 60);
					var s = seconds % 60;
					return m + 'm ' + s + 's';
				}
				var h = Math.floor(seconds / 3600);
				var m = Math.floor((seconds % 3600) / 60);
				return h + 'h ' + m + 'm';
			}

			function updateAllElapsed() {
				var now = Math.floor(Date.now() / 1000);

				document.querySelectorAll('[data-activity-ts]').forEach(function(el) {
					var ts = parseInt(el.getAttribute('data-activity-ts'), 10);
					if (!ts || ts <= 0) { return; }
					var diff = now - ts;
					el.textContent = formatElapsed(diff) + ' ' + LANG.ago;
				});
			}

			function refreshLogins() {
				var loading = document.getElementById('jacklogu-loading');
				if (loading) { loading.style.display = 'block'; }

				var xhr = new XMLHttpRequest();
				xhr.open('POST', AJAX_URL, true);
				xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8');

				xhr.onload = function() {
					if (loading) { loading.style.display = 'none'; }
					if (xhr.status !== 200) { return; }

					try {
						var resp = JSON.parse(xhr.responseText);
						if (!resp.success) { return; }

						updateTable(resp.data.logins);
						updateCount(resp.data);

						var refresh = document.getElementById('jacklogu-last-refresh');
						if (refresh) {
							refresh.textContent = ' (Last refresh: ' + resp.data.time + ')';
						}
					} catch (e) {}
				};

				xhr.onerror = function() {
					if (loading) { loading.style.display = 'none'; }
				};

				xhr.send('action=jacklogu_get_current_logins&nonce=' + encodeURIComponent(NONCE));
			}

			function updateCount(data) {
				var totalEl = document.getElementById('jacklogu-total-count');
				if (totalEl) { totalEl.textContent = data.count; }
			}

			function updateTable(logins) {
				var tbody = document.getElementById('jacklogu-logins-body');
				if (!tbody) { return; }

				if (logins.length === 0) {
					tbody.innerHTML = '<tr><td colspan="9">' + LANG.none + '</td></tr>';
					return;
				}

				var now = Math.floor(Date.now() / 1000);
				var html = '';

				logins.forEach(function(l, index) {
					var diff = now - l.last_activity_ts;
					var elapsed = formatElapsed(diff);
					var isSelf = (parseInt(l.user_id, 10) === CURRENT_USER_ID);

					var statusHtml;
					if (diff <= 300) {
						statusHtml = '<span style="color:#46b450;font-weight:bold;">🟢 ' + LANG.online + '</span>';
					} else {
						statusHtml = '<span style="color:#dba617;">🟡 ' + elapsed + ' ' + LANG.ago + '</span>';
					}

					var logoutUrl = buildActionUrl('force_logout', { user_id: l.user_id });
					var whiteUrl  = buildActionUrl('whitelist_ip', { ip: l.ip });
					var blackUrl  = buildActionUrl('blacklist_ip', { ip: l.ip });

					html += '<tr>';
					html += '<td><input type="checkbox" class="jacklogu-bulk-select" name="selected_ids[]" value="' + l.user_id + '" /></td>';
					html += '<td>' + (index + 1) + '</td>';
					html += '<td><strong>' + escapeHtml(l.username) + '</strong></td>';
					html += '<td>' + escapeHtml(l.display_name) + '</td>';
					html += '<td><code>' + escapeHtml(l.role) + '</code></td>';
					html += '<td><code>' + escapeHtml(l.ip) + '</code><span class="jacklogu-flag-placeholder" data-ip="' + escapeHtml(l.ip) + '"></span></td>';
					html += '<td><span class="jacklogu-ago" data-activity-ts="' + l.last_activity_ts + '">' + elapsed + ' ' + LANG.ago + '</span></td>';
					html += '<td>' + statusHtml + '</td>';
					html += '<td>';
					html += '<a href="' + logoutUrl + '" class="button button-small" style="color:#dc3232;" onclick="return confirm(\'' + LANG.confirm.replace(/'/g, "\\'") + '\');">' + LANG.logout + '</a> ';
					html += '<a href="' + whiteUrl + '" class="button button-small" style="color:#46b450;">' + LANG.white + '</a>';
					if (!isSelf) {
						html += ' <a href="' + blackUrl + '" class="button button-small" style="color:#dc3232;">' + LANG.black + '</a>';
					}
					html += '</td>';
					html += '</tr>';
				});

				tbody.innerHTML = html;

				if (window.jackloguFetchFlags) {
					window.jackloguFetchFlags();
				}
			}

			function escapeHtml(text) {
				var div = document.createElement('div');
				div.textContent = text == null ? '' : text;
				return div.innerHTML;
			}

			function startTimer() {
				stopTimer();
				timer = setInterval(refreshLogins, REFRESH_INTERVAL);
			}

			function stopTimer() {
				if (timer) { clearInterval(timer); timer = null; }
			}

			function startTick() {
				stopTick();
				tickTimer = setInterval(updateAllElapsed, TICK_INTERVAL);
			}

			function stopTick() {
				if (tickTimer) { clearInterval(tickTimer); tickTimer = null; }
			}

			document.addEventListener('visibilitychange', function() {
				if (document.visibilityState === 'visible') {
					refreshLogins();
					startTimer();
					startTick();
				} else {
					stopTimer();
					stopTick();
				}
			});

			refreshLogins();
			startTimer();
			startTick();
		})();
		</script>
		<?php
	}

	/**
	 * Render rows for the Current Login table.
	 *
	 * @since 1.0.0
	 * @param array<int, array<string, mixed>> $logins          List of login records.
	 * @param int                              $current_user_id Current user ID.
	 * @return void
	 */
	private function render_login_rows( $logins, $current_user_id = 0 ) {
		if ( empty( $logins ) ) {
			echo '<tr><td colspan="9">' . esc_html__( 'No online sessions.', 'jacker-login-guard' ) . '</td></tr>';
			return;
		}

		$now = time();

		foreach ( $logins as $index => $login ) {
			$activity_ts  = isset( $login['last_activity_ts'] ) ? (int) $login['last_activity_ts'] : 0;
			$elapsed      = $activity_ts > 0 ? ( $now - $activity_ts ) : 0;
			$elapsed_text = $this->format_elapsed( $elapsed );
			$is_self      = ( (int) $login['user_id'] === (int) $current_user_id );
			$is_online    = ( $elapsed <= 5 * MINUTE_IN_SECONDS );
			?>
			<tr>
				<td><input type="checkbox" class="jacklogu-bulk-select" name="selected_ids[]" value="<?php echo esc_attr( $login['user_id'] ); ?>" /></td>
				<td><?php echo esc_html( $index + 1 ); ?></td>
				<td><strong><?php echo esc_html( $login['username'] ); ?></strong></td>
				<td><?php echo esc_html( $login['display_name'] ); ?></td>
				<td><code><?php echo esc_html( $login['role'] ); ?></code></td>
				<td>
					<code><?php echo esc_html( $login['ip'] ); ?></code>
					<?php
					// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
					echo IpUtils::get_country_flag_html( $login['ip'] );
					?>
				</td>
				<td>
					<span class="jacklogu-ago" data-activity-ts="<?php echo esc_attr( $activity_ts ); ?>">
						<?php
						printf(
							/* translators: %s: time diff */
							esc_html__( '%s ago', 'jacker-login-guard' ),
							esc_html( $elapsed_text )
						);
						?>
					</span>
				</td>
				<td>
					<?php if ( $is_online ) : ?>
						<span style="color:#46b450;font-weight:bold;">🟢 <?php esc_html_e( 'Online', 'jacker-login-guard' ); ?></span>
					<?php else : ?>
						<span style="color:#dba617;">🟡 <?php esc_html_e( 'Away', 'jacker-login-guard' ); ?></span>
					<?php endif; ?>
				</td>
				<td>
					<a href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin.php?page=jacker-login-guard&tab=current-login&jacklogu_action=force_logout&user_id=' . intval( $login['user_id'] ) ), 'jacklogu_event_action', 'jacklogu_nonce' ) ); ?>"
					   class="button button-small" style="color:#dc3232;"
					   onclick="return confirm('<?php echo esc_js( __( 'Force this user to log out?', 'jacker-login-guard' ) ); ?>');">
						<?php esc_html_e( 'Logout', 'jacker-login-guard' ); ?>
					</a>
					<a href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin.php?page=jacker-login-guard&tab=current-login&jacklogu_action=whitelist_ip&ip=' . rawurlencode( $login['ip'] ) ), 'jacklogu_event_action', 'jacklogu_nonce' ) ); ?>"
					   class="button button-small" style="color:#46b450;">
						<?php esc_html_e( 'Whitelist', 'jacker-login-guard' ); ?>
					</a>
					<?php if ( ! $is_self ) : ?>
						<a href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin.php?page=jacker-login-guard&tab=current-login&jacklogu_action=blacklist_ip&ip=' . rawurlencode( $login['ip'] ) ), 'jacklogu_event_action', 'jacklogu_nonce' ) ); ?>"
						   class="button button-small" style="color:#dc3232;">
							<?php esc_html_e( 'Blacklist', 'jacker-login-guard' ); ?>
						</a>
					<?php endif; ?>
				</td>
			</tr>
			<?php
		}
	}

	/**
	 * Format an elapsed-seconds count as a short human-readable string.
	 *
	 * @since 1.0.0
	 * @param int $seconds Elapsed seconds.
	 * @return string
	 */
	private function format_elapsed( $seconds ) {
		$seconds = max( 0, (int) $seconds );

		if ( $seconds < 60 ) {
			return $seconds . 's';
		}

		if ( $seconds < 3600 ) {
			$m = floor( $seconds / 60 );
			$s = $seconds % 60;
			return $m . 'm ' . $s . 's';
		}

		$h = floor( $seconds / 3600 );
		$m = floor( ( $seconds % 3600 ) / 60 );

		return $h . 'h ' . $m . 'm';
	}

	/**
	 * Render the Access Log tab.
	 *
	 * @since 1.0.0
	 * @return void
	 */
	private function render_access_log() {
		global $wpdb;

		$table = Tables::get( JACKLOGU_ACCESS_TABLE );
		$limit = $this->settings->get_log_limit();
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$page = isset( $_GET['paged'] ) ? max( 1, intval( $_GET['paged'] ) ) : 1;
		$per  = 30;
		$off  = ( $page - 1 ) * $per;

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$filter_status = isset( $_GET['filter_status'] ) ? sanitize_key( wp_unslash( $_GET['filter_status'] ) ) : '';
		$valid_status  = array( '', 'allowed', 'blocked' );

		if ( ! in_array( $filter_status, $valid_status, true ) ) {
			$filter_status = '';
		}

		$where = '1=1';
		if ( 'allowed' === $filter_status || 'blocked' === $filter_status ) {
			$where .= $wpdb->prepare( ' AND status = %s', $filter_status );
		}

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$total = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE {$where}" );

		$rows = $wpdb->get_results(
			$wpdb->prepare( "SELECT * FROM {$table} WHERE {$where} ORDER BY id DESC LIMIT %d OFFSET %d", $per, $off )
		);
		// phpcs:enable

		$base_url = admin_url( 'admin.php?page=jacker-login-guard&tab=access-log' );

		$filters = array(
			''        => __( 'All', 'jacker-login-guard' ),
			'allowed' => __( 'Allowed', 'jacker-login-guard' ),
			'blocked' => __( 'Blocked', 'jacker-login-guard' ),
		);
		?>
		<form method="post">
			<?php wp_nonce_field( 'jacklogu_event_action', 'jacklogu_nonce' ); ?>
			<input type="hidden" name="jacklogu_action" value="bulk_access_action" />
			<input type="hidden" name="jacklogu_tab" value="access-log" />
			<?php if ( $filter_status ) : ?>
				<input type="hidden" name="filter_status" value="<?php echo esc_attr( $filter_status ); ?>" />
			<?php endif; ?>

			<h2>
				<?php
				/* translators: %s: limit */
				printf( esc_html__( 'Access Log — Last %s Entries', 'jacker-login-guard' ), number_format( $limit ) );
				?>
			</h2>

			<p class="description">
				<?php esc_html_e( 'Records access attempts to sensitive resources: login, wp-admin, REST API, XML-RPC, and configuration files. Normal page views (home, posts) are not logged.', 'jacker-login-guard' ); ?>
			</p>
			<p class="description" style="color:#d63638;">
				<strong><?php esc_html_e( 'Note:', 'jacker-login-guard' ); ?></strong>
				<?php
				printf(
					/* translators: %d: trigger threshold */
					esc_html__( 'An IP is automatically blocked after %d attack attempts. Blocked IPs are listed under Auto Block List.', 'jacker-login-guard' ),
					intval( $this->settings->get_auto_block_trigger_threshold() )
				);
				?>
			</p>

			<ul class="subsubsub" style="margin:8px 0;">
				<?php
				$i = 0;
				foreach ( $filters as $value => $label ) :
					$i++;
					$url       = $value ? add_query_arg( 'filter_status', $value, $base_url ) : $base_url;
					$is_active = ( $filter_status === $value );
					?>
					<li style="margin:0;">
						<a href="<?php echo esc_url( $url ); ?>" class="<?php echo $is_active ? 'current' : ''; ?>">
							<?php echo esc_html( $label ); ?>
						</a>
						<?php if ( $i < count( $filters ) ) : ?>
							<span>|</span>
						<?php endif; ?>
					</li>
				<?php endforeach; ?>
			</ul>

			<div style="margin:10px 0;clear:both;">
				<select name="bulk_action">
					<option value=""><?php esc_html_e( 'Bulk Action', 'jacker-login-guard' ); ?></option>
					<option value="whitelist"><?php esc_html_e( 'Whitelist', 'jacker-login-guard' ); ?></option>
					<option value="blacklist"><?php esc_html_e( 'Blacklist', 'jacker-login-guard' ); ?></option>
					<option value="remove"><?php esc_html_e( 'Remove', 'jacker-login-guard' ); ?></option>
				</select>
				<button type="submit" class="button"><?php esc_html_e( 'Apply', 'jacker-login-guard' ); ?></button>
				<button type="submit" name="clear_all" value="1" class="button" style="float:right;color:#dc3232;border-color:#dc3232;"
						onclick="return confirm('<?php echo esc_js( __( 'Delete all access logs?', 'jacker-login-guard' ) ); ?>');">
					<?php esc_html_e( 'Clear All', 'jacker-login-guard' ); ?>
				</button>
			</div>

			<table class="wp-list-table widefat fixed striped">
				<thead>
					<tr>
						<th style="width:30px;"><input type="checkbox" class="jacklogu-select-all" /></th>
						<th style="width:40px;">ID</th>
						<th style="width:130px;"><?php esc_html_e( 'Time', 'jacker-login-guard' ); ?></th>
						<th style="width:130px;"><?php esc_html_e( 'IP', 'jacker-login-guard' ); ?></th>
						<th><?php esc_html_e( 'Target', 'jacker-login-guard' ); ?></th>
						<th><?php esc_html_e( 'Referer', 'jacker-login-guard' ); ?></th>
						<th style="width:180px;"><?php esc_html_e( 'Reason', 'jacker-login-guard' ); ?></th>
						<th style="width:90px;"><?php esc_html_e( 'Status', 'jacker-login-guard' ); ?></th>
						<th style="width:250px;"><?php esc_html_e( 'Actions', 'jacker-login-guard' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php if ( empty( $rows ) ) : ?>
						<tr><td colspan="9"><?php esc_html_e( 'No access events.', 'jacker-login-guard' ); ?></td></tr>
					<?php else : ?>
						<?php foreach ( $rows as $row ) : ?>
							<tr <?php echo 'blocked' === $row->status ? 'style="background:#fef0f0;"' : ''; ?>>
								<td><input type="checkbox" class="jacklogu-bulk-select" name="selected_ids[]" value="<?php echo esc_attr( $row->id ); ?>" /></td>
								<td><?php echo esc_html( $row->id ); ?></td>
								<td><?php echo esc_html( $row->event_time ); ?></td>
								<td>
									<code><?php echo esc_html( $row->user_ip ); ?></code>
									<?php
									// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
									echo IpUtils::get_country_flag_html( $row->user_ip );
									?>
								</td>
								<td style="max-width:250px;word-break:break-all;font-size:12px;"><?php echo esc_html( $row->request_path ); ?></td>
								<td style="max-width:200px;word-break:break-all;font-size:11px;color:#888;">
									<?php echo ! empty( $row->referer ) ? esc_html( $row->referer ) : esc_html__( '(direct access)', 'jacker-login-guard' ); ?>
								</td>
								<td style="font-size:12px;"><?php echo esc_html( $row->reason ); ?></td>
								<td>
									<?php if ( 'allowed' === $row->status ) : ?>
										<span style="color:#46b450;">✅ <?php esc_html_e( 'Allowed', 'jacker-login-guard' ); ?></span>
									<?php else : ?>
										<span style="color:#dc3232;">⛔ <?php esc_html_e( 'Blocked', 'jacker-login-guard' ); ?></span>
									<?php endif; ?>
								</td>
								<td><?php $this->render_row_actions( $row->user_ip, $row->id, 'access-log' ); ?></td>
							</tr>
						<?php endforeach; ?>
					<?php endif; ?>
				</tbody>
			</table>

			<?php $this->render_pagination( $total, $per, $page ); ?>
		</form>
		<?php
	}

	/**
	 * Render the Auto Block List tab.
	 *
	 * @since 1.0.0
	 * @return void
	 */
	private function render_auto_block() {
		global $wpdb;

		$table = Tables::get( JACKLOGU_AUTO_BLOCK_TABLE );
		$limit = $this->settings->get_log_limit();
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$page = isset( $_GET['paged'] ) ? max( 1, intval( $_GET['paged'] ) ) : 1;
		$per  = 30;
		$off  = ( $page - 1 ) * $per;

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$total = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE is_active = 1" );

		$rows = $wpdb->get_results(
			$wpdb->prepare( "SELECT * FROM {$table} WHERE is_active = 1 ORDER BY id DESC LIMIT %d OFFSET %d", $per, $off )
		);
		// phpcs:enable
		?>
		<form method="post">
			<?php wp_nonce_field( 'jacklogu_event_action', 'jacklogu_nonce' ); ?>
			<input type="hidden" name="jacklogu_action" value="bulk_auto_block_action" />
			<input type="hidden" name="jacklogu_tab" value="auto-block" />

			<h2>
				<?php
				/* translators: %s: limit */
				printf( esc_html__( 'Auto Block List — Last %s Entries', 'jacker-login-guard' ), number_format( $limit ) );
				?>
			</h2>
			<p class="description"><?php esc_html_e( 'Remove = unblock (unless on manual blacklist).', 'jacker-login-guard' ); ?></p>
			<p class="description" style="color:#d63638;">
				<strong><?php esc_html_e( 'Note:', 'jacker-login-guard' ); ?></strong>
				<?php
				printf(
					/* translators: 1: block duration hours, 2: blacklist threshold */
					esc_html__( 'Auto-blocks expire automatically after %1$d hours. An IP that is auto-blocked %2$d times is escalated to the permanent Blacklist.', 'jacker-login-guard' ),
					intval( $this->settings->get( 'auto_block_duration_hours', 24 ) ),
					intval( $this->settings->get_auto_block_to_blacklist_threshold() )
				);
				?>
			</p>

			<div style="margin:10px 0;">
				<select name="bulk_action">
					<option value=""><?php esc_html_e( 'Bulk Action', 'jacker-login-guard' ); ?></option>
					<option value="whitelist"><?php esc_html_e( 'Whitelist', 'jacker-login-guard' ); ?></option>
					<option value="blacklist"><?php esc_html_e( 'Blacklist', 'jacker-login-guard' ); ?></option>
					<option value="remove"><?php esc_html_e( 'Remove (Unblock)', 'jacker-login-guard' ); ?></option>
				</select>
				<button type="submit" class="button"><?php esc_html_e( 'Apply', 'jacker-login-guard' ); ?></button>
				<button type="submit" name="clear_all" value="1" class="button" style="float:right;color:#dc3232;border-color:#dc3232;"
						onclick="return confirm('<?php echo esc_js( __( 'Clear all auto-block records?', 'jacker-login-guard' ) ); ?>');">
					<?php esc_html_e( 'Clear All', 'jacker-login-guard' ); ?>
				</button>
			</div>

			<table class="wp-list-table widefat fixed striped">
				<thead>
					<tr>
						<th style="width:30px;"><input type="checkbox" class="jacklogu-select-all" /></th>
						<th style="width:50px;">#</th>
						<th style="width:150px;"><?php esc_html_e( 'IP', 'jacker-login-guard' ); ?></th>
						<th><?php esc_html_e( 'Reason', 'jacker-login-guard' ); ?></th>
						<th style="width:160px;"><?php esc_html_e( 'Blocked At', 'jacker-login-guard' ); ?></th>
						<th style="width:160px;"><?php esc_html_e( 'Expires At', 'jacker-login-guard' ); ?></th>
						<th style="width:250px;"><?php esc_html_e( 'Actions', 'jacker-login-guard' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php if ( empty( $rows ) ) : ?>
						<tr><td colspan="7"><?php esc_html_e( 'No auto-blocked IPs.', 'jacker-login-guard' ); ?></td></tr>
					<?php else : ?>
						<?php foreach ( $rows as $row ) : ?>
							<tr>
								<td><input type="checkbox" class="jacklogu-bulk-select" name="selected_ids[]" value="<?php echo esc_attr( $row->id ); ?>" /></td>
								<td><?php echo esc_html( $row->id ); ?></td>
								<td>
									<code><?php echo esc_html( $row->user_ip ); ?></code>
									<?php
									// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
									echo IpUtils::get_country_flag_html( $row->user_ip );
									?>
								</td>
								<td><?php echo esc_html( $row->reason ); ?></td>
								<td><?php echo esc_html( $row->block_time ); ?></td>
								<td>
									<?php if ( empty( $row->expire_at ) ) : ?>
										<em style="color:#888;"><?php esc_html_e( 'Never', 'jacker-login-guard' ); ?></em>
									<?php else : ?>
										<?php echo esc_html( $row->expire_at ); ?>
									<?php endif; ?>
								</td>
								<td><?php $this->render_row_actions( $row->user_ip, $row->id, 'auto-block', true ); ?></td>
							</tr>
						<?php endforeach; ?>
					<?php endif; ?>
				</tbody>
			</table>

			<?php $this->render_pagination( $total, $per, $page ); ?>
		</form>
		<?php
	}

	/**
	 * Render the Whitelist / Blacklist / Remove row actions.
	 *
	 * @since 1.0.0
	 * @param string $ip      IP address.
	 * @param int    $id      Row ID.
	 * @param string $tab     Current tab slug.
	 * @param bool   $unblock Whether the row belongs to the auto-block table.
	 * @return void
	 */
	private function render_row_actions( $ip, $id, $tab, $unblock = false ) {
		$base = admin_url( 'admin.php?page=jacker-login-guard&tab=' . $tab );

		$whitelist_url = wp_nonce_url( $base . '&jacklogu_action=whitelist_ip&ip=' . rawurlencode( $ip ), 'jacklogu_event_action', 'jacklogu_nonce' );
		$blacklist_url = wp_nonce_url( $base . '&jacklogu_action=blacklist_ip&ip=' . rawurlencode( $ip ), 'jacklogu_event_action', 'jacklogu_nonce' );

		if ( $unblock ) {
			$remove_url = wp_nonce_url( $base . '&jacklogu_action=unblock_auto&id=' . $id, 'jacklogu_event_action', 'jacklogu_nonce' );
		} else {
			$remove_url = wp_nonce_url( $base . '&jacklogu_action=delete_event&id=' . $id, 'jacklogu_event_action', 'jacklogu_nonce' );
		}
		?>
		<a href="<?php echo esc_url( $whitelist_url ); ?>" class="button button-small" style="color:#46b450;"><?php esc_html_e( 'Whitelist', 'jacker-login-guard' ); ?></a>
		<a href="<?php echo esc_url( $blacklist_url ); ?>" class="button button-small" style="color:#dc3232;"><?php esc_html_e( 'Blacklist', 'jacker-login-guard' ); ?></a>
		<a href="<?php echo esc_url( $remove_url ); ?>" class="button button-small button-link-delete"
		   onclick="return confirm('<?php echo esc_js( __( 'Are you sure?', 'jacker-login-guard' ) ); ?>');">
			<?php esc_html_e( 'Remove', 'jacker-login-guard' ); ?>
		</a>
		<?php
	}

	/**
	 * Render the pagination controls for a log tab.
	 *
	 * @since 1.0.0
	 * @param int $total Total row count.
	 * @param int $per   Rows per page.
	 * @param int $page  Current page.
	 * @return void
	 */
	private function render_pagination( $total, $per, $page ) {
		$pages = (int) ceil( $total / $per );

		if ( $pages <= 1 ) {
			return;
		}
		?>
		<div class="tablenav bottom">
			<div class="tablenav-pages">
				<span class="displaying-num">
					<?php
					/* translators: %s: total items */
					printf( esc_html__( '%s items', 'jacker-login-guard' ), esc_html( number_format_i18n( $total ) ) );
					?>
				</span>

				<?php if ( $page > 1 ) : ?>
					<a class="prev-page button" href="<?php echo esc_url( add_query_arg( 'paged', $page - 1 ) ); ?>">&lsaquo;</a>
				<?php endif; ?>

				<?php
				for ( $i = max( 1, $page - 2 ); $i <= min( $pages, $page + 2 ); $i++ ) :
					if ( $i === $page ) :
						?>
						<span class="button button-primary"><?php echo esc_html( $i ); ?></span>
					<?php else : ?>
						<a class="button" href="<?php echo esc_url( add_query_arg( 'paged', $i ) ); ?>"><?php echo esc_html( $i ); ?></a>
					<?php endif; ?>
				<?php endfor; ?>

				<?php if ( $page < $pages ) : ?>
					<a class="next-page button" href="<?php echo esc_url( add_query_arg( 'paged', $page + 1 ) ); ?>">&rsaquo;</a>
				<?php endif; ?>
			</div>
		</div>
		<?php
	}

	/**
	 * Handle single-row actions (force logout, whitelist, blacklist, remove).
	 *
	 * @since 1.0.0
	 * @return void
	 */
	public function handle_actions() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		// Force-logout via GET.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET['jacklogu_action'] ) && 'force_logout' === $_GET['jacklogu_action'] ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$nonce = isset( $_GET['jacklogu_nonce'] ) ? sanitize_text_field( wp_unslash( $_GET['jacklogu_nonce'] ) ) : '';

			if ( ! wp_verify_nonce( $nonce, 'jacklogu_event_action' ) ) {
				wp_die( esc_html__( 'Security check failed.', 'jacker-login-guard' ) );
			}

			// phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$user_id = isset( $_GET['user_id'] ) ? intval( $_GET['user_id'] ) : 0;

			if ( $user_id > 0 ) {
				SessionTracker::force_logout_user( $user_id );
			}

			wp_safe_redirect( admin_url( 'admin.php?page=jacker-login-guard&tab=current-login' ) );
			exit;
		}

		// Bulk actions via POST.
		if ( isset( $_POST['jacklogu_action'] ) ) {
			$post_action = sanitize_text_field( wp_unslash( $_POST['jacklogu_action'] ) );

			if ( in_array( $post_action, array( 'bulk_login_action', 'bulk_access_action', 'bulk_auto_block_action', 'bulk_current_login_action' ), true ) ) {
				$this->handle_bulk( $post_action );
				return;
			}
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$action = isset( $_GET['jacklogu_action'] ) ? sanitize_text_field( wp_unslash( $_GET['jacklogu_action'] ) ) : '';

		if ( ! in_array( $action, array( 'whitelist_ip', 'blacklist_ip', 'delete_event', 'unblock_auto' ), true ) ) {
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$nonce = isset( $_GET['jacklogu_nonce'] ) ? sanitize_text_field( wp_unslash( $_GET['jacklogu_nonce'] ) ) : '';

		if ( ! wp_verify_nonce( $nonce, 'jacklogu_event_action' ) ) {
			wp_die( esc_html__( 'Security check failed.', 'jacker-login-guard' ) );
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$tab      = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : 'login-events';
		$redirect = admin_url( 'admin.php?page=jacker-login-guard&tab=' . $tab );

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$ip = isset( $_GET['ip'] ) ? sanitize_text_field( wp_unslash( $_GET['ip'] ) ) : '';
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$id = isset( $_GET['id'] ) ? intval( $_GET['id'] ) : 0;

		global $wpdb;

		switch ( $action ) {
			case 'whitelist_ip':
				if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
					$this->add_to_list( $ip, 'whitelist_ips' );
					$this->remove_auto_block( $ip );
				}
				break;

			case 'blacklist_ip':
				if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
					$this->add_to_list( $ip, 'blacklist_ips' );
					$this->remove_from_list( $ip, 'whitelist_ips' );
				}
				break;

			case 'delete_event':
				if ( $id > 0 ) {
					if ( 'login-events' === $tab ) {
						// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
						$wpdb->delete( Tables::get( JACKLOGU_LOGIN_TABLE ), array( 'id' => $id ), array( '%d' ) );
					} elseif ( 'access-log' === $tab ) {
						// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
						$wpdb->delete( Tables::get( JACKLOGU_ACCESS_TABLE ), array( 'id' => $id ), array( '%d' ) );
					}
				}
				break;

			case 'unblock_auto':
				if ( $id > 0 ) {
					// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
					$wpdb->delete( Tables::get( JACKLOGU_AUTO_BLOCK_TABLE ), array( 'id' => $id ), array( '%d' ) );
				}
				break;
		}

		wp_safe_redirect( $redirect );
		exit;
	}

	/**
	 * Handle bulk actions from any of the log tabs.
	 *
	 * @since 1.0.0
	 * @param string $action Bulk action identifier.
	 * @return void
	 */
	private function handle_bulk( $action ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$nonce = isset( $_POST['jacklogu_nonce'] ) ? sanitize_text_field( wp_unslash( $_POST['jacklogu_nonce'] ) ) : '';

		if ( ! wp_verify_nonce( $nonce, 'jacklogu_event_action' ) ) {
			wp_die( esc_html__( 'Security check failed.', 'jacker-login-guard' ) );
		}

		$tab      = isset( $_POST['jacklogu_tab'] ) ? sanitize_key( wp_unslash( $_POST['jacklogu_tab'] ) ) : 'login-events';
		$redirect = admin_url( 'admin.php?page=jacker-login-guard&tab=' . $tab );

		if ( 'access-log' === $tab && isset( $_POST['filter_status'] ) ) {
			$filter_status = sanitize_key( wp_unslash( $_POST['filter_status'] ) );

			if ( in_array( $filter_status, array( 'allowed', 'blocked' ), true ) ) {
				$redirect = add_query_arg( 'filter_status', $filter_status, $redirect );
			}
		}

		global $wpdb;
		$login_table      = Tables::get( JACKLOGU_LOGIN_TABLE );
		$access_table     = Tables::get( JACKLOGU_ACCESS_TABLE );
		$auto_block_table = Tables::get( JACKLOGU_AUTO_BLOCK_TABLE );

		if ( isset( $_POST['clear_all'] ) && '1' === $_POST['clear_all'] ) {
			// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			if ( 'login-events' === $tab ) {
				$wpdb->query( "DELETE FROM {$login_table}" );
			} elseif ( 'access-log' === $tab ) {
				$wpdb->query( "DELETE FROM {$access_table}" );
			} elseif ( 'auto-block' === $tab ) {
				$wpdb->query( "DELETE FROM {$auto_block_table}" );
			}
			// phpcs:enable

			wp_safe_redirect( $redirect );
			exit;
		}

		$bulk = isset( $_POST['bulk_action'] ) ? sanitize_key( wp_unslash( $_POST['bulk_action'] ) ) : '';
		$ids  = isset( $_POST['selected_ids'] ) ? array_map( 'intval', (array) wp_unslash( $_POST['selected_ids'] ) ) : array();

		if ( empty( $bulk ) || empty( $ids ) ) {
			wp_safe_redirect( $redirect );
			exit;
		}

		if ( 'bulk_current_login_action' === $action ) {
			$this->handle_current_login_bulk( $bulk, $ids, $redirect );
			return;
		}

		$ips = $this->collect_ips_for_tab( $tab, $ids, $login_table, $access_table, $auto_block_table );

		switch ( $bulk ) {
			case 'whitelist':
				foreach ( $ips as $ip ) {
					$this->add_to_list( $ip, 'whitelist_ips' );
					$this->remove_auto_block( $ip );
				}
				break;

			case 'blacklist':
				foreach ( $ips as $ip ) {
					$this->add_to_list( $ip, 'blacklist_ips' );
					$this->remove_from_list( $ip, 'whitelist_ips' );
				}
				break;

			case 'remove':
				foreach ( $ids as $id ) {
					// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
					if ( 'login-events' === $tab ) {
						$wpdb->delete( $login_table, array( 'id' => $id ), array( '%d' ) );
					} elseif ( 'access-log' === $tab ) {
						$wpdb->delete( $access_table, array( 'id' => $id ), array( '%d' ) );
					}
				}
				foreach ( $ips as $ip ) {
					$this->remove_auto_block( $ip );
				}
				break;
		}

		wp_safe_redirect( $redirect );
		exit;
	}

	/**
	 * Handle bulk operations coming from the Current Login tab.
	 *
	 * @since 1.0.0
	 * @param string $bulk     Bulk action slug.
	 * @param int[]  $ids      Selected user IDs.
	 * @param string $redirect Redirect target.
	 * @return void
	 */
	private function handle_current_login_bulk( $bulk, $ids, $redirect ) {
		if ( 'logout' === $bulk ) {
			foreach ( $ids as $user_id ) {
				if ( $user_id > 0 ) {
					SessionTracker::force_logout_user( $user_id );
				}
			}
		} elseif ( 'whitelist' === $bulk || 'blacklist' === $bulk ) {
			foreach ( $ids as $user_id ) {
				if ( $user_id <= 0 ) {
					continue;
				}

				$sessions = \WP_Session_Tokens::get_instance( $user_id );
				$all      = $sessions->get_all();

				foreach ( $all as $session ) {
					if ( empty( $session['ip'] ) || ! filter_var( $session['ip'], FILTER_VALIDATE_IP ) ) {
						continue;
					}

					if ( 'whitelist' === $bulk ) {
						$this->add_to_list( $session['ip'], 'whitelist_ips' );
						$this->remove_auto_block( $session['ip'] );
					} else {
						$this->add_to_list( $session['ip'], 'blacklist_ips' );
						$this->remove_from_list( $session['ip'], 'whitelist_ips' );
					}
				}
			}
		}

		wp_safe_redirect( $redirect );
		exit;
	}

	/**
	 * Collect IP addresses for the selected rows of a given tab.
	 *
	 * @since 1.0.0
	 * @param string $tab              Tab slug.
	 * @param int[]  $ids              Selected row IDs.
	 * @param string $login_table      Fully-prefixed login table.
	 * @param string $access_table     Fully-prefixed access table.
	 * @param string $auto_block_table Fully-prefixed auto-block table.
	 * @return string[]
	 */
	private function collect_ips_for_tab( $tab, $ids, $login_table, $access_table, $auto_block_table ) {
		global $wpdb;
		$ips = array();

		foreach ( $ids as $id ) {
			// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			if ( 'login-events' === $tab ) {
				$ip = $wpdb->get_var( $wpdb->prepare( "SELECT user_ip FROM {$login_table} WHERE id = %d", $id ) );
			} elseif ( 'access-log' === $tab ) {
				$ip = $wpdb->get_var( $wpdb->prepare( "SELECT user_ip FROM {$access_table} WHERE id = %d", $id ) );
			} else {
				$ip = $wpdb->get_var( $wpdb->prepare( "SELECT user_ip FROM {$auto_block_table} WHERE id = %d", $id ) );
			}
			// phpcs:enable

			if ( ! empty( $ip ) && filter_var( $ip, FILTER_VALIDATE_IP ) ) {
				$ips[] = $ip;
			}
		}

		return $ips;
	}

	/**
	 * Add an IP to a whitelist/blacklist setting.
	 *
	 * @since 1.0.0
	 * @param string $ip  IP address.
	 * @param string $key Settings key.
	 * @return void
	 */
	private function add_to_list( $ip, $key ) {
		$current = $this->settings->get( $key, '' );
		$lines   = array_filter( array_map( 'trim', explode( "\n", $current ) ) );

		$existing = array();

		foreach ( $lines as $line ) {
			$parts      = explode( ' #', $line, 2 );
			$existing[] = trim( $parts[0] );
		}

		if ( ! in_array( $ip, $existing, true ) ) {
			$lines[] = $ip;
			$this->settings->update( $key, implode( "\n", $lines ) );
		}
	}

	/**
	 * Remove an IP from a whitelist/blacklist setting.
	 *
	 * @since 1.0.0
	 * @param string $ip  IP address.
	 * @param string $key Settings key.
	 * @return void
	 */
	private function remove_from_list( $ip, $key ) {
		$current = $this->settings->get( $key, '' );
		$lines   = array_filter( array_map( 'trim', explode( "\n", $current ) ) );
		$new     = array();

		foreach ( $lines as $line ) {
			$parts = explode( ' #', $line, 2 );

			if ( trim( $parts[0] ) !== $ip ) {
				$new[] = $line;
			}
		}

		$this->settings->update( $key, implode( "\n", $new ) );
	}

	/**
	 * Remove every auto-block record for an IP.
	 *
	 * @since 1.0.0
	 * @param string $ip IP address.
	 * @return void
	 */
	private function remove_auto_block( $ip ) {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->delete( Tables::get( JACKLOGU_AUTO_BLOCK_TABLE ), array( 'user_ip' => $ip ), array( '%s' ) );
	}

	/**
	 * Handle the "Reset All Settings" action.
	 *
	 * @since 1.0.0
	 * @return void
	 */
	public function handle_reset() {
		if ( ! isset( $_POST['jacklogu_action'] ) || 'reset_settings_post' !== $_POST['jacklogu_action'] ) {
			return;
		}

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Permission denied.', 'jacker-login-guard' ) );
		}

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash
		if ( ! isset( $_POST['jacklogu_reset_nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['jacklogu_reset_nonce'] ) ), 'jacklogu_reset_action' ) ) {
			wp_die( esc_html__( 'Security check failed.', 'jacker-login-guard' ) );
		}

		delete_option( JACKLOGU_OPTION_KEY );
		delete_transient( 'jacklogu_cloudflare_ips' );

		wp_safe_redirect( admin_url( 'options-general.php?page=jacker-login-guard&jacklogu_reset_success=1' ) );
		exit;
	}

	/**
	 * Handle settings import and export.
	 *
	 * @since 1.0.0
	 * @return void
	 */
	public function handle_import_export() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		// Export via GET.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET['jacklogu_action'] ) && 'export_settings' === $_GET['jacklogu_action'] ) {
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash
			$nonce = isset( $_GET['jacklogu_export_nonce'] ) ? sanitize_text_field( wp_unslash( $_GET['jacklogu_export_nonce'] ) ) : '';

			if ( ! wp_verify_nonce( $nonce, 'jacklogu_export_action' ) ) {
				wp_die( esc_html__( 'Security check failed.', 'jacker-login-guard' ) );
			}

			$data = array(
				'version'     => JACKLOGU_VERSION,
				'export_time' => current_time( 'mysql' ),
				'settings'    => get_option( JACKLOGU_OPTION_KEY, array() ),
			);

			header( 'Content-Type: application/json' );
			header( 'Content-Disposition: attachment; filename="jacker-login-guard-' . gmdate( 'Y-m-d' ) . '.json"' );

			// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			echo wp_json_encode( $data, JSON_PRETTY_PRINT );
			exit;
		}

		// Import via POST.
		if ( isset( $_POST['jacklogu_action'] ) && 'import_settings' === $_POST['jacklogu_action'] ) {
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash
			$nonce = isset( $_POST['jacklogu_import_nonce'] ) ? sanitize_text_field( wp_unslash( $_POST['jacklogu_import_nonce'] ) ) : '';

			if ( ! wp_verify_nonce( $nonce, 'jacklogu_import_action' ) ) {
				wp_die( esc_html__( 'Security check failed.', 'jacker-login-guard' ) );
			}

			if ( ! isset( $_FILES['jacklogu_settings_file']['error'] ) || UPLOAD_ERR_OK !== $_FILES['jacklogu_settings_file']['error'] ) {
				add_settings_error( JACKLOGU_OPTION_KEY, 'import_error', __( 'File upload failed.', 'jacker-login-guard' ) );
				return;
			}

			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash
			$tmp_name = isset( $_FILES['jacklogu_settings_file']['tmp_name'] ) ? $_FILES['jacklogu_settings_file']['tmp_name'] : '';

			if ( empty( $tmp_name ) || ! is_uploaded_file( $tmp_name ) ) {
				add_settings_error( JACKLOGU_OPTION_KEY, 'import_error', __( 'Invalid upload.', 'jacker-login-guard' ) );
				return;
			}

			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
			$content = file_get_contents( $tmp_name );
			$data    = json_decode( $content, true );

			if ( ! is_array( $data ) || ! isset( $data['settings'] ) ) {
				add_settings_error( JACKLOGU_OPTION_KEY, 'import_error', __( 'Invalid settings file.', 'jacker-login-guard' ) );
				return;
			}

			$sanitized = $this->settings->sanitize( $data['settings'] );
			$this->settings->update_all( $sanitized );

			add_settings_error( JACKLOGU_OPTION_KEY, 'import_success', __( 'Settings imported successfully!', 'jacker-login-guard' ), 'success' );
		}
	}

	/**
	 * Output the collected settings errors.
	 *
	 * @since 1.0.0
	 * @return void
	 */
	public function show_settings_errors() {
		if ( current_user_can( 'manage_options' ) ) {
			settings_errors( JACKLOGU_OPTION_KEY );
		}
	}

	/**
	 * Show the "settings reset" admin notice.
	 *
	 * @since 1.0.0
	 * @return void
	 */
	public function show_reset_notice() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( ! isset( $_GET['jacklogu_reset_success'] ) || '1' !== $_GET['jacklogu_reset_success'] ) {
			return;
		}
		?>
		<div class="notice notice-warning is-dismissible">
			<p><?php esc_html_e( 'Jacker Login Guard settings have been reset to default.', 'jacker-login-guard' ); ?></p>
		</div>
		<?php
	}

	/**
	 * Inject a "Settings" link into the plugin's row on the Plugins screen.
	 *
	 * @since 1.0.0
	 * @param string[] $links Existing action links.
	 * @param string   $file  Plugin basename.
	 * @return string[] Filtered action links.
	 */
	public function action_links( $links, $file ) {
		if ( plugin_basename( JACKLOGU_FILE ) !== $file ) {
			return $links;
		}

		$url = admin_url( 'options-general.php?page=jacker-login-guard' );
		array_unshift( $links, '<a href="' . esc_url( $url ) . '">' . esc_html__( 'Settings', 'jacker-login-guard' ) . '</a>' );

		return $links;
	}
}