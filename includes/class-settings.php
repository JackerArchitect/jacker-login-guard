<?php
/**
 * Settings management.
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
 * Class Settings
 *
 * @since 1.0.0
 */
class Settings {

	/**
	 * Singleton instance.
	 *
	 * @since 1.0.0
	 * @var   Settings|null
	 */
	private static $instance = null;

	/**
	 * Loaded settings.
	 *
	 * @since 1.0.0
	 * @var   array<string, mixed>
	 */
	private $settings = array();

	/**
	 * Get the singleton instance.
	 *
	 * @since 1.0.0
	 * @return Settings
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Constructor.
	 *
	 * @since 1.0.0
	 */
	private function __construct() {
		$this->migrate_old_option();
		$this->load();
	}

	/**
	 * Migrate the legacy option key to the current one.
	 *
	 * @since 1.0.0
	 * @return void
	 */
	private function migrate_old_option() {
		$old = get_option( JACKLOGU_OLD_OPTION_KEY );

		if ( false !== $old && false === get_option( JACKLOGU_OPTION_KEY ) ) {
			update_option( JACKLOGU_OPTION_KEY, $old );
			delete_option( JACKLOGU_OLD_OPTION_KEY );
		}
	}

	/**
	 * Load and merge the stored settings with the defaults.
	 *
	 * @since 1.0.0
	 * @return void
	 */
	private function load() {
		$saved          = get_option( JACKLOGU_OPTION_KEY, array() );
		$this->settings = wp_parse_args( $saved, self::get_defaults() );
	}

	/**
	 * Return the default settings.
	 *
	 * @since 1.0.0
	 * @return array<string, mixed>
	 */
	public static function get_defaults() {
		return array(
			'slug'                              => JACKLOGU_DEFAULT_SLUG,
			'unauthorized_response'             => '0.0.0.0',
			'login_protection_mode'             => 'compatibility',
			'bind_ip_to_cookie'                 => false,
			'enable_security_headers'           => true,
			'whitelist_ips'                     => '',
			'blacklist_ips'                     => '',
			'enable_logging'                    => true,
			'block_xmlrpc'                      => true,
			'block_author_enum'                 => true,
			'block_rest_api_users'              => true,
			'remove_author_body_class'          => true,
			'hide_author_in_feed'               => true,
			'unify_login_errors'                => true,
			'uninstall_remove_data'             => false,
			'api_whitelist'                     => '',
			'path_whitelist'                    => '',
			'auto_block_attacks'                => true,
			'auto_block_trigger_threshold'      => 3,
			'auto_block_duration_hours'         => 24,
			'auto_block_to_blacklist_threshold' => 3,
			'failed_login_block_threshold'      => 5,
			'trusted_ip_window_days'            => 7,
			'log_retention_limit'               => 300,
			'session_lifetime'                  => 0,
		);
	}

	/**
	 * Persist the defaults on activation when the option does not exist yet.
	 *
	 * @since 1.0.0
	 * @return void
	 */
	public function set_defaults() {
		if ( false === get_option( JACKLOGU_OPTION_KEY ) ) {
			add_option( JACKLOGU_OPTION_KEY, self::get_defaults() );
		}
	}

	/**
	 * Get a single setting.
	 *
	 * @since 1.0.0
	 * @param string $key     Setting key.
	 * @param mixed  $default Value to return when the key is missing.
	 * @return mixed
	 */
	public function get( $key, $default = null ) {
		return isset( $this->settings[ $key ] ) ? $this->settings[ $key ] : $default;
	}

	/**
	 * Get the full settings array.
	 *
	 * @since 1.0.0
	 * @return array<string, mixed>
	 */
	public function get_all() {
		return $this->settings;
	}

	/**
	 * Persist a single setting.
	 *
	 * @since 1.0.0
	 * @param string $key   Setting key.
	 * @param mixed  $value Setting value.
	 * @return void
	 */
	public function update( $key, $value ) {
		$this->settings[ $key ] = $value;
		update_option( JACKLOGU_OPTION_KEY, $this->settings );
	}

	/**
	 * Replace the entire settings array.
	 *
	 * @since 1.0.0
	 * @param array<string, mixed> $settings Full settings array.
	 * @return void
	 */
	public function update_all( $settings ) {
		$this->settings = wp_parse_args( $settings, self::get_defaults() );
		update_option( JACKLOGU_OPTION_KEY, $this->settings );
	}

	/**
	 * Get the log retention limit (clamped to 10-5000).
	 *
	 * @since 1.0.0
	 * @return int
	 */
	public function get_log_limit() {
		$limit = (int) $this->get( 'log_retention_limit', 300 );

		if ( $limit < 10 ) {
			$limit = 10;
		} elseif ( $limit > 5000 ) {
			$limit = 5000;
		}

		return $limit;
	}

	/**
	 * Get the session lifetime in seconds (0 = use WordPress default).
	 *
	 * @since 1.0.0
	 * @return int
	 */
	public function get_session_lifetime() {
		$minutes = (int) $this->get( 'session_lifetime', 0 );

		if ( $minutes <= 0 ) {
			return 0;
		}

		if ( $minutes > 10080 ) {
			$minutes = 10080;
		}

		return $minutes * MINUTE_IN_SECONDS;
	}

	/**
	 * Get the auto-block trigger threshold.
	 *
	 * @since 1.0.0
	 * @return int
	 */
	public function get_auto_block_trigger_threshold() {
		$value = (int) $this->get( 'auto_block_trigger_threshold', 3 );

		if ( $value < 1 ) {
			$value = 1;
		} elseif ( $value > 100 ) {
			$value = 100;
		}

		return $value;
	}

	/**
	 * Get the auto-block duration in seconds.
	 *
	 * @since 1.0.0
	 * @return int
	 */
	public function get_auto_block_duration_seconds() {
		$hours = (int) $this->get( 'auto_block_duration_hours', 24 );

		if ( $hours < 1 ) {
			$hours = 1;
		} elseif ( $hours > 8760 ) {
			$hours = 8760;
		}

		return $hours * HOUR_IN_SECONDS;
	}

	/**
	 * Get the auto-block to blacklist escalation threshold.
	 *
	 * @since 1.0.0
	 * @return int 0 = disabled.
	 */
	public function get_auto_block_to_blacklist_threshold() {
		$value = (int) $this->get( 'auto_block_to_blacklist_threshold', 3 );

		if ( $value < 0 ) {
			$value = 0;
		} elseif ( $value > 100 ) {
			$value = 100;
		}

		return $value;
	}

	/**
	 * Get the failed-login auto-block threshold.
	 *
	 * @since 1.0.0
	 * @return int 0 = disabled.
	 */
	public function get_failed_login_block_threshold() {
		$value = (int) $this->get( 'failed_login_block_threshold', 5 );

		if ( $value < 0 ) {
			$value = 0;
		} elseif ( $value > 100 ) {
			$value = 100;
		}

		return $value;
	}

	/**
	 * Get the trusted-IP window in seconds.
	 *
	 * @since 1.0.0
	 * @return int 0 = disabled.
	 */
	public function get_trusted_ip_window_seconds() {
		$days = (int) $this->get( 'trusted_ip_window_days', 7 );

		if ( $days < 0 ) {
			$days = 0;
		} elseif ( $days > 365 ) {
			$days = 365;
		}

		return $days * DAY_IN_SECONDS;
	}

	/**
	 * Register the plugin setting with the WordPress settings API.
	 *
	 * @since 1.0.0
	 * @return void
	 */
	public function register() {
		register_setting(
			'jacklogu_settings_group',
			JACKLOGU_OPTION_KEY,
			array(
				'type'              => 'array',
				'sanitize_callback' => array( $this, 'sanitize' ),
				'default'           => self::get_defaults(),
			)
		);
	}

	/**
	 * Sanitize the settings input.
	 *
	 * @since 1.0.0
	 * @param array<string, mixed> $input Raw input array.
	 * @return array<string, mixed> Sanitized settings.
	 */
	public function sanitize( $input ) {
		if ( ! is_array( $input ) ) {
			return $this->settings;
		}

		$sanitized = $this->settings;

		// Login slug.
		if ( isset( $input['slug'] ) ) {
			$raw_slug = sanitize_title( $input['slug'] );

			if ( ! preg_match( '/^[a-z0-9]+(?:-[a-z0-9]+)*$/', $raw_slug ) ) {
				add_settings_error(
					JACKLOGU_OPTION_KEY,
					'invalid_slug_format',
					__( 'Invalid slug format. Use only lowercase letters, numbers, and hyphens (e.g., my-login).', 'jacker-login-guard' )
				);
				$sanitized['slug'] = ! empty( $this->settings['slug'] ) ? $this->settings['slug'] : JACKLOGU_DEFAULT_SLUG;
			} else {
				$sanitized['slug'] = $raw_slug;
			}

			if ( ! empty( $this->settings['slug'] ) ) {
				wp_cache_delete( 'jacklogu_page_check_' . md5( $this->settings['slug'] ), 'jackerloginguard' );
			}
			wp_cache_delete( 'jacklogu_page_check_' . md5( $sanitized['slug'] ), 'jackerloginguard' );
		}

		// Unauthorized response mode.
		if ( isset( $input['unauthorized_response'] ) ) {
			$valid                              = array( '0.0.0.0', '404', '403', 'homepage' );
			$sanitized['unauthorized_response'] = in_array( $input['unauthorized_response'], $valid, true )
				? $input['unauthorized_response']
				: '0.0.0.0';
		}

		// Login protection mode.
		if ( isset( $input['login_protection_mode'] ) ) {
			$valid                              = array( 'compatibility', 'strict' );
			$sanitized['login_protection_mode'] = in_array( $input['login_protection_mode'], $valid, true )
				? $input['login_protection_mode']
				: 'compatibility';
		}

		// Boolean checkboxes.
		$boolean_keys = array(
			'bind_ip_to_cookie',
			'enable_security_headers',
			'enable_logging',
			'block_xmlrpc',
			'block_author_enum',
			'block_rest_api_users',
			'remove_author_body_class',
			'hide_author_in_feed',
			'unify_login_errors',
			'auto_block_attacks',
			'uninstall_remove_data',
		);

		foreach ( $boolean_keys as $key ) {
			if ( array_key_exists( $key, $input ) ) {
				$sanitized[ $key ] = ! empty( $input[ $key ] );
			}
		}

		// IP lists.
		if ( isset( $input['whitelist_ips'] ) ) {
			$sanitized['whitelist_ips'] = IpUtils::sanitize_ip_list( $input['whitelist_ips'] );
		}
		if ( isset( $input['blacklist_ips'] ) ) {
			$sanitized['blacklist_ips'] = IpUtils::sanitize_ip_list( $input['blacklist_ips'] );
		}

		// API whitelist.
		if ( isset( $input['api_whitelist'] ) ) {
			$lines       = array_filter( array_map( 'trim', explode( "\n", $input['api_whitelist'] ) ) );
			$valid_lines = array();

			foreach ( $lines as $line ) {
				if ( strpos( $line, '/' ) === 0 ) {
					$valid_lines[] = sanitize_text_field( $line );
				}
			}

			$sanitized['api_whitelist'] = implode( "\n", $valid_lines );
		}

		// Path whitelist.
		if ( isset( $input['path_whitelist'] ) ) {
			$lines       = array_filter( array_map( 'trim', explode( "\n", $input['path_whitelist'] ) ) );
			$valid_lines = array();

			foreach ( $lines as $line ) {
				if ( strpos( $line, '/' ) === 0 ) {
					$valid_lines[] = sanitize_text_field( $line );
				}
			}

			$sanitized['path_whitelist'] = implode( "\n", $valid_lines );
		}

		// Log retention limit.
		if ( isset( $input['log_retention_limit'] ) ) {
			$limit = (int) $input['log_retention_limit'];

			if ( $limit < 10 ) {
				$limit = 10;
			} elseif ( $limit > 5000 ) {
				$limit = 5000;
			}

			$sanitized['log_retention_limit'] = $limit;
		}

		// Session lifetime.
		if ( isset( $input['session_lifetime'] ) ) {
			$lifetime = (int) $input['session_lifetime'];

			if ( $lifetime < 0 ) {
				$lifetime = 0;
			} elseif ( $lifetime > 10080 ) {
				$lifetime = 10080;
			}

			$sanitized['session_lifetime'] = $lifetime;
		}

		// Auto-block trigger threshold.
		if ( isset( $input['auto_block_trigger_threshold'] ) ) {
			$value = (int) $input['auto_block_trigger_threshold'];

			if ( $value < 1 ) {
				$value = 1;
			} elseif ( $value > 100 ) {
				$value = 100;
			}

			$sanitized['auto_block_trigger_threshold'] = $value;
		}

		// Auto-block duration hours.
		if ( isset( $input['auto_block_duration_hours'] ) ) {
			$hours = (int) $input['auto_block_duration_hours'];

			if ( $hours < 1 ) {
				$hours = 1;
			} elseif ( $hours > 8760 ) {
				$hours = 8760;
			}

			$sanitized['auto_block_duration_hours'] = $hours;
		}

		// Auto-block to blacklist threshold.
		if ( isset( $input['auto_block_to_blacklist_threshold'] ) ) {
			$value = (int) $input['auto_block_to_blacklist_threshold'];

			if ( $value < 0 ) {
				$value = 0;
			} elseif ( $value > 100 ) {
				$value = 100;
			}

			$sanitized['auto_block_to_blacklist_threshold'] = $value;
		}

		// Failed login block threshold.
		if ( isset( $input['failed_login_block_threshold'] ) ) {
			$value = (int) $input['failed_login_block_threshold'];

			if ( $value < 0 ) {
				$value = 0;
			} elseif ( $value > 100 ) {
				$value = 100;
			}

			$sanitized['failed_login_block_threshold'] = $value;
		}

		// Trusted IP window days.
		if ( isset( $input['trusted_ip_window_days'] ) ) {
			$days = (int) $input['trusted_ip_window_days'];

			if ( $days < 0 ) {
				$days = 0;
			} elseif ( $days > 365 ) {
				$days = 365;
			}

			$sanitized['trusted_ip_window_days'] = $days;
		}

		$this->settings = $sanitized;

		return $sanitized;
	}
}