<?php
/**
 * IP address helpers.
 *
 * Detects the real client IP (Cloudflare-aware), validates CIDR ranges,
 * IP ranges (A-B), and single addresses, and batch-resolves country codes
 * for display in the admin logs.
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
 * Class IpUtils
 *
 * Static helpers for IP detection, validation, and country lookup.
 *
 * @since 1.0.0
 */
class IpUtils {

	/**
	 * Per-request cache of resolved country codes.
	 *
	 * @since 1.0.0
	 * @var   array<string, string>
	 */
	private static $country_cache = array();

	/**
	 * Static Cloudflare IP ranges used when the remote API is unreachable.
	 *
	 * @since 1.0.0
	 * @var   string[]
	 */
	private static $cloudflare_fallback = array(
		'173.245.48.0/20',
		'103.21.244.0/22',
		'103.22.200.0/22',
		'103.31.4.0/22',
		'141.101.64.0/18',
		'108.162.192.0/18',
		'190.93.240.0/20',
		'188.114.96.0/20',
		'197.234.240.0/22',
		'198.41.128.0/17',
		'162.158.0.0/15',
		'104.16.0.0/13',
		'104.24.0.0/14',
		'172.64.0.0/13',
		'131.0.72.0/22',
		'2400:cb00::/32',
		'2606:4700::/32',
		'2803:f800::/32',
		'2405:b500::/32',
		'2405:8100::/32',
		'2a06:98c0::/29',
		'2c0f:f248::/32',
	);

	/**
	 * Return the client IP address.
	 *
	 * Uses `HTTP_CF_CONNECTING_IP` only when `REMOTE_ADDR` is a known
	 * Cloudflare IP, preventing header spoofing on non-Cloudflare setups.
	 *
	 * @since 1.0.0
	 * @return string Valid IP, or `0.0.0.0` when it cannot be determined.
	 */
	public static function get_client_ip() {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash
		$remote_addr = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';

		if ( $remote_addr && self::is_cloudflare_ip( $remote_addr ) ) {
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash
			$cf_ip = isset( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) : '';

			if ( filter_var( $cf_ip, FILTER_VALIDATE_IP ) ) {
				return $cf_ip;
			}
		}

		if ( filter_var( $remote_addr, FILTER_VALIDATE_IP ) ) {
			return $remote_addr;
		}

		return '0.0.0.0';
	}

	/**
	 * Whether the given IP belongs to a Cloudflare range.
	 *
	 * @since 1.0.0
	 * @param string $ip IP address.
	 * @return bool
	 */
	public static function is_cloudflare_ip( $ip ) {
		foreach ( self::get_cloudflare_ips() as $range ) {
			if ( self::ip_in_range( $ip, $range ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Return the official Cloudflare IP ranges, cached for 7 days.
	 *
	 * @since 1.0.0
	 * @return string[]
	 */
	private static function get_cloudflare_ips() {
		$cached = get_transient( 'jacklogu_cloudflare_ips' );

		if ( false !== $cached && is_array( $cached ) ) {
			return $cached;
		}

		$response = wp_remote_get(
			'https://api.cloudflare.com/client/v4/ips',
			array( 'timeout' => 5 )
		);

		if ( ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) ) {
			$body = json_decode( wp_remote_retrieve_body( $response ), true );

			if ( isset( $body['result']['ipv4_cidrs'], $body['result']['ipv6_cidrs'] ) ) {
				$ips = array_merge( $body['result']['ipv4_cidrs'], $body['result']['ipv6_cidrs'] );
				set_transient( 'jacklogu_cloudflare_ips', $ips, 7 * DAY_IN_SECONDS );
				return $ips;
			}
		}

		return self::$cloudflare_fallback;
	}

	/**
	 * Check whether an IP falls inside a range or matches exactly.
	 *
	 * Supported formats:
	 *   - Single IP:      192.168.1.5
	 *   - CIDR range:     192.168.1.0/24
	 *   - Range (A-B):    192.168.1.10-192.168.1.50
	 *
	 * Both IPv4 and IPv6 are supported.
	 *
	 * @since 1.0.0
	 * @param string $ip    IP address.
	 * @param string $range Range expression (single / CIDR / A-B).
	 * @return bool
	 */
	public static function ip_in_range( $ip, $range ) {
		if ( empty( $ip ) || empty( $range ) ) {
			return false;
		}

		// Range format: A-B.
		if ( strpos( $range, '-' ) !== false ) {
			list( $start, $end ) = array_map( 'trim', explode( '-', $range, 2 ) );

			if ( ! filter_var( $start, FILTER_VALIDATE_IP ) || ! filter_var( $end, FILTER_VALIDATE_IP ) ) {
				return false;
			}

			$ip_bin    = @inet_pton( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			$start_bin = @inet_pton( $start ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			$end_bin   = @inet_pton( $end ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged

			// Must be same family (both IPv4 or both IPv6).
			if ( false === $ip_bin || false === $start_bin || false === $end_bin ) {
				return false;
			}

			if ( strlen( $ip_bin ) !== strlen( $start_bin ) || strlen( $start_bin ) !== strlen( $end_bin ) ) {
				return false;
			}

			return ( strcmp( $ip_bin, $start_bin ) >= 0 ) && ( strcmp( $ip_bin, $end_bin ) <= 0 );
		}

		// CIDR range.
		if ( strpos( $range, '/' ) !== false ) {
			list( $subnet, $bits ) = explode( '/', $range, 2 );
			$bits                  = (int) $bits;

			$ip_bin     = @inet_pton( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			$subnet_bin = @inet_pton( $subnet ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged

			if ( false === $ip_bin || false === $subnet_bin ) {
				return false;
			}

			$is_ipv4  = ( 4 === strlen( $ip_bin ) );
			$max_bits = $is_ipv4 ? 32 : 128;

			if ( $bits < 0 || $bits > $max_bits ) {
				return false;
			}

			if ( $is_ipv4 ) {
				$mask        = 0 === $bits ? 0 : ( ~0 << ( 32 - $bits ) );
				$ip_long     = unpack( 'N', $ip_bin )[1];
				$subnet_long = unpack( 'N', $subnet_bin )[1];
				return ( $ip_long & $mask ) === ( $subnet_long & $mask );
			}

			$mask = str_repeat( "\xff", $bits >> 3 );
			if ( $bits & 7 ) {
				$mask .= chr( 0xff << ( 8 - ( $bits & 7 ) ) );
			}
			$mask = str_pad( $mask, 16, "\x00" );

			for ( $i = 0; $i < 16; $i++ ) {
				if ( ( $ip_bin[ $i ] & $mask[ $i ] ) !== ( $subnet_bin[ $i ] & $mask[ $i ] ) ) {
					return false;
				}
			}

			return true;
		}

		// Single IP.
		return $ip === $range;
	}

	/**
	 * Resolve a single IP to a country code.
	 *
	 * @since 1.0.0
	 * @param string $ip IP address.
	 * @return string Two-letter country code, or empty string.
	 */
	public static function get_country_code( $ip ) {
		$result = self::get_country_codes_batch( array( $ip ) );
		return isset( $result[ $ip ] ) ? $result[ $ip ] : '';
	}

	/**
	 * Resolve a batch of IPs to country codes.
	 *
	 * @since 1.0.0
	 * @param string[] $ips List of IP addresses.
	 * @return array<string, string> Map of IP => country code.
	 */
	public static function get_country_codes_batch( $ips ) {
		$result  = array();
		$missing = array();

		foreach ( $ips as $ip ) {
			$ip = (string) $ip;

			if ( empty( $ip ) ) {
				continue;
			}

			if ( '0.0.0.0' === $ip || '::1' === $ip || '127.0.0.1' === $ip ) {
				$result[ $ip ] = 'localhost';
				continue;
			}

			if ( isset( self::$country_cache[ $ip ] ) ) {
				$result[ $ip ] = self::$country_cache[ $ip ];
				continue;
			}

			$cache_key = 'jacklogu_geo_' . md5( $ip );
			$cached    = get_transient( $cache_key );

			if ( false !== $cached ) {
				self::$country_cache[ $ip ] = $cached;
				$result[ $ip ]              = $cached;
				continue;
			}

			$missing[] = $ip;
		}

		if ( empty( $missing ) ) {
			return $result;
		}

		$chunks = array_chunk( $missing, 100 );

		foreach ( $chunks as $chunk ) {
			$payload = array();

			foreach ( $chunk as $ip ) {
				$payload[] = array(
					'query'  => $ip,
					'fields' => 'status,countryCode,query',
				);
			}

			$response = wp_remote_post(
				'http://ip-api.com/batch?fields=status,countryCode,query',
				array(
					'timeout' => 5,
					'headers' => array( 'Content-Type' => 'application/json' ),
					'body'    => wp_json_encode( $payload ),
				)
			);

			if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
				foreach ( $chunk as $ip ) {
					self::$country_cache[ $ip ] = '';
					$result[ $ip ]              = '';
				}
				continue;
			}

			$body = json_decode( wp_remote_retrieve_body( $response ), true );

			if ( ! is_array( $body ) ) {
				foreach ( $chunk as $ip ) {
					self::$country_cache[ $ip ] = '';
					$result[ $ip ]              = '';
				}
				continue;
			}

			$lookup = array();
			foreach ( $body as $item ) {
				if ( isset( $item['query'], $item['countryCode'] ) ) {
					$lookup[ $item['query'] ] = strtoupper( $item['countryCode'] );
				}
			}

			foreach ( $chunk as $ip ) {
				$country = isset( $lookup[ $ip ] ) ? $lookup[ $ip ] : '';

				self::$country_cache[ $ip ] = $country;
				$result[ $ip ]              = $country;

				set_transient( 'jacklogu_geo_' . md5( $ip ), $country, 7 * DAY_IN_SECONDS );
			}
		}

		return $result;
	}

	/**
	 * Return HTML flag placeholders for a batch of IPs.
	 *
	 * @since 1.0.0
	 * @param string[] $ips List of IP addresses.
	 * @return array<string, string> Map of IP => HTML flag string.
	 */
	public static function get_country_flags_batch( $ips ) {
		$codes = self::get_country_codes_batch( $ips );
		$flags = array();

		foreach ( $codes as $ip => $country ) {
			if ( empty( $country ) ) {
				$flags[ $ip ] = '';
				continue;
			}

			$emoji        = self::get_flag_emoji( $country );
			$flags[ $ip ] = ' <span style="font-size:16px;" title="' . esc_attr( $country ) . '">' . esc_html( $emoji ) . '</span>';
		}

		return $flags;
	}

	/**
	 * Convert a two-letter country code to its flag emoji.
	 *
	 * @since 1.0.0
	 * @param string $country_code Two-letter ISO country code.
	 * @return string Flag emoji, or the globe emoji as fallback.
	 */
	public static function get_flag_emoji( $country_code ) {
		if ( empty( $country_code ) || 'localhost' === $country_code || strlen( $country_code ) !== 2 ) {
			return '🌐';
		}

		$country_code = strtoupper( $country_code );

		$regional_offset = 0x1F1E6;
		$ascii_offset    = 65;

		$emoji  = '';
		$emoji .= mb_chr( $regional_offset + ord( $country_code[0] ) - $ascii_offset );
		$emoji .= mb_chr( $regional_offset + ord( $country_code[1] ) - $ascii_offset );

		return $emoji;
	}

	/**
	 * Return an HTML flag for a single IP, using only cached data.
	 *
	 * @since 1.0.0
	 * @param string $ip IP address.
	 * @return string HTML fragment.
	 */
	public static function get_country_flag_html( $ip ) {
		if ( empty( $ip ) || '0.0.0.0' === $ip || '::1' === $ip || '127.0.0.1' === $ip ) {
			return '';
		}

		$cache_key = 'jacklogu_geo_' . md5( $ip );
		$country   = get_transient( $cache_key );

		if ( false === $country || '' === $country ) {
			return '<span class="jacklogu-flag-placeholder" data-ip="' . esc_attr( $ip ) . '"></span>';
		}

		$flag = self::get_flag_emoji( $country );

		return ' <span style="font-size:16px;" title="' . esc_attr( $country ) . '">' . esc_html( $flag ) . '</span>';
	}

	/**
	 * Sanitize a multi-line list of IPs / CIDR ranges / IP ranges.
	 *
	 * Accepts one entry per line. Supported per-line formats:
	 *   - Single IPv4:      192.168.1.100
	 *   - Single IPv6:      2001:db8::1
	 *   - IPv4 CIDR:        192.168.1.0/24
	 *   - IPv6 CIDR:        2001:db8::/32
	 *   - IPv4 range:       192.168.1.10-192.168.1.50
	 *   - IPv6 range:       2001:db8::1-2001:db8::ffff
	 *   - Inline comment:   192.168.1.100 # My Office
	 *
	 * @since 1.0.0
	 * @param string $text Raw textarea content.
	 * @return string Cleaned multi-line list.
	 */
	public static function sanitize_ip_list( $text ) {
		$lines     = explode( "\n", $text );
		$valid_ips = array();

		foreach ( $lines as $line ) {
			$ip = trim( $line );

			if ( empty( $ip ) ) {
				continue;
			}

			$ip = explode( ' #', $ip )[0];
			$ip = trim( $ip );

			if ( empty( $ip ) ) {
				continue;
			}

			// Range format: A-B.
			if ( strpos( $ip, '-' ) !== false ) {
				list( $start, $end ) = array_map( 'trim', explode( '-', $ip, 2 ) );

				if ( ! filter_var( $start, FILTER_VALIDATE_IP ) || ! filter_var( $end, FILTER_VALIDATE_IP ) ) {
					continue;
				}

				// Both must be same family.
				$start_is_v4 = (bool) filter_var( $start, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 );
				$end_is_v4   = (bool) filter_var( $end, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 );

				if ( $start_is_v4 !== $end_is_v4 ) {
					continue;
				}

				// Start must not be greater than end.
				$start_bin = @inet_pton( $start ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
				$end_bin   = @inet_pton( $end ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged

				if ( false === $start_bin || false === $end_bin ) {
					continue;
				}

				if ( strcmp( $start_bin, $end_bin ) > 0 ) {
					continue;
				}

				$valid_ips[] = $start . '-' . $end;
				continue;
			}

			// CIDR format.
			if ( strpos( $ip, '/' ) !== false ) {
				list( $address, $prefix ) = explode( '/', $ip, 2 );
				$prefix                   = trim( $prefix );
				$address                  = trim( $address );

				if ( ! filter_var( $address, FILTER_VALIDATE_IP ) ) {
					continue;
				}

				if ( filter_var( $address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
					if ( ! is_numeric( $prefix ) || $prefix < 0 || $prefix > 32 ) {
						continue;
					}
				} elseif ( filter_var( $address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
					if ( ! is_numeric( $prefix ) || $prefix < 0 || $prefix > 128 ) {
						continue;
					}
				} else {
					continue;
				}

				$valid_ips[] = $address . '/' . $prefix;
				continue;
			}

			// Single IP.
			if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
				$valid_ips[] = $ip;
			}
		}

		return implode( "\n", $valid_ips );
	}
}