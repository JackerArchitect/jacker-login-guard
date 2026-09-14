<?php
/**
 * IP address helpers.
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
	 * Per-request cache of Cloudflare IP checks.
	 *
	 * @since 1.0.0
	 * @var   array<string, bool>
	 */
	private static $cloudflare_check_cache = array();

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
	 * @since 1.0.0
	 * @return string Valid IP, or `0.0.0.0`.
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
	 * Results are cached per-request to avoid repeated CIDR scans.
	 *
	 * @since 1.0.0
	 * @param string $ip IP address.
	 * @return bool
	 */
	public static function is_cloudflare_ip( $ip ) {
		if ( empty( $ip ) || ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return false;
		}

		if ( isset( self::$cloudflare_check_cache[ $ip ] ) ) {
			return self::$cloudflare_check_cache[ $ip ];
		}

		$result = false;

		foreach ( self::get_cloudflare_ips() as $range ) {
			if ( self::ip_in_range( $ip, $range ) ) {
				$result = true;
				break;
			}
		}

		self::$cloudflare_check_cache[ $ip ] = $result;

		return $result;
	}

	/**
	 * Return the official Cloudflare IP ranges, cached for 7 days.
	 *
	 * On failure, the fallback list is cached for 5 minutes to avoid
	 * hammering the API on every request.
	 *
	 * @since 1.0.0
	 * @return string[]
	 */
	private static function get_cloudflare_ips() {
		$cached = get_transient( 'jacklogu_cloudflare_ips' );

		if ( is_array( $cached ) && ! empty( $cached ) ) {
			return $cached;
		}

		$response = wp_remote_get(
			'https://api.cloudflare.com/client/v4/ips',
			array(
				'timeout'    => 3,
				'user-agent' => 'JackerLoginGuard/' . JACKLOGU_VERSION . '; ' . home_url( '/' ),
			)
		);

		if ( ! is_wp_error( $response ) && 200 === (int) wp_remote_retrieve_response_code( $response ) ) {
			$body = json_decode( wp_remote_retrieve_body( $response ), true );

			if ( isset( $body['result']['ipv4_cidrs'], $body['result']['ipv6_cidrs'] )
				&& is_array( $body['result']['ipv4_cidrs'] )
				&& is_array( $body['result']['ipv6_cidrs'] ) ) {
				$ips = array_merge( $body['result']['ipv4_cidrs'], $body['result']['ipv6_cidrs'] );
				set_transient( 'jacklogu_cloudflare_ips', $ips, 7 * DAY_IN_SECONDS );
				return $ips;
			}
		}

		set_transient( 'jacklogu_cloudflare_ips', self::$cloudflare_fallback, 5 * MINUTE_IN_SECONDS );
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
	 * @since 1.0.0
	 * @param string $ip    IP address.
	 * @param string $range Range expression.
	 * @return bool
	 */
	public static function ip_in_range( $ip, $range ) {
		if ( empty( $ip ) || empty( $range ) ) {
			return false;
		}

		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return false;
		}

		// Range format: A-B.
		if ( false !== strpos( $range, '-' ) ) {
			list( $start, $end ) = array_map( 'trim', explode( '-', $range, 2 ) );

			if ( ! filter_var( $start, FILTER_VALIDATE_IP ) || ! filter_var( $end, FILTER_VALIDATE_IP ) ) {
				return false;
			}

			$ip_bin    = inet_pton( $ip );
			$start_bin = inet_pton( $start );
			$end_bin   = inet_pton( $end );

			if ( false === $ip_bin || false === $start_bin || false === $end_bin ) {
				return false;
			}

			if ( strlen( $ip_bin ) !== strlen( $start_bin ) || strlen( $start_bin ) !== strlen( $end_bin ) ) {
				return false;
			}

			return ( strcmp( $ip_bin, $start_bin ) >= 0 ) && ( strcmp( $ip_bin, $end_bin ) <= 0 );
		}

		// CIDR range.
		if ( false !== strpos( $range, '/' ) ) {
			list( $subnet, $bits ) = explode( '/', $range, 2 );
			$bits                  = (int) $bits;

			$ip_bin     = inet_pton( $ip );
			$subnet_bin = inet_pton( $subnet );

			if ( false === $ip_bin || false === $subnet_bin ) {
				return false;
			}

			$is_ipv4  = ( 4 === strlen( $ip_bin ) );
			$max_bits = $is_ipv4 ? 32 : 128;

			if ( $bits < 0 || $bits > $max_bits ) {
				return false;
			}

			if ( $is_ipv4 ) {
				$mask        = 0 === $bits ? 0 : ( 0xFFFFFFFF << ( 32 - $bits ) ) & 0xFFFFFFFF;
				$ip_long     = unpack( 'N', $ip_bin )[1];
				$subnet_long = unpack( 'N', $subnet_bin )[1];
				return ( $ip_long & $mask ) === ( $subnet_long & $mask );
			}

			$mask = str_repeat( "\xff", intdiv( $bits, 8 ) );
			$rem  = $bits % 8;
			if ( $rem ) {
				$mask .= chr( ( 0xFF << ( 8 - $rem ) ) & 0xFF );
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

			if ( empty( $ip ) || ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
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

			$endpoints = array();

			$api_key = (string) apply_filters( 'jacklogu_ipapi_key', '' );
			if ( '' !== $api_key ) {
				$endpoints[] = 'https://pro.ip-api.com/batch?key=' . rawurlencode( $api_key ) . '&fields=status,countryCode,query';
			}

			$endpoints[] = 'http://ip-api.com/batch?fields=status,countryCode,query';

			$body = null;

			foreach ( $endpoints as $endpoint ) {
				$response = wp_remote_post(
					$endpoint,
					array(
						'timeout'    => 5,
						'headers'    => array( 'Content-Type' => 'application/json' ),
						'body'       => wp_json_encode( $payload ),
						'user-agent' => 'JackerLoginGuard/' . JACKLOGU_VERSION,
					)
				);

				if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
					continue;
				}

				$decoded = json_decode( wp_remote_retrieve_body( $response ), true );

				if ( is_array( $decoded ) ) {
					$body = $decoded;
					break;
				}
			}

			if ( null === $body ) {
				foreach ( $chunk as $ip ) {
					self::$country_cache[ $ip ] = '';
					$result[ $ip ]              = '';
					set_transient( 'jacklogu_geo_' . md5( $ip ), '', 5 * MINUTE_IN_SECONDS );
				}
				continue;
			}

			$lookup = array();
			foreach ( $body as $item ) {
				if ( isset( $item['query'], $item['countryCode'] ) && is_string( $item['query'] ) && is_string( $item['countryCode'] ) ) {
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
		if ( empty( $country_code ) || 'localhost' === $country_code ) {
			return '🌐';
		}

		$country_code = strtoupper( (string) $country_code );

		if ( ! preg_match( '/^[A-Z]{2}$/', $country_code ) ) {
			return '🌐';
		}

		$regional_offset = 0x1F1E6;
		$ascii_offset    = 65;

		if ( function_exists( 'mb_chr' ) ) {
			$emoji  = '';
			$emoji .= mb_chr( $regional_offset + ord( $country_code[0] ) - $ascii_offset, 'UTF-8' );
			$emoji .= mb_chr( $regional_offset + ord( $country_code[1] ) - $ascii_offset, 'UTF-8' );
			return $emoji;
		}

		$emoji  = '&#x' . dechex( $regional_offset + ord( $country_code[0] ) - $ascii_offset ) . ';';
		$emoji .= '&#x' . dechex( $regional_offset + ord( $country_code[1] ) - $ascii_offset ) . ';';

		return html_entity_decode( $emoji, ENT_QUOTES, 'UTF-8' );
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
	 * @since 1.0.0
	 * @param string $text Raw textarea content.
	 * @return string Cleaned multi-line list.
	 */
	public static function sanitize_ip_list( $text ) {
		if ( ! is_string( $text ) ) {
			return '';
		}

		$lines     = explode( "\n", $text );
		$valid_ips = array();

		foreach ( $lines as $line ) {
			$ip = trim( $line );

			if ( empty( $ip ) ) {
				continue;
			}

			$parts = explode( ' #', $ip, 2 );
			$ip    = trim( $parts[0] );

			if ( empty( $ip ) ) {
				continue;
			}

			// Reject null bytes.
			if ( false !== strpos( $ip, "\0" ) ) {
				continue;
			}

			// Range format: A-B.
			if ( false !== strpos( $ip, '-' ) ) {
				list( $start, $end ) = array_map( 'trim', explode( '-', $ip, 2 ) );

				if ( ! filter_var( $start, FILTER_VALIDATE_IP ) || ! filter_var( $end, FILTER_VALIDATE_IP ) ) {
					continue;
				}

				$start_is_v4 = (bool) filter_var( $start, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 );
				$end_is_v4   = (bool) filter_var( $end, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 );

				if ( $start_is_v4 !== $end_is_v4 ) {
					continue;
				}

				$start_bin = inet_pton( $start );
				$end_bin   = inet_pton( $end );

				if ( false === $start_bin || false === $end_bin ) {
					continue;
				}

				if ( strcmp( $start_bin, $end_bin ) > 0 ) {
					continue;
				}

				$start_norm = inet_ntop( $start_bin );
				$end_norm   = inet_ntop( $end_bin );

				if ( false === $start_norm || false === $end_norm ) {
					continue;
				}

				$valid_ips[] = $start_norm . '-' . $end_norm;
				continue;
			}

			// CIDR format.
			if ( false !== strpos( $ip, '/' ) ) {
				list( $address, $prefix ) = explode( '/', $ip, 2 );
				$address                  = trim( $address );
				$prefix                   = trim( $prefix );

				if ( ! filter_var( $address, FILTER_VALIDATE_IP ) ) {
					continue;
				}

				if ( ! is_numeric( $prefix ) ) {
					continue;
				}

				$prefix = (int) $prefix;

				if ( filter_var( $address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
					if ( $prefix < 0 || $prefix > 32 ) {
						continue;
					}
				} else {
					if ( $prefix < 0 || $prefix > 128 ) {
						continue;
					}
				}

				$address_bin = inet_pton( $address );
				if ( false === $address_bin ) {
					continue;
				}

				$address_norm = inet_ntop( $address_bin );
				if ( false === $address_norm ) {
					continue;
				}

				$valid_ips[] = $address_norm . '/' . $prefix;
				continue;
			}

			// Single IP.
			if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
				$packed = inet_pton( $ip );
				if ( false !== $packed ) {
					$normalized = inet_ntop( $packed );
					if ( false !== $normalized ) {
						$valid_ips[] = $normalized;
						continue;
					}
				}
				$valid_ips[] = $ip;
			}
		}

		return implode( "\n", $valid_ips );
	}
}