<?php
/**
 * Plugin Name: Hide Login – Secure Admin & Login Protection
 * Plugin URI:  https://jackerteo.com/plugin
 * Description: Hide and protect your WordPress login page with a custom login URL, short-lived signed access protection, IP controls, and login security hardening. Reduces brute-force exposure.
 * Version:     1.0.0
 * Author:      Jacker Architect
 * Author URI:  https://jackerteo.com/plugin
 * License:     GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: hide-login-secure
 * Requires PHP: 7.4
 * Requires at least: 5.8
 */

namespace JackerArchitect\HideLoginSecure;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

const VERSION            = '1.0.0';
const OPTION_KEY         = 'hls_settings';
const TEXT_DOMAIN        = 'hide-login-secure';
const DEFAULT_SLUG       = 'my-login';
const AUTH_COOKIE_NAME   = 'hls_gate';
const DB_TABLE           = 'hls_login_events';

final class Plugin {

    private static ?Plugin $instance = null;
    private array $settings = [];

    private array $reserved_slugs = [
        'wp-admin', 'wp-login', 'wp-content', 'wp-includes',
        'admin', 'dashboard', 'login', 'register', 'signup',
        'wp-json', 'xmlrpc', 'feed', 'author', 'wp-cron',
        'api', 'rest', 'wp', 'wordpress', 'index', 'search',
        'sitemap', 'robots', 'favicon', 'comments', 'category',
        'tag', 'page', 'embed', 'trackback',
    ];

    private array $sensitive_paths = [
        'login', 'admin', 'signin', 'sign-in', 'log-in', 'wp-json', 'xmlrpc',
    ];

    private array $sensitive_files = [
        'wp-config.php', '.htaccess', 'install.php', 'upgrade.php',
    ];

    private array $cloudflare_ips_fallback = [
        '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
        '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
        '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
        '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
        '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
        '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
    ];

    public static function get_instance(): self {
        if ( null === self::$instance ) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        $this->load_settings();
        $this->register_hooks();
    }

    private function load_settings(): void {
        $defaults = [
            'slug'                     => DEFAULT_SLUG,
            'unauthorized_response'    => '404',
            'login_protection_mode'    => 'compatibility',
            'bind_ip_to_cookie'        => false,
            'enable_security_headers'  => true,
            'whitelist_ips'            => '',
            'blacklist_ips'            => '',
            'enable_logging'           => true,
            'block_xmlrpc'             => true,
            'block_author_enum'        => true,
            'block_rest_api_users'     => true,
            'remove_author_body_class' => true,
            'hide_author_in_feed'      => true,
            'unify_login_errors'       => true,
        ];
        $saved = get_option( OPTION_KEY, [] );
        $this->settings = wp_parse_args( $saved, $defaults );
    }

    private function register_hooks(): void {
        add_action( 'init', [ $this, 'check_login_access' ], 5 );
        add_action( 'template_redirect', [ $this, 'block_sensitive_paths' ], 1 );
        add_action( 'template_redirect', [ $this, 'block_user_enumeration' ], 1 );
        add_action( 'wp_login', [ $this, 'log_successful_login' ], 10, 2 );
        
        add_filter( 'body_class', [ $this, 'remove_author_body_class' ] );
        add_filter( 'the_author', [ $this, 'hide_author_in_feed' ] );
        add_filter( 'get_the_author', [ $this, 'hide_author_in_feed' ] );
        add_filter( 'login_errors', [ $this, 'custom_login_error_message' ] );

        add_action( 'admin_menu', [ $this, 'add_admin_menu' ] );
        add_action( 'admin_init', [ $this, 'register_settings' ] );
        add_action( 'admin_init', [ $this, 'handle_event_actions' ] );
        add_action( 'admin_init', [ $this, 'handle_reset_request' ] );
        add_action( 'admin_notices', [ $this, 'show_reset_success_notice' ] );

        add_filter( 'author_link', [ $this, 'filter_author_link' ], 10, 3 );
        add_filter( 'robots_txt', [ $this, 'filter_robots_txt' ], 10, 2 );
        add_action( 'send_headers', [ $this, 'add_security_headers' ] );
        add_filter( 'plugin_action_links', [ $this, 'plugin_action_links' ], 10, 2 );
    }

    public static function activate(): void {
        global $wpdb;
        $table_name = $wpdb->prefix . DB_TABLE;
        $charset_collate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE IF NOT EXISTS $table_name (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            username varchar(255) NOT NULL,
            login_time datetime NOT NULL,
            user_ip varchar(45) NOT NULL,
            status varchar(20) DEFAULT 'success' NOT NULL,
            PRIMARY KEY (id)
        ) $charset_collate;";

        require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );
        dbDelta( $sql );

        if ( false === get_option( OPTION_KEY ) ) {
            add_option( OPTION_KEY, [] );
        }
        flush_rewrite_rules();
    }

    public static function deactivate(): void {
        flush_rewrite_rules();
        delete_transient( 'hls_cloudflare_ips' );
    }

    public function log_successful_login( string $user_login, $user ): void {
        if ( empty( $this->settings['enable_logging'] ) ) return;
        
        global $wpdb;
        $table_name = $wpdb->prefix . DB_TABLE;
        
        $wpdb->insert( $table_name, [
            'username'   => sanitize_user( $user_login ),
            'login_time' => current_time( 'mysql' ),
            'user_ip'    => $this->get_client_ip(),
            'status'     => 'success'
        ], [ '%s', '%s', '%s', '%s' ] );

        $count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table_name}" );
        if ( $count > 300 ) {
            $delete_limit = $count - 300;
            $wpdb->query( $wpdb->prepare( "DELETE FROM {$table_name} ORDER BY id ASC LIMIT %d", $delete_limit ) );
        }
    }

    public function check_login_access(): void {
        if ( defined( 'WP_INSTALLING' ) && WP_INSTALLING ) return;

        wp_get_current_user();

        $client_ip = $this->get_client_ip();

        if ( $this->is_blacklisted_ip( $client_ip ) ) {
            $this->apply_unauthorized_response( 'blacklisted_ip:' . $client_ip );
            exit;
        }

        if ( $this->is_whitelisted_ip( $client_ip ) ) return;

        $request_uri = $this->get_clean_request_uri();
        $script_name = $this->get_script_name();

        if ( $this->is_custom_slug( $request_uri ) ) {
            $this->generate_auth_cookie_and_redirect( $client_ip );
            return;
        }

        if ( basename( $script_name ) === 'wp-login.php' ) {
            $action = isset( $_GET['action'] ) ? sanitize_key( $_GET['action'] ) : '';
            $method = $_SERVER['REQUEST_METHOD'];
            $is_strict = ( $this->settings['login_protection_mode'] === 'strict' );

            $allowed_get_actions = [ 'logout', 'lostpassword', 'rp', 'resetpass', 'register', 'postpass', 'confirm_admin_email' ];
            if ( $method === 'GET' && in_array( $action, $allowed_get_actions ) && ! $is_strict ) {
                return;
            }

            if ( isset( $_GET['loggedout'] ) && $_GET['loggedout'] === 'true' ) {
                wp_safe_redirect( $this->get_custom_login_url() );
                exit;
            }
            if ( isset( $_GET['login'] ) && $_GET['login'] === 'failed' ) {
                wp_safe_redirect( $this->get_custom_login_url( 'login=failed' ) );
                exit;
            }

            if ( is_user_logged_in() ) {
                return;
            }

            if ( $this->verify_auth_cookie( $client_ip ) ) {
                return;
            }
            
            $this->apply_unauthorized_response( 'no_valid_cookie' );
            exit;
        }

        if ( basename( $script_name ) === 'xmlrpc.php' && ! empty( $this->settings['block_xmlrpc'] ) ) {
            $this->apply_unauthorized_response( 'xmlrpc_blocked' );
            exit;
        }

        if ( in_array( basename( $script_name ), $this->sensitive_files, true ) ) {
            $this->apply_unauthorized_response( 'sensitive_file:' . basename( $script_name ) );
            exit;
        }

        if ( $this->is_admin_request( $request_uri ) && ! is_user_logged_in() ) {
            if ( strpos( $request_uri, 'admin-ajax.php' ) !== false ) {
                return;
            }
            $this->apply_unauthorized_response( 'wp_admin_access' );
            exit;
        }
    }

    private function generate_auth_cookie_and_redirect( string $client_ip ): void {
        $time = time();
        $rand = wp_rand( 100000, 999999 );
        
        $payload = $time . '|' . $rand;
        
        if ( ! empty( $this->settings['bind_ip_to_cookie'] ) ) {
            $payload .= '|' . hash( 'sha256', $client_ip );
        }
        
        $sig = hash_hmac( 'sha256', $payload, wp_salt( 'auth' ) );
        $cookie_val = base64_encode( $payload . '|' . $sig );

        setcookie(
            AUTH_COOKIE_NAME,
            $cookie_val,
            [
                'expires'  => time() + 5 * MINUTE_IN_SECONDS,
                'path'     => COOKIEPATH ?: '/',
                'domain'   => COOKIE_DOMAIN,
                'secure'   => is_ssl(),
                'httponly' => true,
                'samesite' => 'Lax',
            ]
        );
        
        wp_safe_redirect( site_url( 'wp-login.php' ), 302 );
        exit;
    }

    private function verify_auth_cookie( string $current_ip ): bool {
        if ( empty( $_COOKIE[ AUTH_COOKIE_NAME ] ) ) return false;

        $decoded = base64_decode( $_COOKIE[ AUTH_COOKIE_NAME ] );
        if ( ! $decoded ) return false;

        $parts = explode( '|', $decoded );
        $expected_parts = ! empty( $this->settings['bind_ip_to_cookie'] ) ? 4 : 3;
        if ( count( $parts ) !== $expected_parts ) return false;

        $time = $parts[0];
        $rand = $parts[1];
        $sig  = end( $parts );
        
        $payload = $time . '|' . $rand;
        if ( ! empty( $this->settings['bind_ip_to_cookie'] ) ) {
            $payload .= '|' . $parts[2];
        }

        $expected_sig = hash_hmac( 'sha256', $payload, wp_salt( 'auth' ) );
        if ( ! hash_equals( $expected_sig, $sig ) ) {
            return false;
        }

        if ( ( time() - (int) $time ) > 5 * MINUTE_IN_SECONDS ) {
            return false;
        }

        if ( ! empty( $this->settings['bind_ip_to_cookie'] ) ) {
            if ( $parts[2] !== hash( 'sha256', $current_ip ) ) {
                return false;
            }
        }

        return true;
    }

    private function apply_unauthorized_response( string $reason = '' ): void {
        $mode = $this->settings['unauthorized_response'] ?? '404';
        
        switch ( $mode ) {
            case 'localhost':
                header( 'Location: http://127.0.0.1/', true, 302 );
                exit;
            case 'homepage':
                wp_safe_redirect( home_url() );
                exit;
            case '404':
            default:
                $this->send_404();
                exit;
        }
    }

    private function send_404(): void {
        global $wp_query;
        if ( isset( $wp_query ) ) $wp_query->set_404();
        status_header( 404 ); 
        nocache_headers();
        $template = get_stylesheet_directory() . '/404.php';
        if ( file_exists( $template ) ) {
            include $template;
        } else {
            wp_die( esc_html__( 'Page not found', TEXT_DOMAIN ), esc_html__( '404 - Not Found', TEXT_DOMAIN ), [ 'response' => 404 ] );
        }
        exit;
    }

    public function block_sensitive_paths(): void {
        if ( $this->is_whitelisted_ip( $this->get_client_ip() ) || is_user_logged_in() ) return;

        $request_path = $this->get_request_path();
        if ( empty( $request_path ) || $this->is_custom_slug( $request_path ) ) return;

        $blocked_slugs = apply_filters( 'hls_blocked_slugs', $this->sensitive_paths );
        if ( ! in_array( $request_path, $blocked_slugs, true ) ) return;
        if ( $this->real_page_exists( $request_path ) ) return;

        $this->apply_unauthorized_response( 'sensitive_path:/' . $request_path );
        exit;
    }

    public function block_user_enumeration(): void {
        if ( $this->is_whitelisted_ip( $this->get_client_ip() ) || is_user_logged_in() ) return;

        if ( ! empty( $this->settings['block_author_enum'] ) && isset( $_GET['author'] ) && is_numeric( $_GET['author'] ) ) {
            $this->apply_unauthorized_response( 'user_enum:author=' . intval( $_GET['author'] ) );
            exit;
        }

        if ( $this->is_rest_user_enumeration_request() ) {
            $this->apply_unauthorized_response( 'user_enum:rest_api' );
            exit;
        }

        $request_path = $this->get_request_path();
        if ( ! empty( $this->settings['block_author_enum'] ) && preg_match( '#^feed/?#', $request_path ) && isset( $_GET['author'] ) ) {
            $this->apply_unauthorized_response( 'user_enum:feed' );
            exit;
        }
    }

    private function is_rest_user_enumeration_request(): bool {
        if ( empty( $this->settings['block_rest_api_users'] ) ) {
            return false;
        }

        $rest_route = isset( $_GET['rest_route'] ) ? sanitize_text_field( wp_unslash( $_GET['rest_route'] ) ) : '';
        $request_path = $this->get_request_path();

        if ( preg_match( '#^/?wp/v2/users(?:/|$)#', $rest_route ) || 
             preg_match( '#^wp-json/wp/v2/users(?:/|$)#', $request_path ) ) {
            return true;
        }

        return false;
    }

    public function remove_author_body_class( array $classes ): array {
        if ( empty( $this->settings['remove_author_body_class'] ) ) return $classes;
        foreach ( $classes as $key => $class ) {
            if ( strpos( $class, 'author-' ) === 0 ) unset( $classes[ $key ] );
        }
        return array_values( $classes );
    }

    public function hide_author_in_feed( string $name ): string {
        if ( ! empty( $this->settings['hide_author_in_feed'] ) && is_feed() ) {
            return get_bloginfo( 'name' );
        }
        return $name;
    }

    public function custom_login_error_message( string $error ): string {
        if ( empty( $this->settings['unify_login_errors'] ) ) return $error;
        $patterns = [
            'The password you entered for the username', 'Invalid username',
            'The email could not be sent', 'Unknown email address',
            'There is no user registered with that email',
        ];
        foreach ( $patterns as $pattern ) {
            if ( strpos( $error, $pattern ) !== false ) {
                return '<strong>' . esc_html__( 'ERROR', TEXT_DOMAIN ) . '</strong>: ' . esc_html__( 'Invalid username or password.', TEXT_DOMAIN );
            }
        }
        return $error;
    }

    private function is_whitelisted_ip( string $ip ): bool {
        $list = $this->parse_ip_list( $this->settings['whitelist_ips'] ?? '' );
        foreach ( $list as $range ) {
            if ( $ip === $range || ( strpos( $range, '/' ) !== false && $this->ip_in_range( $ip, $range ) ) ) return true;
        }
        return false;
    }

    private function is_blacklisted_ip( string $ip ): bool {
        $list = $this->parse_ip_list( $this->settings['blacklist_ips'] ?? '' );
        foreach ( $list as $range ) {
            if ( $ip === $range || ( strpos( $range, '/' ) !== false && $this->ip_in_range( $ip, $range ) ) ) return true;
        }
        return false;
    }

    private function parse_ip_list( string $text ): array {
        $lines = explode( "\n", $text );
        return array_filter( array_map( 'trim', $lines ) );
    }

    private function get_client_ip(): string {
        $remote_addr = isset( $_SERVER['REMOTE_ADDR'] ) ? filter_var( $_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP ) : false;

        if ( $remote_addr && $this->is_cloudflare_ip( $remote_addr ) && ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
            $ip = filter_var( $_SERVER['HTTP_CF_CONNECTING_IP'], FILTER_VALIDATE_IP );
            if ( $ip ) return $ip;
        }

        if ( $remote_addr ) {
            return $remote_addr;
        }

        return '0.0.0.0';
    }

    private function get_cloudflare_ips(): array {
        $cached = get_transient( 'hls_cloudflare_ips' );
        if ( false !== $cached && is_array( $cached ) ) {
            return $cached;
        }

        $response = wp_remote_get( 'https://api.cloudflare.com/client/v4/ips', [ 'timeout' => 5 ] );
        if ( ! is_wp_error( $response ) && wp_remote_retrieve_response_code( $response ) === 200 ) {
            $body = json_decode( wp_remote_retrieve_body( $response ), true );
            if ( isset( $body['result']['ipv4_cidrs'], $body['result']['ipv6_cidrs'] ) ) {
                $ips = array_merge( $body['result']['ipv4_cidrs'], $body['result']['ipv6_cidrs'] );
                set_transient( 'hls_cloudflare_ips', $ips, 7 * DAY_IN_SECONDS );
                return $ips;
            }
        }

        return $this->cloudflare_ips_fallback;
    }

    private function is_cloudflare_ip( string $ip ): bool {
        foreach ( $this->get_cloudflare_ips() as $range ) {
            if ( $this->ip_in_range( $ip, $range ) ) {
                return true;
            }
        }
        return false;
    }
    
    private function ip_in_range( string $ip, string $range ): bool {
        if ( strpos( $range, '/' ) === false ) {
            return $ip === $range;
        }
        
        list( $subnet, $bits ) = explode( '/', $range, 2 );
        $bits = (int) $bits;
        
        $ip_bin = @inet_pton( $ip );
        $subnet_bin = @inet_pton( $subnet );
        
        if ( false === $ip_bin || false === $subnet_bin ) return false;
        
        $is_ipv4 = ( strlen( $ip_bin ) === 4 );
        $max_bits = $is_ipv4 ? 32 : 128;
        
        if ( $bits < 0 || $bits > $max_bits ) return false;
        
        if ( $is_ipv4 ) {
            $mask = $bits === 0 ? 0 : ( ~0 << ( 32 - $bits ) );
            $ip_long = unpack( 'N', $ip_bin )[1];
            $subnet_long = unpack( 'N', $subnet_bin )[1];
            return ( $ip_long & $mask ) === ( $subnet_long & $mask );
        } else {
            $mask = str_repeat( "\xff", $bits >> 3 );
            if ( $bits & 7 ) $mask .= chr( 0xff << ( 8 - ( $bits & 7 ) ) );
            $mask = str_pad( $mask, 16, "\x00" );
            
            for ( $i = 0; $i < 16; $i++ ) {
                if ( ( $ip_bin[ $i ] & $mask[ $i ] ) !== ( $subnet_bin[ $i ] & $mask[ $i ] ) ) return false;
            }
            return true;
        }
    }

    private function get_clean_request_uri(): string {
        $uri = isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : '';
        return trim( strtok( $uri, '?' ), '/' );
    }
    
    private function get_request_path(): string { return $this->get_clean_request_uri(); }
    private function get_script_name(): string { return isset( $_SERVER['SCRIPT_NAME'] ) ? wp_unslash( $_SERVER['SCRIPT_NAME'] ) : ''; }
    
    private function is_custom_slug( string $path ): bool {
        $slug = trim( $this->settings['slug'] ?? '', '/' );
        return ! empty( $slug ) && $path === $slug;
    }
    
    private function is_admin_request( string $path ): bool {
        $admin_path = trim( wp_parse_url( admin_url(), PHP_URL_PATH ) ?? '', '/' );
        return ! empty( $admin_path ) && ( $path === $admin_path || strpos( $path, $admin_path . '/' ) === 0 );
    }

    private function real_page_exists( string $slug ): bool {
        $cache_key = 'hls_page_check_' . md5( $slug );
        $cached = wp_cache_get( $cache_key, 'hide_login_secure' );
        
        if ( false !== $cached ) {
            return (bool) $cached;
        }

        $query = new \WP_Query( [
            'name'          => $slug,
            'post_type'     => get_post_types( [ 'public' => true ] ),
            'post_status'   => 'publish',
            'posts_per_page'=> 1,
            'fields'        => 'ids',
            'no_found_rows' => true,
        ] );
        
        if ( $query->have_posts() ) {
            wp_cache_set( $cache_key, 1, 'hide_login_secure', HOUR_IN_SECONDS );
            return true;
        }

        $terms = get_terms( [
            'taxonomy'   => get_taxonomies( [ 'public' => true ] ),
            'slug'       => $slug,
            'hide_empty' => false,
            'fields'     => 'ids',
            'number'     => 1,
        ] );

        $exists = ( ! is_wp_error( $terms ) && ! empty( $terms ) );
        wp_cache_set( $cache_key, $exists ? 1 : 0, 'hide_login_secure', HOUR_IN_SECONDS );
        
        return $exists;
    }

    public function filter_author_link( string $link, string $author_id, string $author_nicename ): string {
        if ( ! empty( $this->settings['block_author_enum'] ) && ! is_user_logged_in() ) return home_url( '/' );
        return $link;
    }

    private function get_custom_login_url( string $query = '' ): string {
        $slug = trim( $this->settings['slug'] ?? '', '/' );
        $url = home_url( '/' . ( $slug ? $slug . '/' : '' ) );
        if ( ! empty( $query ) ) {
            $url .= ( strpos( $url, '?' ) === false ? '?' : '&' ) . ltrim( $query, '?' );
        }
        return $url;
    }

    public function filter_robots_txt( string $output, bool $public ): string {
        if ( ! $public ) return $output;
        $output .= "Disallow: /wp-login.php\nDisallow: /wp-admin/\nDisallow: /wp-json/\nDisallow: /xmlrpc.php\nDisallow: /*?author=\n";
        return $output;
    }

    public function add_security_headers(): void {
        if ( empty( $this->settings['enable_security_headers'] ) ) return;
        if ( headers_sent() ) return;

        remove_action( 'wp_head', 'wp_generator' );
        header( 'X-Content-Type-Options: nosniff' );
        header( 'X-Frame-Options: SAMEORIGIN' );
        header( 'Referrer-Policy: strict-origin-when-cross-origin' );
        header_remove( 'X-Powered-By' );
    }

    public function add_admin_menu(): void {
        add_options_page(
            __( 'Hide Login Settings', TEXT_DOMAIN ),
            __( 'Hide Login', TEXT_DOMAIN ),
            'manage_options',
            'hide-login-secure',
            [ $this, 'render_main_page' ]
        );
    }

    public function render_main_page(): void {
        if ( ! current_user_can( 'manage_options' ) ) return;
        $active_tab = isset( $_GET['tab'] ) ? sanitize_key( $_GET['tab'] ) : 'settings';
        ?>
        <div class="wrap">
            <h1><?php echo esc_html( get_admin_page_title() ); ?></h1>
            <h2 class="nav-tab-wrapper">
                <a href="?page=hide-login-secure&tab=settings" class="nav-tab <?php echo $active_tab === 'settings' ? 'nav-tab-active' : ''; ?>"><?php esc_html_e( 'Settings', TEXT_DOMAIN ); ?></a>
                <a href="?page=hide-login-secure&tab=events" class="nav-tab <?php echo $active_tab === 'events' ? 'nav-tab-active' : ''; ?>"><?php esc_html_e( 'Login Events', TEXT_DOMAIN ); ?></a>
            </h2>
            <?php
            if ( $active_tab === 'settings' ) $this->render_settings_tab();
            else $this->render_events_tab();
            ?>
        </div>
        <?php
    }

    public function render_settings_tab(): void {
        $slug = trim( $this->settings['slug'] ?? '', '/' );
        ?>
        <div class="notice notice-info inline" style="margin:15px 0;padding:10px 15px;">
            <p><strong><?php esc_html_e( 'Hidden Entry URL:', TEXT_DOMAIN ); ?></strong> <code id="hls-url"><?php echo esc_html( home_url( '/' . $slug . '/' ) ); ?></code> 
            <button type="button" class="button button-small" onclick="navigator.clipboard.writeText(document.getElementById('hls-url').textContent);this.textContent='<?php echo esc_js( __( 'Copied!', TEXT_DOMAIN ) ); ?>';"><?php esc_html_e( 'Copy', TEXT_DOMAIN ); ?></button></p>
            <p style="color:#666;font-size:13px;margin-top:10px;">
                <?php esc_html_e( 'Note: If you encounter a 404 error on first use, please visit Settings > Permalinks and click "Save Changes" to refresh rewrite rules.', TEXT_DOMAIN ); ?>
            </p>
        </div>

        <form method="post" action="options.php">
            <?php settings_fields( 'hls_settings_group' ); ?>
            <table class="form-table">
                <tr>
                    <th><?php esc_html_e( 'Login Slug', TEXT_DOMAIN ); ?></th>
                    <td>
                        <input type="text" name="<?php echo OPTION_KEY; ?>[slug]" value="<?php echo esc_attr( $this->settings['slug'] ); ?>" class="regular-text" placeholder="my-login" />
                        <p class="description"><?php esc_html_e( 'Enter a single URL slug (lowercase letters, numbers, and hyphens only). Example: my-login', TEXT_DOMAIN ); ?></p>
                    </td>
                </tr>
                <tr>
                    <th><?php esc_html_e( 'Login Protection Mode', TEXT_DOMAIN ); ?></th>
                    <td>
                        <label>
                            <input type="radio" name="<?php echo OPTION_KEY; ?>[login_protection_mode]" value="compatibility" <?php checked( $this->settings['login_protection_mode'], 'compatibility' ); ?> /> 
                            <strong><?php esc_html_e( 'Compatibility Mode (Recommended)', TEXT_DOMAIN ); ?></strong><br>
                            <span class="description"><?php esc_html_e( 'Allows WordPress password reset and recovery links to work normally without the hidden URL.', TEXT_DOMAIN ); ?></span>
                        </label><br><br>
                        <label>
                            <input type="radio" name="<?php echo OPTION_KEY; ?>[login_protection_mode]" value="strict" <?php checked( $this->settings['login_protection_mode'], 'strict' ); ?> /> 
                            <strong><?php esc_html_e( 'Strict Mode', TEXT_DOMAIN ); ?></strong><br>
                            <span class="description"><?php esc_html_e( 'Maximum protection. Requires the hidden login authorization cookie for all wp-login.php requests.', TEXT_DOMAIN ); ?></span>
                        </label>
                    </td>
                </tr>
                <tr>
                    <th><?php esc_html_e( 'Unauthorized Request Response', TEXT_DOMAIN ); ?></th>
                    <td>
                        <label>
                            <input type="radio" name="<?php echo OPTION_KEY; ?>[unauthorized_response]" value="404" <?php checked( $this->settings['unauthorized_response'], '404' ); ?> /> 
                            <strong><?php esc_html_e( 'Return 404 (Recommended)', TEXT_DOMAIN ); ?></strong><br>
                            <span class="description"><?php esc_html_e( 'Shows a standard "Page Not Found" error.', TEXT_DOMAIN ); ?></span>
                        </label><br><br>
                        <label>
                            <input type="radio" name="<?php echo OPTION_KEY; ?>[unauthorized_response]" value="localhost" <?php checked( $this->settings['unauthorized_response'], 'localhost' ); ?> /> 
                            <strong><?php esc_html_e( 'Redirect to 127.0.0.1', TEXT_DOMAIN ); ?></strong><br>
                            <span class="description"><?php esc_html_e( 'Redirects unauthorized requests to 127.0.0.1 to reduce automated scanning and attack traffic (acts as a honeypot).', TEXT_DOMAIN ); ?></span>
                        </label><br><br>
                        <label>
                            <input type="radio" name="<?php echo OPTION_KEY; ?>[unauthorized_response]" value="homepage" <?php checked( $this->settings['unauthorized_response'], 'homepage' ); ?> /> 
                            <strong><?php esc_html_e( 'Redirect to homepage', TEXT_DOMAIN ); ?></strong><br>
                            <span class="description"><?php esc_html_e( 'Redirects unauthorized requests to the site homepage.', TEXT_DOMAIN ); ?></span>
                        </label>
                    </td>
                </tr>
                <tr>
                    <th><?php esc_html_e( 'Cookie Security', TEXT_DOMAIN ); ?></th>
                    <td>
                        <label><input type="checkbox" name="<?php echo OPTION_KEY; ?>[bind_ip_to_cookie]" value="1" <?php checked( $this->settings['bind_ip_to_cookie'] ); ?> /> 
                        <?php esc_html_e( 'Bind authorization to visitor IP (Optional).', TEXT_DOMAIN ); ?></label><br>
                        <span class="description"><?php esc_html_e( 'If enabled, the cookie becomes invalid if the user\'s IP changes.', TEXT_DOMAIN ); ?></span>
                    </td>
                </tr>
                <tr>
                    <th><?php esc_html_e( 'Whitelist IPs', TEXT_DOMAIN ); ?><br>
                    <span class="description">
                        <?php esc_html_e( 'IPv4 or IPv6. CIDR supported: IPv4 (0-32), IPv6 (0-128). One per line.', TEXT_DOMAIN ); ?><br>
                        <em style="color:#666;"><?php esc_html_e( 'Security Note: Cloudflare headers are only trusted if the request originates from an official Cloudflare IP range.', TEXT_DOMAIN ); ?></em>
                    </span></th>
                    <td><textarea name="<?php echo OPTION_KEY; ?>[whitelist_ips]" rows="5" class="large-text code"><?php echo esc_textarea( $this->settings['whitelist_ips'] ); ?></textarea></td>
                </tr>
                <tr>
                    <th><?php esc_html_e( 'Blacklist IPs', TEXT_DOMAIN ); ?><br>
                    <span class="description">
                        <?php esc_html_e( 'IPv4 or IPv6. CIDR supported: IPv4 (0-32), IPv6 (0-128). One per line.', TEXT_DOMAIN ); ?><br>
                        <em style="color:#d63638;"><?php esc_html_e( 'Note: Blacklist always takes priority over Whitelist.', TEXT_DOMAIN ); ?></em>
                    </span></th>
                    <td><textarea name="<?php echo OPTION_KEY; ?>[blacklist_ips]" rows="5" class="large-text code"><?php echo esc_textarea( $this->settings['blacklist_ips'] ); ?></textarea></td>
                </tr>
                <tr>
                    <th><?php esc_html_e( 'Security Options', TEXT_DOMAIN ); ?></th>
                    <td>
                        <label><input type="checkbox" name="<?php echo OPTION_KEY; ?>[enable_security_headers]" value="1" <?php checked( $this->settings['enable_security_headers'] ); ?> /> <?php esc_html_e( 'Add basic Security Headers (X-Frame-Options, etc.)', TEXT_DOMAIN ); ?></label><br>
                        <label><input type="checkbox" name="<?php echo OPTION_KEY; ?>[enable_logging]" value="1" <?php checked( $this->settings['enable_logging'] ); ?> /> <?php esc_html_e( 'Enable Event Logging (Auto-cleans to keep last 300)', TEXT_DOMAIN ); ?></label><br>
                        <label><input type="checkbox" name="<?php echo OPTION_KEY; ?>[block_xmlrpc]" value="1" <?php checked( $this->settings['block_xmlrpc'] ); ?> /> <?php esc_html_e( 'Block XML-RPC', TEXT_DOMAIN ); ?></label><br>
                        <label><input type="checkbox" name="<?php echo OPTION_KEY; ?>[block_author_enum]" value="1" <?php checked( $this->settings['block_author_enum'] ); ?> /> <?php esc_html_e( 'Block Author Enumeration', TEXT_DOMAIN ); ?></label><br>
                        <label><input type="checkbox" name="<?php echo OPTION_KEY; ?>[block_rest_api_users]" value="1" <?php checked( $this->settings['block_rest_api_users'] ); ?> /> <?php esc_html_e( 'Protect REST API User Enumeration', TEXT_DOMAIN ); ?></label><br>
                        <label><input type="checkbox" name="<?php echo OPTION_KEY; ?>[remove_author_body_class]" value="1" <?php checked( $this->settings['remove_author_body_class'] ); ?> /> <?php esc_html_e( 'Remove Username from Body Class', TEXT_DOMAIN ); ?></label><br>
                        <label><input type="checkbox" name="<?php echo OPTION_KEY; ?>[hide_author_in_feed]" value="1" <?php checked( $this->settings['hide_author_in_feed'] ); ?> /> <?php esc_html_e( 'Hide Author Name in RSS Feed', TEXT_DOMAIN ); ?></label><br>
                        <label><input type="checkbox" name="<?php echo OPTION_KEY; ?>[unify_login_errors]" value="1" <?php checked( $this->settings['unify_login_errors'] ); ?> /> <?php esc_html_e( 'Unify Login Error Messages', TEXT_DOMAIN ); ?></label>
                    </td>
                </tr>
            </table>
            <?php submit_button(); ?>
        </form>
        <?php
    }

    public function render_events_tab(): void {
        global $wpdb;
        $table_name = $wpdb->prefix . DB_TABLE;
        
        $per_page = 30;
        $current_page = isset( $_GET['paged'] ) ? max( 1, intval( $_GET['paged'] ) ) : 1;
        $offset = ( $current_page - 1 ) * $per_page;
        
        $total_items = (int) $wpdb->get_var( "SELECT COUNT(*) FROM $table_name" );
        $total_pages = ceil( $total_items / $per_page );
        
        $events = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM $table_name ORDER BY id DESC LIMIT %d OFFSET %d", $per_page, $offset ) );
        ?>
        
        <div style="margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center;">
            <h3><?php printf( esc_html__( 'Login Events — Last 300 Entries (%s total)', TEXT_DOMAIN ), number_format( $total_items ) ); ?></h3>
            <form method="post" style="margin:0;" onsubmit="return confirm('<?php echo esc_js( __( 'Are you sure you want to clear all events?', TEXT_DOMAIN ) ); ?>');">
                <input type="hidden" name="hls_action" value="clear_events" />
                <?php wp_nonce_field( 'hls_event_action', 'hls_nonce' ); ?>
                <button type="submit" class="button button-secondary" style="color:#dc3232; border-color:#dc3232;"><?php esc_html_e( 'Clear All Events', TEXT_DOMAIN ); ?></button>
            </form>
        </div>

        <table class="wp-list-table widefat fixed striped">
            <thead>
                <tr>
                    <th style="width: 50px;">ID</th>
                    <th><?php esc_html_e( 'Username', TEXT_DOMAIN ); ?></th>
                    <th><?php esc_html_e( 'Event Time', TEXT_DOMAIN ); ?></th>
                    <th><?php esc_html_e( 'User IP', TEXT_DOMAIN ); ?></th>
                    <th style="width: 250px;"><?php esc_html_e( 'Actions', TEXT_DOMAIN ); ?></th>
                </tr>
            </thead>
            <tbody>
                <?php if ( empty( $events ) ) : ?>
                    <tr><td colspan="5"><?php esc_html_e( 'No events recorded.', TEXT_DOMAIN ); ?></td></tr>
                <?php else : ?>
                    <?php foreach ( $events as $event ) : ?>
                        <tr>
                            <td><?php echo esc_html( $event->id ); ?></td>
                            <td><strong><?php echo esc_html( $event->username ); ?></strong></td>
                            <td><?php echo esc_html( $event->login_time ); ?></td>
                            <td><code><?php echo esc_html( $event->user_ip ); ?></code></td>
                            <td>
                                <a href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin.php?page=hide-login-secure&tab=events&hls_action=whitelist_ip&ip=' . urlencode( $event->user_ip ) ), 'hls_event_action', 'hls_nonce' ) ); ?>" class="button button-small"><?php esc_html_e( 'White', TEXT_DOMAIN ); ?></a>
                                <a href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin.php?page=hide-login-secure&tab=events&hls_action=blacklist_ip&ip=' . urlencode( $event->user_ip ) ), 'hls_event_action', 'hls_nonce' ) ); ?>" class="button button-small" style="color:#dc3232;"><?php esc_html_e( 'Block', TEXT_DOMAIN ); ?></a>
                                <a href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin.php?page=hide-login-secure&tab=events&hls_action=delete_event&id=' . $event->id ), 'hls_event_action', 'hls_nonce' ) ); ?>" class="button button-small button-link-delete" onclick="return confirm('<?php echo esc_js( __( 'Delete this event?', TEXT_DOMAIN ) ); ?>');"><?php esc_html_e( 'Delete', TEXT_DOMAIN ); ?></a>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
            </tbody>
        </table>

        <?php
        if ( $total_pages > 1 ) {
            echo '<div class="tablenav bottom" style="margin-top: 15px;"><div class="tablenav-pages">';
            echo '<span class="displaying-num">' . number_format( $total_items ) . ' ' . esc_html__( 'items', TEXT_DOMAIN ) . '</span>';
            echo '<span class="pagination-links">';
            
            if ( $current_page > 1 ) {
                echo '<a class="prev-page button" href="' . esc_url( add_query_arg( 'paged', $current_page - 1 ) ) . '">&lsaquo; ' . esc_html__( 'Prev', TEXT_DOMAIN ) . '</a>';
            } else {
                echo '<span class="tablenav-pages-navspan button disabled" aria-hidden="true">&lsaquo; ' . esc_html__( 'Prev', TEXT_DOMAIN ) . '</span>';
            }

            echo '<span class="paging-input">';
            $start_page = max( 1, $current_page - 2 );
            $end_page = min( $total_pages, $current_page + 2 );
            
            for ( $i = $start_page; $i <= $end_page; $i++ ) {
                if ( $i === $current_page ) {
                    echo '<span class="tablenav-pages-navspan button button-primary" style="border-color:#0073aa;background:#0073aa;color:#fff;">' . $i . '</span>';
                } else {
                    echo '<a class="button" href="' . esc_url( add_query_arg( 'paged', $i ) ) . '">' . $i . '</a>';
                }
            }
            echo '</span>';

            if ( $current_page < $total_pages ) {
                echo '<a class="next-page button" href="' . esc_url( add_query_arg( 'paged', $current_page + 1 ) ) . '">' . esc_html__( 'Next', TEXT_DOMAIN ) . ' &rsaquo;</a>';
            } else {
                echo '<span class="tablenav-pages-navspan button disabled" aria-hidden="true">' . esc_html__( 'Next', TEXT_DOMAIN ) . ' &rsaquo;</span>';
            }
            echo '</span></div></div>';
        }
    }

    public function handle_event_actions(): void {
        $action = $_GET['hls_action'] ?? $_POST['hls_action'] ?? '';
        if ( empty( $action ) ) return;
        
        if ( ! current_user_can( 'manage_options' ) ) wp_die( esc_html__( 'Permission denied.', TEXT_DOMAIN ) );

        $nonce = $_GET['hls_nonce'] ?? $_POST['hls_nonce'] ?? '';
        if ( ! wp_verify_nonce( $nonce, 'hls_event_action' ) ) wp_die( esc_html__( 'Security check failed.', TEXT_DOMAIN ) );

        global $wpdb;
        $table_name = $wpdb->prefix . DB_TABLE;

        switch ( $action ) {
            case 'delete_event':
                $id = intval( $_GET['id'] ?? 0 );
                if ( $id > 0 ) $wpdb->delete( $table_name, [ 'id' => $id ], [ '%d' ] );
                break;
            
            case 'clear_events':
                $wpdb->query( "TRUNCATE TABLE $table_name" );
                break;

            case 'whitelist_ip':
            case 'blacklist_ip':
                $ip = sanitize_text_field( $_GET['ip'] ?? '' );
                if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
                    $key = $action === 'whitelist_ip' ? 'whitelist_ips' : 'blacklist_ips';
                    $current_list = $this->settings[ $key ] ?? '';
                    $lines = array_filter( array_map( 'trim', explode( "\n", $current_list ) ) );
                    if ( ! in_array( $ip, $lines ) ) {
                        $lines[] = $ip;
                        $this->settings[ $key ] = implode( "\n", $lines );
                        update_option( OPTION_KEY, $this->settings );
                    }
                }
                break;
        }
        
        wp_safe_redirect( admin_url( 'admin.php?page=hide-login-secure&tab=events' ) );
        exit;
    }

    public function register_settings(): void {
        register_setting( 'hls_settings_group', OPTION_KEY, [ $this, 'sanitize_settings' ] );
    }

    public function sanitize_settings( array $input ): array {
        $sanitized = $this->settings;
        
        $raw_slug = isset( $input['slug'] ) ? sanitize_title( $input['slug'] ) : '';
        
        if ( ! preg_match( '/^[a-z0-9]+(?:-[a-z0-9]+)*$/', $raw_slug ) ) {
            add_settings_error( OPTION_KEY, 'invalid_slug_format', __( 'Invalid slug format. Use only lowercase letters, numbers, and hyphens (e.g., my-login).', TEXT_DOMAIN ) );
            $sanitized['slug'] = ! empty( $this->settings['slug'] ) ? $this->settings['slug'] : DEFAULT_SLUG;
        } elseif ( in_array( $raw_slug, $this->reserved_slugs, true ) ) {
            add_settings_error( OPTION_KEY, 'reserved_slug', __( 'This slug is reserved by WordPress core. Please choose another.', TEXT_DOMAIN ) );
            $sanitized['slug'] = ! empty( $this->settings['slug'] ) ? $this->settings['slug'] : DEFAULT_SLUG;
        } else {
            $query = new \WP_Query( [
                'name'          => $raw_slug,
                'post_type'     => get_post_types( [ 'public' => true ] ),
                'post_status'   => 'publish',
                'posts_per_page'=> 1,
                'fields'        => 'ids',
                'no_found_rows' => true,
            ] );
            
            if ( $query->have_posts() ) {
                add_settings_error( OPTION_KEY, 'slug_conflict_post', __( 'This slug is already in use by an existing page or post.', TEXT_DOMAIN ) );
                $sanitized['slug'] = ! empty( $this->settings['slug'] ) ? $this->settings['slug'] : DEFAULT_SLUG;
            } else {
                $terms = get_terms( [
                    'taxonomy'   => get_taxonomies( [ 'public' => true ] ),
                    'slug'       => $raw_slug,
                    'hide_empty' => false,
                    'fields'     => 'ids',
                    'number'     => 1,
                ] );
                
                if ( ! is_wp_error( $terms ) && ! empty( $terms ) ) {
                    add_settings_error( OPTION_KEY, 'slug_conflict_term', __( 'This slug is already in use by an existing category or tag.', TEXT_DOMAIN ) );
                    $sanitized['slug'] = ! empty( $this->settings['slug'] ) ? $this->settings['slug'] : DEFAULT_SLUG;
                } else {
                    $sanitized['slug'] = $raw_slug;
                }
            }
        }
        
        $valid_responses = [ '404', 'localhost', 'homepage' ];
        $sanitized['unauthorized_response'] = in_array( $input['unauthorized_response'] ?? '', $valid_responses ) ? $input['unauthorized_response'] : '404';

        $valid_modes = [ 'compatibility', 'strict' ];
        $sanitized['login_protection_mode'] = in_array( $input['login_protection_mode'] ?? '', $valid_modes ) ? $input['login_protection_mode'] : 'compatibility';
        
        $sanitized['bind_ip_to_cookie'] = ! empty( $input['bind_ip_to_cookie'] );
        $sanitized['enable_security_headers'] = ! empty( $input['enable_security_headers'] );
        
        $sanitized['whitelist_ips'] = isset( $input['whitelist_ips'] ) ? $this->sanitize_ip_list( $input['whitelist_ips'] ) : '';
        $sanitized['blacklist_ips'] = isset( $input['blacklist_ips'] ) ? $this->sanitize_ip_list( $input['blacklist_ips'] ) : '';

        $sanitized['enable_logging'] = ! empty( $input['enable_logging'] );
        $sanitized['block_xmlrpc'] = ! empty( $input['block_xmlrpc'] );
        $sanitized['block_author_enum'] = ! empty( $input['block_author_enum'] );
        $sanitized['block_rest_api_users'] = ! empty( $input['block_rest_api_users'] );
        $sanitized['remove_author_body_class'] = ! empty( $input['remove_author_body_class'] );
        $sanitized['hide_author_in_feed'] = ! empty( $input['hide_author_in_feed'] );
        $sanitized['unify_login_errors'] = ! empty( $input['unify_login_errors'] );
        
        return $sanitized;
    }

    private function sanitize_ip_list( string $text ): string {
        $lines = explode( "\n", $text );
        $valid_ips = [];
        
        foreach ( $lines as $line ) {
            $ip = trim( $line );
            if ( empty( $ip ) ) continue;
            
            if ( strpos( $ip, '/' ) !== false ) {
                list( $address, $prefix ) = explode( '/', $ip, 2 );
                $prefix = trim( $prefix );
                $address = trim( $address );
                
                if ( ! filter_var( $address, FILTER_VALIDATE_IP ) ) continue;
                
                if ( filter_var( $address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
                    if ( ! is_numeric( $prefix ) || $prefix < 0 || $prefix > 32 ) continue;
                } elseif ( filter_var( $address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
                    if ( ! is_numeric( $prefix ) || $prefix < 0 || $prefix > 128 ) continue;
                } else {
                    continue;
                }
                
                $valid_ips[] = $address . '/' . $prefix;
            } else {
                if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
                    $valid_ips[] = $ip;
                }
            }
        }
        
        return implode( "\n", $valid_ips );
    }

    public function plugin_action_links( array $links, string $plugin_file ): array {
        if ( plugin_basename( __FILE__ ) !== $plugin_file ) return $links;

        $settings_link = sprintf( '<a href="%s">%s</a>', admin_url( 'options-general.php?page=hide-login-secure' ), esc_html__( 'Settings', TEXT_DOMAIN ) );
        array_unshift( $links, $settings_link );

        if ( current_user_can( 'manage_options' ) ) {
            $reset_url = wp_nonce_url( admin_url( 'plugins.php?hls_action=reset_settings' ), 'hls_reset_settings', 'hls_nonce' );
            $reset_link = sprintf( '<a href="%s" onclick="return confirm(\'%s\');" style="color:#dc3232;">%s</a>', esc_url( $reset_url ), esc_js( __( 'Are you sure? This will reset all settings to default.', TEXT_DOMAIN ) ), esc_html__( 'Reset Settings', TEXT_DOMAIN ) );
            $links[] = $reset_link;
        }
        return $links;
    }

    public function handle_reset_request(): void {
        if ( ! isset( $_GET['hls_action'] ) || $_GET['hls_action'] !== 'reset_settings' ) return;
        if ( ! current_user_can( 'manage_options' ) ) wp_die( esc_html__( 'Permission denied.', TEXT_DOMAIN ) );
        if ( ! isset( $_GET['hls_nonce'] ) || ! wp_verify_nonce( $_GET['hls_nonce'], 'hls_reset_settings' ) ) wp_die( esc_html__( 'Security check failed.', TEXT_DOMAIN ) );

        delete_option( OPTION_KEY );
        wp_safe_redirect( admin_url( 'plugins.php?hls_reset_success=1' ) );
        exit;
    }

    public function show_reset_success_notice(): void {
        if ( ! isset( $_GET['hls_reset_success'] ) || $_GET['hls_reset_success'] !== '1' ) return;
        ?>
        <div class="notice notice-warning is-dismissible" style="border-left-color: #dc3232; padding: 15px;">
            <h3 style="margin-top: 0; color: #dc3232;"><?php esc_html_e( '⚠️ Settings Reset to Default!', TEXT_DOMAIN ); ?></h3>
            <p><?php esc_html_e( 'All plugin settings have been cleared. The plugin is now using default values.', TEXT_DOMAIN ); ?></p>
            <p style="font-size: 16px; background: #fff; padding: 10px; border: 1px solid #dc3232;">
                <strong><?php esc_html_e( 'Your current entry URL is now:', TEXT_DOMAIN ); ?></strong><br>
                <code style="font-size: 18px;"><?php echo esc_html( home_url( '/' . DEFAULT_SLUG . '/' ) ); ?></code>
            </p>
        </div>
        <?php
    }
}

// Bootstrap
Plugin::get_instance();

// Register activation/deactivation hooks outside the class
register_activation_hook( __FILE__, [ Plugin::class, 'activate' ] );
register_deactivation_hook( __FILE__, [ Plugin::class, 'deactivate' ] );