<?php
/*
Plugin Name: DDoS Detection Plugin
Description: Detects and mitigates DDoS attempts on your WordPress site.
Version: 1.0
Author: Joshua Selvidge, CTO | PurpleSec https://purplesec.us/
*/

function ddos_monitor_requests() {
    $ip = !empty($_SERVER['HTTP_CF_CONNECTING_IP']) ? $_SERVER['HTTP_CF_CONNECTING_IP'] : $_SERVER['REMOTE_ADDR'];
    
    // Check if the IP is from CloudFlare, skip further checks if true
    if (ddos_is_cloudflare_ip($ip)) {
        return;
    }
    
    $current_time = time();
    $request_count = get_transient('ddos_request_' . $ip);

    if ($request_count === false) {
        $request_count = array('count' => 0, 'timestamp' => $current_time);
    }

    $request_count['count']++;
    if ($request_count['count'] > 100 && ($current_time - $request_count['timestamp']) < 60) {
        ddos_block_ip($ip);
        ddos_send_alert($ip);
    }

    set_transient('ddos_request_' . $ip, $request_count, 60);
}
add_action('init', 'ddos_monitor_requests');

function ddos_is_cloudflare_ip($ip) {
    $cloudflare_ips = array(
        '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', 
        '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18', 
        '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', 
        '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/12', 
        '172.64.0.0/13', '131.0.72.0/22'
    );

    foreach ($cloudflare_ips as $cidr) {
        list($subnet, $mask) = explode('/', $cidr);
        if ((ip2long($ip) & ~((1 << (32 - $mask)) - 1)) == ip2long($subnet)) {
            return true;
        }
    }
    return false;
}

function ddos_block_ip($ip) {
    $blocked_ips = get_option('ddos_blocked_ips', array());
    if (!in_array($ip, $blocked_ips)) {
        $blocked_ips[] = $ip;
        update_option('ddos_blocked_ips', $blocked_ips);
    }
}

function ddos_check_blocked_ips() {
    $ip = !empty($_SERVER['HTTP_CF_CONNECTING_IP']) ? $_SERVER['HTTP_CF_CONNECTING_IP'] : $_SERVER['REMOTE_ADDR'];
    $blocked_ips = get_option('ddos_blocked_ips', array());
    if (in_array($ip, $blocked_ips)) {
        wp_die('Your IP has been blocked due to suspicious activity.');
    }
}
add_action('init', 'ddos_check_blocked_ips', 1);

function ddos_add_admin_menu() {
    add_menu_page('DDoS Detection', 'DDoS Detection', 'manage_options', 'ddos-detection', 'ddos_admin_page');
}
add_action('admin_menu', 'ddos_add_admin_menu');

function ddos_admin_page() {
    $blocked_ips = get_option('ddos_blocked_ips', array());
    ?>
    <div class="wrap">
        <h1>DDoS Detection Settings</h1>
        <h2>Blocked IP Addresses</h2>
        <ul>
            <?php foreach ($blocked_ips as $ip): ?>
                <li><?php echo esc_html($ip); ?></li>
            <?php endforeach; ?>
        </ul>
    </div>
    <?php
}

function ddos_send_alert($ip) {
    $admin_email = get_option('admin_email');
    $subject = 'DDoS Detection Alert';
    $message = 'A new IP address has been blocked due to suspicious activity: ' . $ip;
    wp_mail($admin_email, $subject, $message);
}
