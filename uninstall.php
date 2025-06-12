<?php
if (!defined('WP_UNINSTALL_PLUGIN')) {
    die;
}

delete_option('ddos_blocked_ips');
