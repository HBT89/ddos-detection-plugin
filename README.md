# DDoS Detection Plugin

A WordPress plugin to help prevent and mitigate DDoS (Distributed Denial of Service) attacks on your site.

## Features
- Monitors incoming requests per IP address
- Blocks IPs that exceed a configurable request threshold
- Skips Cloudflare IPs to avoid false positives
- Admin dashboard page to view blocked IPs
- Sends email alerts to the site admin when an IP is blocked

## How It Works
- Each visitor's IP is tracked for the number of requests made within a 60-second window.
- If an IP exceeds 100 requests in 60 seconds, it is automatically blocked and added to a persistent blocklist.
- Blocked IPs are prevented from accessing the site and shown a message.
- The plugin checks for Cloudflare IPs and skips blocking them to avoid interfering with legitimate traffic.

## Installation
1. Download or clone this repository into your WordPress `wp-content/plugins` directory.
2. Activate the plugin from the WordPress admin dashboard.

## Usage
- After activation, a new menu item "DDoS Detection" will appear in the WordPress admin sidebar.
- Visit the DDoS Detection page to view the list of currently blocked IP addresses.

## Uninstallation
- Deactivate and delete the plugin from the WordPress admin dashboard to remove all settings and blocklists.

## Author
Joshua Selvidge, CTO | PurpleSec https://purplesec.us/

## Disclaimer
This plugin provides basic DDoS detection and mitigation. For advanced protection, consider using a dedicated security service or firewall.
