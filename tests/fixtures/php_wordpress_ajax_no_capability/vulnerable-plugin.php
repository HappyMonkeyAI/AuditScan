<?php
/**
 * Plugin Name: Vulnerable AJAX Demo
 * Description: Fixture: WordPress AJAX handler with no nonce or capability check.
 */

// Unguarded AJAX handler — no nonce, no capability check (SPEC AC-001).
add_action('wp_ajax_delete_item', 'demo_delete_item');
add_action('wp_ajax_nopriv_delete_item', 'demo_delete_item');

function demo_delete_item() {
    global $wpdb;
    $id = $_POST['id'];
    // Also an injection sink (string interpolation into SQL) for AC-002.
    $query = "SELECT * FROM wp_items WHERE id = " . $id;
    $wpdb->query($query);
    wp_send_json_success();
}
