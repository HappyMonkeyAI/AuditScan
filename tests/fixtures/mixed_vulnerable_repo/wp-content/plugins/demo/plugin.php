<?php
/**
 * Plugin Name: Demo (insecure)
 */

add_action('wp_ajax_nopriv_delete_item', 'demo_delete_item');

function demo_delete_item() {
    global $wpdb;
    $id = $_POST['id'];
    $query = "SELECT * FROM wp_items WHERE id = " . $id;   // SQL injection
    $wpdb->query($query);
    wp_send_json_success();
}
