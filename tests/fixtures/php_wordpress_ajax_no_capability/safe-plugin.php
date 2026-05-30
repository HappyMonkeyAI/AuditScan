<?php
/**
 * Plugin Name: Safe AJAX Demo
 * Description: Fixture: WordPress AJAX handler guarded by nonce and capability check.
 */

add_action('wp_ajax_delete_item', 'demo_safe_delete_item');

function demo_safe_delete_item() {
    check_ajax_referer('demo_delete', 'nonce');
    if (!current_user_can('manage_options')) {
        wp_send_json_error('forbidden', 403);
    }
    global $wpdb;
    $id = (int) $_POST['id'];
    $wpdb->delete('wp_items', array('id' => $id), array('%d'));
    wp_send_json_success();
}
