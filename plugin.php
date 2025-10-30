<?php
/*
Plugin Name: Database Users for YOURLS
Plugin URI: https://go.wjct.org
Description: Store YOURLS user credentials in the database and provide management tools.
Version: 1.1.0
Author: Ray Hollister
*/

// No direct access.
if( !defined( 'YOURLS_ABSPATH' ) ) {
    die();
}

db_users_bootstrap();

yourls_add_action( 'plugins_loaded', 'db_users_register_pages' );
yourls_add_action( 'login', 'db_users_handle_login' );
yourls_add_filter( 'admin_sublinks', 'db_users_move_menu_link' );

/**
 * Prepare database and credential cache.
 *
 * @return void
 */
function db_users_bootstrap() {
    db_users_ensure_table_exists();
    db_users_import_legacy_credentials();
    db_users_refresh_credentials_cache();
}

/**
 * Return table name used by the plugin.
 *
 * @return string
 */
function db_users_table_name() {
    return YOURLS_DB_PREFIX . 'user_credentials';
}

/**
 * Get database helper.
 *
 * @return \YOURLS\Database\YDB
 */
function db_users_db() {
    return yourls_get_db();
}

/**
 * Ensure the credential table exists.
 *
 * @return void
 */
function db_users_ensure_table_exists() {
    $table = db_users_table_name();

    $sql = 'CREATE TABLE IF NOT EXISTS `' . $table . '` (' .
        '`id` int unsigned NOT NULL AUTO_INCREMENT,' .
        '`user_login` varchar(64) COLLATE utf8mb4_unicode_ci NOT NULL,' .
        '`user_pass` varchar(255) COLLATE utf8mb4_bin NOT NULL,' .
        '`user_role` varchar(20) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT \'user\',' .
        '`created_at` datetime NOT NULL,' .
        '`updated_at` datetime NOT NULL,' .
        'PRIMARY KEY (`id`),' .
        'UNIQUE KEY `user_login` (`user_login`)' .
    ') DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;';

    db_users_db()->perform( $sql );
}

/**
 * Import credentials from config.php if table is empty.
 *
 * @return void
 */
function db_users_import_legacy_credentials() {
    $table = db_users_table_name();
    $count = (int) db_users_db()->fetchValue( "SELECT COUNT(*) FROM `$table`" );

    if( $count > 0 ) {
        return;
    }

    global $yourls_user_passwords;
    if( empty( $yourls_user_passwords ) || !is_array( $yourls_user_passwords ) ) {
        return;
    }

    $now = db_users_now();

    foreach( $yourls_user_passwords as $username => $password ) {
        $username = db_users_sanitize_username( $username );
        if( $username === '' ) {
            continue;
        }

        $stored_password = db_users_normalize_password_storage( $password );
        // Preserve current access level for existing users.
        db_users_insert_user( $username, $stored_password, 'admin', $now );
    }
}

/**
 * Refresh the global YOURLS credential cache with DB values.
 *
 * @return array<string,string>
 */
function db_users_refresh_credentials_cache() {
    $table = db_users_table_name();
    $rows  = db_users_db()->fetchObjects( "SELECT user_login, user_pass, user_role FROM `$table` ORDER BY user_login ASC" );

    $credentials = [];
    $roles       = [];

    if( $rows ) {
        foreach( $rows as $row ) {
            $credentials[ $row->user_login ] = $row->user_pass;
            $roles[ $row->user_login ]       = $row->user_role;
        }
    }

    $GLOBALS['yourls_user_passwords'] = $credentials;
    $GLOBALS['db_users_roles']         = $roles;

    return $credentials;
}

/**
 * Record user role after login succeeds.
 *
 * @return void
 */
function db_users_handle_login() {
    if( !defined( 'YOURLS_USER' ) ) {
        return;
    }

    $role = db_users_get_role( YOURLS_USER );
    if( !defined( 'YOURLS_USER_ROLE' ) ) {
        define( 'YOURLS_USER_ROLE', $role ?: 'user' );
    }
}

/**
 * Register plugin admin pages (implemented later).
 *
 * @return void
 */
function db_users_register_pages() {
    yourls_register_plugin_page( 'db_users', yourls__( 'User Accounts' ), 'db_users_render_admin_page' );
}

/**
 * Insert a new user row.
 *
 * @param string $username        Username.
 * @param string $stored_password Stored password with prefix (phpass/md5/plain).
 * @param string $role            Role name.
 * @param string|null $timestamp  Optional timestamp to reuse for creation/update.
 * @return bool
 */
function db_users_insert_user( $username, $stored_password, $role = 'user', $timestamp = null ) {
    $username        = db_users_sanitize_username( $username );
    $stored_password = (string) $stored_password;
    $role            = db_users_sanitize_role( $role );

    if( $username === '' || $stored_password === '' ) {
        return false;
    }

    $now = $timestamp ?: db_users_now();

    $sql = "INSERT INTO `" . db_users_table_name() . "` (user_login, user_pass, user_role, created_at, updated_at)
            VALUES (:login, :pass, :role, :created, :updated)";

    try {
        db_users_db()->fetchAffected( $sql, [
            'login'   => $username,
            'pass'    => $stored_password,
            'role'    => $role,
            'created' => $now,
            'updated' => $now,
        ] );

        return true;
    } catch ( \Exception $e ) {
        yourls_debug_log( 'db-users insert failed: ' . $e->getMessage() );
        return false;
    }
}

/**
 * Public helper to add a user with a plain password.
 *
 * @param string $username
 * @param string $password
 * @param string $role
 * @return bool
 */
function db_users_add_user( $username, $password, $role = 'user' ) {
    $username = db_users_sanitize_username( $username );
    $password = (string) $password;

    if( $username === '' || $password === '' ) {
        return false;
    }

    $stored = db_users_normalize_password_storage( $password );

    return db_users_insert_user( $username, $stored, $role );
}

/**
 * Normalize stored password format.
 *
 * @param mixed $password Raw password or stored hash from config.
 * @return string
 */
function db_users_normalize_password_storage( $password ) {
    $password = (string) $password;

    if( db_users_is_phpass_password( $password ) ) {
        $hash = substr( $password, 7 );
        $hash = str_replace( '!', '$', $hash );

        return 'phpass:' . $hash;
    }

    if( db_users_is_md5_password( $password ) ) {
        return $password;
    }

    $hash = yourls_phpass_hash( $password );

    return 'phpass:' . $hash;
}

/**
 * Tell if stored password is a phpass hash.
 *
 * @param string $password
 * @return bool
 */
function db_users_is_phpass_password( $password ) {
    return ( strpos( $password, 'phpass:' ) === 0 );
}

/**
 * Tell if stored password is an md5 hash.
 *
 * @param string $password
 * @return bool
 */
function db_users_is_md5_password( $password ) {
    return ( strpos( $password, 'md5:' ) === 0 );
}

/**
 * Check if a submitted password matches stored credentials.
 *
 * @param string $stored
 * @param string $submitted
 * @return bool
 */
function db_users_password_matches( $stored, $submitted ) {
    $stored    = (string) $stored;
    $submitted = (string) $submitted;

    if( db_users_is_phpass_password( $stored ) ) {
        $hash = substr( $stored, 7 );
        $hash = str_replace( '!', '$', $hash );

        return yourls_phpass_check( $submitted, $hash );
    }

    if( db_users_is_md5_password( $stored ) ) {
        $parts = explode( ':', $stored );
        if( count( $parts ) === 3 ) {
            list( , $salt, ) = $parts;
            return $stored === 'md5:' . $salt . ':' . md5( $salt . $submitted );
        }
    }

    return $stored === $submitted;
}

/**
 * Verify a user's password against stored credentials.
 *
 * @param string $username
 * @param string $password
 * @return bool
 */
function db_users_verify_password( $username, $password ) {
    $username = db_users_sanitize_username( $username );

    if( $username === '' ) {
        return false;
    }

    $credentials = $GLOBALS['yourls_user_passwords'] ?? [];

    if( !isset( $credentials[ $username ] ) ) {
        db_users_refresh_credentials_cache();
        $credentials = $GLOBALS['yourls_user_passwords'] ?? [];
    }

    if( !isset( $credentials[ $username ] ) ) {
        return false;
    }

    return db_users_password_matches( $credentials[ $username ], $password );
}

/**
 * Sanitize usernames.
 *
 * @param string $username
 * @return string
 */
function db_users_sanitize_username( $username ) {
    $username = trim( (string) $username );

    return preg_replace( '/[^A-Za-z0-9_\-\.@]/', '', $username );
}

/**
 * Sanitize role string.
 *
 * @param string $role
 * @return string
 */
function db_users_sanitize_role( $role ) {
    $role = strtolower( trim( (string) $role ) );

    if( !in_array( $role, [ 'admin', 'user' ], true ) ) {
        $role = 'user';
    }

    return $role;
}

/**
 * Provide the current timestamp string.
 *
 * @return string
 */
function db_users_now() {
    return date( 'Y-m-d H:i:s' );
}

/**
 * Retrieve cached roles.
 *
 * @return array<string,string>
 */
function db_users_get_role_map() {
    return $GLOBALS['db_users_roles'] ?? [];
}

/**
 * Get role for a username.
 *
 * @param string $username
 * @return string|null
 */
function db_users_get_role( $username ) {
    $roles = db_users_get_role_map();

    return $roles[ $username ] ?? null;
}

/**
 * Check if a username has the admin role.
 *
 * @param string|null $username
 * @return bool
 */
function db_users_is_admin( $username = null ) {
    if( $username === null ) {
        if( !defined( 'YOURLS_USER' ) ) {
            return false;
        }
        $username = YOURLS_USER;
    }

    return db_users_get_role( $username ) === 'admin';
}

/**
 * Render plugin administration page.
 *
 * @return void
 */
function db_users_render_admin_page() {
    $messages = [];
    $errors   = [];

    db_users_handle_admin_post( $messages, $errors );

    $users = db_users_get_all_users();

    echo '<h2>' . yourls__( 'User Accounts' ) . '</h2>';
    echo '<style>
    .db-users-form { max-width: 480px; margin: 0 0 1.5em; padding: 1em; border: 1px solid #d9d9d9; border-radius: 4px; background: #fff; }
    .db-users-form p { margin: 0.4em 0; }
    .db-users-form select { min-width: 160px; }
    .db-users-table { width: 100%; max-width: 720px; margin: 1.5em 0; border-collapse: collapse; background: #fff; }
    .db-users-table th, .db-users-table td { padding: 0.6em 0.8em; border: 1px solid #d9d9d9; text-align: left; }
    .db-users-table tbody tr:nth-child(odd) { background: #fafafa; }
    .db-users-table .db-users-toggle { font-weight: 600; text-decoration: none; }
    .db-users-table .db-users-toggle:focus, .db-users-table .db-users-toggle:hover { text-decoration: underline; }
    .db-users-current { font-weight: 600; color: #444; }
    .db-users-current-note { color: #777; font-size: 0.85em; margin-left: 0.4em; }
    .db-users-edit-row { background: #fefefe; }
    .db-users-edit-row .db-users-edit-form { padding: 1em 0.4em; }
    .db-users-edit-row form p { margin: 0.4em 0; }
    .db-users-edit-header { display: flex; justify-content: space-between; align-items: center; gap: 1em; margin-bottom: 0.8em; }
    .db-users-header-actions { display: flex; align-items: center; gap: 0.6em; }
    .db-users-delete-form { margin: 0; }
    .db-users-delete-form .button-delete { background: #e74c3c; border-color: #c0392b; color: #fff; }
    .db-users-delete-form .button-delete:hover { background: #c0392b; }
    .db-users-delete-form .button-delete[disabled] { opacity: 0.5; cursor: not-allowed; background: #aaa; border-color: #999; }
    .db-users-delete-note { color: #777; font-size: 0.85em; }
    </style>';

    foreach( $errors as $error ) {
        echo yourls_notice_box( yourls_esc_html( $error ), 'error' );
    }

    foreach( $messages as $message ) {
        echo yourls_notice_box( yourls_esc_html( $message ), 'success' );
    }

    if( db_users_is_admin() ) {
        db_users_render_admin_create_form();
        db_users_render_admin_users_list( $users );
    } else {
        echo '<p>' . yourls__( 'You do not have permission to manage other users.' ) . '</p>';
    }

    db_users_render_self_service_form();
}

/**
 * Handle POST actions for the admin page.
 *
 * @param array $messages
 * @param array $errors
 * @return void
 */
function db_users_handle_admin_post( array &$messages, array &$errors ) {
    if( $_SERVER['REQUEST_METHOD'] !== 'POST' ) {
        return;
    }

    $action = $_POST['db_users_action'] ?? '';
    if( $action === '' ) {
        return;
    }

    switch( $action ) {
        case 'create_user':
            db_users_process_create_user_action( $messages, $errors );
            break;
        case 'update_user':
            db_users_process_update_user_action( $messages, $errors );
            break;
        case 'self_update_password':
            db_users_process_self_update_action( $messages, $errors );
            break;
        case 'delete_user':
            db_users_process_delete_user_action( $messages, $errors );
            break;
    }
}

/**
 * Process create user request.
 *
 * @param array $messages
 * @param array $errors
 * @return void
 */
function db_users_process_create_user_action( array &$messages, array &$errors ) {
    if( !db_users_is_admin() ) {
        $errors[] = yourls__( 'Only administrators can create new users.' );
        return;
    }

    yourls_verify_nonce( 'db_users_create_user' );

    $username = db_users_sanitize_username( $_POST['new_username'] ?? '' );
    $password = trim( (string) ( $_POST['new_password'] ?? '' ) );
    $confirm  = trim( (string) ( $_POST['confirm_password'] ?? '' ) );
    $role     = db_users_sanitize_role( $_POST['new_role'] ?? 'user' );

    if( $username === '' ) {
        $errors[] = yourls__( 'Username is required.' );
        return;
    }

    if( db_users_user_exists( $username ) ) {
        $errors[] = yourls__( 'That username already exists.' );
        return;
    }

    if( $password === '' ) {
        $errors[] = yourls__( 'Password is required.' );
        return;
    }

    if( $password !== $confirm ) {
        $errors[] = yourls__( 'Passwords do not match.' );
        return;
    }

    if( db_users_add_user( $username, $password, $role ) ) {
        db_users_refresh_credentials_cache();
        $messages[] = sprintf( yourls__( 'User %s created.' ), $username );
    } else {
        $errors[] = yourls__( 'Could not create user. Check logs for details.' );
    }
}

/**
 * Process update user request.
 *
 * @param array $messages
 * @param array $errors
 * @return void
 */
function db_users_process_update_user_action( array &$messages, array &$errors ) {
    if( !db_users_is_admin() ) {
        $errors[] = yourls__( 'Only administrators can modify users.' );
        return;
    }

    yourls_verify_nonce( 'db_users_update_user' );

    $username = db_users_sanitize_username( $_POST['target_user'] ?? '' );
    if( $username === '' ) {
        $errors[] = yourls__( 'Unknown user.' );
        return;
    }

    if( defined( 'YOURLS_USER' ) && $username === YOURLS_USER ) {
        $errors[] = yourls__( 'Use the self-service form to manage your own account.' );
        return;
    }

    $user = db_users_get_user( $username );
    if( !$user ) {
        $errors[] = yourls__( 'Unknown user.' );
        return;
    }

    $new_role  = db_users_sanitize_role( $_POST['new_role'] ?? $user->user_role );
    $password  = trim( (string) ( $_POST['new_password'] ?? '' ) );
    $confirm   = trim( (string) ( $_POST['confirm_password'] ?? '' ) );
    $changed   = false;

    if( $password !== '' ) {
        if( $password !== $confirm ) {
            $errors[] = sprintf( yourls__( 'Passwords do not match for %s.' ), $username );
        } else {
            if( db_users_update_user_password( $username, $password ) ) {
                $messages[] = sprintf( yourls__( 'Password updated for %s.' ), $username );
                $changed = true;

                if( defined( 'YOURLS_USER' ) && $username === YOURLS_USER ) {
                    yourls_store_cookie( $username );
                }
            } else {
                $errors[] = sprintf( yourls__( 'Could not update password for %s.' ), $username );
            }
        }
    }

    if( $new_role !== $user->user_role ) {
        if( $new_role !== 'admin' && db_users_is_last_admin( $username ) ) {
            $errors[] = yourls__( 'Cannot remove the final administrator.' );
        } else {
            if( db_users_update_user_role( $username, $new_role ) ) {
                $messages[] = sprintf( yourls__( 'Role updated for %s.' ), $username );
                $changed = true;
            } else {
                $errors[] = sprintf( yourls__( 'Could not update role for %s.' ), $username );
            }
        }
    }

    if( $changed ) {
        db_users_refresh_credentials_cache();
    } elseif( empty( $errors ) ) {
        $messages[] = yourls__( 'No changes made.' );
    }
}

/**
 * Process delete user request.
 *
 * @param array $messages
 * @param array $errors
 * @return void
 */
function db_users_process_delete_user_action( array &$messages, array &$errors ) {
    if( !db_users_is_admin() ) {
        $errors[] = yourls__( 'Only administrators can delete users.' );
        return;
    }

    yourls_verify_nonce( 'db_users_delete_user' );

    $username = db_users_sanitize_username( $_POST['target_user'] ?? '' );
    if( $username === '' ) {
        $errors[] = yourls__( 'Unknown user.' );
        return;
    }

    if( defined( 'YOURLS_USER' ) && $username === YOURLS_USER ) {
        $errors[] = yourls__( 'You cannot delete the account you are logged in with.' );
        return;
    }

    if( !db_users_user_exists( $username ) ) {
        $errors[] = yourls__( 'Unknown user.' );
        return;
    }

    if( db_users_is_last_admin( $username ) ) {
        $errors[] = yourls__( 'Cannot delete the last remaining administrator.' );
        return;
    }

    if( db_users_delete_user( $username ) ) {
        db_users_refresh_credentials_cache();
        $messages[] = sprintf( yourls__( 'User %s deleted.' ), $username );
    } else {
        $errors[] = yourls__( 'Could not delete user. Check logs for details.' );
    }
}

/**
 * Process a self-service password change request.
 *
 * @param array $messages
 * @param array $errors
 * @return void
 */
function db_users_process_self_update_action( array &$messages, array &$errors ) {
    if( !defined( 'YOURLS_USER' ) ) {
        $errors[] = yourls__( 'You must be logged in to update your password.' );
        return;
    }

    yourls_verify_nonce( 'db_users_change_own_password' );

    $username = YOURLS_USER;
    $current  = (string) ( $_POST['current_password'] ?? '' );
    $new      = trim( (string) ( $_POST['self_new_password'] ?? '' ) );
    $confirm  = trim( (string) ( $_POST['self_confirm_password'] ?? '' ) );

    if( $current === '' ) {
        $errors[] = yourls__( 'Current password is required.' );
        return;
    }

    if( $new === '' ) {
        $errors[] = yourls__( 'New password is required.' );
        return;
    }

    if( $new !== $confirm ) {
        $errors[] = yourls__( 'New passwords do not match.' );
        return;
    }

    if( !db_users_verify_password( $username, $current ) ) {
        $errors[] = yourls__( 'Current password is incorrect.' );
        return;
    }

    if( db_users_update_user_password( $username, $new ) ) {
        db_users_refresh_credentials_cache();
        yourls_store_cookie( $username );
        $messages[] = yourls__( 'Your password has been updated.' );
    } else {
        $errors[] = yourls__( 'Could not update your password.' );
    }
}

/**
 * Render administrator create user form.
 *
 * @return void
 */
function db_users_render_admin_create_form() {
    echo '<h3>' . yourls__( 'Create User' ) . '</h3>';
    echo '<form method="post" class="db-users-form">';
    echo '<input type="hidden" name="db_users_action" value="create_user" />';
    yourls_nonce_field( 'db_users_create_user' );
    echo '<p><label for="db-users-new-username">' . yourls__( 'Username' ) . '</label><br />';
    echo '<input type="text" class="text" id="db-users-new-username" name="new_username" required /></p>';
    echo '<p><label for="db-users-new-password">' . yourls__( 'Password' ) . '</label><br />';
    echo '<input type="password" class="text" id="db-users-new-password" name="new_password" autocomplete="new-password" required /></p>';
    echo '<p><label for="db-users-new-confirm">' . yourls__( 'Confirm password' ) . '</label><br />';
    echo '<input type="password" class="text" id="db-users-new-confirm" name="confirm_password" autocomplete="new-password" required /></p>';
    echo '<p><label for="db-users-new-role">' . yourls__( 'Role' ) . '</label><br />';
    echo '<select id="db-users-new-role" name="new_role">';
    echo '<option value="user">' . yourls__( 'User' ) . '</option>';
    echo '<option value="admin">' . yourls__( 'Administrator' ) . '</option>';
    echo '</select></p>';
    echo '<p><button type="submit" class="button button-primary">' . yourls__( 'Create user' ) . '</button></p>';
    echo '</form>';
}

/**
 * Render administrator list of existing users.
 *
 * @param array $users
 * @return void
 */
function db_users_render_admin_users_list( array $users ) {
    echo '<h3>' . yourls__( 'Existing Users' ) . '</h3>';

    if( empty( $users ) ) {
        echo '<p>' . yourls__( 'No users found.' ) . '</p>';
        return;
    }

    echo '<table class="db-users-table">';
    echo '<thead><tr><th>' . yourls__( 'Username' ) . '</th><th>' . yourls__( 'Role' ) . '</th><th>' . yourls__( 'Last updated' ) . '</th></tr></thead>';
    echo '<tbody>';

    foreach( $users as $user ) {
        $raw_username  = $user->user_login;
        $display_name  = yourls_esc_html( $raw_username );
        $attr_username = yourls_esc_attr( $raw_username );
        $role_label    = $user->user_role === 'admin' ? yourls__( 'Administrator' ) : yourls__( 'User' );
        $unique_id     = 'db-users-edit-' . md5( $raw_username );
        $updated       = yourls_esc_html( $user->updated_at );
        $role_admin    = $user->user_role === 'admin' ? 'selected="selected"' : '';
        $role_user     = $user->user_role === 'user' ? 'selected="selected"' : '';
        $is_current    = defined( 'YOURLS_USER' ) && YOURLS_USER === $raw_username;
        $is_last_admin = db_users_is_last_admin( $raw_username );

        echo '<tr>';
        if( $is_current ) {
            echo '<td><span class="db-users-current">' . $display_name . '</span><span class="db-users-current-note">' . yourls__( '(You)' ) . '</span></td>';
        } else {
            echo '<td><a href="#" class="db-users-toggle" data-target="' . $unique_id . '">' . $display_name . '</a></td>';
        }
        echo '<td>' . yourls_esc_html( $role_label ) . '</td>';
        echo '<td>' . $updated . '</td>';
        echo '</tr>';

        if( $is_current ) {
            continue;
        }

        $delete_disabled = $is_last_admin ? ' disabled="disabled"' : '';
        $delete_note_text = $is_last_admin ? yourls__( 'At least one administrator is required.' ) : '';
        $confirm_text    = yourls_esc_js( sprintf( yourls__( 'Delete user %s? This cannot be undone.' ), $raw_username ) );

        echo '<tr id="' . $unique_id . '" class="db-users-edit-row" style="display:none">';
        echo '<td colspan="3">';
        echo '<div class="db-users-edit-form">';
        echo '<div class="db-users-edit-header">';
        echo '<strong>' . sprintf( yourls__( 'Editing %s' ), $display_name ) . '</strong>';
        echo '<div class="db-users-header-actions">';
        echo '<form method="post" class="db-users-delete-form" onsubmit="return confirm(\'' . $confirm_text . '\');">';
        echo '<input type="hidden" name="db_users_action" value="delete_user" />';
        echo '<input type="hidden" name="target_user" value="' . $attr_username . '" />';
        yourls_nonce_field( 'db_users_delete_user' );
        echo '<button type="submit" class="button button-delete"' . $delete_disabled . '>' . yourls__( 'Delete user' ) . '</button>';
        echo '</form>';
        if( $delete_note_text !== '' ) {
            echo '<span class="db-users-delete-note">' . yourls_esc_html( $delete_note_text ) . '</span>';
        }
        echo '</div>';
        echo '</div>';
        echo '<form method="post">';
        echo '<input type="hidden" name="db_users_action" value="update_user" />';
        echo '<input type="hidden" name="target_user" value="' . $attr_username . '" />';
        yourls_nonce_field( 'db_users_update_user' );
        echo '<p><label>' . yourls__( 'Role' ) . '</label><br />';
        echo '<select name="new_role">';
        echo '<option value="admin" ' . $role_admin . '>' . yourls__( 'Administrator' ) . '</option>';
        echo '<option value="user" ' . $role_user . '>' . yourls__( 'User' ) . '</option>';
        echo '</select></p>';
        echo '<p><label>' . yourls__( 'Set new password (optional)' ) . '</label><br />';
        echo '<input type="password" class="text" name="new_password" autocomplete="new-password" />';
        echo '</p>';
        echo '<p><label>' . yourls__( 'Confirm new password' ) . '</label><br />';
        echo '<input type="password" class="text" name="confirm_password" autocomplete="new-password" />';
        echo '</p>';
        echo '<p><button type="submit" class="button">' . yourls__( 'Save changes' ) . '</button></p>';
        echo '</form>';
        echo '</div>';
        echo '</td>';
        echo '</tr>';
    }

    echo '</tbody></table>';

    static $script_rendered = false;
    if( !$script_rendered ) {
        $script_rendered = true;
        echo '<script>
        document.addEventListener("click", function(event) {
            var trigger = event.target.closest(".db-users-toggle");
            if (!trigger) {
                return;
            }
            event.preventDefault();
            var targetId = trigger.getAttribute("data-target");
            if (!targetId) {
                return;
            }
            var row = document.getElementById(targetId);
            if (!row) {
                return;
            }
            if (row.style.display === "none" || row.style.display === "") {
                row.style.display = "table-row";
            } else {
                row.style.display = "none";
            }
        });
        </script>';
    }
}

/**
 * Move plugin admin page link under the Admin interface menu.
 *
 * @param array $sublinks
 * @return array
 */
function db_users_move_menu_link( array $sublinks ) {
    if( isset( $sublinks['plugins']['db_users'] ) ) {
        $link = $sublinks['plugins']['db_users'];
        unset( $sublinks['plugins']['db_users'] );
        if( empty( $sublinks['plugins'] ) ) {
            unset( $sublinks['plugins'] );
        }
        if( !isset( $sublinks['admin'] ) || !is_array( $sublinks['admin'] ) ) {
            $sublinks['admin'] = [];
        }
        $sublinks['admin']['db_users'] = $link;
    }

    return $sublinks;
}

/**
 * Placeholder for user self-service form (implemented later).
 *
 * @return void
 */
function db_users_render_self_service_form() {
    if( !defined( 'YOURLS_USER' ) ) {
        return;
    }

    $username = YOURLS_USER;

    echo '<h3>' . yourls__( 'Change Your Password' ) . '</h3>';
    echo '<form method="post" class="db-users-form">';
    echo '<input type="hidden" name="db_users_action" value="self_update_password" />';
    yourls_nonce_field( 'db_users_change_own_password' );
    echo '<p>' . sprintf( yourls__( 'You are logged in as %s.' ), yourls_esc_html( $username ) ) . '</p>';
    echo '<p><label for="db-users-current-password">' . yourls__( 'Current password' ) . '</label><br />';
    echo '<input type="password" class="text" id="db-users-current-password" name="current_password" autocomplete="current-password" required /></p>';
    echo '<p><label for="db-users-self-new-password">' . yourls__( 'New password' ) . '</label><br />';
    echo '<input type="password" class="text" id="db-users-self-new-password" name="self_new_password" autocomplete="new-password" required /></p>';
    echo '<p><label for="db-users-self-confirm-password">' . yourls__( 'Confirm new password' ) . '</label><br />';
    echo '<input type="password" class="text" id="db-users-self-confirm-password" name="self_confirm_password" autocomplete="new-password" required /></p>';
    echo '<p><button type="submit" class="button button-primary">' . yourls__( 'Update password' ) . '</button></p>';
    echo '</form>';
}

/**
 * Update a user password.
 *
 * @param string $username
 * @param string $password
 * @return bool
 */
function db_users_update_user_password( $username, $password ) {
    $username = db_users_sanitize_username( $username );
    $password = (string) $password;

    if( $username === '' || $password === '' ) {
        return false;
    }

    $stored = db_users_normalize_password_storage( $password );

    $sql = "UPDATE `" . db_users_table_name() . "` SET user_pass = :pass, updated_at = :updated WHERE user_login = :login";
    $affected = db_users_db()->fetchAffected( $sql, [
        'pass'    => $stored,
        'updated' => db_users_now(),
        'login'   => $username,
    ] );

    return $affected !== false;
}

/**
 * Update a user role.
 *
 * @param string $username
 * @param string $role
 * @return bool
 */
function db_users_update_user_role( $username, $role ) {
    $username = db_users_sanitize_username( $username );
    $role     = db_users_sanitize_role( $role );

    if( $username === '' ) {
        return false;
    }

    $sql = "UPDATE `" . db_users_table_name() . "` SET user_role = :role, updated_at = :updated WHERE user_login = :login";
    $affected = db_users_db()->fetchAffected( $sql, [
        'role'    => $role,
        'updated' => db_users_now(),
        'login'   => $username,
    ] );

    return $affected !== false;
}

/**
 * Retrieve all users with metadata.
 *
 * @return array
 */
function db_users_get_all_users() {
    $table = db_users_table_name();
    $rows  = db_users_db()->fetchObjects( "SELECT user_login, user_role, created_at, updated_at FROM `$table` ORDER BY user_login ASC" );

    return $rows ? (array) $rows : [];
}

/**
 * Fetch a user row.
 *
 * @param string $username
 * @return object|false
 */
function db_users_get_user( $username ) {
    $username = db_users_sanitize_username( $username );

    if( $username === '' ) {
        return false;
    }

    return db_users_db()->fetchObject(
        "SELECT user_login, user_role, created_at, updated_at FROM `" . db_users_table_name() . "` WHERE user_login = :login LIMIT 1",
        [ 'login' => $username ]
    );
}

/**
 * Determine if a user exists.
 *
 * @param string $username
 * @return bool
 */
function db_users_user_exists( $username ) {
    return (bool) db_users_get_user( $username );
}

/**
 * Delete a user.
 *
 * @param string $username
 * @return bool
 */
function db_users_delete_user( $username ) {
    $username = db_users_sanitize_username( $username );

    if( $username === '' ) {
        return false;
    }

    $sql = "DELETE FROM `" . db_users_table_name() . "` WHERE user_login = :login LIMIT 1";
    $affected = db_users_db()->fetchAffected( $sql, [
        'login' => $username,
    ] );

    return $affected !== false && $affected > 0;
}

/**
 * Count administrators.
 *
 * @return int
 */
function db_users_count_admins() {
    $table = db_users_table_name();

    return (int) db_users_db()->fetchValue( "SELECT COUNT(*) FROM `$table` WHERE user_role = 'admin'" );
}

/**
 * Determine if a given username is the final admin.
 *
 * @param string $username
 * @return bool
 */
function db_users_is_last_admin( $username ) {
    $username = db_users_sanitize_username( $username );

    if( $username === '' ) {
        return false;
    }

    $role = db_users_db()->fetchValue(
        "SELECT user_role FROM `" . db_users_table_name() . "` WHERE user_login = :login LIMIT 1",
        [ 'login' => $username ]
    );

    if( $role !== 'admin' ) {
        return false;
    }

    return db_users_count_admins() <= 1;
}
