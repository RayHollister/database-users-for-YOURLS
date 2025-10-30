# Database Users for YOURLS

Database Users replaces the static credential array in `user/config.php` with a database-backed user table and a lightweight administration panel. Activate it to keep logins inside YOURLS, grant a password self-service form, and stay compatible with existing hashing schemes.

## Features
- Creates and maintains the `<prefix>user_credentials` table for logins, roles, and timestamps.
- Imports the legacy `$yourls_user_passwords` array the first time the table is empty, preserving existing admins.
- Adds a Plugin page (`Plugins → Database Users → User Accounts`) for creating users, resetting passwords, and switching between the built-in `admin` and `user` roles.
- Provides a self-service password change form for the currently logged-in account.
- Normalizes hashes to YOURLS-style `phpass:` values while still accepting `md5:` and plain strings.
- Populates the `YOURLS_USER_ROLE` constant at login so the rest of your install can respect roles.

## Requirements
- YOURLS 1.8 or newer (other versions are untested).
- Database user able to run `CREATE TABLE` on the YOURLS database.
- Access to manage YOURLS plugins in the admin dashboard.

## Installation
1. Copy or clone this folder to `user/plugins/db-users`.
2. Sign in to the YOURLS admin area and activate **Database Users** on the Plugins page.
3. On activation the plugin creates the credential table and, if it is empty, migrates every entry from `$yourls_user_passwords` in `user/config.php`.

## Usage
- Open `Plugins → Database Users → User Accounts` to manage credentials.
- **Create users**: fill in username, password, confirmation, and role; the plugin prevents duplicates and missing values.
- **Update users**: expand a user row to change role or set a new password. The plugin guards against removing the final administrator.
- **Self-service**: the bottom form lets the signed-in user change their own password after validating the current one. Successful changes refresh the session cookie.

## Programmatic helpers
- `db_users_add_user( $username, $password, $role = 'user' )` inserts a user with normalized password storage.
- `db_users_verify_password( $username, $password )` checks credentials against the cached values, reloading if necessary.
- `db_users_refresh_credentials_cache()` repopulates the global `$yourls_user_passwords` array from the database.

Call `db_users_refresh_credentials_cache()` after programmatic inserts or updates so new credentials are instantly available to YOURLS.

## Data model
Records live in `<prefix>user_credentials` with columns for `user_login`, `user_pass`, `user_role`, `created_at`, and `updated_at`. Passwords are stored as YOURLS-compatible `phpass:` hashes unless an `md5:` hash is supplied. Timestamps are updated automatically on create and update actions.

## Troubleshooting
- Enable `YOURLS_DEBUG` to capture log entries written with `yourls_debug_log()` when insert or update operations fail.
- If logins appear stale, trigger `db_users_refresh_credentials_cache()` or revisit the admin page to rebuild the cache.
- Ensure the database account can create tables the first time the plugin activates; otherwise, manually run the schema from `plugin.php`.

## Roadmap
- Allow deleting users from the interface.

## Credits
Built and maintained by Ray Hollister.
