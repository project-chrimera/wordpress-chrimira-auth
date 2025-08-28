<?php
/**
 * Plugin Name: Internal Groups Management API
 * Description: API endpoints to add/remove WordPress roles and bbPress roles from users using email identity and token authentication.
 * Version: 1.1.0
 * Author: Your Name
 */

defined('ABSPATH') || die('No direct access allowed!');

class Internal_Groups_API {
    private $api_namespace = 'internal-groups/v1';
    private $db;
    private $token_table;

    public function __construct() {
        global $wpdb;
        $this->db = $wpdb;
        $this->token_table = $wpdb->prefix . 'ig_api_tokens';
        register_activation_hook(__FILE__, array($this, 'activate'));
        add_action('plugins_loaded', array($this, 'init'));
    }

private function verify_ip($ip) {
    // Get all whitelisted IPs
    $allowed_ips = $this->db->get_col("SELECT ip_address FROM {$this->db->prefix}ig_api_ips");

    // If no IPs are stored, allow everyone
    if (empty($allowed_ips)) {
        return true;
    }

    return in_array($ip, $allowed_ips, true);
}


    public function init() {
        add_action('rest_api_init', array($this, 'register_routes'));
        add_action('admin_menu', array($this, 'add_admin_menu'));
    }

public function activate() {
    require_once(ABSPATH . 'wp-admin/includes/upgrade.php');

    // Token table
    $sql_token = "CREATE TABLE {$this->token_table} (
        id mediumint(9) NOT NULL AUTO_INCREMENT,
        token varchar(64) NOT NULL,
        name varchar(100) NOT NULL,
        created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY token (token)
    ) {$this->db->get_charset_collate()};";
    dbDelta($sql_token);

    // IP whitelist table
    $ip_table = $this->db->prefix . 'ig_api_ips';
    $sql_ip = "CREATE TABLE {$ip_table} (
        id mediumint(9) NOT NULL AUTO_INCREMENT,
        ip_address varchar(45) NOT NULL,
        created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY ip_address (ip_address)
    ) {$this->db->get_charset_collate()};";
    dbDelta($sql_ip);

    // Make sure table actually exists
    if ($this->db->get_var("SHOW TABLES LIKE '{$ip_table}'") != $ip_table) {
        $this->db->query($sql_ip);
    }
}



    public function register_routes() {
        register_rest_route($this->api_namespace, '/add-role', array(
            'methods' => 'POST',
            'callback' => array($this, 'add_role_to_user'),
            'permission_callback' => array($this, 'verify_token')
        ));
        register_rest_route($this->api_namespace, '/remove-role', array(
            'methods' => 'POST',
            'callback' => array($this, 'remove_role_from_user'),
            'permission_callback' => array($this, 'verify_token')
        ));
        register_rest_route($this->api_namespace, '/user-roles', array(
            'methods' => 'GET',
            'callback' => array($this, 'get_user_roles'),
            'permission_callback' => array($this, 'verify_token')
        ));
        register_rest_route($this->api_namespace, '/create-user', array(
            'methods' => 'POST',
            'callback' => array($this, 'create_user_api'),
            'permission_callback' => array($this, 'verify_token')
        ));

        // bbPress endpoints
        register_rest_route($this->api_namespace, '/bbpress-set-role', array(
            'methods' => 'POST',
            'callback' => array($this, 'bbpress_set_role'),
            'permission_callback' => array($this, 'verify_token')
        ));
        register_rest_route($this->api_namespace, '/bbpress-get-role', array(
            'methods' => 'GET',
            'callback' => array($this, 'bbpress_get_role'),
            'permission_callback' => array($this, 'verify_token')
        ));
    }

public function verify_token($request) {
    $token = $request->get_header('X-API-Token');
    $ip = $_SERVER['REMOTE_ADDR'];

    if (!$this->verify_ip($ip)) {
        return new WP_Error('ip_not_allowed', 'Your IP is not allowed', ['status' => 403]);
    }

    if (empty($token)) {
        return new WP_Error('missing_token', 'API token is required', ['status' => 401]);
    }

    $valid_token = $this->db->get_var($this->db->prepare(
        "SELECT token FROM {$this->token_table} WHERE token = %s", $token
    ));
    if (!$valid_token) {
        return new WP_Error('invalid_token', 'Invalid API token', ['status' => 403]);
    }

    return true;
}

    // ================= WordPress Roles =================
    public function add_role_to_user($request) {
        $params = $request->get_json_params();
        $email = sanitize_email($params['email'] ?? '');
        $role = sanitize_text_field($params['role'] ?? '');

        if (empty($email) || !is_email($email)) return new WP_Error('invalid_email', 'Valid email is required', ['status'=>400]);
        if (empty($role)) return new WP_Error('invalid_role', 'Role is required', ['status'=>400]);

        $user = get_user_by('email', $email);
        if (!$user) return new WP_Error('user_not_found', 'User does not exist', ['status'=>404]);

        if (in_array($role, $user->roles)) {
            return new WP_REST_Response(['message'=>'User already has this role','user_id'=>$user->ID,'role'=>$role],200);
        }

        $user->add_role($role);

        return new WP_REST_Response(['message'=>'Role added','user_id'=>$user->ID,'role'=>$role,'all_roles'=>$user->roles],200);
    }

    public function remove_role_from_user($request) {
        $params = $request->get_json_params();
        $email = sanitize_email($params['email'] ?? '');
        $role = sanitize_text_field($params['role'] ?? '');

        if (empty($email) || !is_email($email)) return new WP_Error('invalid_email', 'Valid email is required', ['status'=>400]);
        if (empty($role)) return new WP_Error('invalid_role', 'Role is required', ['status'=>400]);

        $user = get_user_by('email', $email);
        if (!$user) return new WP_Error('user_not_found', 'User does not exist', ['status'=>404]);

        if (!in_array($role, $user->roles)) {
            return new WP_REST_Response(['message'=>'User does not have this role','user_id'=>$user->ID,'role'=>$role],200);
        }

        $user->remove_role($role);

        return new WP_REST_Response(['message'=>'Role removed','user_id'=>$user->ID,'role'=>$role,'all_roles'=>$user->roles],200);
    }

    public function get_user_roles($request) {
        $email = sanitize_email($request->get_param('email') ?? '');
        if (empty($email) || !is_email($email)) return new WP_Error('invalid_email', 'Valid email is required', ['status'=>400]);

        $user = get_user_by('email', $email);
        if (!$user) return new WP_Error('user_not_found', 'User does not exist', ['status'=>404]);

        return new WP_REST_Response(['user_id'=>$user->ID,'email'=>$email,'roles'=>$user->roles],200);
    }

    public function create_user_api($request) {
        $params = $request->get_json_params();
        $username = sanitize_user($params['username'] ?? '', true);
        $email = sanitize_email($params['email'] ?? '');
        $role = sanitize_text_field($params['role'] ?? 'subscriber');

        if (!function_exists('get_editable_roles')) require_once ABSPATH.'wp-admin/includes/user.php';

        if (!in_array($role,array_keys(get_editable_roles()))) return new WP_Error('invalid_role','Role does not exist',['status'=>400]);
        if (empty($username) || username_exists($username)) return new WP_Error('invalid_username','Username invalid',['status'=>400]);
        if (empty($email) || !is_email($email) || email_exists($email)) return new WP_Error('invalid_email','Email invalid',['status'=>400]);

        $password = wp_generate_password(12,true);
        $user_id = wp_create_user($username,$password,$email);
        if (is_wp_error($user_id)) return $user_id;

        $user = new WP_User($user_id);
        $user->set_role($role);

        return new WP_REST_Response([
            'message'=>'User created',
            'user_id'=>$user_id,
            'username'=>$username,
            'email'=>$email,
            'role'=>$role,
            'password'=>$password
        ],200);
    }

// ================= bbPress Roles =================
public function bbpress_set_role($request) {
    if (!function_exists('bbp_set_user_role')) {
        return new WP_Error('bbpress_not_loaded', 'bbPress must be active', ['status' => 500]);
    }

    $params = $request->get_json_params();
    $email  = sanitize_email($params['email'] ?? '');
    $role   = sanitize_text_field($params['role'] ?? '');

    if (empty($email) || !is_email($email)) {
        return new WP_Error('invalid_email', 'Valid email required', ['status' => 400]);
    }
    if (empty($role)) {
        return new WP_Error('invalid_role', 'bbPress role required', ['status' => 400]);
    }

    $user = get_user_by('email', $email);
    if (!$user) {
        return new WP_Error('user_not_found', 'User does not exist', ['status' => 404]);
    }

    // Allowed bbPress roles
    $valid_roles = [
        'bbp_keymaster',
        'bbp_moderator',
        'bbp_participant',
        'bbp_spectator',
        'bbp_blocked'
    ];

    if (!in_array($role, $valid_roles, true)) {
        return new WP_Error('invalid_role', 'Invalid bbPress role. See allowed roles in the admin help page.', [
            'status'        => 400,
            'allowed_roles' => $valid_roles
        ]);
    }

    bbp_set_user_role($user->ID, $role);

    return new WP_REST_Response([
        'message'       => 'bbPress role set successfully',
        'user_id'       => $user->ID,
        'email'         => $email,
        'bbpress_role'  => $role,
    ], 200);
}

public function bbpress_get_role($request) {
    if (!function_exists('bbp_get_user_role')) {
        return new WP_Error('bbpress_not_loaded', 'bbPress must be active', ['status' => 500]);
    }

    $email = sanitize_email($request->get_param('email') ?? '');
    if (empty($email) || !is_email($email)) {
        return new WP_Error('invalid_email', 'Valid email required', ['status' => 400]);
    }

    $user = get_user_by('email', $email);
    if (!$user) {
        return new WP_Error('user_not_found', 'User does not exist', ['status' => 404]);
    }

    $bb_role = bbp_get_user_role($user->ID);

    return new WP_REST_Response([
        'user_id'       => $user->ID,
        'email'         => $email,
        'bbpress_role'  => $bb_role
    ], 200);
}

    // ================= Admin Page =================
    public function add_admin_menu() {
        add_options_page(
            'Yap2stw API Settings',
            'yap2stw-api',
            'manage_options',
            'yap2stw-api',
            array($this,'admin_page_html')
        );
    }

    public function admin_page_html() {
        if (!current_user_can('manage_options')) return;

        global $wpdb;

if (!empty($_POST['action']) && $_POST['action'] === 'add_ip') {
    check_admin_referer('add_ip');
    $ip_address = sanitize_text_field($_POST['ip_address']);
    if (filter_var($ip_address, FILTER_VALIDATE_IP)) {
        $result = $this->db->insert($this->db->prefix . 'ig_api_ips', ['ip_address' => $ip_address]);
        $message = $result ? 'IP added successfully.' : 'Failed to insert IP: ' . $this->db->last_error;
    } else {
        $message = 'Invalid IP address.';
    }
}

if (!empty($_POST['action']) && $_POST['action'] === 'delete_ip') {
    $delete_id = intval($_POST['delete_ip_id']);
    check_admin_referer('delete_ip_' . $delete_id);
    $result = $this->db->delete($this->db->prefix . 'ig_api_ips', ['id' => $delete_id]);
    $message = $result ? 'IP deleted successfully.' : 'Failed to delete IP: ' . $this->db->last_error;
}



        // Handle token deletion
        if (isset($_POST['delete_token'])) {
            $delete_id = intval($_POST['delete_token_id']);
            if (check_admin_referer('delete_ig_token_' . $delete_id)) {
                $this->db->delete($this->token_table,['id'=>$delete_id]);
                $message='Token deleted successfully.';
            }
        }

        // Handle token generation
        $new_token='';
        if (isset($_POST['generate_token'])) {
            check_admin_referer('generate_ig_token');
            $token_name = sanitize_text_field($_POST['token_name']);
            if (!empty($token_name)) {
                $new_token = bin2hex(random_bytes(32));
                $this->db->insert($this->token_table,['name'=>$token_name,'token'=>$new_token]);
            }
        }
        ?>
        <div class="wrap">
        <h1><?php echo esc_html(get_admin_page_title()); ?></h1>
        <?php if (!empty($message)) : ?>
            <div class="notice notice-success"><p><?php echo $message; ?></p></div>
        <?php endif; ?>

        <h2>Generate New API Token</h2>
        <form method="post">
            <?php wp_nonce_field('generate_ig_token'); ?>
            <table class="form-table">
                <tr>
                    <th scope="row"><label for="token_name">Token Name</label></th>
                    <td><input name="token_name" type="text" id="token_name" class="regular-text" required></td>
                </tr>
            </table>


            <?php submit_button('Generate Token','primary','generate_token'); ?>
        </form>

        <?php if(!empty($new_token)): ?>
            <div style="border-left:4px solid #0073aa;padding:10px;margin:10px 0;font-family:monospace;">
                <strong>New Token:</strong> <?php echo esc_html($new_token); ?>
            </div>
        <?php endif; ?>


        <h2>Existing Tokens</h2>
        <?php
        $tokens = $this->db->get_results("SELECT id,name, created_at FROM {$this->token_table} ORDER BY created_at DESC");
        if($tokens):
        ?>
            <table class="widefat striped">
            <thead><tr><th>Name</th><th>Created</th><th>Actions</th></tr></thead>
            <tbody>
            <?php foreach($tokens as $token): ?>
                <tr>
                    <td><?php echo esc_html($token->name); ?></td>
                    <td><?php echo $token->created_at; ?></td>
                    <td>
                        <form method="post">
                            <?php wp_nonce_field('delete_ig_token_'.$token->id); ?>
                            <input type="hidden" name="delete_token_id" value="<?php echo $token->id; ?>">
                            <?php submit_button('Delete','small','delete_token',false); ?>
                        </form>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody></table>
        <?php else: ?>
            <p>No API tokens generated yet.</p>
<?php endif; ?>
<?php
$ips = $this->db->get_results("SELECT id, ip_address FROM {$this->db->prefix}ig_api_ips ORDER BY created_at DESC");
?>
<h2>IP Whitelist</h2>

<!-- Add IP Form -->
<form method="post">
    <?php wp_nonce_field('add_ip'); ?>
    <input type="hidden" name="action" value="add_ip">
    <input type="text" name="ip_address" placeholder="Enter IP" required>
    <?php submit_button('Add IP'); ?>
</form>

<!-- Existing IPs -->
<table class="widefat striped">
    <thead><tr><th>IP Address</th><th>Actions</th></tr></thead>
    <tbody>
        <?php foreach ($ips as $ip): ?>
        <tr>
            <td><?php echo esc_html($ip->ip_address); ?></td>
            <td>
                <form method="post">
                    <?php wp_nonce_field('delete_ip_' . $ip->id); ?>
                    <input type="hidden" name="action" value="delete_ip">
                    <input type="hidden" name="delete_ip_id" value="<?php echo $ip->id; ?>">
                    <?php submit_button('Delete', 'small'); ?>
                </form>
            </td>
        </tr>
        <?php endforeach; ?>
    </tbody>
</table>


    <h2>API Usage / Help</h2>
    <p>Use the <code>X-API-Token</code> header in all requests.</p>

    <h3>1. Add a WordPress role</h3>
    <pre>curl -X POST <?php echo home_url('/wp-json/internal-groups/v1/add-role'); ?> \
-H "Content-Type: application/json" \
-H "X-API-Token: YOUR_TOKEN_HERE" \
-d '{"email":"user@example.com","role":"subscriber"}'</pre>

    <h3>2. Remove a WordPress role</h3>
    <pre>curl -X POST <?php echo home_url('/wp-json/internal-groups/v1/remove-role'); ?> \
-H "Content-Type: application/json" \
-H "X-API-Token: YOUR_TOKEN_HERE" \
-d '{"email":"user@example.com","role":"subscriber"}'</pre>

    <h3>3. List a user’s roles</h3>
    <pre>curl -X GET "<?php echo home_url('/wp-json/internal-groups/v1/user-roles?email=user@example.com'); ?>" \
-H "X-API-Token: YOUR_TOKEN_HERE"</pre>

    <h3>4. Create a new user</h3>
    <pre>curl -X POST <?php echo home_url('/wp-json/internal-groups/v1/create-user'); ?> \
-H "Content-Type: application/json" \
-H "X-API-Token: YOUR_TOKEN_HERE" \
-d '{"username":"newuser","email":"newuser@example.com","role":"subscriber"}'</pre>

    <h3>5. bbPress Role Management</h3>
    <p>Use these endpoints to assign or view bbPress roles:</p>
    <pre>curl -X POST <?php echo home_url('/wp-json/internal-groups/v1/bbpress-set-role'); ?> \
-H "Content-Type: application/json" \
-H "X-API-Token: YOUR_TOKEN_HERE" \
-d '{"email":"user@example.com","role":"bbp_participant"}'</pre>

    <pre>curl -X GET "<?php echo home_url('/wp-json/internal-groups/v1/bbpress-get-role'); ?>?email=user@example.com" \
-H "X-API-Token: YOUR_TOKEN_HERE"</pre>

    <h4>Allowed bbPress Roles</h4>
    <ul>
        <li><code>bbp_keymaster</code> – Keymaster (full admin access)</li>
        <li><code>bbp_moderator</code> – Moderator (manage content and users)</li>
        <li><code>bbp_participant</code> – Participant (regular member)</li>
        <li><code>bbp_spectator</code> – Spectator (read-only)</li>
        <li><code>bbp_blocked</code> – Blocked (no access)</li>
    </ul>

</div>
<?php
}
}
// Instantiate plugin
new Internal_Groups_API();
?>
