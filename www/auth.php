<?php
if (session_status() === PHP_SESSION_NONE) session_start();

// ─── DÉTECTION PREMIER LANCEMENT ─────────────────────────────────────────────
// Si la DB n'existe pas ou est vide → wizard setup
define('_DB_PATH', '/var/www/html/ipam.db');
$_currentPage = basename($_SERVER['PHP_SELF']);
if ($_currentPage !== 'setup.php') {
    $_needsSetup = false;
    if (!file_exists(_DB_PATH)) {
        $_needsSetup = true;
    } else {
        try {
            $_setupDb = new PDO('sqlite:' . _DB_PATH);
            $_setupDb->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $_needsSetup = (int)$_setupDb->query("SELECT COUNT(*) FROM users")->fetchColumn() === 0;
        } catch (Throwable $_e) { $_needsSetup = true; }
    }
    if ($_needsSetup) {
        header('Location: setup.php');
        exit;
    }
}

$_publicPages = ['login.php', 'logout.php', 'license.php', 'login_otp.php', 'setup.php'];

// ─── HEADERS SÉCURITÉ ────────────────────────────────────────────────────────
if (!headers_sent()) {
    header('X-Frame-Options: SAMEORIGIN');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: strict-origin-when-cross-origin');
}

// ─── SESSION TIMEOUT ─────────────────────────────────────────────────────────
if (!defined('SESSION_TIMEOUT')) define('SESSION_TIMEOUT', 3600);

if (isset($_SESSION['user_id']) && !in_array($_currentPage, $_publicPages)) {
    if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > SESSION_TIMEOUT) {
        $uid = $_SESSION['user_id'] ?? null;
        session_unset();
        session_destroy();
        session_write_close();
        session_start();
        session_regenerate_id(true);
        header('Location: login.php?timeout=1');
        exit;
    }
    $_SESSION['last_activity'] = time();
}

// ─── REDIRECTION SI NON CONNECTÉ ─────────────────────────────────────────────
if (!isset($_SESSION['user_id']) && !in_array($_currentPage, $_publicPages)) {
    header('Location: login.php');
    exit;
}

// ─── PROTECTION 2FA ──────────────────────────────────────────────────────────
if (isset($_SESSION['2fa_pending_user_id'])
    && $_currentPage !== 'login_otp.php'
    && $_currentPage !== 'logout.php') {
    header('Location: login_otp.php');
    exit;
}

$_role      = $_SESSION['role'] ?? 'viewer';
$isSysAdmin = ($_role === 'sysadmin');
$isAdmin    = ($_role === 'admin' || $_role === 'sysadmin');
$isViewer   = ($_role === 'viewer');

if (!function_exists('validateLicenseKey')) {
    require_once __DIR__ . '/config.php';
}

// ─── VÉRIFICATION LICENCE ────────────────────────────────────────────────────
if (isset($_SESSION['user_id'])
    && !isset($_SESSION['2fa_pending_user_id'])
    && !in_array($_currentPage, $_publicPages)) {
    $lic = getLicense();
    if (!$lic) {
        header('Location: license.php');
        exit;
    }
}

// ─── FORCER CHANGEMENT MOT DE PASSE ──────────────────────────────────────────
// Pages où on peut aller même avec mdp expiré/forcé
$_pwExemptPages = ['my_password.php', 'logout.php', 'settings.php', 'db_init.php'];
if (isset($_SESSION['user_id'])
    && !isset($_SESSION['2fa_pending_user_id'])
    && !in_array($_currentPage, array_merge($_publicPages, $_pwExemptPages))) {
    if (!empty($_SESSION['must_change_password'])) {
        $_SESSION['flash'] = ['msg' => '🔑 Vous devez définir un nouveau mot de passe avant de continuer.', 'type' => 'warning'];
        header('Location: my_password.php');
        exit;
    }
    if (!empty($_SESSION['password_expires_at']) && strtotime($_SESSION['password_expires_at']) < time()) {
        $_SESSION['flash'] = ['msg' => '⏰ Votre mot de passe a expiré. Veuillez le renouveler.', 'type' => 'warning'];
        header('Location: my_password.php');
        exit;
    }
}


// ─── FONCTIONS RÔLES ─────────────────────────────────────────────────────────
function requireSysAdmin(string $back = 'index.php'): void {
    global $isSysAdmin;
    if (!$isSysAdmin) redirect($back, 'Accès réservé au Sysadmin.', 'danger');
}
function requireAdmin(string $back = 'index.php'): void {
    global $isAdmin;
    if (!$isAdmin) redirect($back, 'Accès refusé.', 'danger');
}
function roleLabel(string $role): string {
    return match($role) {
        'sysadmin' => 'Sysadmin', 'admin' => 'Admin', 'viewer' => 'Viewer',
        default    => ucfirst($role),
    };
}
function roleBadgeClass(string $role): string {
    return match($role) {
        'sysadmin' => 'role-sysadmin', 'admin' => 'bg-danger',
        'viewer'   => 'bg-info text-dark', default => 'bg-secondary',
    };
}

// ─── BASE DE DONNÉES ─────────────────────────────────────────────────────────
function db(): PDO {
    static $pdo = null;
    if ($pdo === null) {
        $pdo = new PDO('sqlite:/var/www/html/ipam.db');
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        $pdo->exec('PRAGMA foreign_keys = ON');
        $pdo->exec('PRAGMA journal_mode = WAL');
    }
    return $pdo;
}

// ─── RATE LIMITING ───────────────────────────────────────────────────────────
if (!defined('LOGIN_MAX_ATTEMPTS'))    define('LOGIN_MAX_ATTEMPTS',    5);
if (!defined('LOGIN_LOCKOUT_MINUTES')) define('LOGIN_LOCKOUT_MINUTES', 15);

function _ensureLoginAttemptsTable(): void {
    db()->exec("CREATE TABLE IF NOT EXISTS login_attempts (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        ip           TEXT NOT NULL,
        username     TEXT NOT NULL,
        attempts     INTEGER NOT NULL DEFAULT 0,
        locked_until DATETIME,
        last_attempt DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(ip, username)
    )");
}

function checkLoginRateLimit(string $username, string $ip): array {
    try {
        _ensureLoginAttemptsTable();
        $stmt = db()->prepare('SELECT * FROM login_attempts WHERE ip=? AND username=?');
        $stmt->execute([$ip, $username]);
        $row = $stmt->fetch();
        if ($row && $row['locked_until']) {
            $rem = strtotime($row['locked_until']) - time();
            if ($rem > 0) return ['locked' => true, 'remaining_min' => (int)ceil($rem / 60)];
        }
        return ['locked' => false];
    } catch (Exception $e) { return ['locked' => false]; }
}

function recordLoginFailure(string $username, string $ip): void {
    try {
        _ensureLoginAttemptsTable();
        $stmt = db()->prepare('SELECT attempts FROM login_attempts WHERE ip=? AND username=?');
        $stmt->execute([$ip, $username]);
        $row = $stmt->fetch();
        if ($row) {
            $n    = $row['attempts'] + 1;
            $lock = $n >= LOGIN_MAX_ATTEMPTS
                  ? date('Y-m-d H:i:s', time() + LOGIN_LOCKOUT_MINUTES * 60) : null;
            db()->prepare('UPDATE login_attempts SET attempts=?,locked_until=?,last_attempt=CURRENT_TIMESTAMP WHERE ip=? AND username=?')
               ->execute([$n, $lock, $ip, $username]);
        } else {
            db()->prepare('INSERT INTO login_attempts (ip,username,attempts) VALUES (?,?,1)')
               ->execute([$ip, $username]);
        }
    } catch (Exception $e) {}
}

function resetLoginAttempts(string $username, string $ip): void {
    try {
        db()->prepare('DELETE FROM login_attempts WHERE ip=? AND username=?')
            ->execute([$ip, $username]);
    } catch (Exception $e) {}
}

// ─── JOURNAL D'AUDIT ─────────────────────────────────────────────────────────
function audit(string $action, string $target = '', string $detail = ''): void {
    try {
        $pdo = db();
        $pdo->exec("CREATE TABLE IF NOT EXISTS audit_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER,
            username   TEXT NOT NULL DEFAULT 'system',
            action     TEXT NOT NULL,
            target     TEXT NOT NULL DEFAULT '',
            detail     TEXT NOT NULL DEFAULT '',
            ip_address TEXT NOT NULL DEFAULT '',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )");
        $pdo->prepare('INSERT INTO audit_log (user_id,username,action,target,detail,ip_address) VALUES (?,?,?,?,?,?)')
            ->execute([
                $_SESSION['user_id']  ?? null,
                $_SESSION['user']     ?? 'system',
                $action, $target, $detail,
                $_SERVER['REMOTE_ADDR'] ?? '',
            ]);
    } catch (Exception $e) {}
}

// ─── UTILITAIRES ─────────────────────────────────────────────────────────────
function e(string $v): string {
    return htmlspecialchars($v, ENT_QUOTES, 'UTF-8');
}

function validateIpInSubnet(string $ip, string $cidr): bool|string {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return "Syntaxe IP invalide : « $ip ».";
    if (!str_contains($cidr, '/')) return "Format CIDR invalide (ex: 192.168.1.0/24).";
    [$net, $mask] = explode('/', $cidr, 2);
    $maskInt = (int)$mask;
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        if (!filter_var($net, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4))
            return "Le sous-réseau du VLAN n'est pas un IPv4 valide.";
        if ($maskInt < 0 || $maskInt > 32)
            return "Masque IPv4 invalide : /$mask (doit être entre /0 et /32).";
        $ipL = ip2long($ip); $netL = ip2long($net);
        $m   = $maskInt === 0 ? 0 : (~0 << (32 - $maskInt));
        if (($ipL & $m) !== ($netL & $m)) return "L'IP $ip n'appartient pas au réseau $cidr.";
    } else {
        if (!filter_var($net, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6))
            return "Le sous-réseau du VLAN n'est pas un IPv6 valide.";
        if ($maskInt < 0 || $maskInt > 128)
            return "Masque IPv6 invalide : /$mask (doit être entre /0 et /128).";
        $ipB = inet_pton($ip); $netB = inet_pton($net);
        $mb  = (int)floor($maskInt / 8);
        if (substr($ipB, 0, $mb) !== substr($netB, 0, $mb))
            return "L'IPv6 n'appartient pas au préfixe $cidr.";
    }
    return true;
}

function validateSubnet(string $cidr): bool|string {
    if (!str_contains($cidr, '/')) return "Format CIDR invalide — slash manquant.";
    [$net, $mask] = explode('/', $cidr, 2);
    if (!is_numeric($mask)) return "Masque invalide.";
    $m = (int)$mask;
    if (filter_var($net, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        if ($m < 0 || $m > 32) return "Masque IPv4 invalide : /$mask (0-32).";
    } elseif (filter_var($net, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        if ($m < 0 || $m > 128) return "Masque IPv6 invalide : /$mask (0-128).";
    } else { return "Adresse réseau invalide : « $net »."; }
    return true;
}

function getTags(): array {
    static $tags = null;
    if ($tags === null) {
        try { $tags = db()->query('SELECT * FROM tags ORDER BY name ASC')->fetchAll(); }
        catch (Exception $e) { $tags = []; }
    }
    return $tags;
}

function getTag(string $name): array {
    foreach (getTags() as $t) { if ($t['name'] === $name) return $t; }
    return ['name' => $name, 'color' => 'secondary', 'icon' => 'tag'];
}

function redirect(string $url, string $msg = '', string $type = 'success'): never {
    if ($msg !== '') $_SESSION['flash'] = ['msg' => $msg, 'type' => $type];
    header("Location: $url");
    exit;
}

function flash(): void {
    if (!isset($_SESSION['flash'])) return;
    $f = $_SESSION['flash']; unset($_SESSION['flash']);
    echo '<div class="alert alert-' . e($f['type']) . ' alert-dismissible fade show py-2 small" role="alert">'
       . $f['msg']
       . '<button type="button" class="btn-close" data-bs-dismiss="alert"></button></div>';
}