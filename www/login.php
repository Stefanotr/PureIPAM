<?php
if (session_status() === PHP_SESSION_NONE) session_start();

if (isset($_SESSION['user_id'])) { header("Location: index.php"); exit; }

if (!function_exists('db')) {
    function db(): PDO {
        static $db = null;
        if ($db === null) {
            $db = new PDO('sqlite:/var/www/html/ipam.db');
            $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        }
        return $db;
    }
}
if (!function_exists('e')) {
    function e(string $v): string { return htmlspecialchars($v, ENT_QUOTES, 'UTF-8'); }
}
require_once __DIR__ . '/config.php';

// ─── RATE LIMITING INLINE pour login.php ─────────────────────────────────────
define('_LOGIN_MAX',     5);
define('_LOGIN_LOCKOUT', 15);

function _ensureAttemptsTable(): void {
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
function _checkLock(string $user, string $ip): array {
    try {
        _ensureAttemptsTable();
        $stmt = db()->prepare("SELECT * FROM login_attempts WHERE ip=? AND username=?");
        $stmt->execute([$ip,$user]);
        $row = $stmt->fetch();
        if ($row && $row['locked_until']) {
            $rem = strtotime($row['locked_until']) - time();
            if ($rem > 0) return ['locked'=>true,'min'=>(int)ceil($rem/60)];
        }
        return ['locked'=>false];
    } catch (Exception $e) { return ['locked'=>false]; }
}
function _recordFail(string $user, string $ip): void {
    try {
        _ensureAttemptsTable();
        $stmt = db()->prepare("SELECT attempts FROM login_attempts WHERE ip=? AND username=?");
        $stmt->execute([$ip,$user]);
        $row = $stmt->fetch();
        if ($row) {
            $n = $row['attempts'] + 1;
            $lock = $n >= _LOGIN_MAX ? date('Y-m-d H:i:s', time() + _LOGIN_LOCKOUT*60) : null;
            db()->prepare("UPDATE login_attempts SET attempts=?,locked_until=?,last_attempt=CURRENT_TIMESTAMP WHERE ip=? AND username=?")
               ->execute([$n,$lock,$ip,$user]);
        } else {
            db()->prepare("INSERT INTO login_attempts (ip,username,attempts) VALUES (?,?,1)")->execute([$ip,$user]);
        }
    } catch (Exception $e) {}
}
function _resetFail(string $user, string $ip): void {
    try { db()->prepare("DELETE FROM login_attempts WHERE ip=? AND username=?")->execute([$ip,$user]); }
    catch (Exception $e) {}
}
function _audit(string $action, string $target='', string $detail=''): void {
    try {
        db()->exec("CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER,
            username TEXT NOT NULL DEFAULT 'system', action TEXT NOT NULL,
            target TEXT NOT NULL DEFAULT '', detail TEXT NOT NULL DEFAULT '',
            ip_address TEXT NOT NULL DEFAULT '', created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )");
        db()->prepare("INSERT INTO audit_log (username,action,target,detail,ip_address) VALUES (?,?,?,?,?)")
           ->execute([$target,$action,$target,$detail,$_SERVER['REMOTE_ADDR']??'']);
    } catch (Exception $e) {}
}

$error   = '';
$timeout = isset($_GET['timeout']);
$clientIp = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['user'] ?? '');
    $password = $_POST['pw'] ?? '';

    // Vérifier le verrouillage rate-limiting
    $lock = _checkLock($username, $clientIp);
    if ($lock['locked']) {
        $error = "Compte temporairement bloqué. Réessayez dans {$lock['min']} minute(s).";
    } else {
        try {
            $stmt = db()->prepare("SELECT * FROM users WHERE username = ?");
            $stmt->execute([$username]);
            $user = $stmt->fetch();

            // Vérifier blocage manuel sysadmin (colonne users.locked) — priorité sur tout
            if ($user && !empty($user['locked'])) {
                $error = "🔒 Ce compte est verrouillé. Contactez votre administrateur.";
                _audit('user.login.blocked', $username, 'Tentative sur compte verrouillé manuellement');
                goto end_login; // sortir sans enregistrer un échec de mdp
            }

            $valid = false;
            if ($user && password_verify($password, $user['password'])) {
                $valid = true;
            } elseif ($user && !str_starts_with($user['password'], '$') && $user['password'] === $password) {
                db()->prepare("UPDATE users SET password=? WHERE id=?")->execute([password_hash($password, PASSWORD_DEFAULT), $user['id']]);
                $valid = true;
            }

            if ($valid) {
                _resetFail($username, $clientIp);
                _audit('user.login', $username, 'Login réussi');
                session_regenerate_id(true);
                $_SESSION['2fa_pending_user_id'] = $user['id'];
                $_SESSION['last_activity'] = time();

                if (!empty($user['google_2fa_secret'])) {
                    header("Location: login_otp.php"); exit;
                } else {
                    $_SESSION['user_id'] = $user['id'];
                    $_SESSION['user']                = $user['username'];
                    $_SESSION['role']                = $user['role'];
                    $_SESSION['must_change_password'] = (int)($user['must_change_password'] ?? 0);
                    $_SESSION['password_expires_at']  = $user['password_expires_at'] ?? null;
                    unset($_SESSION['2fa_pending_user_id']);
                    header("Location: index.php"); exit;
                }
            } else {
                _recordFail($username, $clientIp);
                // Vérifier si on vient de se faire bloquer
                $lock2 = _checkLock($username, $clientIp);
                if ($lock2['locked']) {
                    $error = "Trop de tentatives. Compte bloqué pour {$lock2['min']} minute(s).";
                    _audit('user.login.locked', $username, "Blocage après "._LOGIN_MAX." tentatives");
                } else {
                    $error = t('login.error');
                    _audit('user.login.fail', $username, 'Échec login');
                }
            }
        } catch (Exception $ex) {
            $error = t('err.db');
        }
        end_login:;
    }
}

$theme  = getTheme();
$accent = $theme['--ipam-accent'] ?? '#0d6efd';
$navBg  = $theme['--ipam-navbar-bg'] ?? '#1a1a2e';
?>
<!DOCTYPE html>
<html lang="<?= e(siteLang()) ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css">
    <?php renderThemeCSS(); ?>
    <title><?= e(siteName()) ?> — <?= te('login.title') ?></title>
    <style>
        body {
            background: linear-gradient(135deg, <?= $navBg ?> 0%, color-mix(in srgb, <?= $navBg ?> 70%, <?= $accent ?>) 100%);
            min-height: 100vh;
        }
        .login-card { border-radius: 16px; border: 1px solid rgba(255,255,255,.08); background: rgba(255,255,255,.97); }
    </style>
</head>
<body class="d-flex align-items-center justify-content-center p-3">
<div class="login-card shadow-lg p-5" style="width:100%;max-width:420px">

    <div class="text-center mb-4">
        <div class="mb-2">
            <i class="bi bi-<?= e(siteIcon()) ?>" style="font-size:2.5rem;color:<?= $accent ?>"></i>
        </div>
        <h3 class="fw-bold mb-0"><?= e(siteName()) ?></h3>
        <p class="text-muted small mt-1"><?= te('login.subtitle') ?></p>
    </div>

    <?php if ($timeout): ?>
        <div class="alert alert-warning py-2 small text-center">
            <i class="bi bi-clock me-1"></i>Session expirée. Veuillez vous reconnecter.
        </div>
    <?php endif; ?>

    <?php if ($error): ?>
        <div class="alert alert-danger py-2 small text-center">
            <i class="bi bi-exclamation-circle me-1"></i><?= e($error) ?>
        </div>
    <?php endif; ?>

    <form method="POST" autocomplete="off">
        <?php csrfField(); ?>
        <div class="mb-3">
            <label class="form-label small fw-semibold"><?= te('login.user') ?></label>
            <div class="input-group">
                <span class="input-group-text"><i class="bi bi-person"></i></span>
                <input type="text" name="user" class="form-control" value="<?= e($_POST['user']??'') ?>" autofocus required>
            </div>
        </div>
        <div class="mb-4">
            <label class="form-label small fw-semibold"><?= te('login.password') ?></label>
            <div class="input-group">
                <span class="input-group-text"><i class="bi bi-lock"></i></span>
                <input type="password" name="pw" class="form-control" required>
            </div>
        </div>
        <button type="submit" class="btn w-100 py-2 fw-semibold text-white"
                style="background:<?= $accent ?>;border-color:<?= $accent ?>">
            <i class="bi bi-box-arrow-in-right me-1"></i><?= te('login.submit') ?>
        </button>
    </form>

</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
