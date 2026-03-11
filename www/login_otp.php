<?php
if (session_status() === PHP_SESSION_NONE) session_start();
require_once 'auth.php';

if (file_exists(__DIR__ . '/vendor/autoload.php')) {
    require_once __DIR__ . '/vendor/autoload.php';
} else {
    die("Erreur critique : dossier 'vendor' absent. Lancez : composer install");
}

use OTPHP\TOTP;

if (!isset($_SESSION['2fa_pending_user_id'])) {
    header("Location: login.php"); exit;
}

require_once __DIR__ . '/config.php';

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrfVerify('login.php');
    try {
        $stmt = db()->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->execute([$_SESSION['2fa_pending_user_id']]);
        $user = $stmt->fetch();

        if ($user && !empty($user['google_2fa_secret'])) {
            $totp = TOTP::createFromSecret($user['google_2fa_secret']);
            $totp->setLabel($user['username']);
            $otpCode = str_replace(' ', '', $_POST['otp'] ?? '');

            if ($totp->verify($otpCode, null, 1)) { // window=1 = ±30s de tolérance
                audit('user.2fa.success', $user['username'], 'OTP vérifié');
                session_regenerate_id(true);
                $_SESSION['user_id']              = $user['id'];
                $_SESSION['user']                 = $user['username'];
                $_SESSION['role']                 = $user['role'];
                $_SESSION['must_change_password'] = (int)($user['must_change_password'] ?? 0);
                $_SESSION['password_expires_at']  = $user['password_expires_at'] ?? null;
                $_SESSION['last_activity']        = time();
                unset($_SESSION['2fa_pending_user_id']);
                header("Location: index.php"); exit;
            } else {
                audit('user.2fa.fail', $user['username'], 'Code OTP invalide');
                $error = t('otp.error_invalid');
            }
        } else {
            $error = "Configuration 2FA introuvable.";
        }
    } catch (Exception $e) {
        $error = t('err.db');
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
    <title><?= e(siteName()) ?> — Double Authentification</title>
    <style>
        body {
            background: linear-gradient(135deg, <?= $navBg ?> 0%, color-mix(in srgb, <?= $navBg ?> 70%, <?= $accent ?>) 100%);
            min-height: 100vh;
        }
        .login-card { border-radius: 16px; border: 1px solid rgba(255,255,255,.08); background: rgba(255,255,255,.97); }
        .otp-input { letter-spacing: 0.5rem; font-size: 1.8rem; font-weight: bold; color: <?= $accent ?>; }
    </style>
</head>
<body class="d-flex align-items-center justify-content-center p-3">
<div class="login-card shadow-lg p-5" style="width:100%;max-width:400px">
    <div class="text-center mb-4">
        <div class="mb-2">
            <i class="bi bi-shield-lock-fill" style="font-size:2.5rem;color:<?= $accent ?>"></i>
        </div>
        <h3 class="fw-bold mb-0"><?= e(siteName()) ?></h3>
        <p class="text-muted small mt-1"><?= te('otp.subtitle') ?></p>
    </div>

    <?php if ($error): ?>
        <div class="alert alert-danger py-2 small text-center">
            <i class="bi bi-exclamation-circle me-1"></i><?= e($error) ?>
        </div>
    <?php endif; ?>

    <form method="POST" autocomplete="off">
        <?php csrfField(); ?>
        <div class="mb-4">
            <label class="form-label fw-semibold small d-block text-center"><?= te('otp.enter_code') ?></label>
            <input type="text" name="otp"
                   class="form-control text-center otp-input"
                   placeholder="000000" maxlength="6" pattern="\d{6}"
                   inputmode="numeric" autofocus required>
        </div>
        <button type="submit" class="btn w-100 py-2 fw-semibold text-white"
                style="background:<?= $accent ?>;border-color:<?= $accent ?>">
            <i class="bi bi-unlock me-1"></i><?= te('otp.verify') ?>
        </button>
    </form>

    <div class="text-center mt-4">
        <a href="logout.php" class="text-decoration-none small text-muted">
            <i class="bi bi-arrow-left me-1"></i><?= te('otp.cancel') ?>
        </a>
    </div>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
