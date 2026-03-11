<?php
/**
 * Changement de mot de passe personnel — v1.7.0
 * Accessible à tous les rôles. Forcé si must_change_password=1 ou mdp expiré.
 */
include('auth.php');
if (!function_exists('siteAccent')) require_once __DIR__ . '/config.php';
if (file_exists(__DIR__ . '/vendor/autoload.php')) require_once __DIR__ . '/vendor/autoload.php';

$db      = db();
$errors  = [];
$ok      = false;
$forced  = !empty($_SESSION['must_change_password'])
         || (!empty($_SESSION['password_expires_at']) && strtotime($_SESSION['password_expires_at']) < time());
$policy  = getPwPolicy();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrfVerify();
    $current = $_POST['current_pw'] ?? '';
    $new1    = $_POST['new_pw']     ?? '';
    $new2    = $_POST['new_pw2']    ?? '';

    // Vérifier mot de passe actuel
    $stmt = $db->prepare("SELECT password FROM users WHERE id=?");
    $stmt->execute([$_SESSION['user_id']]);
    $row = $stmt->fetch();

    if (!$row || !password_verify($current, $row['password'])) {
        $errors[] = "Mot de passe actuel incorrect.";
    } elseif ($new1 !== $new2) {
        $errors[] = "Les deux nouveaux mots de passe ne correspondent pas.";
    } else {
        // Valider avec la politique (l'utilisateur doit respecter la politique)
        $pwErrors = validatePassword($new1, false);
        $errors   = array_merge($errors, $pwErrors);
    }

    if (empty($errors)) {
        $hash    = password_hash($new1, PASSWORD_BCRYPT);
        // Calculer la prochaine expiration
        $expires = null;
        if ($policy['expiry'] > 0) {
            $expires = date('Y-m-d H:i:s', strtotime("+{$policy['expiry']} days"));
        }
        $db->prepare("UPDATE users SET password=?, must_change_password=0, password_expires_at=? WHERE id=?")
           ->execute([$hash, $expires, $_SESSION['user_id']]);
        // Mettre à jour la session
        $_SESSION['must_change_password'] = 0;
        $_SESSION['password_expires_at']  = $expires;
        audit('user.password_changed', $_SESSION['user'] ?? '', 'Mot de passe modifié');
        redirect('index.php', '✅ Mot de passe mis à jour avec succès.', 'success');
    }
}

$accent  = siteAccent();
$theme   = siteTheme();
$lang    = siteLang();
if (file_exists(__DIR__ . '/lang/' . $lang . '.php')) require_once __DIR__ . '/lang/' . $lang . '.php';
?>
<!DOCTYPE html>
<html lang="<?= $lang ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Mot de passe — <?= e(siteName()) ?></title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css">
    <style>
        :root { --ipam-accent: <?= $accent ?>; }
        body { background: #f0f2f5; }
        .card { border-radius: 16px; }
        .strength-bar div { height: 6px; border-radius: 3px; transition: width .3s, background .3s; }
    </style>
</head>
<body>
<div class="container" style="max-width:480px;margin-top:80px">

<?php if ($forced): ?>
    <div class="alert alert-warning d-flex align-items-center gap-2 mb-4">
        <i class="bi bi-exclamation-triangle-fill fs-5"></i>
        <div>Vous devez définir un nouveau mot de passe avant de continuer.</div>
    </div>
<?php endif; ?>

    <div class="card shadow-sm">
        <div class="card-body p-4">
            <h5 class="fw-bold mb-1"><i class="bi bi-key-fill me-2" style="color:var(--ipam-accent)"></i>Changer mon mot de passe</h5>
            <p class="text-muted small mb-4">Politique : <?= $policy['min'] ?>–<?= $policy['max'] ?> caractères
                <?php if ($policy['complexity'] >= 1): ?>, majuscule + minuscule<?php endif; ?>
                <?php if ($policy['complexity'] >= 2): ?>, chiffre<?php endif; ?>
                <?php if ($policy['complexity'] >= 3): ?>, caractère spécial<?php endif; ?>
                <?php if ($policy['expiry'] > 0): ?>, expire tous les <?= $policy['expiry'] ?> jours<?php endif; ?>
            </p>

            <?php if (!empty($errors)): ?>
                <div class="alert alert-danger py-2 small">
                    <?php foreach ($errors as $err): ?><div><i class="bi bi-x-circle me-1"></i><?= e($err) ?></div><?php endforeach; ?>
                </div>
            <?php endif; ?>

            <form method="POST">
                <?= csrfField() ?>
                <div class="mb-3">
                    <label class="form-label small fw-semibold">Mot de passe actuel</label>
                    <input type="password" name="current_pw" class="form-control" required autofocus>
                </div>
                <div class="mb-3">
                    <label class="form-label small fw-semibold">Nouveau mot de passe</label>
                    <input type="password" name="new_pw" id="newPw" class="form-control"
                           minlength="<?= $policy['min'] ?>" maxlength="64" required
                           oninput="updateStrength(this.value)">
                    <!-- Barre de force -->
                    <div class="strength-bar mt-2 d-flex gap-1">
                        <div id="s1" style="width:25%;background:#dee2e6"></div>
                        <div id="s2" style="width:25%;background:#dee2e6"></div>
                        <div id="s3" style="width:25%;background:#dee2e6"></div>
                        <div id="s4" style="width:25%;background:#dee2e6"></div>
                    </div>
                    <small id="strengthLabel" class="text-muted"></small>
                </div>
                <div class="mb-4">
                    <label class="form-label small fw-semibold">Confirmer le nouveau mot de passe</label>
                    <input type="password" name="new_pw2" id="newPw2" class="form-control"
                           maxlength="64" required oninput="checkMatch()">
                    <small id="matchLabel" class="text-muted"></small>
                </div>
                <div class="d-flex gap-2">
                    <button type="submit" class="btn flex-fill fw-semibold text-white"
                            style="background:var(--ipam-accent)">
                        <i class="bi bi-check-lg me-1"></i>Mettre à jour
                    </button>
                    <?php if (!$forced): ?>
                        <a href="index.php" class="btn btn-outline-secondary">Annuler</a>
                    <?php endif; ?>
                </div>
            </form>
        </div>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script>
const MIN = <?= $policy['min'] ?>, MAX = 64;
const COMPLEXITY = <?= $policy['complexity'] ?>;

function scorePassword(pw) {
    let score = 0;
    if (pw.length >= MIN) score++;
    if (pw.length >= Math.round((MIN + MAX) / 2)) score++;
    if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) score++;
    if (/[0-9]/.test(pw)) score++;
    if (/[^A-Za-z0-9]/.test(pw)) score++;
    return Math.min(4, score);
}

function updateStrength(pw) {
    const score  = scorePassword(pw);
    const colors = ['#dee2e6', '#dc3545', '#fd7e14', '#ffc107', '#198754'];
    const labels = ['', 'Très faible', 'Faible', 'Moyen', 'Fort'];
    for (let i = 1; i <= 4; i++) {
        document.getElementById('s' + i).style.background = i <= score ? colors[score] : '#dee2e6';
    }
    document.getElementById('strengthLabel').textContent = labels[score] || '';
    checkMatch();
}

function checkMatch() {
    const a = document.getElementById('newPw').value;
    const b = document.getElementById('newPw2').value;
    const el = document.getElementById('matchLabel');
    if (!b) { el.textContent = ''; return; }
    el.textContent = a === b ? '✓ Identiques' : '✗ Ne correspondent pas';
    el.style.color  = a === b ? '#198754' : '#dc3545';
}
</script>
</body>
</html>
