<?php
/**
 * IPAM Light — Script de secours : promotion sysadmin
 * À SUPPRIMER IMMÉDIATEMENT après utilisation.
 *
 * Ce script n'a PAS besoin de session.
 * Il suffit de le déposer dans www/ et de l'ouvrir dans le navigateur.
 */

// ─── JETON DE SÉCURITÉ ────────────────────────────────────────────────────────
// Changez cette valeur avant de déposer le fichier, ou laissez celle-ci et
// notez-la. Le script refuse tout accès sans ce jeton dans l'URL.
define('RESCUE_TOKEN', 'rescue-' . substr(sha1('ipam-rescue-v160-voyager3'), 0, 12));

$token = $_GET['token'] ?? '';
if ($token !== RESCUE_TOKEN) {
    http_response_code(403);
    echo '<!DOCTYPE html><html><head><meta charset="UTF-8">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    </head><body class="bg-dark d-flex align-items-center justify-content-center" style="min-height:100vh">
    <div class="card text-center p-5 shadow border-0" style="max-width:420px">
        <div class="display-1 mb-3">🔐</div>
        <h4 class="fw-bold text-danger">Accès refusé</h4>
        <p class="text-muted small">Jeton manquant ou incorrect.</p>
        <p class="small"><code>?token=VOTRE_JETON</code></p>
        <hr>
        <p class="small text-muted">Jeton attendu (visible dans le code source) :<br>
        <code>' . RESCUE_TOKEN . '</code></p>
    </div></body></html>';
    exit;
}

// ─── CONNEXION DB ─────────────────────────────────────────────────────────────
try {
    $db = new PDO('sqlite:/var/www/html/ipam.db');
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
} catch (Exception $e) {
    die('<div style="color:red;padding:2rem">Erreur DB : ' . htmlspecialchars($e->getMessage()) . '</div>');
}

$message = '';
$success = false;

// ─── ACTION : PROMOUVOIR ──────────────────────────────────────────────────────
if (isset($_POST['promote']) && isset($_POST['user_id'])) {
    $uid = (int)$_POST['user_id'];
    $stmt = $db->prepare("SELECT username, role FROM users WHERE id=?");
    $stmt->execute([$uid]);
    $user = $stmt->fetch();

    if ($user) {
        // Vérifier si déjà sysadmin
        if ($user['role'] === 'sysadmin') {
            $message = "ℹ️ <strong>{$user['username']}</strong> est déjà Sysadmin.";
        } else {
            $db->prepare("UPDATE users SET role='sysadmin' WHERE id=?")->execute([$uid]);
            $message = "✅ <strong>{$user['username']}</strong> a été promu <strong>Sysadmin</strong> avec succès !<br>
                        <span class='small'>Vous pouvez maintenant vous connecter et accéder à db_init.php.</span>";
            $success = true;
        }
    } else {
        $message = "❌ Utilisateur introuvable.";
    }
}

// ─── LISTE DES UTILISATEURS ───────────────────────────────────────────────────
try {
    $users = $db->query("SELECT id, username, role FROM users ORDER BY id ASC")->fetchAll();
} catch (Exception $e) {
    $users = [];
    $message = "❌ Impossible de lire la table users : " . htmlspecialchars($e->getMessage());
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css">
    <title>IPAM — Secours Sysadmin</title>
    <style>
        body { background: linear-gradient(135deg,#1a1a2e,#16213e); min-height:100vh; }
        .rescue-card { border-radius:16px; border:2px solid #dc3545; max-width:520px; }
    </style>
</head>
<body class="d-flex align-items-center justify-content-center p-3">
<div class="rescue-card card shadow-lg p-0 overflow-hidden w-100">

    <div class="card-header bg-danger text-white py-3 px-4">
        <div class="d-flex align-items-center gap-2">
            <i class="bi bi-shield-exclamation fs-4"></i>
            <div>
                <div class="fw-bold">Script de secours — Promotion Sysadmin</div>
                <div style="font-size:.75rem;opacity:.85">⚠️ Supprimez ce fichier immédiatement après utilisation</div>
            </div>
        </div>
    </div>

    <div class="card-body p-4">

        <?php if ($message): ?>
            <div class="alert <?= $success ? 'alert-success' : 'alert-info' ?> py-2 mb-3">
                <?= $message ?>
            </div>
        <?php endif; ?>

        <?php if ($success): ?>
            <div class="d-flex gap-2">
                <a href="login.php" class="btn btn-primary"><i class="bi bi-box-arrow-in-right me-1"></i>Se connecter</a>
                <a href="db_init.php?via=rescue" class="btn btn-outline-secondary btn-sm">Lancer db_init</a>
            </div>
        <?php else: ?>
            <p class="text-muted small mb-3">
                Sélectionnez l'utilisateur à promouvoir en <strong>Sysadmin</strong>.
                Cette action ne supprime ni ne réinitialise aucun mot de passe.
            </p>

            <?php if (empty($users)): ?>
                <div class="alert alert-warning">Aucun utilisateur trouvé dans la base de données.</div>
            <?php else: ?>
                <div class="list-group mb-3">
                    <?php foreach ($users as $u): ?>
                    <form method="POST" class="list-group-item list-group-item-action d-flex align-items-center justify-content-between gap-3 py-2">
                        <input type="hidden" name="user_id" value="<?= $u['id'] ?>">
                        <input type="hidden" name="token"   value="<?= htmlspecialchars(RESCUE_TOKEN) ?>">
                        <div>
                            <strong><?= htmlspecialchars($u['username']) ?></strong>
                            <span class="badge ms-2
                                <?= $u['role']==='sysadmin' ? 'bg-purple' :
                                   ($u['role']==='admin'    ? 'bg-danger'  : 'bg-secondary') ?>"
                                style="<?= $u['role']==='sysadmin'?'background:linear-gradient(135deg,#6f42c1,#0d6efd)':'' ?> font-size:.65rem">
                                <?= strtoupper(htmlspecialchars($u['role'])) ?>
                            </span>
                            <span class="text-muted small ms-2">#<?= $u['id'] ?></span>
                        </div>
                        <?php if ($u['role'] !== 'sysadmin'): ?>
                            <button type="submit" name="promote" class="btn btn-danger btn-sm flex-shrink-0">
                                <i class="bi bi-arrow-up-circle me-1"></i>Promouvoir Sysadmin
                            </button>
                        <?php else: ?>
                            <span class="badge bg-success">Déjà Sysadmin ✓</span>
                        <?php endif; ?>
                    </form>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>

            <div class="alert alert-warning d-flex gap-2 py-2 small">
                <i class="bi bi-exclamation-triangle-fill flex-shrink-0 mt-1"></i>
                <span>Supprimez <code>promote_sysadmin.php</code> de votre serveur dès que vous avez terminé.</span>
            </div>
        <?php endif; ?>

        <div class="mt-3 pt-3 border-top text-muted" style="font-size:.7rem">
            <i class="bi bi-info-circle me-1"></i>
            Jeton actif : <code><?= RESCUE_TOKEN ?></code>
            &nbsp;·&nbsp; URL : <code>?token=<?= RESCUE_TOKEN ?></code>
        </div>
    </div>
</div>
</body>
</html>
