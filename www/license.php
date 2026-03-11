<?php
if (session_status() === PHP_SESSION_NONE) session_start();

// Note : license.php est accessible sans être connecté (activation initiale)

// Charger config + auth (db helper)
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/config.php';

// Si licence déjà active → dashboard
$existing = getLicense();
if ($existing) {
    header("Location: index.php");
    exit;
}

$error   = '';
$success = '';

// ─── ACTIVATION ──────────────────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['activate'])) {
    $key   = strtoupper(trim($_POST['license_key'] ?? ''));
    $owner = trim($_POST['owner'] ?? '');

    if (empty($owner)) {
        $error = "Le nom du titulaire est requis.";
    } elseif (!validateLicenseKey($key)) {
        $error = "Clé de licence invalide. Vérifiez le format : XXXX-XXXX-XXXX-XXXX.";
    } else {
        try {
            $db = db();
            $db->exec("CREATE TABLE IF NOT EXISTS license (
                id           INTEGER PRIMARY KEY CHECK (id = 1),
                key          TEXT NOT NULL,
                owner        TEXT NOT NULL DEFAULT '',
                activated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )");
            $db->prepare("INSERT OR REPLACE INTO license (id, key, owner, activated_at) VALUES (1, ?, ?, CURRENT_TIMESTAMP)")
               ->execute([$key, $owner]);

            $_SESSION['flash'] = ['msg' => "✅ Licence activée avec succès pour <strong>" . htmlspecialchars($owner) . "</strong>.", 'type' => 'success'];
            header("Location: index.php");
            exit;
        } catch (Exception $e) {
            $error = "Erreur lors de l'activation.";
        }
    }
}

// ─── DÉMO : génération d'une clé de test (visible seulement sur cette page) ──
$demoKey = generateLicenseKey();
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css">
    <title>IPAM Light — Activation de la licence</title>
    <style>
        body {
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            min-height: 100vh;
        }
        .lic-card {
            border-radius: 16px;
            border: 1px solid rgba(255,255,255,.08);
            background: rgba(255,255,255,.97);
            max-width: 520px;
            width: 100%;
        }
        .key-input {
            font-family: 'Courier New', monospace;
            letter-spacing: 2px;
            text-transform: uppercase;
            font-size: 1rem;
            text-align: center;
        }
        .key-input::placeholder { text-transform: none; letter-spacing: normal; font-size: .875rem; }
        .step-badge {
            width: 28px; height: 28px;
            border-radius: 50%;
            background: #0d6efd;
            color: #fff;
            font-size: .75rem;
            font-weight: 700;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
        }
        .demo-key {
            background: #f8f9fa;
            border: 1px dashed #adb5bd;
            border-radius: 8px;
            font-family: monospace;
            letter-spacing: 2px;
            cursor: pointer;
            transition: background .15s;
        }
        .demo-key:hover { background: #e9f0ff; border-color: #0d6efd; }
    </style>
</head>
<body class="d-flex align-items-center justify-content-center p-3">
<div class="lic-card shadow-lg p-0 overflow-hidden">

    <!-- EN-TÊTE -->
    <div class="bg-dark text-white text-center py-4 px-4">
        <i class="bi bi-shield-lock-fill text-warning" style="font-size:2.5rem"></i>
        <h4 class="fw-bold mt-2 mb-0">Activation du logiciel</h4>
        <p class="text-secondary small mb-0 mt-1">IPAM Light v<?= APP_VERSION ?> — Une licence est requise pour continuer</p>
    </div>

    <div class="p-4">

        <?php if ($error): ?>
            <div class="alert alert-danger py-2 small d-flex align-items-center gap-2">
                <i class="bi bi-x-circle-fill flex-shrink-0"></i>
                <?= htmlspecialchars($error) ?>
            </div>
        <?php endif; ?>

        <!-- FORMULAIRE D'ACTIVATION -->
        <form method="POST" id="licForm">
            <div class="mb-3">
                <label class="form-label fw-semibold small">
                    <span class="step-badge me-2">1</span>Titulaire de la licence
                </label>
                <input type="text" name="owner" class="form-control" required
                       placeholder="Nom de la société ou de l'utilisateur"
                       value="<?= htmlspecialchars($_POST['owner'] ?? '') ?>">
            </div>

            <div class="mb-4">
                <label class="form-label fw-semibold small">
                    <span class="step-badge me-2">2</span>Clé de licence
                </label>
                <input type="text" name="license_key" id="licenseKey" class="form-control key-input"
                       placeholder="XXXX-XXXX-XXXX-XXXX" maxlength="19" required
                       value="<?= htmlspecialchars($_POST['license_key'] ?? '') ?>"
                       oninput="formatKey(this)">
                <div class="form-text small">Format : 4 blocs de 4 caractères séparés par des tirets.</div>
            </div>

            <button type="submit" name="activate" class="btn btn-primary w-100 py-2 fw-semibold">
                <i class="bi bi-patch-check-fill me-2"></i>Activer la licence
            </button>
        </form>

        <!-- SÉPARATEUR -->
        <hr class="my-4">

        <!-- CLÉ DE DÉMONSTRATION -->
        <div class="mb-0">
            <p class="small text-muted mb-2">
                <i class="bi bi-info-circle me-1"></i>
                <strong>Clé de test</strong> — générée automatiquement, cliquez pour l'utiliser :
            </p>
            <div class="demo-key text-center py-2 px-3 fw-bold fs-5 text-primary"
                 id="demoKey" onclick="useDemo()" title="Cliquer pour remplir automatiquement">
                <?= $demoKey ?>
            </div>
            <div class="text-center mt-1" style="font-size:.7rem; color:#aaa">
                ↑ Cliquez sur la clé pour la copier dans le formulaire
            </div>
        </div>

    </div>

    <!-- FOOTER -->
    <div class="bg-light border-top text-center py-2 px-3 d-flex justify-content-between align-items-center">
        <span class="text-muted small">
            <i class="bi bi-person-circle me-1"></i>Connecté en tant que <strong><?= htmlspecialchars($_SESSION['user']) ?></strong>
        </span>
        <a href="logout.php" class="btn btn-link btn-sm text-danger p-0">
            <i class="bi bi-box-arrow-right me-1"></i>Déconnexion
        </a>
    </div>
</div>

<script>
function formatKey(input) {
    let val = input.value.replace(/[^A-Za-z0-9]/g, '').toUpperCase();
    let formatted = '';
    for (let i = 0; i < val.length && i < 16; i++) {
        if (i > 0 && i % 4 === 0) formatted += '-';
        formatted += val[i];
    }
    input.value = formatted;
}

function useDemo() {
    const key = document.getElementById('demoKey').textContent.trim();
    document.getElementById('licenseKey').value = key;
    document.getElementById('licenseKey').focus();
}
</script>
</body>
</html>
