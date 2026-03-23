<?php
/**
 * IPAM Light — Assistant de premier lancement
 * S'affiche automatiquement si la DB n'existe pas.
 * Après le setup, cette page devient inaccessible.
 */

if (session_status() === PHP_SESSION_NONE) session_start();

define('DB_PATH', '/var/www/html/ipam.db');
define('SETUP_DONE', file_exists(DB_PATH) && _dbHasUsers());

function _dbHasUsers(): bool {
    try {
        $db = new PDO('sqlite:' . DB_PATH);
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        return (int)$db->query("SELECT COUNT(*) FROM users")->fetchColumn() > 0;
    } catch (Throwable $e) { return false; }
}

// Si setup déjà fait → login
if (SETUP_DONE) {
    header('Location: login.php');
    exit;
}

// Si un utilisateur connecté arrive ici → index
if (isset($_SESSION['user_id'])) {
    header('Location: index.php');
    exit;
}

$errors  = [];
$success = false;
$step    = 1; // 1 = formulaire, 2 = résultat

// ─── TRAITEMENT ───────────────────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['do_setup'])) {

    $siteName  = trim($_POST['site_name']  ?? 'PureIPAM');
    $adminUser = trim($_POST['admin_user'] ?? '');
    $adminPw   = $_POST['admin_pw']   ?? '';
    $adminPw2  = $_POST['admin_pw2']  ?? '';
    $lang      = in_array($_POST['lang'] ?? '', ['fr','en']) ? $_POST['lang'] : 'fr';

    // Validations
    if (strlen($siteName) < 2)   $errors[] = 'Le nom du site doit faire au moins 2 caractères.';
    if (strlen($adminUser) < 3)  $errors[] = 'Le nom d\'utilisateur doit faire au moins 3 caractères.';
    if (strlen($adminPw) < 6)    $errors[] = 'Le mot de passe doit faire au moins 6 caractères.';
    if ($adminPw !== $adminPw2)  $errors[] = 'Les deux mots de passe ne correspondent pas.';
    if (preg_match('/[^a-zA-Z0-9._\-]/', $adminUser)) $errors[] = 'Nom d\'utilisateur : lettres, chiffres, . _ - uniquement.';

    if (empty($errors)) {
        try {
            // Créer / ouvrir la DB
            $db = new PDO('sqlite:' . DB_PATH);
            $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $db->exec("PRAGMA foreign_keys = ON;");
            $db->exec("PRAGMA journal_mode = WAL;");

            // ── Tables ──────────────────────────────────────────────────────
            $db->exec("CREATE TABLE IF NOT EXISTS users (
                id                   INTEGER PRIMARY KEY AUTOINCREMENT,
                username             TEXT    UNIQUE NOT NULL,
                password             TEXT    NOT NULL,
                role                 TEXT    NOT NULL DEFAULT 'viewer',
                google_2fa_secret    TEXT    DEFAULT NULL,
                must_change_password INTEGER NOT NULL DEFAULT 0,
                password_expires_at  DATETIME DEFAULT NULL,
                locked               INTEGER NOT NULL DEFAULT 0,
                created_at           DATETIME DEFAULT CURRENT_TIMESTAMP
            )");

            $db->exec("CREATE TABLE IF NOT EXISTS vlans (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                vid         INTEGER UNIQUE NOT NULL,
                name        TEXT    NOT NULL,
                subnet      TEXT    NOT NULL,
                description TEXT    DEFAULT '',
                notes       TEXT    DEFAULT '',
                group_id    INTEGER DEFAULT NULL,
                updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP
            )");

            $db->exec("CREATE TABLE IF NOT EXISTS ips (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                vlan_id     INTEGER NOT NULL REFERENCES vlans(id) ON DELETE CASCADE,
                ip_address  TEXT    NOT NULL,
                hostname    TEXT    DEFAULT '',
                description TEXT    DEFAULT '',
                domain      TEXT    DEFAULT '',
                tag         TEXT    DEFAULT 'client',
                status      TEXT    NOT NULL DEFAULT 'used',
                UNIQUE(vlan_id, ip_address)
            )");

            $db->exec("CREATE TABLE IF NOT EXISTS tags (
                id    INTEGER PRIMARY KEY AUTOINCREMENT,
                name  TEXT UNIQUE NOT NULL,
                color TEXT NOT NULL DEFAULT 'secondary',
                icon  TEXT NOT NULL DEFAULT 'tag'
            )");

            $db->exec("CREATE TABLE IF NOT EXISTS license (
                id           INTEGER PRIMARY KEY CHECK (id = 1),
                key          TEXT NOT NULL,
                owner        TEXT NOT NULL DEFAULT '',
                activated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )");

            $db->exec("CREATE TABLE IF NOT EXISTS settings (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL DEFAULT ''
            )");

            $db->exec("CREATE TABLE IF NOT EXISTS audit_log (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER,
                username   TEXT NOT NULL DEFAULT 'system',
                action     TEXT NOT NULL,
                target     TEXT NOT NULL DEFAULT '',
                detail     TEXT NOT NULL DEFAULT '',
                ip_address TEXT NOT NULL DEFAULT '',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )");

            $db->exec("CREATE TABLE IF NOT EXISTS login_attempts (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                ip           TEXT NOT NULL,
                username     TEXT NOT NULL,
                attempts     INTEGER NOT NULL DEFAULT 0,
                locked_until DATETIME,
                last_attempt DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(ip, username)
            )");

            $db->exec("CREATE TABLE IF NOT EXISTS vlan_groups (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                name       TEXT UNIQUE NOT NULL,
                color      TEXT NOT NULL DEFAULT 'primary',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )");

            $db->exec("CREATE TABLE IF NOT EXISTS ip_history (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_id      INTEGER NOT NULL,
                ip_address TEXT NOT NULL,
                vlan_id    INTEGER NOT NULL,
                field      TEXT NOT NULL,
                old_value  TEXT NOT NULL DEFAULT '',
                new_value  TEXT NOT NULL DEFAULT '',
                changed_by TEXT NOT NULL DEFAULT 'system',
                changed_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )");

            // ── Tags par défaut ──────────────────────────────────────────────
            $defaultTags = [
                ['client',    'info',    'pc'],
                ['serveur',   'danger',  'server'],
                ['dns',       'warning', 'globe'],
                ['imprimante','secondary','printer'],
                ['camera',    'dark',    'camera-video'],
                ['switch',    'success', 'diagram-3-fill'],
            ];
            $tagIns = $db->prepare("INSERT OR IGNORE INTO tags (name,color,icon) VALUES (?,?,?)");
            foreach ($defaultTags as [$n,$c,$i]) $tagIns->execute([$n,$c,$i]);

            // ── Settings par défaut ──────────────────────────────────────────
            $defaults = [
                'site_name'            => $siteName,
                'site_icon'            => 'hdd-network-fill',
                'site_theme'           => 'default',
                'site_welcome'         => '',
                'site_lang'            => $lang,
                'pw_min_length'        => '8',
                'pw_max_length'        => '64',
                'pw_complexity'        => '0',
                'pw_expiry_days'       => '0',
                'audit_retention_days' => '0',
            ];
            $setIns = $db->prepare("INSERT OR IGNORE INTO settings (key,value) VALUES (?,?)");
            foreach ($defaults as $k => $v) $setIns->execute([$k,$v]);

            // ── Compte sysadmin ──────────────────────────────────────────────
            $hash = password_hash($adminPw, PASSWORD_BCRYPT);
            $db->prepare("INSERT INTO users (username,password,role) VALUES (?,?,'sysadmin')")
               ->execute([$adminUser, $hash]);

            // ── Audit de setup ───────────────────────────────────────────────
            $db->prepare("INSERT INTO audit_log (username,action,target,detail,ip_address) VALUES (?,?,?,?,?)")
               ->execute(['system', 'setup.complete', $adminUser, "Initialisation PureIPAM v1.8.0 — site: $siteName", $_SERVER['REMOTE_ADDR'] ?? '']);

            $success = true;
            $step = 2;

        } catch (Throwable $e) {
            $errors[] = 'Erreur lors de l\'initialisation : ' . $e->getMessage();
        }
    }
}

$accent = '#6366f1'; // violet setup, indépendant des thèmes
?>
<!DOCTYPE html>
<html lang="<?= !empty($_POST['lang']) ? htmlspecialchars($_POST['lang']) : 'fr' ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css">
    <title>PureIPAM — Installation</title>
    <style>
        :root { --accent: <?= $accent ?>; }
        body {
            min-height: 100vh;
            background: linear-gradient(135deg, #0f0c29 0%, #302b63 50%, #24243e 100%);
            display: flex; align-items: center; justify-content: center;
        }
        .setup-card {
            width: 100%; max-width: 560px;
            background: rgba(255,255,255,.97);
            border-radius: 20px;
            box-shadow: 0 24px 64px rgba(0,0,0,.4);
            overflow: hidden;
        }
        .setup-header {
            background: linear-gradient(135deg, #6366f1, #8b5cf6);
            padding: 2rem 2rem 1.5rem;
            color: #fff;
        }
        .setup-body { padding: 2rem; }
        .step-dot {
            width: 28px; height: 28px; border-radius: 50%;
            display: inline-flex; align-items: center; justify-content: center;
            font-size: .75rem; font-weight: 700;
        }
        .pw-strength { height: 4px; border-radius: 2px; transition: width .3s, background .3s; }
        .form-label { font-weight: 600; font-size: .85rem; }
        .btn-setup {
            background: linear-gradient(135deg, #6366f1, #8b5cf6);
            border: none; color: #fff; font-weight: 600;
            padding: .75rem; border-radius: 10px; width: 100%;
            font-size: 1rem; transition: opacity .2s;
        }
        .btn-setup:hover { opacity: .9; color: #fff; }
        .success-icon { font-size: 4rem; animation: pop .5s ease; }
        @keyframes pop { 0%{transform:scale(0)} 80%{transform:scale(1.1)} 100%{transform:scale(1)} }
        .progress-bar-setup { height: 3px; background: linear-gradient(90deg,#6366f1,#8b5cf6); }
    </style>
</head>
<body class="p-3">

<div class="setup-card">

    <!-- En-tête -->
    <div class="setup-header">
        <div class="d-flex align-items-center gap-3 mb-3">
            <i class="bi bi-hdd-network-fill" style="font-size:2.2rem;opacity:.9"></i>
            <div>
                <h4 class="fw-bold mb-0">PureIPAM</h4>
                <div style="opacity:.8;font-size:.85rem">Assistant d'installation</div>
            </div>
            <div class="ms-auto d-flex gap-2">
                <span class="step-dot <?= $step >= 1 ? 'bg-white text-primary' : 'bg-white bg-opacity-25 text-white' ?>">1</span>
                <span class="step-dot <?= $step >= 2 ? 'bg-white text-primary' : 'bg-white bg-opacity-25 text-white' ?>">2</span>
            </div>
        </div>
        <?php if ($step === 1): ?>
        <div style="font-size:.9rem;opacity:.85">
            <i class="bi bi-info-circle me-1"></i>
            Aucune base de données détectée. Configurez votre installation en 30 secondes.
        </div>
        <?php else: ?>
        <div style="font-size:.9rem;opacity:.85">
            <i class="bi bi-check-circle me-1"></i>
            Installation terminée avec succès !
        </div>
        <?php endif; ?>
    </div>
    <div class="progress-bar-setup" style="width:<?= $step === 1 ? '50%' : '100%' ?>"></div>

    <div class="setup-body">

    <?php if ($step === 1): ?>
    <!-- ── ÉTAPE 1 : Formulaire ─────────────────────────────────────────── -->

    <?php if (!empty($errors)): ?>
    <div class="alert alert-danger py-2 small mb-4">
        <?php foreach ($errors as $err): ?>
            <div><i class="bi bi-exclamation-circle me-1"></i><?= htmlspecialchars($err) ?></div>
        <?php endforeach; ?>
    </div>
    <?php endif; ?>

    <form method="POST" id="setupForm" autocomplete="off">
        <input type="hidden" name="do_setup" value="1">

        <!-- Nom du site -->
        <div class="mb-4">
            <label class="form-label">
                <i class="bi bi-type me-1 text-primary"></i>Nom de l'application
            </label>
            <input type="text" name="site_name" class="form-control form-control-lg"
                   value="<?= htmlspecialchars($_POST['site_name'] ?? 'PureIPAM') ?>"
                   placeholder="PureIPAM" maxlength="40" required>
            <div class="form-text">Affiché dans la barre de navigation et l'onglet du navigateur.</div>
        </div>

        <!-- Langue -->
        <div class="mb-4">
            <label class="form-label">
                <i class="bi bi-translate me-1 text-primary"></i>Langue de l'interface
            </label>
            <div class="d-flex gap-3">
                <div class="form-check">
                    <input class="form-check-input" type="radio" name="lang" id="langFr" value="fr"
                           <?= ($_POST['lang'] ?? 'fr') === 'fr' ? 'checked' : '' ?>>
                    <label class="form-check-label" for="langFr">🇫🇷 Français</label>
                </div>
                <div class="form-check">
                    <input class="form-check-input" type="radio" name="lang" id="langEn" value="en"
                           <?= ($_POST['lang'] ?? 'fr') === 'en' ? 'checked' : '' ?>>
                    <label class="form-check-label" for="langEn">🇬🇧 English</label>
                </div>
            </div>
        </div>

        <hr class="my-4">

        <div class="mb-2 text-muted small fw-semibold text-uppercase" style="letter-spacing:.05em">
            <i class="bi bi-person-fill-gear me-1"></i>Compte Sysadmin
        </div>

        <!-- Nom d'utilisateur -->
        <div class="mb-3">
            <label class="form-label">
                <i class="bi bi-person me-1 text-primary"></i>Nom d'utilisateur
            </label>
            <input type="text" name="admin_user" class="form-control"
                   value="<?= htmlspecialchars($_POST['admin_user'] ?? '') ?>"
                   placeholder="admin" minlength="3" maxlength="64" required
                   pattern="[a-zA-Z0-9._\-]+" autocomplete="off">
            <div class="form-text">Lettres, chiffres, . _ - uniquement.</div>
        </div>

        <!-- Mot de passe -->
        <div class="mb-3">
            <label class="form-label">
                <i class="bi bi-lock me-1 text-primary"></i>Mot de passe
            </label>
            <div class="input-group">
                <input type="password" name="admin_pw" id="pw1" class="form-control"
                       placeholder="Min 6 caractères" minlength="6" maxlength="64"
                       required oninput="checkPw(this.value)">
                <button type="button" class="btn btn-outline-secondary" onclick="togglePw('pw1',this)">
                    <i class="bi bi-eye"></i>
                </button>
            </div>
            <div class="mt-1">
                <div class="bg-light rounded" style="height:4px">
                    <div class="pw-strength" id="pwBar" style="width:0%"></div>
                </div>
                <div class="d-flex justify-content-between mt-1">
                    <small id="pwLabel" class="text-muted">Force du mot de passe</small>
                    <small id="pwHint" class="text-muted"></small>
                </div>
            </div>
        </div>

        <!-- Confirmer mot de passe -->
        <div class="mb-4">
            <label class="form-label">
                <i class="bi bi-lock-fill me-1 text-primary"></i>Confirmer le mot de passe
            </label>
            <div class="input-group">
                <input type="password" name="admin_pw2" id="pw2" class="form-control"
                       placeholder="Répétez le mot de passe" required oninput="checkMatch()">
                <button type="button" class="btn btn-outline-secondary" onclick="togglePw('pw2',this)">
                    <i class="bi bi-eye"></i>
                </button>
            </div>
            <small id="matchMsg" class="text-muted"></small>
        </div>

        <!-- Résumé -->
        <div class="alert alert-info py-2 small mb-4" id="summaryBox" style="display:none">
            <i class="bi bi-info-circle me-1"></i>
            Prêt à créer <strong id="summaryApp"></strong> avec le compte
            <strong id="summaryUser"></strong> (Sysadmin).
        </div>

        <button type="submit" class="btn-setup" id="submitBtn">
            <i class="bi bi-rocket-takeoff me-2"></i>Lancer l'installation
        </button>
    </form>

    <?php else: ?>
    <!-- ── ÉTAPE 2 : Succès ─────────────────────────────────────────────── -->
    <div class="text-center py-3">
        <div class="success-icon text-success mb-3">
            <i class="bi bi-check-circle-fill"></i>
        </div>
        <h5 class="fw-bold mb-2">Installation réussie !</h5>
        <p class="text-muted mb-4">
            Votre instance <strong><?= htmlspecialchars($_POST['site_name'] ?? 'PureIPAM') ?></strong>
            est prête.
        </p>

        <div class="card border-0 bg-light text-start mb-4">
            <div class="card-body py-3">
                <div class="d-flex align-items-center gap-2 mb-2">
                    <i class="bi bi-check-lg text-success"></i>
                    <span class="small">Base de données créée (<code>ipam.db</code>)</span>
                </div>
                <div class="d-flex align-items-center gap-2 mb-2">
                    <i class="bi bi-check-lg text-success"></i>
                    <span class="small">Toutes les tables initialisées</span>
                </div>
                <div class="d-flex align-items-center gap-2 mb-2">
                    <i class="bi bi-check-lg text-success"></i>
                    <span class="small">Tags par défaut créés</span>
                </div>
                <div class="d-flex align-items-center gap-2 mb-2">
                    <i class="bi bi-check-lg text-success"></i>
                    <span class="small">Compte Sysadmin <strong><?= htmlspecialchars($_POST['admin_user'] ?? '') ?></strong> créé</span>
                </div>
                <div class="d-flex align-items-center gap-2">
                    <i class="bi bi-check-lg text-success"></i>
                    <span class="small">Langue : <?= ($_POST['lang'] ?? 'fr') === 'fr' ? '🇫🇷 Français' : '🇬🇧 English' ?></span>
                </div>
            </div>
        </div>

        <div class="alert alert-warning py-2 small text-start mb-4">
            <i class="bi bi-shield-exclamation me-1"></i>
            <strong>Important :</strong> Activez votre licence dans Paramètres → Licence après la première connexion.
        </div>

        <a href="login.php" class="btn-setup d-block text-decoration-none text-center">
            <i class="bi bi-box-arrow-in-right me-2"></i>Se connecter maintenant
        </a>
    </div>
    <?php endif; ?>

    </div><!-- /setup-body -->

    <div class="px-4 pb-3 text-center">
        <small class="text-muted">PureIPAM v1.8.0 — <a href="https://github.com" class="text-muted text-decoration-none">Documentation</a></small>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script>
// ── Force du mot de passe ─────────────────────────────────────────────────────
function checkPw(pw) {
    let score = 0;
    if (pw.length >= 6)  score++;
    if (pw.length >= 10) score++;
    if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) score++;
    if (/\d/.test(pw)) score++;
    if (/[^a-zA-Z0-9]/.test(pw)) score++;

    const bar    = document.getElementById('pwBar');
    const label  = document.getElementById('pwLabel');
    const hint   = document.getElementById('pwHint');
    const colors = ['#dc3545','#fd7e14','#ffc107','#20c997','#198754'];
    const labels = ['Très faible','Faible','Moyen','Fort','Très fort ✓'];
    const hints  = ['Trop court','Ajoutez des majuscules','Ajoutez des chiffres','Ajoutez des symboles',''];
    const idx    = Math.min(score, 4);

    bar.style.width      = ((score / 5) * 100) + '%';
    bar.style.background = colors[idx];
    label.textContent    = labels[idx];
    label.style.color    = colors[idx];
    hint.textContent     = hints[idx] || '';

    checkMatch();
    updateSummary();
}

// ── Correspondance mot de passe ───────────────────────────────────────────────
function checkMatch() {
    const pw1 = document.getElementById('pw1').value;
    const pw2 = document.getElementById('pw2').value;
    const msg = document.getElementById('matchMsg');
    if (!pw2) { msg.textContent = ''; return; }
    if (pw1 === pw2) {
        msg.textContent = '✓ Les mots de passe correspondent';
        msg.className   = 'text-success small';
    } else {
        msg.textContent = '✗ Ne correspond pas';
        msg.className   = 'text-danger small';
    }
    updateSummary();
}

// ── Résumé live ───────────────────────────────────────────────────────────────
function updateSummary() {
    const appName  = document.querySelector('[name=site_name]')?.value;
    const userName = document.querySelector('[name=admin_user]')?.value;
    const pw1 = document.getElementById('pw1')?.value;
    const pw2 = document.getElementById('pw2')?.value;
    const box = document.getElementById('summaryBox');
    if (appName && userName && pw1 && pw1 === pw2 && pw1.length >= 6) {
        document.getElementById('summaryApp').textContent  = appName;
        document.getElementById('summaryUser').textContent = userName;
        box.style.display = '';
    } else {
        box.style.display = 'none';
    }
}

// ── Afficher/masquer mot de passe ─────────────────────────────────────────────
function togglePw(id, btn) {
    const input = document.getElementById(id);
    const icon  = btn.querySelector('i');
    if (input.type === 'password') {
        input.type = 'text';
        icon.className = 'bi bi-eye-slash';
    } else {
        input.type = 'password';
        icon.className = 'bi bi-eye';
    }
}

// ── Résumé en temps réel sur les autres champs ────────────────────────────────
document.querySelector('[name=site_name]')?.addEventListener('input', updateSummary);
document.querySelector('[name=admin_user]')?.addEventListener('input', updateSummary);
</script>
</body>
</html>