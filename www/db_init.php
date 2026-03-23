<?php
/**
 * IPAM Light - Initialisation & Migration de la base de données
 * Ce script peut être relancé sans risque : il ne supprime aucune donnée existante.
 * ACCÈS RESTREINT : sysadmin connecté uniquement.
 */

// ─── PROTECTION SYSADMIN ─────────────────────────────────────────────────────
if (session_status() === PHP_SESSION_NONE) session_start();

if (!isset($_SESSION['user_id']) || ($_SESSION['role'] ?? '') !== 'sysadmin') {
    http_response_code(403);
    // Si pas connecté du tout → login, sinon → accès refusé
    if (!isset($_SESSION['user_id'])) {
        header("Location: login.php?next=db_init.php");
        exit;
    }
    ?><!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css">
        <title>Accès refusé</title>
        <style>body{background:#f0f2f5}</style>
    </head>
    <body class="d-flex align-items-center justify-content-center" style="min-height:100vh">
        <div class="card shadow border-0 text-center p-5" style="max-width:420px">
            <div class="mb-3"><i class="bi bi-shield-lock-fill text-danger" style="font-size:3rem"></i></div>
            <h4 class="fw-bold text-danger mb-2">Accès refusé</h4>
            <p class="text-muted small mb-4">
                La migration de base de données est réservée aux comptes <strong>Sysadmin</strong>.<br>
                Vous êtes connecté avec le rôle <strong><?= htmlspecialchars($_SESSION['role'] ?? 'inconnu') ?></strong>.
            </p>
            <a href="index.php" class="btn btn-primary btn-sm">
                <i class="bi bi-arrow-left me-1"></i>Retour au dashboard
            </a>
        </div>
    </body>
    </html><?php
    exit;
}
// ─────────────────────────────────────────────────────────────────────────────

// Charger config pour version + footer
if (!function_exists('db')) {
    function db(): PDO {
        static $_db = null;
        if ($_db === null) {
            $_db = new PDO('sqlite:/var/www/html/ipam.db');
            $_db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $_db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        }
        return $_db;
    }
}
if (!function_exists('e')) {
    function e(string $v): string { return htmlspecialchars($v, ENT_QUOTES, 'UTF-8'); }
}
require_once __DIR__ . '/config.php';

$db_file = '/var/www/html/ipam.db';

try {
    $db = new PDO("sqlite:$db_file");
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $db->exec("PRAGMA foreign_keys = ON;");
    $db->exec("PRAGMA journal_mode = WAL;");

    $log = [];

    // ─── TABLE USERS ────────────────────────────────────────────────────────────
    $db->exec("CREATE TABLE IF NOT EXISTS users (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT    UNIQUE NOT NULL,
        password TEXT    NOT NULL,
        role     TEXT    NOT NULL DEFAULT 'viewer',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");
    $log[] = "✔ Table <code>users</code> vérifiée.";

    // Migration : colonne created_at si elle n'existe pas
    $cols = array_column($db->query("PRAGMA table_info(users)")->fetchAll(), 'name');
    if (!in_array('created_at', $cols)) {
        $db->exec("ALTER TABLE users ADD COLUMN created_at DATETIME DEFAULT CURRENT_TIMESTAMP");
        $log[] = "↑ Colonne <code>users.created_at</code> ajoutée.";
    }

    // ─── TABLE VLANS ────────────────────────────────────────────────────────────
    $db->exec("CREATE TABLE IF NOT EXISTS vlans (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        vid        INTEGER UNIQUE NOT NULL,
        name       TEXT    NOT NULL,
        subnet     TEXT    NOT NULL,
        description TEXT DEFAULT '',
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");
    $log[] = "✔ Table <code>vlans</code> vérifiée.";

    // Migration : colonne description si absente
    $cols = array_column($db->query("PRAGMA table_info(vlans)")->fetchAll(), 'name');
    if (!in_array('description', $cols)) {
        $db->exec("ALTER TABLE vlans ADD COLUMN description TEXT DEFAULT ''");
        $log[] = "↑ Colonne <code>vlans.description</code> ajoutée.";
    }

    // ─── TABLE LICENSE ───────────────────────────────────────────────────────────
    $db->exec("CREATE TABLE IF NOT EXISTS license (
        id           INTEGER PRIMARY KEY CHECK (id = 1),
        key          TEXT NOT NULL,
        owner        TEXT NOT NULL DEFAULT '',
        activated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");
    $log[] = "✔ Table <code>license</code> vérifiée.";

    // ─── TABLE SETTINGS (paramètres site) ────────────────────────────────────────
    $db->exec("CREATE TABLE IF NOT EXISTS settings (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL DEFAULT ''
    )");
    $log[] = "✔ Table <code>settings</code> vérifiée.";

    // ─── MIGRATION : Supprimer SSO (désactivé en v1.6.0) ─────────────────────────
    try {
        $db->exec("DROP TABLE IF EXISTS sso_tokens");
        $log[] = "✔ Table <code>sso_tokens</code> supprimée (SSO désactivé).";
    } catch (Exception $e) {}

    // ─── MIGRATION v1.7.0 : Colonnes politique mdp dans users ───────────────────
    $userCols = $db->query("PRAGMA table_info(users)")->fetchAll(PDO::FETCH_ASSOC);
    $userColNames = array_column($userCols, 'name');
    if (!in_array('must_change_password', $userColNames)) {
        $db->exec("ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0");
        $log[] = "✔ Colonne <code>must_change_password</code> ajoutée.";
    }
    if (!in_array('locked', $userColNames)) {
        $db->exec("ALTER TABLE users ADD COLUMN locked INTEGER NOT NULL DEFAULT 0");
        $log[] = "✔ Colonne <code>locked</code> ajoutée (blocage manuel sysadmin).";
    }
    if (!in_array('password_expires_at', $userColNames)) {
        $db->exec("ALTER TABLE users ADD COLUMN password_expires_at DATETIME DEFAULT NULL");
        $log[] = "✔ Colonne <code>password_expires_at</code> ajoutée.";
    }

    // ─── MIGRATION v1.7.0 : Paramètres politique mdp ─────────────────────────────
    $pwDefaults = [
        'pw_min_length'   => '8',
        'pw_max_length'   => '64',
        'pw_complexity'   => '0',   // 0=aucune, 1=maj+min, 2=maj+min+chiffre, 3=maj+min+chiffre+spécial
        'pw_expiry_days'  => '0',   // 0 = jamais
    ];
    $ins = $db->prepare("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)");
    foreach ($pwDefaults as $k => $v) {
        $ins->execute([$k, $v]);
    }
    $log[] = "✔ Paramètres politique mot de passe initialisés.";


    // ─── MIGRATION v1.8.0 : Groupes de VLANs ────────────────────────────────────
    $db->exec("CREATE TABLE IF NOT EXISTS vlan_groups (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        name       TEXT UNIQUE NOT NULL,
        color      TEXT NOT NULL DEFAULT 'primary',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");
    $log[] = "✔ Table <code>vlan_groups</code> vérifiée.";

    // Colonne group_id dans vlans
    $vlanCols = $db->query("PRAGMA table_info(vlans)")->fetchAll(PDO::FETCH_ASSOC);
    $vlanColNames = array_column($vlanCols, 'name');
    if (!in_array('group_id', $vlanColNames)) {
        $db->exec("ALTER TABLE vlans ADD COLUMN group_id INTEGER DEFAULT NULL REFERENCES vlan_groups(id) ON DELETE SET NULL");
        $log[] = "✔ Colonne <code>group_id</code> ajoutée à vlans.";
    }
    // Colonne notes dans vlans
    if (!in_array('notes', $vlanColNames)) {
        $db->exec("ALTER TABLE vlans ADD COLUMN notes TEXT DEFAULT ''");
        $log[] = "✔ Colonne <code>notes</code> ajoutée à vlans.";
    }

    // ─── MIGRATION v1.8.0 : Historique des IPs ───────────────────────────────────
    $db->exec("CREATE TABLE IF NOT EXISTS ip_history (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_id       INTEGER NOT NULL,
        ip_address  TEXT NOT NULL,
        vlan_id     INTEGER NOT NULL,
        field       TEXT NOT NULL,
        old_value   TEXT NOT NULL DEFAULT '',
        new_value   TEXT NOT NULL DEFAULT '',
        changed_by  TEXT NOT NULL DEFAULT 'system',
        changed_at  DATETIME DEFAULT CURRENT_TIMESTAMP
    )");
    $log[] = "✔ Table <code>ip_history</code> vérifiée.";

    // ─── MIGRATION v1.8.0 : Rétention audit ─────────────────────────────────────
    $auditDefaults = [
        'audit_retention_days' => '0',  // 0 = indéfini
    ];
    $ins2 = $db->prepare("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)");
    foreach ($auditDefaults as $k => $v) {
        $ins2->execute([$k, $v]);
    }
    $log[] = "✔ Paramètre rétention audit initialisé.";

    // ─── TABLE TAGS ─────────────────────────────────────────────────────────────
    $db->exec("CREATE TABLE IF NOT EXISTS tags (
        id    INTEGER PRIMARY KEY AUTOINCREMENT,
        name  TEXT UNIQUE NOT NULL,
        color TEXT NOT NULL DEFAULT 'secondary',
        icon  TEXT NOT NULL DEFAULT 'tag'
    )");
    $log[] = "✔ Table <code>tags</code> vérifiée.";

    // Tags par défaut
    $tagCount = $db->query("SELECT COUNT(*) FROM tags")->fetchColumn();
    if ($tagCount == 0) {
        $defaultTags = [
            ['client',    'info',      'pc'],
            ['serveur',   'danger',    'server'],
            ['dns',       'warning',   'globe'],
            ['gateway',   'dark',      'router'],
            ['printer',   'secondary', 'printer'],
            ['switch',    'primary',   'hdd-network'],
            ['phone',     'success',   'telephone'],
        ];
        $ins = $db->prepare("INSERT OR IGNORE INTO tags (name, color, icon) VALUES (?,?,?)");
        foreach ($defaultTags as [$n, $c, $i]) $ins->execute([$n, $c, $i]);
        $log[] = "✚ Tags par défaut créés (" . count($defaultTags) . ").";
    }

    // ─── TABLE IPS ──────────────────────────────────────────────────────────────
    $db->exec("CREATE TABLE IF NOT EXISTS ips (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        vlan_id     INTEGER NOT NULL,
        ip_address  TEXT    NOT NULL,
        hostname    TEXT    DEFAULT '',
        description TEXT    DEFAULT '',
        domain      TEXT    DEFAULT '',
        tag         TEXT    DEFAULT 'client',
        status      TEXT    DEFAULT 'used',
        created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(vlan_id, ip_address),
        FOREIGN KEY (vlan_id) REFERENCES vlans(id) ON DELETE CASCADE
    )");
    $log[] = "✔ Table <code>ips</code> vérifiée.";

    // Migration : colonne created_at si absente
    $cols = array_column($db->query("PRAGMA table_info(ips)")->fetchAll(), 'name');
    if (!in_array('created_at', $cols)) {
        $db->exec("ALTER TABLE ips ADD COLUMN created_at DATETIME DEFAULT CURRENT_TIMESTAMP");
        $log[] = "↑ Colonne <code>ips.created_at</code> ajoutée.";
    }

    // ─── MIGRATION RÔLES : sysadmin / admin / viewer ─────────────────────────────
    // Si la colonne role contient 'admin' et qu'aucun sysadmin n'existe encore,
    // le premier admin existant est promu sysadmin automatiquement.
    $sysadminCount = $db->query("SELECT COUNT(*) FROM users WHERE role='sysadmin'")->fetchColumn();
    if ($sysadminCount == 0) {
        $firstAdmin = $db->query("SELECT id, username FROM users WHERE role='admin' ORDER BY id ASC LIMIT 1")->fetch();
        if ($firstAdmin) {
            $db->prepare("UPDATE users SET role='sysadmin' WHERE id=?")->execute([$firstAdmin['id']]);
            $log[] = "↑ Utilisateur <strong>{$firstAdmin['username']}</strong> promu <strong>sysadmin</strong> (premier admin détecté, migration automatique).";
        }
    } else {
        $log[] = "✔ Rôles vérifiés — " . (int)$sysadminCount . " sysadmin(s) présent(s).";
    }

    // ─── UTILISATEUR SYSADMIN PAR DÉFAUT ─────────────────────────────────────────
    $anyUser = $db->query("SELECT COUNT(*) FROM users")->fetchColumn();
    if ($anyUser == 0) {
        $hash = password_hash('admin', PASSWORD_DEFAULT);
        $db->prepare("INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, 'sysadmin')")
           ->execute(['admin', $hash]);
        $log[] = "✚ Utilisateur <strong>admin</strong> créé (rôle : sysadmin, mdp : <code>admin</code>). <span class='text-danger fw-bold'>Changez-le immédiatement !</span>";
    }

    // Migration auto bcrypt pour tous les mots de passe en clair
    $plainUsers = $db->query("SELECT id, password FROM users")->fetchAll(PDO::FETCH_ASSOC);
    $migrated = 0;
    foreach ($plainUsers as $u) {
        if (!str_starts_with($u['password'], '$')) {
            $db->prepare("UPDATE users SET password=? WHERE id=?")->execute([password_hash($u['password'], PASSWORD_DEFAULT), $u['id']]);
            $migrated++;
        }
    }
    if ($migrated > 0) $log[] = "↑ {$migrated} mot(s) de passe migré(s) vers bcrypt.";


    // ─── DONNÉES DE DÉMONSTRATION ────────────────────────────────────────────────
    $vlanCount = $db->query("SELECT COUNT(*) FROM vlans")->fetchColumn();
    if ($vlanCount == 0) {
        $db->exec("INSERT INTO vlans (vid, name, subnet, description) VALUES
            (10, 'SERVEURS_PROD', '10.0.10.0/24', 'Serveurs de production'),
            (20, 'WIFI_GUEST',   '192.168.20.0/24', 'Réseau invités WiFi'),
            (99, 'MGMT',         '172.16.99.0/24', 'Management OOB')");

        $v1 = $db->query("SELECT id FROM vlans WHERE vid=10")->fetchColumn();
        $db->prepare("INSERT INTO ips (vlan_id, ip_address, hostname, domain, tag, description) VALUES
            (?, '10.0.10.1',  'gw-prod',   'infra.local', 'gateway', 'Passerelle par défaut'),
            (?, '10.0.10.10', 'web-01',    'infra.local', 'serveur', 'Serveur web Apache'),
            (?, '10.0.10.11', 'db-01',     'infra.local', 'serveur', 'Base de données MySQL')")
           ->execute([$v1, $v1, $v1]);

        $log[] = "✚ Données de démonstration créées (3 VLANs, 3 IPs).";
    }

    $ok = true;

} catch (PDOException $e) {
    $error = $e->getMessage();
    $ok = false;
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <title>IPAM – Initialisation DB</title>
</head>
<body class="bg-light d-flex align-items-center justify-content-center" style="min-height:100vh">
<div class="card shadow" style="max-width:560px;width:100%">
    <div class="card-header bg-dark text-white d-flex align-items-center gap-2">
        <span class="fs-5">⚙️</span>
        <strong>Initialisation / Migration de la base de données</strong>
    </div>
    <div class="card-body">
        <?php if (!$ok): ?>
            <div class="alert alert-danger">
                <strong>Erreur :</strong> <?= htmlspecialchars($error) ?>
            </div>
        <?php else: ?>
            <ul class="list-unstyled mb-3">
                <?php foreach ($log as $l): ?>
                    <li class="py-1 border-bottom small"><?= $l ?></li>
                <?php endforeach; ?>
            </ul>
            <div class="alert alert-success mb-0">
                <strong>✅ Base de données prête.</strong>
            </div>
        <?php endif; ?>
    </div>
    <?php if ($ok): ?>
    <div class="card-footer text-end">
        <a href="index.php" class="btn btn-primary btn-sm">Aller au Dashboard →</a>
    </div>
    <?php endif; ?>
    <div class="card-footer text-center text-muted" style="font-size:.75rem">
        <?= APP_NAME ?> v<?= APP_VERSION ?> — build <?= APP_BUILD ?>
    </div>
</div>
</body>
</html>