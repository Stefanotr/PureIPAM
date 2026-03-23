<?php
include('auth.php');
requireSysAdmin();

// ─── OTPHP (spomky-labs/otphp) ─────────────────────────────────────────────
if (file_exists(__DIR__ . '/vendor/autoload.php')) require_once __DIR__ . '/vendor/autoload.php';
use OTPHP\TOTP; // seul le sysadmin accède aux paramètres complets

$db     = db();
$errors = [];
$tab    = in_array($_GET['tab'] ?? '', ['users','license','site','database','audit','security']) ? $_GET['tab'] : 'users';

// ─── Charger politique mdp ────────────────────────────────────────────────────
$pwPolicy = ['pw_min_length'=>'8','pw_max_length'=>'64','pw_complexity'=>'0','pw_expiry_days'=>'0'];
try {
    $rows = $db->query("SELECT key, value FROM settings WHERE key LIKE 'pw_%'")->fetchAll();
    foreach ($rows as $r) $pwPolicy[$r['key']] = $r['value'];
} catch (Exception $e) {}

// ════════════════════════════════════════════════════════════════════════════
// ONGLET UTILISATEURS
// ════════════════════════════════════════════════════════════════════════════

function generateTotpSecret(): string {
    // Génère un secret Base32 compatible RFC 6238 via spomky-labs/otphp
    return \OTPHP\TOTP::create()->getSecret();
}

if (isset($_GET['setup_2fa']))   {
    $uid = (int)$_GET['setup_2fa'];
    $secret = generateTotpSecret();
    $db->prepare("UPDATE users SET google_2fa_secret=? WHERE id=?")->execute([$secret, $uid]);
    $targetUser = $db->query("SELECT username FROM users WHERE id=$uid")->fetchColumn();
    audit('user.2fa.enabled', $targetUser ?: "id:$uid", 'Secret TOTP généré');
    redirect('settings.php?tab=users','Secret 2FA généré.');
}
if (isset($_GET['disable_2fa'])) {
    $uid = (int)$_GET['disable_2fa'];
    $targetUser = $db->query("SELECT username FROM users WHERE id=$uid")->fetchColumn();
    $db->prepare("UPDATE users SET google_2fa_secret=NULL WHERE id=?")->execute([$uid]);
    audit('user.2fa.disabled', $targetUser ?: "id:$uid", '2FA désactivé par sysadmin');
    redirect('settings.php?tab=users','2FA désactivé.','warning');
}

// ─── FORCER CHANGEMENT MDP ───────────────────────────────────────────────────
if (isset($_GET['force_pw_change'])) {
    $uid = (int)$_GET['force_pw_change'];
    $targetUser = $db->query("SELECT username FROM users WHERE id=$uid")->fetchColumn();
    if ($targetUser) {
        $db->prepare("UPDATE users SET must_change_password=1 WHERE id=?")->execute([$uid]);
        audit('user.force_pw_change', $targetUser, 'Changement mdp forcé par sysadmin');
        redirect('settings.php?tab=users', "🔑 Changement de mot de passe forcé pour « $targetUser ».", 'warning');
    }
}
// ─── DÉFINIR MDP PAR SYSADMIN ────────────────────────────────────────────────
if (isset($_POST['set_pw_admin'])) {
    csrfVerify();
    $uid   = (int)($_POST['target_uid'] ?? 0);
    $newpw = $_POST['admin_pw'] ?? '';
    $targetUser = $db->query("SELECT username FROM users WHERE id=$uid")->fetchColumn();
    if (!$targetUser) redirect('settings.php?tab=users', 'Utilisateur introuvable.', 'danger');
    $pwErrors = validatePassword($newpw, true); // sysadmin : min 4 chars, pas de politique
    if (!empty($pwErrors)) redirect('settings.php?tab=users', implode(' ', $pwErrors), 'danger');
    $hash = password_hash($newpw, PASSWORD_BCRYPT);
    $mustChange = isset($_POST['must_change']) ? 1 : 0;
    $db->prepare("UPDATE users SET password=?, must_change_password=? WHERE id=?")
       ->execute([$hash, $mustChange, $uid]);
    audit('user.password_set', $targetUser, 'Mot de passe défini par sysadmin' . ($mustChange ? ' (changement forcé)' : ''));
    redirect('settings.php?tab=users', "✅ Mot de passe défini pour « $targetUser ».");
}

// ─── BLOQUER / DÉBLOQUER UN UTILISATEUR ──────────────────────────────────────
if (isset($_GET['lock_user'])) {
    $uid = (int)$_GET['lock_user'];
    $targetUser = $db->query("SELECT username FROM users WHERE id=$uid")->fetchColumn();
    if ($targetUser) {
        $db->prepare("UPDATE users SET locked=1 WHERE id=?")->execute([$uid]);
        audit('user.lock', $targetUser, 'Blocage manuel par sysadmin');
        redirect('settings.php?tab=users', "Utilisateur « $targetUser » bloqué.", 'warning');
    }
    redirect('settings.php?tab=users', 'Utilisateur introuvable.', 'danger');
}
if (isset($_GET['unlock_user'])) {
    $uid = (int)$_GET['unlock_user'];
    $targetUser = $db->query("SELECT username FROM users WHERE id=$uid")->fetchColumn();
    if ($targetUser) {
        // Débloquer : verrou manuel + rate limiting (toutes IPs)
        $db->prepare("UPDATE users SET locked=0 WHERE id=?")->execute([$uid]);
        $db->prepare("DELETE FROM login_attempts WHERE username=?")->execute([$targetUser]);
        audit('user.unlock', $targetUser, 'Déblocage manuel par sysadmin');
        redirect('settings.php?tab=users', "Utilisateur « $targetUser » débloqué.", 'success');
    }
    redirect('settings.php?tab=users', 'Utilisateur introuvable.', 'danger');
}

if (isset($_POST['add_user'])) {
    csrfVerify();
    $u = trim($_POST['new_u'] ?? '');
    $p = $_POST['new_p'] ?? '';
    $r = in_array($_POST['new_r'] ?? '', ['sysadmin','admin','viewer']) ? $_POST['new_r'] : 'viewer';
    $mustChange = isset($_POST['new_must_change']) ? 1 : 0;
    if (strlen($u) < 3)  $errors[] = "Nom trop court (min 3 car.).";
    if (strlen($p) < 4)  $errors[] = "Mot de passe trop court (min 4 car.).";
    if (strlen($p) > 64) $errors[] = "Mot de passe trop long (max 64 car.).";
    if (empty($errors)) {
        try {
            $db->prepare("INSERT INTO users (username,password,role,must_change_password) VALUES (?,?,?,?)")
               ->execute([$u, password_hash($p, PASSWORD_BCRYPT), $r, $mustChange]);
            audit("user.create", $u, "Rôle: $r" . ($mustChange ? " (chgt mdp forcé)" : ""));
            redirect('settings.php?tab=users', "Utilisateur « $u » créé.");
        }
        catch (Exception $e) { $errors[]="Nom d'utilisateur déjà pris."; }
    }
    $tab='users';
}

if (isset($_POST['change_pw'])) {
    $id=(int)($_POST['uid']??0); $newp=$_POST['newpw']??'';
    if (strlen($newp)<6) { $errors[]="Mot de passe trop court (min 6 car.)."; $tab='users'; }
    else { $db->prepare("UPDATE users SET password=? WHERE id=?")->execute([password_hash($newp,PASSWORD_DEFAULT),$id]); redirect('settings.php?tab=users','Mot de passe mis à jour.'); }
}

if (isset($_POST['change_role'])) {
    $id=(int)($_POST['uid']??0);
    $role=in_array($_POST['role']??'',['sysadmin','admin','viewer'])?$_POST['role']:'viewer';
    if ($id===(int)$_SESSION['user_id']&&$role!=='sysadmin') redirect('settings.php?tab=users','Vous ne pouvez pas changer votre propre rôle.','warning');
    // Garder au moins un sysadmin
    if ($role!=='sysadmin') {
        $sas=$db->query("SELECT COUNT(*) FROM users WHERE role='sysadmin'")->fetchColumn();
        $cur=$db->prepare("SELECT role FROM users WHERE id=?"); $cur->execute([$id]);
        if ($cur->fetchColumn()==='sysadmin'&&$sas<=1) redirect('settings.php?tab=users','Il faut au moins un Sysadmin.','warning');
    }
    $db->prepare("UPDATE users SET role=? WHERE id=?")->execute([$role,$id]);
    redirect('settings.php?tab=users','Rôle mis à jour.');
}

if (isset($_GET['delete'])) {
    $id=(int)$_GET['delete'];
    if ($id===(int)$_SESSION['user_id']) redirect('settings.php?tab=users','Vous ne pouvez pas vous supprimer.','warning');
    $sas=$db->query("SELECT COUNT(*) FROM users WHERE role='sysadmin'")->fetchColumn();
    $role=$db->prepare("SELECT role FROM users WHERE id=?"); $role->execute([$id]);
    if ($role->fetchColumn()==='sysadmin'&&$sas<=1) redirect('settings.php?tab=users','Il faut au moins un Sysadmin.','warning');
    $db->prepare("DELETE FROM users WHERE id=?")->execute([$id]);
    redirect('settings.php?tab=users','Utilisateur supprimé.');
}

// ════════════════════════════════════════════════════════════════════════════
// ONGLET LICENCE
// ════════════════════════════════════════════════════════════════════════════

if (isset($_GET['revoke_license'])) { $db->exec("DELETE FROM license WHERE id=1"); redirect('settings.php?tab=license','Licence révoquée.','warning'); }

if (isset($_POST['activate_license'])) {
    $key=strtoupper(trim($_POST['license_key']??'')); $owner=trim($_POST['owner']??'');
    if (!$owner) $errors[]="Titulaire requis.";
    elseif (!validateLicenseKey($key)) $errors[]="Clé invalide. Format : XXXX-XXXX-XXXX-XXXX.";
    else {
        $db->prepare("INSERT OR REPLACE INTO license (id,key,owner,activated_at) VALUES (1,?,?,CURRENT_TIMESTAMP)")->execute([$key,$owner]);
        redirect('settings.php?tab=license',"Licence activée pour <strong>".e($owner)."</strong>.");
    }
    $tab='license';
}

// ════════════════════════════════════════════════════════════════════════════
// ONGLET SITE
// ════════════════════════════════════════════════════════════════════════════

if (isset($_POST['save_site'])) {
    $themes = unserialize(IPAM_THEMES);
    setSetting('site_name',    trim($_POST['site_name']??''));
    setSetting('site_icon',    preg_replace('/[^a-z0-9\-]/','',$_POST['site_icon']??'hdd-network-fill'));
    setSetting('site_theme',   isset($themes[$_POST['site_theme']??''])?$_POST['site_theme']:'default');
    setSetting('site_welcome', trim($_POST['site_welcome']??''));
    setSetting('site_lang',    in_array($_POST['site_lang']??'',['fr','en'])?$_POST['site_lang']:'fr');
    redirect('settings.php?tab=site', t('site.saved'));
}

// ─── Sauvegarder politique mot de passe ──────────────────────────────────────
if (isset($_POST['save_pw_policy'])) {
    csrfVerify();
    $pwMin  = max(1,  min(64, (int)($_POST['pw_min_length']  ?? 8)));
    $pwMax  = max(1,  min(64, (int)($_POST['pw_max_length']  ?? 64)));
    $pwCplx = min(3,  max(0,  (int)($_POST['pw_complexity']  ?? 0)));
    $pwExp  = max(0,          (int)($_POST['pw_expiry_days'] ?? 0));
    if ($pwMin > $pwMax) $pwMin = $pwMax;
    $upd = $db->prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)");
    foreach (['pw_min_length'=>$pwMin,'pw_max_length'=>$pwMax,'pw_complexity'=>$pwCplx,'pw_expiry_days'=>$pwExp] as $k=>$v)
        $upd->execute([$k, (string)$v]);
    audit('settings.pw_policy','security',"min:{$pwMin} max:{$pwMax} complexity:{$pwCplx} expiry:{$pwExp}");
    redirect('settings.php?tab=security', te('pw.saved'));
}

// ─── AUDIT : Export CSV ───────────────────────────────────────────────────────
if (isset($_GET['export_audit']) && $_GET['export_audit'] === 'csv') {
    $rows = $db->query("SELECT * FROM audit_log ORDER BY created_at DESC")->fetchAll();
    audit('audit.export', $_SESSION['user'], 'Export CSV journal d'audit');
    header('Content-Type: text/csv; charset=UTF-8');
    header('Content-Disposition: attachment; filename="audit_log_' . date('Ymd_His') . '.csv"');
    $out = fopen('php://output', 'w');
    fprintf($out, chr(0xEF).chr(0xBB).chr(0xBF));
    fputcsv($out, ['ID','Date','Utilisateur','Action','Cible','Détail','IP Source'], ';');
    foreach ($rows as $r) fputcsv($out, [$r['id'],$r['created_at'],$r['username'],$r['action'],$r['target'],$r['detail'],$r['ip_address']], ';');
    fclose($out); exit;
}

// ─── AUDIT : Export JSON ──────────────────────────────────────────────────────
if (isset($_GET['export_audit']) && $_GET['export_audit'] === 'json') {
    $rows = $db->query("SELECT * FROM audit_log ORDER BY created_at DESC")->fetchAll();
    audit('audit.export', $_SESSION['user'], 'Export JSON journal d'audit');
    header('Content-Type: application/json; charset=UTF-8');
    header('Content-Disposition: attachment; filename="audit_log_' . date('Ymd_His') . '.json"');
    echo json_encode(['exported_at' => date('c'), 'total' => count($rows), 'entries' => $rows], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    exit;
}

// ─── AUDIT : Purge / Rétention ────────────────────────────────────────────────
if (isset($_POST['save_audit_retention'])) {
    csrfVerify();
    $days = max(0, (int)($_POST['audit_retention_days'] ?? 0));
    $db->prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('audit_retention_days', ?)")->execute([(string)$days]);
    audit('settings.audit_retention', 'audit', "Rétention définie : {$days} jours");
    redirect('settings.php?tab=audit', '✅ Rétention des logs sauvegardée.');
}
if (isset($_POST['purge_audit'])) {
    csrfVerify();
    $days = max(1, (int)($_POST['purge_days'] ?? 30));
    $stmt = $db->prepare("DELETE FROM audit_log WHERE created_at < datetime('now', '-' || ? || ' days')");
    $stmt->execute([$days]);
    $deleted = $db->lastInsertId() ? 0 : 0; // sqlite rowCount workaround
    $deleted = $stmt->rowCount();
    audit('audit.purge', $_SESSION['user'], "Purge des logs > {$days}j : {$deleted} supprimés");
    redirect('settings.php?tab=audit', "✅ {$deleted} entrée(s) supprimée(s).");
}

// ─── DB : Backup ──────────────────────────────────────────────────────────────
if (isset($_GET['db_backup'])) {
    $dbPath = '/var/www/html/ipam.db';
    if (!file_exists($dbPath)) redirect('settings.php?tab=database','Base de données introuvable.','danger');
    audit('db.backup', $_SESSION['user'], 'Backup téléchargé');
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="ipam_backup_' . date('Ymd_His') . '.db"');
    header('Content-Length: ' . filesize($dbPath));
    readfile($dbPath); exit;
}

// ─── DB : Restore ─────────────────────────────────────────────────────────────
if (isset($_POST['db_restore'])) {
    csrfVerify();
    if (isset($_FILES['restore_file']) && $_FILES['restore_file']['error'] === 0) {
        $tmp = $_FILES['restore_file']['tmp_name'];
        // Vérifier signature SQLite
        $magic = file_get_contents($tmp, false, null, 0, 16);
        if (strpos($magic, 'SQLite format 3') === 0) {
            $dbPath = '/var/www/html/ipam.db';
            copy($dbPath, $dbPath . '.bak_' . date('Ymd_His'));
            copy($tmp, $dbPath);
            audit('db.restore', $_SESSION['user'], 'Base de données restaurée');
            redirect('settings.php?tab=database', '✅ Base de données restaurée. Un backup de l'ancienne a été créé.');
        } else {
            redirect('settings.php?tab=database', '❌ Fichier invalide — ce n'est pas une base SQLite.', 'danger');
        }
    }
    redirect('settings.php?tab=database', '❌ Erreur lors de l'upload.', 'danger');
}

// ─── DB : Nettoyage orphelins ─────────────────────────────────────────────────
if (isset($_POST['db_cleanup'])) {
    csrfVerify();
    $deleted = 0;
    // IPs sans VLAN
    $stmt = $db->prepare("DELETE FROM ips WHERE vlan_id NOT IN (SELECT id FROM vlans)");
    $stmt->execute(); $deleted += $stmt->rowCount();
    // Tentatives de login expirées
    $stmt2 = $db->prepare("DELETE FROM login_attempts WHERE locked_until < datetime('now') AND locked_until IS NOT NULL");
    $stmt2->execute(); $deleted += $stmt2->rowCount();
    audit('db.cleanup', $_SESSION['user'], "Nettoyage orphelins : {$deleted} lignes supprimées");
    redirect('settings.php?tab=database', "✅ Nettoyage terminé — {$deleted} ligne(s) supprimée(s).");
}

// ════════════════════════════════════════════════════════════════════════════
// DONNÉES
// ════════════════════════════════════════════════════════════════════════════

// Récupérer les users avec leur statut de blocage depuis login_attempts
$allUsers = $db->query("
    SELECT u.id, u.username, u.role, u.google_2fa_secret, u.created_at,
           u.locked, u.must_change_password,
           la.locked_until, la.ip
    FROM users u
    LEFT JOIN login_attempts la ON la.username = u.username AND la.ip != 'manual'
    ORDER BY u.role DESC, u.username ASC
")->fetchAll();

// ─── Rétention audit ─────────────────────────────────────────────────────────
$auditRetention = '0';
try {
    $r = $db->prepare("SELECT value FROM settings WHERE key='audit_retention_days'");
    $r->execute(); $auditRetention = $r->fetchColumn() ?: '0';
} catch(Exception $e) {}
$lic      = getLicense();
$demoKey  = generateLicenseKey();
$themes   = unserialize(IPAM_THEMES);
$siteIcons = ['hdd-network-fill','router','server','globe','shield-check','cpu','broadcast','wifi','diagram-3-fill','layers'];

// ════════════════════════════════════════════════════════════════════════════
// ONGLET JOURNAL D'AUDIT
// ════════════════════════════════════════════════════════════════════════════
$auditLogs = [];
$auditTotal = 0;
if ($tab === 'audit') {
    try {
        $db->exec("CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER,
            username TEXT NOT NULL DEFAULT 'system', action TEXT NOT NULL,
            target TEXT NOT NULL DEFAULT '', detail TEXT NOT NULL DEFAULT '',
            ip_address TEXT NOT NULL DEFAULT '', created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )");
        $auditPage    = max(1, (int)($_GET['apage'] ?? 1));
        $auditPerPage = 50;
        $auditFilter  = trim($_GET['af'] ?? '');
        if ($auditFilter) {
            $af = "%$auditFilter%";
            $cntS = $db->prepare("SELECT COUNT(*) FROM audit_log WHERE username LIKE ? OR action LIKE ? OR target LIKE ?");
            $cntS->execute([$af,$af,$af]);
            $auditTotal = (int)$cntS->fetchColumn();
        } else {
            $auditTotal = (int)$db->query("SELECT COUNT(*) FROM audit_log")->fetchColumn();
        }
        $auditTotalPages = max(1, (int)ceil($auditTotal / $auditPerPage));
        $auditPage = min($auditPage, $auditTotalPages);
        $auditOffset = ($auditPage - 1) * $auditPerPage;
        if ($auditFilter) {
            $af = "%$auditFilter%";
            $ls = $db->prepare("SELECT * FROM audit_log WHERE username LIKE ? OR action LIKE ? OR target LIKE ? ORDER BY created_at DESC LIMIT ? OFFSET ?");
            $ls->execute([$af,$af,$af,$auditPerPage,$auditOffset]);
        } else {
            $ls = $db->prepare("SELECT * FROM audit_log ORDER BY created_at DESC LIMIT ? OFFSET ?");
            $ls->execute([$auditPerPage,$auditOffset]);
        }
        $auditLogs = $ls->fetchAll();
    } catch (Exception $e) { $auditLogs = []; }
}
?>
<!DOCTYPE html>
<html lang="<?= e(siteLang()) ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css">
    <?php renderThemeCSS(); ?>
    <title><?= e(siteName()) ?> — <?= te('settings.title') ?></title>
    <style>
        .nav-tabs .nav-link { color:#6c757d; font-weight:500; }
        .nav-tabs .nav-link.active { color:var(--ipam-accent,#0d6efd); font-weight:600; border-bottom:2px solid var(--ipam-accent,#0d6efd); }
        .key-input { font-family:'Courier New',monospace; letter-spacing:2px; text-transform:uppercase; text-align:center; }
        .key-input::placeholder { text-transform:none; letter-spacing:normal; }
        .demo-key { background:#f8f9fa; border:1px dashed #adb5bd; border-radius:8px; font-family:monospace; letter-spacing:2px; cursor:pointer; transition:background .15s; }
        .demo-key:hover { background:#e9f0ff; border-color:var(--ipam-accent,#0d6efd); }
        .icon-grid { display:grid; grid-template-columns:repeat(5,1fr); gap:6px; }
        .icon-opt { cursor:pointer; border:2px solid transparent; border-radius:8px; padding:8px 4px; text-align:center; transition:all .15s; }
        .icon-opt:hover,.icon-opt.active { border-color:var(--ipam-accent,#0d6efd); background:rgba(13,110,253,.08); }
        .icon-opt i { font-size:1.3rem; display:block; }
        .icon-opt span { font-size:.6rem; color:#666; }
        .db-section { border-left:4px solid #dc3545; }
        /* Sélecteur de thèmes */
        .theme-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(130px,1fr)); gap:10px; }
        .theme-card { border:2px solid transparent; border-radius:12px; overflow:hidden; cursor:pointer; transition:all .2s; }
        .theme-card:hover { transform:translateY(-2px); box-shadow:0 4px 16px rgba(0,0,0,.15); }
        .theme-card.active { border-color:var(--ipam-accent,#0d6efd); box-shadow:0 0 0 3px rgba(13,110,253,.2); }
        .theme-preview { height:52px; display:flex; flex-direction:column; }
        .theme-preview-nav { height:18px; }
        .theme-preview-body { flex:1; display:flex; align-items:center; justify-content:center; gap:4px; }
        .theme-preview-btn { width:20px; height:8px; border-radius:3px; }
        .theme-label { font-size:.72rem; font-weight:600; padding:4px 6px; text-align:center; border-top:1px solid rgba(0,0,0,.08); }
    </style>
</head>
<body>
<nav class="navbar ipam-navbar shadow-sm px-3">
    <div class="container-fluid">
        <a class="navbar-brand fw-bold" href="index.php">
            <i class="bi bi-<?= e(siteIcon()) ?> me-2" style="color:var(--ipam-accent,#0d6efd)"></i><?= e(siteName()) ?>
        </a>
        <div class="d-flex align-items-center gap-2">
            <span style="color:var(--ipam-navbar-text,#ccc)" class="small">
                <i class="bi bi-person-circle me-1"></i><?= e($_SESSION['user']) ?>
                <span class="badge role-sysadmin ms-1" style="font-size:.6rem">SYSADMIN</span>
            </span>
            <a href="logout.php" class="btn btn-outline-danger btn-sm"><i class="bi bi-box-arrow-right"></i></a>
        </div>
    </div>
</nav>

<div class="container py-4" style="max-width:1000px">
    <div class="d-flex align-items-center gap-3 mb-4">
        <a href="index.php" class="btn btn-sm btn-outline-secondary"><i class="bi bi-arrow-left me-1"></i><?= te('action.back') ?></a>
        <div>
            <h4 class="mb-0 fw-bold"><i class="bi bi-gear-fill me-2 text-primary"></i><?= te('settings.title') ?></h4>
            <div class="text-muted small mt-1"><?= te('settings.subtitle') ?></div>
        </div>
        <div class="ms-auto"><span class="badge bg-secondary" style="font-size:.7rem">v<?= APP_VERSION ?> — build <?= APP_BUILD ?></span></div>
    </div>

    <?php flash(); ?>
    <?php if (!empty($errors)): ?>
        <div class="alert alert-danger py-2 small"><?php foreach($errors as $err) echo '<div><i class="bi bi-exclamation-circle me-1"></i>'.e($err).'</div>'; ?></div>
    <?php endif; ?>

    <!-- ONGLETS -->
    <ul class="nav nav-tabs mb-0">
        <li class="nav-item">
            <a class="nav-link <?= $tab==='users'?'active':'' ?>" href="?tab=users">
                <i class="bi bi-people-fill me-1"></i><?= te('settings.tab.users') ?>
                <span class="badge bg-secondary ms-1"><?= count($allUsers) ?></span>
            </a>
        </li>
        <li class="nav-item">
            <a class="nav-link <?= $tab==='license'?'active':'' ?>" href="?tab=license">
                <i class="bi bi-patch-check-fill me-1"></i><?= te('settings.tab.license') ?>
                <span class="badge <?= $lic?'bg-success':'bg-warning text-dark' ?> ms-1" style="font-size:.65rem"><?= $lic ? te('lic.active') : te('lic.none') ?></span>
            </a>
        </li>
        <li class="nav-item">
            <a class="nav-link <?= $tab==='site'?'active':'' ?>" href="?tab=site">
                <i class="bi bi-sliders me-1"></i><?= te('settings.tab.site') ?>
            </a>
        </li>
        <li class="nav-item">
            <a class="nav-link <?= $tab==='database'?'active':'' ?>" href="?tab=database">
                <i class="bi bi-database-gear me-1"></i><?= te('settings.tab.database') ?>
            </a>
        </li>
        <li class="nav-item">
            <a class="nav-link <?= $tab==='audit'?'active':'' ?>" href="?tab=audit">
                <i class="bi bi-journal-text me-1"></i><?= te('settings.tab.audit') ?>
            </a>
        </li>
        <li class="nav-item">
            <a class="nav-link <?= $tab==='security'?'active':'' ?>" href="?tab=security">
                <i class="bi bi-shield-lock me-1"></i><?= te('settings.tab.security') ?>
            </a>
        </li>
    </ul>

    <div class="card border-0 shadow-sm" style="border-radius:0 0 12px 12px">
    <div class="card-body p-4">

    <?php if ($tab==='users'): ?>
    <!-- ══ UTILISATEURS ══════════════════════════════════════════════════════ -->

    <!-- Créer un utilisateur -->
    <div class="card border-0 bg-light mb-4">
        <div class="card-body py-3">
            <h6 class="fw-semibold mb-3"><i class="bi bi-person-plus-fill me-2 text-success"></i><?= te('user.create_title') ?></h6>
            <form method="POST" class="row g-2 align-items-end">
                <?= csrfField() ?>
                <div class="col-md-4">
                    <label class="form-label small mb-1"><?= te('user.username') ?> <span class="text-danger">*</span></label>
                    <input type="text" name="new_u" class="form-control form-control-sm" placeholder="ex: jean.dupont" required minlength="3" maxlength="64">
                </div>
                <div class="col-md-3">
                    <label class="form-label small mb-1"><?= te('user.password') ?> <span class="text-danger">*</span></label>
                    <input type="password" name="new_p" class="form-control form-control-sm" placeholder="<?= te('user.min_pw_chars') ?>" required minlength="4" maxlength="64">
                </div>
                <div class="col-md-3">
                    <label class="form-label small mb-1"><?= te('user.role') ?></label>
                    <select name="new_r" class="form-select form-select-sm">
                        <option value="viewer"><?= te('role.viewer') ?></option>
                        <option value="admin"><?= te('role.admin') ?></option>
                        <option value="sysadmin"><?= te('role.sysadmin') ?></option>
                    </select>
                </div>
                <div class="col-md-2">
                    <div class="form-check form-switch mb-1">
                        <input class="form-check-input" type="checkbox" name="new_must_change" id="newMustChange" checked>
                        <label class="form-check-label small" for="newMustChange"><?= te('user.force_pw') ?></label>
                    </div>
                    <button type="submit" name="add_user" class="btn btn-success btn-sm w-100"><i class="bi bi-plus-lg me-1"></i>Créer</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Table utilisateurs -->
    <div class="table-responsive">
        <table class="table table-hover align-middle mb-0" style="font-size:.88rem">
            <thead class="table-dark">
                <tr>
                    <th><?= te('user.username') ?></th>
                    <th><?= te('user.role') ?></th>
                    <th style="width:80px"><?= te('user.2fa') ?></th>
                    <th style="width:100px"><?= te('user.status') ?></th>
                    <th style="width:90px"><?= te('user.created_at') ?></th>
                    <th style="width:160px" class="text-end pe-2"><?= te('vlan.actions') ?></th>
                </tr>
            </thead>
            <tbody>
            <?php foreach($allUsers as $u):
                $isManualLocked = !empty($u['locked']);  // Blocage manuel sysadmin
                $isRateLocked   = !empty($u['locked_until']) && strtotime($u['locked_until']) > time();
                $isLocked       = $isManualLocked || $isRateLocked;
                $remMin         = $isRateLocked ? (int)ceil((strtotime($u['locked_until']) - time()) / 60) : 0;
                $isMe     = $u['id'] === (int)$_SESSION['user_id'];
            ?>
            <tr>
                <!-- Utilisateur -->
                <td class="fw-semibold">
                    <?= e($u['username']) ?>
                    <?php if ($isMe): ?>
                        <span class="badge bg-secondary ms-1" style="font-size:.6rem"><?= siteLang()==='fr'?'vous':'you' ?></span>
                    <?php endif; ?>
                    <?php if (!empty($u['must_change_password'])): ?>
                        <span class="badge bg-warning text-dark ms-1" style="font-size:.6rem" title="Doit changer son mot de passe"><i class="bi bi-key-fill"></i></span>
                    <?php endif; ?>
                </td>

                <!-- Rôle -->
                <td><span class="badge <?= roleBadgeClass($u['role']) ?>" style="font-size:.7rem"><?= roleLabel($u['role']) ?></span></td>

                <!-- 2FA -->
                <td>
                    <?php if ($u['google_2fa_secret']): ?>
                        <span class="badge bg-success" style="font-size:.7rem"><i class="bi bi-shield-check me-1"></i><?= te('user.2fa.active') ?></span>
                    <?php else: ?>
                        <span class="badge bg-light text-muted border" style="font-size:.7rem"><i class="bi bi-shield-slash me-1"></i><?= te('user.2fa.inactive') ?></span>
                    <?php endif; ?>
                </td>

                <!-- Statut -->
                <td>
                    <?php if ($isMe): ?>
                        <span class="badge bg-success" style="font-size:.7rem"><i class="bi bi-circle-fill me-1"></i><?= te('user.status.connected') ?></span>
                    <?php elseif ($isManualLocked): ?>
                        <span class="badge bg-danger" style="font-size:.7rem"><i class="bi bi-lock-fill me-1"></i><?= te('user.status.locked') ?></span>
                    <?php elseif ($isRateLocked): ?>
                        <span class="badge bg-warning text-dark" style="font-size:.7rem"><i class="bi bi-hourglass-split me-1"></i><?= $remMin ?>min</span>
                    <?php else: ?>
                        <span class="badge bg-light text-muted border" style="font-size:.7rem"><i class="bi bi-check-circle me-1"></i><?= te('user.status.active') ?></span>
                    <?php endif; ?>
                </td>

                <!-- Créé le -->
                <td class="text-muted small"><?= e(substr($u['created_at'] ?? '—', 0, 10)) ?></td>

                <!-- Actions -->
                <td class="text-end pe-2">
                    <div class="btn-group btn-group-sm">

                        <?php if ($u['google_2fa_secret']): ?>
                            <!-- Voir QR 2FA -->
                            <button class="btn btn-outline-primary" data-bs-toggle="modal"
                                    data-bs-target="#modal2FA<?= $u['id'] ?>" title="Voir QR Code 2FA">
                                <i class="bi bi-qr-code"></i>
                            </button>
                            <!-- Désactiver 2FA -->
                            <button class="btn btn-outline-secondary"
                                    data-bs-toggle="modal"
                                    data-bs-target="#modalDis2fa<?= $u['id'] ?>"
                                    title="<?= te('user.2fa.disable_title') ?>">
                                <i class="bi bi-shield-x"></i>
                            </button>
                        <?php else: ?>
                            <!-- Activer 2FA -->
                            <a href="?setup_2fa=<?= $u['id'] ?>&tab=users"
                               class="btn btn-outline-primary" title="Activer 2FA">
                                <i class="bi bi-shield-plus"></i>
                            </a>
                        <?php endif; ?>

                        <?php if (!$isMe): ?>
                            <!-- Définir mot de passe -->
                            <button class="btn btn-outline-secondary" data-bs-toggle="modal"
                                    data-bs-target="#modalSetPw<?= $u['id'] ?>" title="Définir le mot de passe">
                                <i class="bi bi-key"></i>
                            </button>
                            <!-- Changer rôle -->
                            <button class="btn btn-outline-warning" data-bs-toggle="modal"
                                    data-bs-target="#modalRole<?= $u['id'] ?>" title="Changer le rôle">
                                <i class="bi bi-shield-half"></i>
                            </button>
                            <!-- Bloquer / Débloquer -->
                            <?php if ($isLocked): ?>
                                <a href="?unlock_user=<?= $u['id'] ?>&tab=users"
                                   class="btn btn-outline-success" title="<?= te('user.unlock_title') ?>">
                                    <i class="bi bi-unlock-fill"></i>
                                </a>
                            <?php else: ?>
                                <button class="btn btn-outline-danger"
                                        data-bs-toggle="modal"
                                        data-bs-target="#modalLock<?= $u['id'] ?>"
                                        title="<?= te('user.lock_title') ?>">
                                    <i class="bi bi-lock-fill"></i>
                                </button>
                            <?php endif; ?>
                            <?php if ($isRateLocked && !$isManualLocked): ?>
                                <a href="?unlock_user=<?= $u['id'] ?>&tab=users"
                                   class="btn btn-outline-warning btn-sm"
                                   title="Lever le blocage auto (<?= $remMin ?>min)">
                                    <i class="bi bi-hourglass"></i>
                                </a>
                            <?php endif; ?>
                            <!-- Supprimer -->
                            <button class="btn btn-outline-danger"
                                    data-bs-toggle="modal"
                                    data-bs-target="#modalDelete<?= $u['id'] ?>"
                                    title="<?= te('user.delete_title') ?>">
                                <i class="bi bi-trash"></i>
                            </button>
                        <?php endif; ?>
                    </div>
                </td>
            </tr>

            <!-- ── MODALS ────────────────────────────────────────────────────── -->

            <?php if ($u['google_2fa_secret']): ?>
            <div class="modal fade" id="modal2FA<?= $u['id'] ?>" tabindex="-1">
                <div class="modal-dialog modal-sm"><div class="modal-content text-center p-3">
                    <h6 class="fw-bold mb-1"><i class="bi bi-shield-lock me-1"></i>2FA — <?= e($u['username']) ?></h6>
                    <p class="text-muted small mb-2">Scannez avec Google Authenticator, Aegis…</p>
                    <?php
                        $totp = \OTPHP\TOTP::createFromSecret($u['google_2fa_secret']);
                        $totp->setLabel($u['username']);
                        $totp->setIssuer(siteName());
                        $otpUri = $totp->getProvisioningUri();
                        try {
                            $renderer = new \BaconQrCode\Renderer\ImageRenderer(
                                new \BaconQrCode\Renderer\RendererStyle\RendererStyle(200),
                                new \BaconQrCode\Renderer\Image\SvgImageBackEnd()
                            );
                            $qrSvg = (new \BaconQrCode\Writer($renderer))->writeString($otpUri);
                        } catch (\Throwable $e) { $qrSvg = null; }
                    ?>
                    <div class="bg-white p-2 border rounded mb-2 d-inline-block" style="line-height:0">
                        <?php if ($qrSvg): ?>
                            <?= $qrSvg ?>
                        <?php else: ?>
                            <div class="alert alert-warning p-2 small mb-0">QR indisponible</div>
                        <?php endif; ?>
                    </div>
                    <p class="small text-muted mb-1">Secret :</p>
                    <code class="d-block bg-light p-2 mb-3 border rounded user-select-all small"><?= e($u['google_2fa_secret']) ?></code>
                    <button class="btn btn-secondary btn-sm w-100" data-bs-dismiss="modal">Fermer</button>
                </div></div>
            </div>
            <?php endif; ?>

            <?php if (!$isMe): ?>
            <!-- Modal définir mot de passe -->
            <div class="modal fade" id="modalSetPw<?= $u['id'] ?>" tabindex="-1">
                <div class="modal-dialog modal-sm"><div class="modal-content">
                    <form method="POST">
                        <?= csrfField() ?>
                        <input type="hidden" name="target_uid" value="<?= $u['id'] ?>">
                        <div class="modal-header py-2">
                            <h6 class="modal-title small fw-semibold"><i class="bi bi-key me-1"></i>Mot de passe — <?= e($u['username']) ?></h6>
                            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body">
                            <input type="password" name="admin_pw" class="form-control form-control-sm mb-3"
                                   placeholder="<?= te('user.min_pw_chars') ?>" required minlength="4" maxlength="64" autofocus>
                            <div class="form-check form-switch">
                                <input class="form-check-input" type="checkbox" name="must_change"
                                       id="mc<?= $u['id'] ?>" checked>
                                <label class="form-check-label small" for="mc<?= $u['id'] ?>">
                                    <?= te('user.must_change') ?>
                                </label>
                            </div>
                        </div>
                        <div class="modal-footer p-2">
                            <button type="submit" name="set_pw_admin" class="btn btn-primary btn-sm w-100">
                                <i class="bi bi-floppy me-1"></i>Enregistrer
                            </button>
                        </div>
                    </form>
                </div></div>
            </div>

            <!-- Modal changer rôle -->
            <div class="modal fade" id="modalRole<?= $u['id'] ?>" tabindex="-1">
                <div class="modal-dialog modal-sm"><div class="modal-content">
                    <form method="POST">
                        <?= csrfField() ?>
                        <input type="hidden" name="uid" value="<?= $u['id'] ?>">
                        <div class="modal-header py-2">
                            <h6 class="modal-title small fw-semibold"><i class="bi bi-shield-half me-1"></i>Rôle — <?= e($u['username']) ?></h6>
                            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body">
                            <select name="role" class="form-select form-select-sm">
                                <option value="viewer"   <?= $u['role']==='viewer'   ? 'selected' : '' ?>>Viewer — lecture seule</option>
                                <option value="admin"    <?= $u['role']==='admin'    ? 'selected' : '' ?>>Admin — VLANs + IPs</option>
                                <option value="sysadmin" <?= $u['role']==='sysadmin' ? 'selected' : '' ?>>Sysadmin — accès total</option>
                            </select>
                        </div>
                        <div class="modal-footer p-2">
                            <button type="submit" name="change_role" class="btn btn-warning btn-sm w-100">
                                <i class="bi bi-floppy me-1"></i><?= te('action.save') ?>
                            </button>
                        </div>
                    </form>
                </div></div>
            </div>
            <?php endif; ?>

            <!-- ── MODALS CONFIRMATION (nouveaux v1.8) ──────────────────── -->

            <!-- Modal Désactiver 2FA -->
            <?php if ($u['google_2fa_secret']): ?>
            <div class="modal fade" id="modalDis2fa<?= $u['id'] ?>" tabindex="-1">
                <div class="modal-dialog modal-sm"><div class="modal-content">
                    <div class="modal-header py-2 border-0">
                        <h6 class="modal-title fw-semibold"><i class="bi bi-shield-x me-2 text-warning"></i><?= te('user.2fa.disable_title') ?></h6>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body pt-0">
                        <p class="mb-1"><?= str_replace('{user}', '<strong>'.e($u['username']).'</strong>', te('user.2fa.disable_confirm')) ?></p>
                        <div class="alert alert-warning py-2 small mb-0"><i class="bi bi-exclamation-triangle me-1"></i><?= te('user.2fa.disable_warning') ?></div>
                    </div>
                    <div class="modal-footer py-2 gap-2">
                        <button type="button" class="btn btn-sm btn-secondary" data-bs-dismiss="modal"><?= te('action.cancel') ?></button>
                        <a href="?disable_2fa=<?= $u['id'] ?>&tab=users" class="btn btn-sm btn-warning"><?= te('action.yes_disable') ?></a>
                    </div>
                </div></div>
            </div>
            <?php endif; ?>

            <!-- Modal Bloquer user -->
            <?php if (!$isMe && !$isManualLocked): ?>
            <div class="modal fade" id="modalLock<?= $u['id'] ?>" tabindex="-1">
                <div class="modal-dialog modal-sm"><div class="modal-content">
                    <div class="modal-header py-2 border-0">
                        <h6 class="modal-title fw-semibold"><i class="bi bi-lock-fill me-2 text-danger"></i><?= te('user.lock_title') ?></h6>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body pt-0">
                        <p class="mb-1"><?= str_replace('{user}', '<strong>'.e($u['username']).'</strong>', te('user.lock_confirm')) ?></p>
                        <div class="alert alert-danger py-2 small mb-0"><i class="bi bi-exclamation-triangle me-1"></i><?= te('user.lock_warning') ?></div>
                    </div>
                    <div class="modal-footer py-2 gap-2">
                        <button type="button" class="btn btn-sm btn-secondary" data-bs-dismiss="modal"><?= te('action.cancel') ?></button>
                        <a href="?lock_user=<?= $u['id'] ?>&tab=users" class="btn btn-sm btn-danger"><?= te('action.yes_lock') ?></a>
                    </div>
                </div></div>
            </div>
            <?php endif; ?>

            <!-- Modal Supprimer user -->
            <?php if (!$isMe): ?>
            <div class="modal fade" id="modalDelete<?= $u['id'] ?>" tabindex="-1">
                <div class="modal-dialog modal-sm"><div class="modal-content">
                    <div class="modal-header py-2 border-0">
                        <h6 class="modal-title fw-semibold"><i class="bi bi-trash me-2 text-danger"></i><?= te('user.delete_title') ?></h6>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body pt-0">
                        <p class="mb-1"><?= str_replace('{user}', '<strong>'.e($u['username']).'</strong>', te('user.delete_confirm')) ?></p>
                        <div class="alert alert-danger py-2 small mb-0"><i class="bi bi-exclamation-triangle me-1"></i><?= te('user.delete_warning') ?></div>
                    </div>
                    <div class="modal-footer py-2 gap-2">
                        <button type="button" class="btn btn-sm btn-secondary" data-bs-dismiss="modal"><?= te('action.cancel') ?></button>
                        <a href="?delete=<?= $u['id'] ?>&tab=users" class="btn btn-sm btn-danger"><?= te('action.yes_delete') ?></a>
                    </div>
                </div></div>
            </div>
            <?php endif; ?>

            <?php endforeach; ?>
            </tbody>
        </table>
    </div>

<?php elseif($tab==='license'): ?>
    <!-- ══ LICENCE ═══════════════════════════════════════════════════════════ -->
    <div class="row g-4 mb-4">
        <div class="col-md-7">
            <div class="card border-0 h-100" style="background:<?= $lic?'linear-gradient(135deg,#d4edda,#c3e6cb)':'linear-gradient(135deg,#fff3cd,#ffeeba)' ?>">
                <div class="card-body py-3">
                    <div class="d-flex align-items-center gap-3">
                        <div style="font-size:2.2rem"><?= $lic?'<i class="bi bi-patch-check-fill text-success"></i>':'<i class="bi bi-patch-exclamation-fill text-warning"></i>' ?></div>
                        <div>
                            <div class="fw-bold"><?= $lic?'Licence active':'Aucune licence' ?></div>
                            <?php if($lic): ?>
                                <div class="small text-success-emphasis">Titulaire : <strong><?= e($lic['owner']) ?></strong></div>
                                <div class="small text-muted">Activée le <?= e(substr($lic['activated_at'],0,16)) ?></div>
                            <?php else: ?>
                                <div class="small text-warning-emphasis">Entrez une clé ci-dessous.</div>
                            <?php endif; ?>
                        </div>
                    </div>
                    <?php if($lic): ?>
                        <hr class="my-2">
                        <div class="d-flex align-items-center gap-2 flex-wrap">
                            <code class="small user-select-all flex-grow-1"><?= e($lic['key']) ?></code>
                            <button class="btn btn-sm btn-outline-danger" data-bs-toggle="modal" data-bs-target="#modalRevokeLic"><i class="bi bi-x-circle me-1"></i><?= te('lic.revoke') ?></button>
                        </div>
                    <?php endif; ?>

<!-- Modal révoquer licence -->
<div class="modal fade" id="modalRevokeLic" tabindex="-1">
    <div class="modal-dialog modal-sm"><div class="modal-content">
        <div class="modal-header py-2 border-0">
            <h6 class="modal-title fw-semibold"><i class="bi bi-x-circle me-2 text-danger"></i><?= te('lic.revoke_title') ?></h6>
            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
        </div>
        <div class="modal-body pt-0">
            <p class="mb-1"><?= te('lic.revoke_confirm') ?></p>
            <div class="alert alert-danger py-2 small mb-0"><i class="bi bi-exclamation-triangle me-1"></i><?= te('lic.revoke_warning') ?></div>
        </div>
        <div class="modal-footer py-2 gap-2">
            <button type="button" class="btn btn-sm btn-secondary" data-bs-dismiss="modal"><?= te('action.cancel') ?></button>
            <a href="?revoke_license=1&tab=license" class="btn btn-sm btn-danger"><?= te('action.yes_revoke') ?></a>
        </div>
    </div></div>
</div>
                </div>
            </div>
        </div>
        <div class="col-md-5">
            <div class="card border-0 bg-light h-100">
                <div class="card-body py-3 text-center">
                    <div class="text-muted small mb-1">Version</div>
                    <div class="fw-bold fs-5"><?= e(siteName()) ?></div>
                    <span class="badge bg-dark px-3 py-2">v<?= APP_VERSION ?></span>
                    <span class="text-muted small ms-2">build <?= APP_BUILD ?></span>
                    <div class="text-muted small mt-2">© <?= APP_AUTHOR ?></div>
                </div>
            </div>
        </div>
    </div>
    <div class="card border-0 bg-light">
        <div class="card-body py-3">
            <h6 class="fw-semibold mb-3"><i class="bi bi-key-fill me-2 text-primary"></i><?= $lic?'Remplacer':'Activer' ?> la licence</h6>
            <form method="POST" class="row g-3">
                <div class="col-md-5">
                    <label class="form-label small fw-semibold">Titulaire <span class="text-danger">*</span></label>
                    <input type="text" name="owner" class="form-control form-control-sm" required value="<?= e($lic['owner']??'') ?>">
                </div>
                <div class="col-md-5">
                    <label class="form-label small fw-semibold">Clé <span class="text-danger">*</span></label>
                    <input type="text" name="license_key" id="licKey" class="form-control form-control-sm key-input" placeholder="XXXX-XXXX-XXXX-XXXX" maxlength="19" required oninput="formatLicKey(this)" value="<?= e($lic['key']??'') ?>">
                </div>
                <div class="col-md-2 d-flex align-items-end">
                    <button type="submit" name="activate_license" class="btn btn-primary btn-sm w-100"><i class="bi bi-patch-check me-1"></i>Activer</button>
                </div>
            </form>
            <div class="mt-3 pt-3 border-top">
                <div class="text-muted small mb-2"><i class="bi bi-info-circle me-1"></i>Clé de test (cliquez pour remplir) :</div>
                <div class="demo-key text-center py-2 px-3 fw-bold text-primary" onclick="document.getElementById('licKey').value='<?= $demoKey ?>';formatLicKey(document.getElementById('licKey'))"><?= $demoKey ?></div>
            </div>
        </div>
    </div>

    <?php elseif($tab==='site'): ?>
    <!-- ══ SITE ══════════════════════════════════════════════════════════════ -->
    <form method="POST">
        <div class="row g-4">

            <!-- Nom du site + langue -->
            <div class="col-md-6">
                <div class="card border-0 bg-light h-100">
                    <div class="card-body d-flex flex-column gap-4">
                        <div>
                            <h6 class="fw-semibold mb-2"><i class="bi bi-type me-2" style="color:var(--ipam-accent)"></i><?= te('site.name') ?></h6>
                            <input type="text" name="site_name" class="form-control" value="<?= e(siteName()) ?>" placeholder="<?= te('nav.dashboard') ?>" maxlength="40" id="siteNameInput">
                            <div class="form-text"><?= te('site.name_help') ?></div>
                        </div>
                        <div>
                            <h6 class="fw-semibold mb-2"><i class="bi bi-translate me-2" style="color:var(--ipam-accent)"></i><?= te('site.lang') ?></h6>
                            <select name="site_lang" class="form-select form-select-sm">
                                <option value="fr" <?= siteLang()==='fr'?'selected':'' ?>>🇫🇷 Français</option>
                                <option value="en" <?= siteLang()==='en'?'selected':'' ?>>🇬🇧 English</option>
                            </select>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Icône + message d'accueil -->
            <div class="col-md-6">
                <div class="card border-0 bg-light h-100">
                    <div class="card-body d-flex flex-column gap-4">
                        <div>
                            <h6 class="fw-semibold mb-2"><i class="bi bi-grid me-2" style="color:var(--ipam-accent)"></i><?= te('site.icon') ?></h6>
                            <input type="hidden" name="site_icon" id="siteIconInput" value="<?= e(siteIcon()) ?>">
                            <div class="icon-grid mb-2">
                                <?php foreach($siteIcons as $ico): ?>
                                    <div class="icon-opt <?= siteIcon()===$ico?'active':'' ?>" data-icon="<?= $ico ?>" onclick="selectSiteIcon(this)">
                                        <i class="bi bi-<?= $ico ?>"></i>
                                        <span><?= $ico ?></span>
                                    </div>
                                <?php endforeach; ?>
                            </div>
                            <input type="text" id="customIcon" class="form-control form-control-sm mt-1" placeholder="<?= te('site.icon_custom') ?>" value="<?= in_array(siteIcon(),$siteIcons)?'':e(siteIcon()) ?>" oninput="document.getElementById('siteIconInput').value=this.value;updateNavPreview()">
                        </div>
                        <div>
                            <h6 class="fw-semibold mb-2"><i class="bi bi-chat-quote me-2" style="color:var(--ipam-accent)"></i><?= te('site.welcome') ?></h6>
                            <textarea name="site_welcome" class="form-control form-control-sm" rows="2" placeholder="<?= te('site.welcome_ph') ?>" maxlength="200"><?= e(siteWelcome()) ?></textarea>
                            <div class="form-text"><?= te('site.welcome_help') ?></div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Thème -->
            <div class="col-12">
                <div class="card border-0 bg-light">
                    <div class="card-body">
                        <h6 class="fw-semibold mb-3"><i class="bi bi-palette-fill me-2" style="color:var(--ipam-accent)"></i><?= te('site.theme') ?></h6>
                        <input type="hidden" name="site_theme" id="siteThemeInput" value="<?= e(siteTheme()) ?>">
                        <div class="theme-grid">
                            <?php foreach($themes as $slug => $theme): ?>
                            <?php
                                $navBg     = $theme['--ipam-navbar-bg'];
                                $accent    = $theme['--ipam-accent'];
                                $bodyBg    = $theme['--ipam-body-bg'];
                                $theadBg   = $theme['--ipam-thead-bg'];
                                $isActive  = siteTheme() === $slug;
                            ?>
                            <div class="theme-card <?= $isActive ? 'active' : '' ?>"
                                 onclick="selectTheme(this, '<?= $slug ?>')"
                                 id="theme-<?= $slug ?>">
                                <div class="theme-preview">
                                    <div class="theme-preview-nav" style="background:<?= $navBg ?>"></div>
                                    <div class="theme-preview-body" style="background:<?= $bodyBg ?>">
                                        <div class="theme-preview-btn" style="background:<?= $accent ?>"></div>
                                        <div class="theme-preview-btn" style="background:<?= $theadBg ?>;opacity:.7"></div>
                                    </div>
                                </div>
                                <div class="theme-label" style="background:<?= $bodyBg ?>">
                                    <?= $theme['emoji'] ?? '🎨' ?> <?= htmlspecialchars($theme['label']) ?>
                                </div>
                            </div>
                            <?php endforeach; ?>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Aperçu live navbar -->
            <div class="col-12">
                <div class="card border-0" id="navPreviewCard" style="background:<?= getTheme()['--ipam-navbar-bg'] ?>">
                    <div class="card-body py-2 px-3 d-flex align-items-center gap-3">
                        <span class="fw-bold" id="navPreview" style="color:<?= getTheme()['--ipam-navbar-text'] ?>">
                            <i class="bi bi-<?= e(siteIcon()) ?> me-2" id="navIcon" style="color:<?= getTheme()['--ipam-accent'] ?>"></i>
                            <span id="navName"><?= e(siteName()) ?></span>
                        </span>
                        <span class="ms-auto small" style="color:<?= getTheme()['--ipam-navbar-text'] ?>;opacity:.5">← <?= te('site.theme_preview') ?></span>
                    </div>
                </div>
            </div>

        </div>
        <div class="mt-4 d-flex justify-content-end">
            <button type="submit" name="save_site" class="btn btn-primary px-4">
                <i class="bi bi-floppy me-2"></i><?= te('site.save') ?>
            </button>
        </div>
    </form>

    <?php elseif($tab==='database'): ?>
    <!-- ══ BASE DE DONNÉES ═══════════════════════════════════════════════════ --><?php
$dbPath = '/var/www/html/ipam.db';
$dbSize = file_exists($dbPath) ? round(filesize($dbPath)/1024,1).'KB' : 'N/A';
try { $dbTables = db()->query("SELECT COUNT(*) FROM sqlite_master WHERE type='table'")->fetchColumn(); } catch(Exception $e) { $dbTables = '?'; }
$tableNames = ['users','vlans','ips','tags','license','settings','audit_log','login_attempts','vlan_groups','ip_history'];
// Stats pour graphiques
$statsIpStatus = ['used'=>0,'free'=>0,'reserved'=>0];
$statsVlanIps = []; $statsRoles = []; $statsAudit7d = [];
try {
    foreach(['used','free','reserved'] as $st) $statsIpStatus[$st] = (int)db()->query("SELECT COUNT(*) FROM ips WHERE status='$st'")->fetchColumn();
    $vr = db()->query("SELECT v.name, COUNT(i.id) as cnt FROM vlans v LEFT JOIN ips i ON i.vlan_id=v.id GROUP BY v.id ORDER BY cnt DESC LIMIT 10")->fetchAll();
    foreach($vr as $r) $statsVlanIps[] = ['name'=>$r['name'],'count'=>(int)$r['cnt']];
    $rr = db()->query("SELECT role, COUNT(*) as cnt FROM users GROUP BY role")->fetchAll();
    foreach($rr as $r) $statsRoles[$r['role']] = (int)$r['cnt'];
    // Activité 7 jours
    for($d=6;$d>=0;$d--) {
        $date = date('Y-m-d', strtotime("-{$d} days"));
        $cnt  = (int)db()->query("SELECT COUNT(*) FROM audit_log WHERE DATE(created_at)='$date'")->fetchColumn();
        $statsAudit7d[] = ['date'=>date('d/m',strtotime("-{$d} days")),'count'=>$cnt];
    }
} catch(Exception $e) {}

// Explorateur de table
$viewTable  = in_array($_GET['view_table'] ?? '', $tableNames) ? $_GET['view_table'] : null;
$viewRows   = [];
if ($viewTable) {
    try { $viewRows = db()->query("SELECT * FROM $viewTable LIMIT 100")->fetchAll(); } catch(Exception $e) { $viewRows = []; }
}
?>
    <div class="alert alert-warning d-flex gap-3 align-items-start py-2">
        <i class="bi bi-exclamation-triangle-fill flex-shrink-0 mt-1"></i>
        <div class="small"><strong><?= te('db.warning_title') ?></strong> — <?= te('db.warning_msg') ?></div>
    </div>

    <!-- Statistiques rapides -->
    <div class="row g-3 mb-4">
        <div class="col-sm-4">
            <div class="card border-0 bg-light text-center py-3">
                <div class="text-muted small"><?= te('db.file') ?></div>
                <code class="small">/var/www/html/ipam.db</code>
            </div>
        </div>
        <div class="col-sm-4">
            <div class="card border-0 bg-light text-center py-3">
                <div class="text-muted small"><?= te('db.size') ?></div>
                <strong><?= $dbSize ?></strong>
            </div>
        </div>
        <div class="col-sm-4">
            <div class="card border-0 bg-light text-center py-3">
                <div class="text-muted small"><?= te('db.tables') ?></div>
                <strong><?= $dbTables ?> tables</strong>
            </div>
        </div>
    </div>

    <div class="row g-4">
    <!-- Col gauche : Migration + Backup + Cleanup -->
    <div class="col-md-5">

        <!-- Migration -->
        <div class="card border-0 bg-light mb-3" style="border-left:4px solid #dc3545!important">
            <div class="card-body p-3">
                <h6 class="fw-semibold mb-1"><i class="bi bi-database-gear me-2 text-danger"></i><?= te('db.migrate_title') ?></h6>
                <p class="text-muted small mb-2"><?= te('db.migrate_desc') ?></p>
                <button class="btn btn-sm btn-danger" data-bs-toggle="modal" data-bs-target="#modalMigrateDB">
                    <i class="bi bi-database-gear me-1"></i><?= te('db.migrate_btn') ?>
                </button>
            </div>
        </div>

        <!-- Backup -->
        <div class="card border-0 bg-light mb-3">
            <div class="card-body p-3">
                <h6 class="fw-semibold mb-1"><i class="bi bi-download me-2 text-success"></i><?= te('db.backup_title') ?></h6>
                <p class="text-muted small mb-2"><?= te('db.backup_desc') ?></p>
                <div class="d-flex gap-2 flex-wrap">
                    <a href="?tab=database&db_backup=1" class="btn btn-sm btn-success">
                        <i class="bi bi-download me-1"></i><?= te('db.backup_btn') ?>
                    </a>
                    <button class="btn btn-sm btn-outline-secondary" data-bs-toggle="modal" data-bs-target="#modalRestore">
                        <i class="bi bi-upload me-1"></i><?= te('db.restore_btn') ?>
                    </button>
                </div>
            </div>
        </div>

        <!-- Nettoyage -->
        <div class="card border-0 bg-light mb-3">
            <div class="card-body p-3">
                <h6 class="fw-semibold mb-1"><i class="bi bi-stars me-2 text-info"></i><?= te('db.cleanup_title') ?></h6>
                <p class="text-muted small mb-2"><?= te('db.cleanup_orphans_desc') ?></p>
                <button class="btn btn-sm btn-outline-info" data-bs-toggle="modal" data-bs-target="#modalCleanup">
                    <i class="bi bi-trash3 me-1"></i><?= te('db.cleanup_orphans') ?>
                </button>
            </div>
        </div>

        <!-- État des tables -->
        <div class="card border-0 bg-light">
            <div class="card-body p-3">
                <h6 class="fw-semibold mb-2"><i class="bi bi-table me-2 text-primary"></i><?= te('db.tables_state') ?></h6>
                <table class="table table-sm mb-0" style="font-size:.82rem">
                    <thead class="table-light"><tr><th><?= te('db.table') ?></th><th class="text-end"><?= te('db.rows') ?></th></tr></thead>
                    <tbody>
                    <?php foreach($tableNames as $t): try { $cnt = db()->query("SELECT COUNT(*) FROM $t")->fetchColumn(); ?>
                        <tr><td><code><?= $t ?></code></td><td class="text-end"><span class="badge bg-secondary"><?= $cnt ?></span></td></tr>
                    <?php } catch(Exception $e) { ?>
                        <tr><td><code class="text-muted"><?= $t ?></code></td><td class="text-end"><span class="badge bg-light text-muted border"><?= te('db.absent') ?></span></td></tr>
                    <?php } endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Col droite : Graphiques -->
    <div class="col-md-7">
        <div class="card border-0 bg-light mb-3">
            <div class="card-body p-3">
                <h6 class="fw-semibold mb-3"><i class="bi bi-bar-chart-fill me-2 text-primary"></i><?= te('db.charts_title') ?></h6>
                <div class="row g-3">
                    <!-- IPs par statut -->
                    <div class="col-6">
                        <p class="text-muted small mb-1 fw-semibold"><?= te('db.chart_ips_status') ?></p>
                        <canvas id="chartIpStatus" height="140"></canvas>
                    </div>
                    <!-- Users par rôle -->
                    <div class="col-6">
                        <p class="text-muted small mb-1 fw-semibold"><?= te('db.chart_roles') ?></p>
                        <canvas id="chartRoles" height="140"></canvas>
                    </div>
                    <!-- IPs par VLAN -->
                    <div class="col-12">
                        <p class="text-muted small mb-1 fw-semibold"><?= te('db.chart_vlans_ips') ?></p>
                        <canvas id="chartVlans" height="110"></canvas>
                    </div>
                    <!-- Activité audit 7j -->
                    <div class="col-12">
                        <p class="text-muted small mb-1 fw-semibold"><?= te('db.chart_audit') ?></p>
                        <canvas id="chartAudit" height="80"></canvas>
                    </div>
                </div>
            </div>
        </div>

        <!-- Explorateur de tables -->
        <div class="card border-0 bg-light">
            <div class="card-body p-3">
                <h6 class="fw-semibold mb-2"><i class="bi bi-search me-2 text-secondary"></i><?= te('db.view_title') ?></h6>
                <form method="GET" class="d-flex gap-2 mb-3">
                    <input type="hidden" name="tab" value="database">
                    <select name="view_table" class="form-select form-select-sm">
                        <option value=""><?= te('db.view_select') ?></option>
                        <?php foreach($tableNames as $t): ?>
                        <option value="<?= $t ?>" <?= $viewTable===$t?'selected':'' ?>><?= $t ?></option>
                        <?php endforeach; ?>
                    </select>
                    <button type="submit" class="btn btn-sm btn-outline-secondary"><?= te('db.view_btn') ?></button>
                </form>
                <?php if ($viewTable && !empty($viewRows)): ?>
                <div class="table-responsive" style="max-height:250px;overflow-y:auto">
                    <table class="table table-sm table-bordered mb-0" style="font-size:.72rem">
                        <thead class="table-dark sticky-top">
                            <tr><?php foreach(array_keys($viewRows[0]) as $col): ?><th><?= e($col) ?></th><?php endforeach; ?></tr>
                        </thead>
                        <tbody>
                        <?php foreach($viewRows as $row): ?>
                            <tr><?php foreach($row as $v): ?><td title="<?= e((string)$v) ?>"><?= e(mb_strimwidth((string)$v,0,40,'…')) ?></td><?php endforeach; ?></tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
                <p class="text-muted small mt-1 mb-0">Affichage limité à 100 lignes.</p>
                <?php elseif ($viewTable): ?>
                    <div class="text-muted small text-center py-3">Aucune donnée ou table absente.</div>
                <?php endif; ?>
            </div>
        </div>
    </div>
    </div>

    <!-- MODALS Base de données -->
    <div class="modal fade" id="modalMigrateDB" tabindex="-1">
        <div class="modal-dialog modal-sm"><div class="modal-content">
            <div class="modal-header py-2 border-0">
                <h6 class="modal-title fw-semibold"><i class="bi bi-database-gear me-2 text-danger"></i><?= te('db.migrate_title') ?></h6>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body pt-0">
                <p class="mb-1"><?= te('db.migrate_confirm') ?></p>
                <div class="alert alert-warning py-2 small mb-0"><i class="bi bi-exclamation-triangle me-1"></i><?= te('db.migrate_warning') ?></div>
            </div>
            <div class="modal-footer py-2 gap-2">
                <button type="button" class="btn btn-sm btn-secondary" data-bs-dismiss="modal"><?= te('action.cancel') ?></button>
                <a href="db_init.php" class="btn btn-sm btn-danger"><?= te('action.yes_run') ?></a>
            </div>
        </div></div>
    </div>

    <div class="modal fade" id="modalRestore" tabindex="-1">
        <div class="modal-dialog modal-sm"><div class="modal-content">
            <form method="POST" enctype="multipart/form-data">
                <?= csrfField() ?>
                <div class="modal-header py-2 border-0">
                    <h6 class="modal-title fw-semibold"><i class="bi bi-upload me-2 text-warning"></i><?= te('db.restore_btn') ?></h6>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body pt-0">
                    <input type="file" name="restore_file" class="form-control form-control-sm mb-2" accept=".db" required>
                    <div class="alert alert-danger py-2 small mb-0"><i class="bi bi-exclamation-triangle me-1"></i><?= te('db.restore_warning') ?></div>
                </div>
                <div class="modal-footer py-2 gap-2">
                    <button type="button" class="btn btn-sm btn-secondary" data-bs-dismiss="modal"><?= te('action.cancel') ?></button>
                    <button type="submit" name="db_restore" class="btn btn-sm btn-warning"><?= te('action.yes_restore') ?></button>
                </div>
            </form>
        </div></div>
    </div>

    <div class="modal fade" id="modalCleanup" tabindex="-1">
        <div class="modal-dialog modal-sm"><div class="modal-content">
            <div class="modal-header py-2 border-0">
                <h6 class="modal-title fw-semibold"><i class="bi bi-stars me-2 text-info"></i><?= te('db.cleanup_title') ?></h6>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body pt-0">
                <p class="mb-1"><?= te('db.cleanup_confirm') ?></p>
                <div class="alert alert-warning py-2 small mb-0"><i class="bi bi-exclamation-triangle me-1"></i><?= te('db.cleanup_warning') ?></div>
            </div>
            <div class="modal-footer py-2 gap-2">
                <button type="button" class="btn btn-sm btn-secondary" data-bs-dismiss="modal"><?= te('action.cancel') ?></button>
                <form method="POST" style="display:inline"><?= csrfField() ?><button type="submit" name="db_cleanup" class="btn btn-sm btn-info text-white"><?= te('action.yes_purge') ?></button></form>
            </div>
        </div></div>
    </div>

    <?php endif; ?>

    <?php if ($tab === 'audit'): ?>
    <!-- ══ JOURNAL D'AUDIT ═══════════════════════════════════════════════════ -->
    <div class="d-flex justify-content-between align-items-center mb-3 flex-wrap gap-2">
        <h6 class="fw-bold mb-0">
            <i class="bi bi-journal-text me-2 text-primary"></i>
            <?= te('audit.title') ?>
            <span class="badge bg-secondary ms-1"><?= number_format($auditTotal) ?> <?= te('audit.entries') ?></span>
        </h6>
        <div class="d-flex gap-2 flex-wrap">
            <a href="?tab=audit&export_audit=csv" class="btn btn-sm btn-outline-success">
                <i class="bi bi-filetype-csv me-1"></i><?= te('audit.export_csv') ?>
            </a>
            <a href="?tab=audit&export_audit=json" class="btn btn-sm btn-outline-primary">
                <i class="bi bi-filetype-json me-1"></i><?= te('audit.export_json') ?>
            </a>
            <button class="btn btn-sm btn-outline-warning" data-bs-toggle="modal" data-bs-target="#modalAuditRetention">
                <i class="bi bi-clock-history me-1"></i><?= te('audit.retention_title') ?>
                <?php if ($auditRetention > 0): ?><span class="badge bg-warning text-dark"><?= $auditRetention ?>j</span><?php endif; ?>
            </button>
        </div>
    </div>
    <form class="d-flex gap-2 mb-3" method="GET">
        <input type="hidden" name="tab" value="audit">
        <input type="text" name="af" class="form-control form-control-sm"
               placeholder="<?= te('audit.filter') ?>"
               value="<?= e($_GET['af'] ?? '') ?>" style="max-width:280px">
        <button class="btn btn-sm btn-outline-secondary" type="submit"><i class="bi bi-search"></i></button>
        <?php if (!empty($_GET['af'])): ?>
            <a href="?tab=audit" class="btn btn-sm btn-outline-danger"><i class="bi bi-x"></i></a>
        <?php endif; ?>
    </form>

    <?php if (empty($auditLogs)): ?>
        <div class="text-center text-muted py-5">
            <i class="bi bi-journal-x" style="font-size:2.5rem;opacity:.3"></i>
            <p class="mt-2 small"><?= te('audit.empty') ?></p>
        </div>
    <?php else: ?>
    <div class="table-responsive">
        <table class="table table-hover table-sm align-middle mb-0" style="font-size:.82rem">
            <thead class="table-dark">
                <tr>
                    <th style="width:145px"><?= te('audit.date') ?></th>
                    <th style="width:100px"><?= te('audit.user') ?></th>
                    <th style="width:140px"><?= te('audit.action') ?></th>
                    <th><?= te('audit.target') ?></th>
                    <th><?= te('audit.detail') ?></th>
                    <th style="width:105px"><?= te('audit.ip') ?></th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($auditLogs as $log):
                $ac = match(true) {
                    str_contains($log['action'], 'delete') || str_contains($log['action'], 'lock')  => 'text-danger fw-semibold',
                    str_contains($log['action'], 'create') || str_contains($log['action'], 'login') && !str_contains($log['action'], 'fail') => 'text-success',
                    str_contains($log['action'], 'fail')  => 'text-warning fw-semibold',
                    str_contains($log['action'], 'export') || str_contains($log['action'], 'import') => 'text-info',
                    default => 'text-muted',
                };
            ?>
            <tr>
                <td class="text-muted small"><?= e($log['created_at']) ?></td>
                <td><span class="badge bg-secondary"><?= e($log['username']) ?></span></td>
                <td><code class="<?= $ac ?>"><?= e($log['action']) ?></code></td>
                <td class="fw-semibold"><?= e($log['target']) ?></td>
                <td class="text-muted small"><?= e($log['detail']) ?></td>
                <td class="text-muted" style="font-size:.75rem"><?= e($log['ip_address']) ?></td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <?php if (isset($auditTotalPages) && $auditTotalPages > 1): ?>
    <nav class="mt-3 d-flex justify-content-between align-items-center">
        <span class="text-muted small"><?= $auditTotal ?> entrées — page <?= $auditPage ?>/<?= $auditTotalPages ?></span>
        <ul class="pagination pagination-sm mb-0">
            <li class="page-item <?= $auditPage <= 1 ? 'disabled' : '' ?>">
                <a class="page-link" href="?tab=audit&apage=<?= $auditPage - 1 ?><?= !empty($_GET['af']) ? '&af='.urlencode($_GET['af']) : '' ?>">«</a>
            </li>
            <?php for ($pi = max(1, $auditPage - 2); $pi <= min($auditTotalPages, $auditPage + 2); $pi++): ?>
            <li class="page-item <?= $pi === $auditPage ? 'active' : '' ?>">
                <a class="page-link" href="?tab=audit&apage=<?= $pi ?><?= !empty($_GET['af']) ? '&af='.urlencode($_GET['af']) : '' ?>"><?= $pi ?></a>
            </li>
            <?php endfor; ?>
            <li class="page-item <?= $auditPage >= $auditTotalPages ? 'disabled' : '' ?>">
                <a class="page-link" href="?tab=audit&apage=<?= $auditPage + 1 ?><?= !empty($_GET['af']) ? '&af='.urlencode($_GET['af']) : '' ?>">»</a>
            </li>
        </ul>
    </nav>
    <?php endif; ?>
    <?php endif; ?>
    <!-- Modal Rétention Audit -->
    <div class="modal fade" id="modalAuditRetention" tabindex="-1">
        <div class="modal-dialog"><div class="modal-content">
            <div class="modal-header py-2 border-0">
                <h6 class="modal-title fw-semibold"><i class="bi bi-clock-history me-2 text-warning"></i><?= te('audit.retention_title') ?></h6>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <form method="POST" id="formRetention">
                    <?= csrfField() ?>
                    <p class="text-muted small mb-3"><?= te('audit.retention_label') ?></p>
                    <div class="d-flex flex-wrap gap-2 mb-3">
                        <?php foreach([
                            '30'  => te('audit.retention_30'),
                            '90'  => te('audit.retention_90'),
                            '180' => te('audit.retention_180'),
                            '365' => te('audit.retention_365'),
                            '0'   => te('audit.retention_forever'),
                        ] as $val => $label): ?>
                        <button type="button" class="btn btn-sm <?= $auditRetention==$val ? 'btn-primary' : 'btn-outline-secondary' ?> retention-preset"
                                data-days="<?= $val ?>"><?= $label ?></button>
                        <?php endforeach; ?>
                    </div>
                    <div class="input-group input-group-sm mb-3">
                        <span class="input-group-text"><?= te('audit.retention_custom') ?></span>
                        <input type="number" name="audit_retention_days" id="retentionDays"
                               class="form-control" min="0" max="3650"
                               value="<?= (int)$auditRetention ?>">
                        <span class="input-group-text">jours (0 = indéfini)</span>
                    </div>
                    <button type="submit" name="save_audit_retention" class="btn btn-sm btn-primary">
                        <i class="bi bi-floppy me-1"></i><?= te('audit.retention_save') ?>
                    </button>
                </form>
                <hr>
                <form method="POST">
                    <?= csrfField() ?>
                    <p class="small fw-semibold mb-2 text-danger"><i class="bi bi-trash me-1"></i><?= te('audit.purge_btn') ?></p>
                    <div class="input-group input-group-sm mb-2">
                        <span class="input-group-text">Purger logs de plus de</span>
                        <input type="number" name="purge_days" class="form-control" min="1" value="<?= max(1,(int)$auditRetention) ?: 30 ?>">
                        <span class="input-group-text">jours</span>
                    </div>
                    <div class="alert alert-danger py-2 small mb-2"><i class="bi bi-exclamation-triangle me-1"></i><?= te('audit.purge_warning') ?></div>
                    <button type="submit" name="purge_audit" class="btn btn-sm btn-danger"
                            onclick="return confirm('<?= te('audit.purge_confirm') ?>')">
                        <i class="bi bi-trash me-1"></i><?= te('audit.purge_btn') ?>
                    </button>
                </form>
            </div>
        </div></div>
    </div>
    <?php endif; // audit ?>

    <?php if ($tab === 'security'): ?>
    <!-- ══ SÉCURITÉ ═══════════════════════════════════════════════════════════ -->
    <h6 class="fw-bold mb-4"><i class="bi bi-shield-lock me-2 text-primary"></i><?= te('pw.policy') ?></h6>

    <form method="POST" class="row g-4">
        <?= csrfField() ?>
        <!-- Longueur -->
        <div class="col-12">
            <div class="card border-0 bg-light">
                <div class="card-body p-3">
                    <h6 class="fw-semibold small mb-3"><i class="bi bi-rulers me-1"></i><?= te('pw.length_section') ?></h6>
                    <div class="row g-3">
                        <div class="col-6">
                            <label class="form-label small fw-semibold"><?= te('pw.min') ?></label>
                            <div class="input-group input-group-sm">
                                <input type="number" name="pw_min_length" class="form-control"
                                       value="<?= (int)$pwPolicy['pw_min_length'] ?>"
                                       min="1" max="64" required>
                                <span class="input-group-text">chars</span>
                            </div>
                            <small class="text-muted"><?= te('pw.min_help') ?></small>
                        </div>
                        <div class="col-6">
                            <label class="form-label small fw-semibold"><?= te('pw.max') ?></label>
                            <div class="input-group input-group-sm">
                                <input type="number" name="pw_max_length" class="form-control"
                                       value="<?= (int)$pwPolicy['pw_max_length'] ?>"
                                       min="1" max="64" required>
                                <span class="input-group-text">chars</span>
                            </div>
                            <small class="text-muted"><?= te('pw.max_help') ?></small>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Complexité -->
        <div class="col-12">
            <div class="card border-0 bg-light">
                <div class="card-body p-3">
                    <h6 class="fw-semibold small mb-3"><i class="bi bi-shield-check me-1"></i><?= te('pw.complexity_section') ?></h6>
                    <div class="d-flex flex-column gap-2">
                        <?php foreach ([
                            0 => ['Aucune',                          'text-muted',   'bi-circle'],
                            1 => ['Majuscule + minuscule',           'text-info',    'bi-check-circle'],
                            2 => ['Majuscule + minuscule + chiffre', 'text-warning', 'bi-check-circle-fill'],
                            3 => ['Tout + caractère spécial',        'text-danger',  'bi-shield-fill'],
                        ] as $val => [$label, $col, $icon]): ?>
                        <div class="form-check">
                            <input class="form-check-input" type="radio" name="pw_complexity"
                                   id="cplx<?= $val ?>" value="<?= $val ?>"
                                   <?= (int)$pwPolicy['pw_complexity'] === $val ? 'checked' : '' ?>>
                            <label class="form-check-label small" for="cplx<?= $val ?>">
                                <i class="bi <?= $icon ?> <?= $col ?> me-1"></i><?= $label ?>
                            </label>
                        </div>
                        <?php endforeach; ?>
                    </div>
                </div>
            </div>
        </div>

        <!-- Expiration -->
        <div class="col-12">
            <div class="card border-0 bg-light">
                <div class="card-body p-3">
                    <h6 class="fw-semibold small mb-3"><i class="bi bi-clock-history me-1"></i><?= te('pw.expiry_section') ?></h6>
                    <div class="row g-3 align-items-end">
                        <div class="col-6">
                            <label class="form-label small fw-semibold"><?= te('pw.expiry') ?></label>
                            <div class="input-group input-group-sm">
                                <input type="number" name="pw_expiry_days" class="form-control"
                                       value="<?= (int)$pwPolicy['pw_expiry_days'] ?>" min="0" max="3650">
                                <span class="input-group-text">jours</span>
                            </div>
                            <small class="text-muted"><?= te('pw.expiry_help') ?></small>
                        </div>
                        <div class="col-6 text-muted small">
                            <?php if ((int)$pwPolicy['pw_expiry_days'] > 0): ?>
                                <?= str_replace('{n}', (string)(int)$pwPolicy['pw_expiry_days'], te('pw.expiry_info')) ?>
                            <?php else: ?>
                                <?= te('pw.expiry.never') ?>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="col-12">
            <button type="submit" name="save_pw_policy" class="btn btn-primary"><i class="bi bi-floppy me-1"></i><?= te('pw.save_policy') ?></button>
        </div>
    </form>
    <?php endif; // security ?>

    </div><!-- /card-body -->
    </div><!-- /card -->
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script>
// ── Licence ──────────────────────────────────────────────────────────────────
function formatLicKey(input) {
    let val = input.value.replace(/[^A-Za-z0-9]/g,'').toUpperCase();
    let out = '';
    for (let i=0;i<val.length&&i<16;i++) { if(i>0&&i%4===0) out+='-'; out+=val[i]; }
    input.value = out;
}

// ── Données des thèmes pour l'aperçu live ────────────────────────────────────
const THEMES = <?php
    $jsThemes = [];
    foreach ($themes as $slug => $theme) {
        $jsThemes[$slug] = [
            'navBg'   => $theme['--ipam-navbar-bg'],
            'navText' => $theme['--ipam-navbar-text'],
            'accent'  => $theme['--ipam-accent'],
            'bodyBg'  => $theme['--ipam-body-bg'],
        ];
    }
    echo json_encode($jsThemes);
?>;

function selectTheme(el, slug) {
    // Activer la carte sélectionnée
    document.querySelectorAll('.theme-card').forEach(x => x.classList.remove('active'));
    el.classList.add('active');
    document.getElementById('siteThemeInput').value = slug;

    // Mettre à jour l'aperçu navbar
    const t = THEMES[slug];
    if (!t) return;
    const card = document.getElementById('navPreviewCard');
    card.style.background = t.navBg;
    document.getElementById('navPreview').style.color = t.navText;
    document.getElementById('navIcon').style.color    = t.accent;
    const subtitleEl = card.querySelector('.ms-auto');
    if (subtitleEl) subtitleEl.style.color = t.navText;
}

// ── Icône ─────────────────────────────────────────────────────────────────────
function selectSiteIcon(el) {
    document.querySelectorAll('.icon-opt').forEach(x => x.classList.remove('active'));
    el.classList.add('active');
    const icon = el.dataset.icon;
    document.getElementById('siteIconInput').value = icon;
    const customEl = document.getElementById('customIcon');
    if (customEl) customEl.value = '';
    updateNavPreview();
}

function updateNavPreview() {
    const icon = document.getElementById('siteIconInput')?.value || 'hdd-network-fill';
    const navIcon = document.getElementById('navIcon');
    if (navIcon) {
        navIcon.className = 'bi bi-' + icon + ' me-2';
        // garder la couleur du thème actif
        const slug = document.getElementById('siteThemeInput')?.value || 'default';
        const t = THEMES[slug];
        if (t) navIcon.style.color = t.accent;
    }
}

// ── Nom ───────────────────────────────────────────────────────────────────────
document.getElementById('siteNameInput')?.addEventListener('input', function() {
    const el = document.getElementById('navName');
    if (el) el.textContent = this.value || '…';
});

// ── Rétention : presets ───────────────────────────────────────────────────────
document.querySelectorAll('.retention-preset').forEach(btn => {
    btn.addEventListener('click', function() {
        document.querySelectorAll('.retention-preset').forEach(b => {
            b.classList.remove('btn-primary'); b.classList.add('btn-outline-secondary');
        });
        this.classList.remove('btn-outline-secondary'); this.classList.add('btn-primary');
        document.getElementById('retentionDays').value = this.dataset.days;
    });
});
</script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js"></script>
<script>
// ── Graphiques ────────────────────────────────────────────────────────────────
const ipStatusData = <?= json_encode(array_values($statsIpStatus ?? [])) ?>;
const ipStatusLabels = ['Utilisées','Libres','Réservées'];
const vlanIpsData   = <?= json_encode($statsVlanIps ?? []) ?>;
const rolesData     = <?= json_encode($statsRoles ?? []) ?>;
const auditData     = <?= json_encode($statsAudit7d ?? []) ?>;
const accent        = getComputedStyle(document.documentElement).getPropertyValue('--ipam-accent').trim() || '#0d6efd';

if (document.getElementById('chartIpStatus')) {
    new Chart('chartIpStatus', { type:'doughnut', data:{
        labels: ipStatusLabels,
        datasets:[{data: ipStatusData,
            backgroundColor:['#dc3545','#198754','#ffc107'],
            borderWidth:2}]
    }, options:{plugins:{legend:{position:'bottom',labels:{font:{size:10}}}},cutout:'60%'}});
}
if (document.getElementById('chartRoles')) {
    new Chart('chartRoles', { type:'doughnut', data:{
        labels: Object.keys(rolesData),
        datasets:[{data: Object.values(rolesData),
            backgroundColor:['#6f42c1','#0d6efd','#6c757d'],
            borderWidth:2}]
    }, options:{plugins:{legend:{position:'bottom',labels:{font:{size:10}}}},cutout:'60%'}});
}
if (document.getElementById('chartVlans') && vlanIpsData.length) {
    new Chart('chartVlans', { type:'bar', data:{
        labels: vlanIpsData.map(v=>v.name),
        datasets:[{label:'IPs',data: vlanIpsData.map(v=>v.count),
            backgroundColor: accent+'cc', borderRadius:4}]
    }, options:{plugins:{legend:{display:false}},scales:{y:{beginAtZero:true,ticks:{stepSize:1}}}}});
}
if (document.getElementById('chartAudit') && auditData.length) {
    new Chart('chartAudit', { type:'line', data:{
        labels: auditData.map(d=>d.date),
        datasets:[{label:'Actions',data: auditData.map(d=>d.count),
            borderColor: accent, backgroundColor: accent+'22',
            fill:true, tension:.3, pointRadius:3}]
    }, options:{plugins:{legend:{display:false}},scales:{y:{beginAtZero:true,ticks:{stepSize:1}}}}});
}
</script>
<?php renderFooterReal(); ?>
</body>
</html>