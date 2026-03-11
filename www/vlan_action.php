<?php
include('auth.php');
if (!$isAdmin) redirect('index.php', 'Accès refusé.', 'danger');

$db = db();

// ─── CSRF ────────────────────────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrfVerify('index.php');
}

// ─── AJOUT ──────────────────────────────────────────────────────────────────
if (isset($_POST['add_vlan'])) {
    $vid  = (int)($_POST['vid']  ?? 0);
    $name = trim($_POST['name'] ?? '');
    $sub  = trim($_POST['subnet'] ?? '');
    $desc = trim($_POST['description'] ?? '');

    if ($vid < 1 || $vid > 4094 || !$name || !$sub) {
        redirect('index.php', 'Données invalides pour la création du VLAN.', 'danger');
    }

    $subCheck = validateSubnet($sub);
    if ($subCheck !== true) {
        redirect('index.php', "Subnet invalide : $subCheck", 'danger');
    }

    try {
        $db->prepare("INSERT INTO vlans (vid, name, subnet, description, updated_at) VALUES (?,?,?,?,CURRENT_TIMESTAMP)")
           ->execute([$vid, $name, $sub, $desc]);
        redirect('index.php', "VLAN $vid — $name créé avec succès.");
    } catch (Exception $e) {
        redirect('index.php', "Erreur : le VID $vid existe peut-être déjà.", 'danger');
    }
}

// ─── MODIFICATION ────────────────────────────────────────────────────────────
if (isset($_POST['edit_vlan'])) {
    $id   = (int)($_POST['id']  ?? 0);
    $vid  = (int)($_POST['vid'] ?? 0);
    $name = trim($_POST['name']   ?? '');
    $sub  = trim($_POST['subnet'] ?? '');
    $desc = trim($_POST['description'] ?? '');

    if (!$id || $vid < 1 || $vid > 4094 || !$name || !$sub) {
        redirect('index.php', 'Données invalides pour la modification.', 'danger');
    }

    $subCheck = validateSubnet($sub);
    if ($subCheck !== true) {
        redirect('index.php', "Subnet invalide : $subCheck", 'danger');
    }

    try {
        $db->prepare("UPDATE vlans SET vid=?, name=?, subnet=?, description=?, updated_at=CURRENT_TIMESTAMP WHERE id=?")
           ->execute([$vid, $name, $sub, $desc, $id]);
        redirect('index.php', "VLAN mis à jour.");
    } catch (Exception $e) {
        redirect('index.php', "Erreur lors de la mise à jour.", 'danger');
    }
}

// ─── SUPPRESSION ─────────────────────────────────────────────────────────────
if (isset($_GET['delete'])) {
    $id = (int)$_GET['delete'];
    $vlan = $db->prepare("SELECT * FROM vlans WHERE id=?");
    $vlan->execute([$id]);
    $v = $vlan->fetch();
    if (!$v) redirect('index.php', 'VLAN introuvable.', 'danger');

    $db->prepare("DELETE FROM vlans WHERE id=?")->execute([$id]);
    redirect('index.php', "VLAN {$v['vid']} — {$v['name']} supprimé.");
}

redirect('index.php');
