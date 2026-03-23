<?php
include('auth.php');
$db = db();

$vlanId = (int)($_GET['id'] ?? 0);
if (!$vlanId) redirect('index.php', 'VLAN non spécifié.', 'danger');

$stmt = $db->prepare("SELECT * FROM vlans WHERE id = ?");
$stmt->execute([$vlanId]);
$vlan = $stmt->fetch();
if (!$vlan) redirect('index.php', 'VLAN introuvable.', 'danger');

$errors = [];

// ─── EXPORT CSV ──────────────────────────────────────────────────────────────
if (isset($_GET['export']) && $_GET['export'] === 'csv') {
    $rows = $db->prepare("SELECT ip_address,hostname,domain,tag,status,description FROM ips WHERE vlan_id=? ORDER BY ip_address ASC");
    $rows->execute([$vlanId]);
    audit('ip.export', "VLAN {$vlan['name']}", 'Export CSV');
    header('Content-Type: text/csv; charset=UTF-8');
    header('Content-Disposition: attachment; filename="vlan_' . $vlan['vid'] . '_' . preg_replace('/[^a-z0-9]/i','_',$vlan['name']) . '_ips.csv"');
    header('Cache-Control: no-cache');
    $out = fopen('php://output', 'w');
    fprintf($out, chr(0xEF).chr(0xBB).chr(0xBF)); // BOM UTF-8 pour Excel
    fputcsv($out, ['IP Address','Hostname','Domain','Tag','Status','Description'], ';');
    foreach ($rows->fetchAll() as $r) {
        fputcsv($out, [$r['ip_address'],$r['hostname'],$r['domain'],$r['tag'],$r['status'],$r['description']], ';');
    }
    fclose($out);
    exit;
}

// ─── EXPORT JSON ─────────────────────────────────────────────────────────────
if (isset($_GET['export']) && $_GET['export'] === 'json') {
    $rows = $db->prepare("SELECT ip_address,hostname,domain,tag,status,description FROM ips WHERE vlan_id=? ORDER BY ip_address ASC");
    $rows->execute([$vlanId]);
    audit('ip.export', "VLAN {$vlan['name']}", 'Export JSON');
    header('Content-Type: application/json; charset=UTF-8');
    header('Content-Disposition: attachment; filename="vlan_' . $vlan['vid'] . '_ips.json"');
    echo json_encode([
        'vlan'  => ['id'=>$vlan['id'],'vid'=>$vlan['vid'],'name'=>$vlan['name'],'subnet'=>$vlan['subnet']],
        'ips'   => $rows->fetchAll(),
        'exported_at' => date('c'),
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    exit;
}

// ─── PING IP (AJAX) ───────────────────────────────────────────────────────────
if (isset($_GET['ping']) && $isAdmin) {
    header('Content-Type: application/json');
    $ipToPing = $_GET['ping'];
    if (!filter_var($ipToPing, FILTER_VALIDATE_IP)) {
        echo json_encode(['status'=>'error','msg'=>'IP invalide']);
        exit;
    }
    // Vérifier que l'IP appartient bien à ce VLAN (sécurité)
    $chk = $db->prepare("SELECT id FROM ips WHERE ip_address=? AND vlan_id=?");
    $chk->execute([$ipToPing, $vlanId]);
    if (!$chk->fetch()) {
        echo json_encode(['status'=>'error','msg'=>'IP non trouvée dans ce VLAN']);
        exit;
    }
    $cmd    = PHP_OS_FAMILY === 'Windows'
              ? 'ping -n 1 -w 1000 ' . escapeshellarg($ipToPing)
              : 'ping -c 1 -W 1 '    . escapeshellarg($ipToPing);
    exec($cmd . ' 2>&1', $output, $retcode);
    echo json_encode([
        'status' => $retcode === 0 ? 'up' : 'down',
        'ip'     => $ipToPing,
        'msg'    => $retcode === 0 ? 'Hôte joignable' : 'Hôte injoignable',
    ]);
    exit;
}

// ─── HISTORIQUE IP (AJAX) ────────────────────────────────────────────────────
if (isset($_GET['ip_history'])) {
    header('Content-Type: application/json');
    $ipId = (int)$_GET['ip_history'];
    try {
        $h = $db->prepare("SELECT * FROM ip_history WHERE ip_id=? ORDER BY changed_at DESC LIMIT 50");
        $h->execute([$ipId]);
        echo json_encode(['ok'=>true,'rows'=>$h->fetchAll()]);
    } catch(Exception $e) { echo json_encode(['ok'=>false,'rows',[]]); }
    exit;
}

// ─── IMPORT CSV ───────────────────────────────────────────────────────────────
if ($isAdmin && isset($_POST['import_csv'])) {
    csrfVerify("vlan_detail.php?id=$vlanId");
    if (isset($_FILES['csv_file']) && $_FILES['csv_file']['error'] === 0) {
        $handle = fopen($_FILES['csv_file']['tmp_name'], 'r');
        // Détecter et skipper le BOM UTF-8
        $bom = fread($handle, 3);
        if ($bom !== "\xEF\xBB\xBF") rewind($handle);
        $imported = 0; $skipped = 0; $csvErrors = [];
        $lineNum = 0;
        while (($row = fgetcsv($handle, 0, ';')) !== false) {
            $lineNum++;
            if ($lineNum === 1 && (strtolower(trim($row[0]??'')) === 'ip address' || strtolower(trim($row[0]??'')) === 'ip_address')) continue;
            $ip   = trim($row[0] ?? '');
            $host = trim($row[1] ?? '');
            $dom  = trim($row[2] ?? '');
            $tag  = trim($row[3] ?? '') ?: 'client';
            $stat = in_array(trim($row[4]??''), ['used','free','reserved']) ? trim($row[4]) : 'used';
            $desc = trim($row[5] ?? '');
            if (!$ip) continue;
            $check = validateIpInSubnet($ip, $vlan['subnet']);
            if ($check !== true) { $csvErrors[] = "Ligne $lineNum ($ip) : $check"; $skipped++; continue; }
            try {
                $db->prepare("INSERT OR IGNORE INTO ips (vlan_id,ip_address,hostname,domain,tag,status,description) VALUES (?,?,?,?,?,?,?)")
                   ->execute([$vlanId,$ip,$host,$dom,$tag,$stat,$desc]);
                $imported++;
            } catch (Exception $e) { $skipped++; }
        }
        fclose($handle);
        audit('ip.import', "VLAN {$vlan['name']}", "Import CSV: $imported importées, $skipped ignorées");
        if ($csvErrors) $errors = array_merge($errors, array_slice($csvErrors, 0, 5));
        $msg = "$imported IP(s) importée(s)" . ($skipped ? ", $skipped ignorée(s)" : '') . '.';
        if ($imported > 0) { $_SESSION['flash'] = ['msg'=>$msg,'type'=>'success']; }
        header("Location: vlan_detail.php?id=$vlanId"); exit;
    } else {
        $errors[] = "Erreur lors de l'upload du fichier.";
    }
}

// ─── AJOUTER UNE IP ───────────────────────────────────────────────────────────
if ($isAdmin && isset($_POST['add_ip'])) {
    csrfVerify("vlan_detail.php?id=$vlanId");
    $ip   = trim($_POST['ip']   ?? '');
    $host = trim($_POST['host'] ?? '');
    $dom  = trim($_POST['dom']  ?? '');
    $tag  = $_POST['tag']  ?? 'client';
    $desc = trim($_POST['desc'] ?? '');

    $check = validateIpInSubnet($ip, $vlan['subnet']);
    if ($check !== true) {
        $errors[] = $check;
    } else {
        try {
            $db->prepare("INSERT INTO ips (vlan_id, ip_address, hostname, description, domain, tag) VALUES (?,?,?,?,?,?)")
               ->execute([$vlanId, $ip, $host, $desc, $dom, $tag]);
            audit('ip.create', $ip, "VLAN {$vlan['name']} | host:$host tag:$tag");
            redirect("vlan_detail.php?id=$vlanId", "IP $ip ajoutée.");
        } catch (Exception $e) {
            $errors[] = "L'adresse IP $ip est déjà enregistrée dans ce VLAN.";
        }
    }
}

// ─── MODIFIER UNE IP ─────────────────────────────────────────────────────────
if ($isAdmin && isset($_POST['edit_ip'])) {
    csrfVerify("vlan_detail.php?id=$vlanId");
    $ipId   = (int)($_POST['ip_id'] ?? 0);
    $ip     = trim($_POST['ip']   ?? '');
    $host   = trim($_POST['host'] ?? '');
    $dom    = trim($_POST['dom']  ?? '');
    $tag    = $_POST['tag']  ?? 'client';
    $desc   = trim($_POST['desc'] ?? '');
    $status = in_array($_POST['status'] ?? '', ['used','free','reserved']) ? $_POST['status'] : 'used';

    $existing = $db->prepare("SELECT * FROM ips WHERE id=? AND vlan_id=?");
    $existing->execute([$ipId, $vlanId]);
    $existingRow = $existing->fetch();

    if (!$existingRow) {
        $errors[] = "IP introuvable.";
    } else {
        if ($ip !== $existingRow['ip_address']) {
            $check = validateIpInSubnet($ip, $vlan['subnet']);
            if ($check !== true) $errors[] = $check;
        }
        if (empty($errors)) {
            try {
                $db->prepare("UPDATE ips SET ip_address=?, hostname=?, domain=?, tag=?, description=?, status=? WHERE id=? AND vlan_id=?")
                   ->execute([$ip, $host, $dom, $tag, $desc, $status, $ipId, $vlanId]);
                // Enregistrer les changements dans ip_history
                $fields = ['ip_address'=>$ip,'hostname'=>$host,'domain'=>$dom,'tag'=>$tag,'description'=>$desc,'status'=>$status];
                $histStmt = $db->prepare("INSERT INTO ip_history (ip_id,ip_address,vlan_id,field,old_value,new_value,changed_by) VALUES (?,?,?,?,?,?,?)");
                foreach($fields as $field => $newVal) {
                    $oldVal = (string)($existingRow[$field] ?? '');
                    if ($oldVal !== (string)$newVal) {
                        try { $histStmt->execute([$ipId, $ip, $vlanId, $field, $oldVal, (string)$newVal, $_SESSION['user']]); } catch(Exception $e) {}
                    }
                }
                audit('ip.update', $ip, "VLAN {$vlan['name']} | status:$status host:$host");
                redirect("vlan_detail.php?id=$vlanId", "IP $ip mise à jour.");
            } catch (Exception $e) {
                $errors[] = "L'adresse IP $ip est déjà utilisée dans ce VLAN.";
            }
        }
    }
}

// ─── SUPPRIMER UNE IP ────────────────────────────────────────────────────────
if ($isAdmin && isset($_GET['del_ip'])) {
    $ipId = (int)$_GET['del_ip'];
    $row  = $db->prepare("SELECT ip_address FROM ips WHERE id=? AND vlan_id=?");
    $row->execute([$ipId, $vlanId]);
    $ipRow = $row->fetch();
    if ($ipRow) {
        $db->prepare("DELETE FROM ips WHERE id=?")->execute([$ipId]);
        audit('ip.delete', $ipRow['ip_address'], "VLAN {$vlan['name']}");
        redirect("vlan_detail.php?id=$vlanId", "IP {$ipRow['ip_address']} supprimée.");
    }
    redirect("vlan_detail.php?id=$vlanId", 'IP introuvable.', 'danger');
}

// ─── PAGINATION + RECHERCHE ───────────────────────────────────────────────────
$search  = trim($_GET['q'] ?? '');
$perPage = max(10, min(200, (int)($_GET['per']??50)));
$page    = max(1, (int)($_GET['page']??1));

// Compter le total
if ($search !== '') {
    $like = "%$search%";
    $total = (int)$db->prepare("SELECT COUNT(*) FROM ips WHERE vlan_id=? AND (ip_address LIKE ? OR hostname LIKE ? OR description LIKE ? OR domain LIKE ?)")
               ->execute([$vlanId,$like,$like,$like,$like]) ? $db->query("SELECT COUNT(*) FROM ips WHERE vlan_id=$vlanId AND (ip_address LIKE '%".addslashes($search)."%' OR hostname LIKE '%".addslashes($search)."%' OR description LIKE '%".addslashes($search)."%' OR domain LIKE '%".addslashes($search)."%')")->fetchColumn() : 0;
    $cntStmt = $db->prepare("SELECT COUNT(*) FROM ips WHERE vlan_id=? AND (ip_address LIKE ? OR hostname LIKE ? OR description LIKE ? OR domain LIKE ?)");
    $cntStmt->execute([$vlanId,$like,$like,$like,$like]);
    $total = (int)$cntStmt->fetchColumn();
} else {
    $cntStmt = $db->prepare("SELECT COUNT(*) FROM ips WHERE vlan_id=?");
    $cntStmt->execute([$vlanId]);
    $total = (int)$cntStmt->fetchColumn();
}

$totalPages = max(1, (int)ceil($total / $perPage));
$page       = min($page, $totalPages);
$offset     = ($page - 1) * $perPage;

// Récupérer la page courante
if ($search !== '') {
    $like = "%$search%";
    $s = $db->prepare("SELECT * FROM ips WHERE vlan_id=? AND (ip_address LIKE ? OR hostname LIKE ? OR description LIKE ? OR domain LIKE ?) ORDER BY ip_address ASC LIMIT ? OFFSET ?");
    $s->execute([$vlanId,$like,$like,$like,$like,$perPage,$offset]);
} else {
    $s = $db->prepare("SELECT * FROM ips WHERE vlan_id=? ORDER BY ip_address ASC LIMIT ? OFFSET ?");
    $s->execute([$vlanId,$perPage,$offset]);
}
$ips     = $s->fetchAll();
$allTags = getTags();
$statusColors = ['used'=>'success','free'=>'light','reserved'=>'warning'];

// URL de base pour pagination
function pageUrl(int $p, int $vlanId, string $search, int $per): string {
    $q = $search ? '&q='.urlencode($search) : '';
    $pp = $per !== 50 ? '&per='.$per : '';
    return "vlan_detail.php?id=$vlanId&page=$p$q$pp";
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
    <title><?= e(siteName()) ?> — VLAN <?= e($vlan['vid']) ?></title>
    <style>
        .ip-row:hover { background-color: rgba(0,0,0,.02); }
        code { font-size: .85em; }
        .copy-btn { cursor:pointer; opacity:.5; font-size:.8rem; }
        .copy-btn:hover { opacity:1; }
        .ping-dot { width:10px;height:10px;border-radius:50%;display:inline-block; }
        .spin { animation: spin 1s linear infinite; }
        @keyframes spin { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }
    </style>
</head>
<body>

<nav class="navbar ipam-navbar shadow-sm px-3">
    <div class="container-fluid">
        <a class="navbar-brand fw-bold" href="index.php">
            <i class="bi bi-<?= e(siteIcon()) ?> me-2" style="color:var(--ipam-accent)"></i><?= e(siteName()) ?>
        </a>
        <div class="d-flex align-items-center gap-2">
            <!-- RECHERCHE GLOBALE -->
            <form action="search.php" method="GET" class="d-flex gap-1">
                <input type="text" name="q" class="form-control form-control-sm" placeholder="Recherche globale…" style="width:180px">
                <button class="btn btn-sm btn-outline-light" type="submit"><i class="bi bi-search"></i></button>
            </form>
            <span class="text-secondary small">
                <i class="bi bi-person-circle me-1"></i><?= e($_SESSION['user']) ?>
            </span>
            <a href="logout.php" class="btn btn-outline-danger btn-sm"><i class="bi bi-box-arrow-right"></i></a>
        </div>
    </div>
</nav>

<div class="container-fluid py-4 px-4">

    <?php flash(); ?>

    <?php if (!empty($errors)): ?>
        <div class="alert alert-danger py-2 small">
            <?php foreach ($errors as $err): ?><div><i class="bi bi-exclamation-circle me-1"></i><?= e($err) ?></div><?php endforeach; ?>
        </div>
    <?php endif; ?>

    <!-- EN-TÊTE VLAN -->
    <div class="d-flex align-items-center gap-3 mb-4 flex-wrap">
        <a href="index.php" class="btn btn-sm btn-outline-secondary">
            <i class="bi bi-arrow-left me-1"></i><?= te('nav.back') ?>
        </a>
        <div>
            <h4 class="mb-0 fw-bold">
                <span class="badge bg-secondary me-2">#<?= e($vlan['vid']) ?></span>
                <?= e($vlan['name']) ?>
                <span class="text-muted fw-normal small ms-2"><?= e($vlan['subnet']) ?></span>
            </h4>
            <?php if ($vlan['description']): ?>
                <div class="text-muted small mt-1"><?= e($vlan['description']) ?></div>
            <?php endif; ?>
        </div>
        <div class="ms-auto d-flex gap-2 flex-wrap align-items-center">
            <span class="badge bg-primary py-2 px-3"><?= $total ?> IP<?= $total > 1 ? 's' : '' ?></span>
            <!-- BOUTONS EXPORT -->
            <a href="?id=<?= $vlanId ?>&export=csv" class="btn btn-sm btn-outline-success" title="Export CSV">
                <i class="bi bi-filetype-csv me-1"></i>CSV
            </a>
            <a href="?id=<?= $vlanId ?>&export=json" class="btn btn-sm btn-outline-info" title="Export JSON">
                <i class="bi bi-filetype-json me-1"></i>JSON
            </a>
            <?php if ($isAdmin): ?>
            <button class="btn btn-sm btn-outline-warning" data-bs-toggle="modal" data-bs-target="#modalImportCSV" title="Import CSV">
                <i class="bi bi-upload me-1"></i>Import
            </button>
            <?php endif; ?>
        </div>
    </div>

    <!-- FORMULAIRE AJOUT IP -->
    <?php if ($isAdmin): ?>
    <div class="card shadow-sm border-0 mb-4">
        <div class="card-header bg-light fw-semibold small py-2">
            <i class="bi bi-plus-circle me-1 text-success"></i><?= te('ip.add_title') ?>
        </div>
        <div class="card-body py-3">
            <form method="POST" class="row g-2 align-items-end">
                <?php csrfField(); ?>
                <div class="col-md-2">
                    <label class="form-label small mb-1"><?= te('ip.address') ?> <span class="text-danger">*</span></label>
                    <input type="text" name="ip" class="form-control form-control-sm" placeholder="<?= explode('/', $vlan['subnet'])[0] ?>" required>
                </div>
                <div class="col-md-2">
                    <label class="form-label small mb-1"><?= te('ip.hostname') ?></label>
                    <input type="text" name="host" class="form-control form-control-sm" placeholder="web-01">
                </div>
                <div class="col-md-2">
                    <label class="form-label small mb-1"><?= te('ip.domain') ?></label>
                    <input type="text" name="dom" class="form-control form-control-sm" placeholder="infra.local">
                </div>
                <div class="col-md-2">
                    <label class="form-label small mb-1"><?= te('ip.tag') ?></label>
                    <select name="tag" class="form-select form-select-sm">
                        <?php foreach ($allTags as $t): ?>
                            <option value="<?= e($t['name']) ?>"><?= ucfirst(e($t['name'])) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="col-md-3">
                    <label class="form-label small mb-1"><?= te('ip.description') ?></label>
                    <input type="text" name="desc" class="form-control form-control-sm" placeholder="Rôle de la machine…">
                </div>
                <div class="col-md-1">
                    <button type="submit" name="add_ip" class="btn btn-success btn-sm w-100">
                        <i class="bi bi-plus-lg"></i>
                    </button>
                </div>
            </form>
        </div>
    </div>
    <?php endif; ?>

    <!-- BARRE RECHERCHE + PER PAGE -->
    <div class="d-flex justify-content-between align-items-center mb-3 gap-2 flex-wrap">
        <form class="d-flex gap-2" style="max-width:400px">
            <input type="hidden" name="id" value="<?= $vlanId ?>">
            <?php if ($perPage !== 50): ?><input type="hidden" name="per" value="<?= $perPage ?>"><?php endif; ?>
            <input type="text" name="q" class="form-control form-control-sm" placeholder="<?= te('ip.search') ?>" value="<?= e($search) ?>">
            <button class="btn btn-sm btn-outline-secondary" type="submit"><i class="bi bi-search"></i></button>
            <?php if ($search): ?>
                <a href="?id=<?= $vlanId ?>" class="btn btn-sm btn-outline-danger"><i class="bi bi-x"></i></a>
            <?php endif; ?>
        </form>
        <div class="d-flex align-items-center gap-2">
            <span class="text-muted small"><?= te('ip.per_page') ?> :</span>
            <?php foreach ([25,50,100,200] as $pp): ?>
                <a href="?id=<?= $vlanId ?>&per=<?= $pp ?><?= $search ? '&q='.urlencode($search) : '' ?>"
                   class="btn btn-sm <?= $perPage === $pp ? 'btn-primary' : 'btn-outline-secondary' ?>"><?= $pp ?></a>
            <?php endforeach; ?>
        </div>
    </div>

    <!-- TABLE IPs -->
    <div class="card shadow-sm border-0">
        <div class="table-responsive">
            <table class="table table-hover align-middle mb-0">
                <thead class="table-dark">
                    <tr>
                        <th><?= te('ip.address') ?></th>
                        <th><?= te('ip.hostname') ?></th>
                        <th><?= te('ip.domain') ?></th>
                        <th><?= te('ip.tag') ?></th>
                        <th><?= te('ip.status') ?></th>
                        <th><?= te('ip.description') ?></th>
                        <?php if ($isAdmin): ?><th class="text-end pe-3"><?= te('ip.actions') ?></th><?php endif; ?>
                    </tr>
                </thead>
                <tbody>
                <?php if (empty($ips)): ?>
                    <tr><td colspan="7" class="text-center text-muted py-4">
                        <?= $search ? te('dash.no_results') : te('ip.none') ?>
                    </td></tr>
                <?php endif; ?>
                <?php foreach ($ips as $ip):
                    $tagData     = getTag($ip['tag']);
                    $statusColor = $statusColors[$ip['status']] ?? 'secondary';
                ?>
                <tr class="ip-row">
                    <td>
                        <code class="fw-semibold"><?= e($ip['ip_address']) ?></code>
                        <span class="copy-btn ms-1" onclick="navigator.clipboard.writeText('<?= e($ip['ip_address']) ?>');this.innerHTML='<i class=\'bi bi-check text-success\'></i>'" title="Copier">
                            <i class="bi bi-clipboard"></i>
                        </span>
                        <?php if ($isAdmin): ?>
                        <span class="ping-indicator ms-1" data-ip="<?= e($ip['ip_address']) ?>" data-vlan="<?= $vlanId ?>" title="Ping">
                            <i class="bi bi-circle-fill text-secondary" style="font-size:.55rem;vertical-align:middle;cursor:pointer"></i>
                        </span>
                        <?php endif; ?>
                    </td>
                    <td><?= e($ip['hostname']) ?></td>
                    <td class="text-muted small"><?= e($ip['domain']) ?></td>
                    <td>
                        <span class="badge bg-<?= e($tagData['color']) ?> <?= $tagData['color'] === 'light' ? 'text-dark border' : '' ?>" style="font-size:.7rem">
                            <i class="bi bi-<?= e($tagData['icon']) ?> me-1"></i><?= strtoupper(e($ip['tag'])) ?>
                        </span>
                    </td>
                    <td>
                        <span class="badge bg-<?= $statusColor ?> <?= $statusColor === 'light' ? 'text-dark border' : '' ?>" style="font-size:.7rem">
                            <?= te('ip.status.'.$ip['status']) ?>
                        </span>
                    </td>
                    <td class="small text-muted"><?= e($ip['description']) ?></td>
                    <?php if ($isAdmin): ?>
                    <td class="text-end pe-3">
                        <div class="btn-group btn-group-sm">
                            <button class="btn btn-outline-warning"
                                    data-bs-toggle="modal" data-bs-target="#modalEditIp<?= $ip['id'] ?>"
                                    title="<?= te('action.edit') ?>">
                                <i class="bi bi-pencil"></i>
                            </button>
                            <!-- Bouton historique -->
                            <button class="btn btn-outline-info"
                                    onclick="loadIpHistory(<?= $ip['id'] ?>, '<?= e($ip['ip_address']) ?>')"
                                    data-bs-toggle="modal"
                                    data-bs-target="#modalIpHistory"
                                    title="<?= te('ip.history') ?>">
                                <i class="bi bi-clock-history"></i>
                            </button>
                            <!-- Bouton suppression → modal Bootstrap -->
                            <button class="btn btn-outline-danger"
                                    data-bs-toggle="modal"
                                    data-bs-target="#modalDelIp"
                                    data-ip-id="<?= $ip['id'] ?>"
                                    data-ip-addr="<?= e($ip['ip_address']) ?>"
                                    title="<?= te('action.delete') ?>">
                                <i class="bi bi-trash"></i>
                            </button>
                        </div>
                    </td>
                    <?php endif; ?>
                </tr>

                <!-- MODAL ÉDITION IP -->
                <?php if ($isAdmin): ?>
                <div class="modal fade" id="modalEditIp<?= $ip['id'] ?>" tabindex="-1">
                    <div class="modal-dialog modal-lg"><div class="modal-content">
                        <form method="POST">
                            <?php csrfField(); ?>
                            <input type="hidden" name="ip_id" value="<?= $ip['id'] ?>">
                            <div class="modal-header" style="background:var(--ipam-accent);color:var(--ipam-accent-text)">
                                <h6 class="modal-title fw-bold">
                                    <i class="bi bi-pencil me-2"></i><?= te('ip.edit_title') ?> <code style="color:inherit"><?= e($ip['ip_address']) ?></code>
                                </h6>
                                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                            </div>
                            <div class="modal-body row g-3">
                                <div class="col-md-4">
                                    <label class="form-label small fw-semibold"><?= te('ip.address') ?> <span class="text-danger">*</span></label>
                                    <input type="text" name="ip" class="form-control form-control-sm" value="<?= e($ip['ip_address']) ?>" required>
                                    <div class="form-text" style="font-size:.7rem"><?= e($vlan['subnet']) ?></div>
                                </div>
                                <div class="col-md-4">
                                    <label class="form-label small fw-semibold"><?= te('ip.hostname') ?></label>
                                    <input type="text" name="host" class="form-control form-control-sm" value="<?= e($ip['hostname']) ?>">
                                </div>
                                <div class="col-md-4">
                                    <label class="form-label small fw-semibold"><?= te('ip.domain') ?></label>
                                    <input type="text" name="dom" class="form-control form-control-sm" value="<?= e($ip['domain']) ?>">
                                </div>
                                <div class="col-md-4">
                                    <label class="form-label small fw-semibold"><?= te('ip.tag') ?></label>
                                    <select name="tag" class="form-select form-select-sm">
                                        <?php foreach ($allTags as $t): ?>
                                            <option value="<?= e($t['name']) ?>" <?= $ip['tag'] === $t['name'] ? 'selected' : '' ?>>
                                                <?= ucfirst(e($t['name'])) ?>
                                            </option>
                                        <?php endforeach; ?>
                                    </select>
                                </div>
                                <div class="col-md-4">
                                    <label class="form-label small fw-semibold"><?= te('ip.status') ?></label>
                                    <select name="status" class="form-select form-select-sm">
                                        <?php foreach (['used','free','reserved'] as $val): ?>
                                            <option value="<?= $val ?>" <?= $ip['status'] === $val ? 'selected' : '' ?>><?= te('ip.status.'.$val) ?></option>
                                        <?php endforeach; ?>
                                    </select>
                                </div>
                                <div class="col-md-4">
                                    <label class="form-label small fw-semibold"><?= te('ip.description') ?></label>
                                    <input type="text" name="desc" class="form-control form-control-sm" value="<?= e($ip['description']) ?>">
                                </div>
                            </div>
                            <div class="modal-footer">
                                <button type="button" class="btn btn-secondary btn-sm" data-bs-dismiss="modal"><?= te('action.cancel') ?></button>
                                <button type="submit" name="edit_ip" class="btn btn-warning btn-sm">
                                    <i class="bi bi-floppy me-1"></i><?= te('action.save') ?>
                                </button>
                            </div>
                        </form>
                    </div></div>
                </div>
                <?php endif; ?>

                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>

    <!-- PAGINATION -->
    <?php if ($totalPages > 1): ?>
    <nav class="mt-3 d-flex justify-content-between align-items-center">
        <span class="text-muted small">
            <?= te('ip.showing', ['from'=>$offset+1,'to'=>min($offset+$perPage,$total),'total'=>$total]) ?>
        </span>
        <ul class="pagination pagination-sm mb-0">
            <li class="page-item <?= $page <= 1 ? 'disabled' : '' ?>">
                <a class="page-link" href="<?= pageUrl($page-1, $vlanId, $search, $perPage) ?>">«</a>
            </li>
            <?php
            $start = max(1, $page - 2);
            $end   = min($totalPages, $page + 2);
            if ($start > 1) echo '<li class="page-item disabled"><span class="page-link">…</span></li>';
            for ($i = $start; $i <= $end; $i++):
            ?>
            <li class="page-item <?= $i === $page ? 'active' : '' ?>">
                <a class="page-link" href="<?= pageUrl($i, $vlanId, $search, $perPage) ?>"><?= $i ?></a>
            </li>
            <?php endfor;
            if ($end < $totalPages) echo '<li class="page-item disabled"><span class="page-link">…</span></li>';
            ?>
            <li class="page-item <?= $page >= $totalPages ? 'disabled' : '' ?>">
                <a class="page-link" href="<?= pageUrl($page+1, $vlanId, $search, $perPage) ?>">»</a>
            </li>
        </ul>
    </nav>
    <?php endif; ?>

</div>

<!-- ═══ MODAL SUPPRESSION IP (centralisé) ═══════════════════════════════════ -->
<?php if ($isAdmin): ?>
<div class="modal fade" id="modalDelIp" tabindex="-1">
    <div class="modal-dialog modal-sm"><div class="modal-content border-danger">
        <div class="modal-header bg-danger text-white py-2">
            <h6 class="modal-title fw-bold"><i class="bi bi-trash me-2"></i><?= te('action.delete') ?></h6>
            <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
        </div>
        <div class="modal-body text-center py-3">
            <p class="mb-1"><?= te('ip.delete_confirm') ?></p>
            <code id="delIpAddr" class="fs-6 fw-bold"></code>
        </div>
        <div class="modal-footer py-2 justify-content-center">
            <button type="button" class="btn btn-secondary btn-sm" data-bs-dismiss="modal"><?= te('action.cancel') ?></button>
            <a id="delIpLink" href="#" class="btn btn-danger btn-sm">
                <i class="bi bi-trash me-1"></i><?= te('action.delete') ?>
            </a>
        </div>
    </div></div>
</div>

<!-- ═══ MODAL IMPORT CSV ═════════════════════════════════════════════════════ -->
<div class="modal fade" id="modalImportCSV" tabindex="-1">
    <div class="modal-dialog"><div class="modal-content">
        <form method="POST" enctype="multipart/form-data">
            <?php csrfField(); ?>
            <div class="modal-header" style="background:var(--ipam-accent);color:var(--ipam-accent-text)">
                <h6 class="modal-title fw-bold"><i class="bi bi-upload me-2"></i><?= te('ip.import_csv_title') ?></h6>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <p class="small text-muted mb-2"><?= te('ip.import_csv_help') ?></p>
                <pre class="bg-light border rounded p-2 small mb-3" style="font-size:.72rem">IP Address;Hostname;Domain;Tag;Status;Description
10.0.10.5;web-01;prod.local;client;used;Serveur web
10.0.10.6;db-01;prod.local;server;reserved;Base de données</pre>
                <div class="mb-3">
                    <label class="form-label small fw-semibold"><?= te('ip.import_csv_file') ?></label>
                    <input type="file" name="csv_file" class="form-control form-control-sm" accept=".csv,.txt" required>
                </div>
                <div class="alert alert-info py-2 small mb-0">
                    <i class="bi bi-info-circle me-1"></i><?= te('ip.import_csv_note') ?>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary btn-sm" data-bs-dismiss="modal"><?= te('action.cancel') ?></button>
                <button type="submit" name="import_csv" class="btn btn-warning btn-sm">
                    <i class="bi bi-upload me-1"></i><?= te('ip.import_csv_btn') ?>
                </button>
            </div>
        </form>
    </div></div>
</div>
<?php endif; ?>

<!-- Modal Historique IP -->
<div class="modal fade" id="modalIpHistory" tabindex="-1">
    <div class="modal-dialog modal-lg"><div class="modal-content">
        <div class="modal-header py-2 border-0">
            <h6 class="modal-title fw-semibold"><i class="bi bi-clock-history me-2 text-info"></i><?= te('ip.history_title') ?> — <span id="histIpAddr"></span></h6>
            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
        </div>
        <div class="modal-body p-0">
            <div id="histLoading" class="text-center py-4 text-muted"><i class="bi bi-arrow-repeat spin me-2"></i>Chargement…</div>
            <div id="histContent" class="d-none">
                <table class="table table-sm table-hover mb-0" style="font-size:.82rem">
                    <thead class="table-dark"><tr>
                        <th>Date</th><th>Champ</th><th>Ancienne valeur</th><th>Nouvelle valeur</th><th>Par</th>
                    </tr></thead>
                    <tbody id="histBody"></tbody>
                </table>
                <p id="histEmpty" class="text-center text-muted py-3 d-none"><?= te('ip.history_empty') ?></p>
            </div>
        </div>
        <div class="modal-footer py-2">
            <button type="button" class="btn btn-sm btn-secondary" data-bs-dismiss="modal"><?= te('action.close') ?></button>
        </div>
    </div></div>
</div>

<!-- Modal Confirmer Suppression IP -->
<div class="modal fade" id="modalDeleteIp" tabindex="-1">
    <div class="modal-dialog modal-sm"><div class="modal-content">
        <div class="modal-header py-2 border-0">
            <h6 class="modal-title fw-semibold"><i class="bi bi-trash me-2 text-danger"></i><?= te('ip.delete_title') ?></h6>
            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
        </div>
        <div class="modal-body pt-0">
            <p class="mb-1"><?= te('ip.delete_confirm') ?> <strong id="deleteIpAddr"></strong></p>
            <div class="alert alert-danger py-2 small mb-0"><i class="bi bi-exclamation-triangle me-1"></i><?= te('ip.delete_warning') ?></div>
        </div>
        <div class="modal-footer py-2 gap-2">
            <button type="button" class="btn btn-sm btn-secondary" data-bs-dismiss="modal"><?= te('action.cancel') ?></button>
            <a id="deleteIpLink" href="#" class="btn btn-sm btn-danger"><?= te('action.yes_delete') ?></a>
        </div>
    </div></div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script>
// ─── Modal suppression IP ─────────────────────────────────────────────────────
document.getElementById('modalDelIp')?.addEventListener('show.bs.modal', function(e) {
    const btn    = e.relatedTarget;
    const ipId   = btn.dataset.ipId;
    const ipAddr = btn.dataset.ipAddr;
    document.getElementById('delIpAddr').textContent = ipAddr;
    document.getElementById('delIpLink').href = `?id=<?= $vlanId ?>&del_ip=${ipId}`;
});

// ─── Historique IP ────────────────────────────────────────────────────────────
function loadIpHistory(ipId, ipAddr) {
    document.getElementById('histIpAddr').textContent = ipAddr;
    const loading = document.getElementById('histLoading');
    const content = document.getElementById('histContent');
    const empty   = document.getElementById('histEmpty');
    if (loading) loading.classList.remove('d-none');
    if (content) content.classList.add('d-none');
    fetch(`?id=<?= $vlanId ?>&ip_history=${ipId}`)
        .then(r => r.json())
        .then(data => {
            if (loading) loading.classList.add('d-none');
            if (content) content.classList.remove('d-none');
            const tbody = document.getElementById('histBody');
            if (!tbody) return;
            tbody.innerHTML = '';
            if (!data.rows || data.rows.length === 0) {
                if (empty) empty.classList.remove('d-none');
                return;
            }
            if (empty) empty.classList.add('d-none');
            data.rows.forEach(r => {
                const tr = document.createElement('tr');
                tr.innerHTML = `<td class="text-muted" style="font-size:.75rem;white-space:nowrap">${r.changed_at}</td>
                    <td><code class="small">${r.field}</code></td>
                    <td class="text-danger small">${r.old_value || '<em class=text-muted>vide</em>'}</td>
                    <td class="text-success small">${r.new_value || '<em class=text-muted>vide</em>'}</td>
                    <td><span class="badge bg-secondary" style="font-size:.65rem">${r.changed_by}</span></td>`;
                tbody.appendChild(tr);
            });
        })
        .catch(() => {
            if (loading) loading.classList.add('d-none');
            if (content) content.classList.remove('d-none');
            if (empty) empty.classList.remove('d-none');
        });
}

// ─── Ping AJAX ────────────────────────────────────────────────────────────────
document.querySelectorAll('.ping-indicator').forEach(function(el) {
    el.addEventListener('click', function() {
        const ip   = el.dataset.ip;
        const vlan = el.dataset.vlan;
        const icon = el.querySelector('i');
        icon.className = 'bi bi-circle-fill text-warning';
        icon.title = 'Ping en cours…';
        fetch(`?id=${vlan}&ping=${encodeURIComponent(ip)}`)
            .then(r => r.json())
            .then(data => {
                if (data.status === 'up') {
                    icon.className = 'bi bi-circle-fill text-success';
                    icon.title = data.msg;
                } else if (data.status === 'down') {
                    icon.className = 'bi bi-circle-fill text-danger';
                    icon.title = data.msg;
                } else {
                    icon.className = 'bi bi-circle-fill text-secondary';
                    icon.title = data.msg || 'Erreur';
                }
            })
            .catch(() => {
                icon.className = 'bi bi-circle-fill text-secondary';
                icon.title = 'Erreur réseau';
            });
    });
});
</script>
<?php renderFooterReal(); ?>
</body>
</html>