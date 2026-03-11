<?php
include('auth.php');
$db    = db();
$vlans = $db->query("SELECT v.*, COUNT(i.id) as ip_count FROM vlans v LEFT JOIN ips i ON i.vlan_id=v.id GROUP BY v.id ORDER BY v.vid ASC")->fetchAll();
?>
<!DOCTYPE html>
<html lang="<?= e(siteLang()) ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css">
    <?php renderThemeCSS(); ?>
    <title><?= e(siteName()) ?> — <?= te('vlans.all_title') ?></title>
</head>
<body>
<nav class="navbar ipam-navbar shadow-sm px-3">
    <div class="container-fluid">
        <a class="navbar-brand fw-bold" href="index.php" style="color:var(--ipam-navbar-text)">
            <i class="bi bi-<?= e(siteIcon()) ?> me-2" style="color:var(--ipam-accent)"></i><?= e(siteName()) ?>
        </a>
        <div class="d-flex align-items-center gap-2">
            <span class="small" style="color:var(--ipam-navbar-text);opacity:.8">
                <i class="bi bi-person-circle me-1"></i><?= e($_SESSION['user']) ?>
            </span>
            <a href="logout.php" class="btn btn-sm btn-outline-danger"><i class="bi bi-box-arrow-right"></i></a>
        </div>
    </div>
</nav>
<div class="container py-4">
    <div class="d-flex align-items-center gap-3 mb-4">
        <a href="index.php" class="btn btn-sm btn-outline-secondary"><i class="bi bi-arrow-left me-1"></i><?= te('nav.back') ?></a>
        <h4 class="mb-0 fw-bold"><i class="bi bi-diagram-3-fill me-2" style="color:var(--ipam-accent)"></i><?= te('vlans.all_title') ?></h4>
        <span class="badge ms-auto" style="background:var(--ipam-accent)"><?= count($vlans) ?> VLANs</span>
    </div>
    <?php flash(); ?>
    <div class="row g-3">
        <?php foreach ($vlans as $v): ?>
        <div class="col-md-4">
            <div class="card shadow-sm border-0 h-100 border-start border-4" style="border-color:var(--ipam-accent)!important">
                <div class="card-body">
                    <div class="d-flex justify-content-between align-items-start mb-2">
                        <h5 class="mb-0">VLAN <span style="color:var(--ipam-accent)"><?= e($v['vid']) ?></span></h5>
                        <span class="badge bg-success"><?= (int)$v['ip_count'] ?> IP<?= $v['ip_count'] > 1 ? 's' : '' ?></span>
                    </div>
                    <div class="fw-semibold"><?= e($v['name']) ?></div>
                    <code class="small"><?= e($v['subnet']) ?></code>
                    <?php if ($v['description']): ?>
                        <p class="text-muted small mt-1 mb-2"><?= e($v['description']) ?></p>
                    <?php endif; ?>
                    <a href="vlan_detail.php?id=<?= $v['id'] ?>" class="btn btn-sm mt-2 text-white" style="background:var(--ipam-accent)">
                        <i class="bi bi-eye me-1"></i><?= te('vlan.manage_ips') ?>
                    </a>
                </div>
            </div>
        </div>
        <?php endforeach; ?>
        <?php if (empty($vlans)): ?>
            <div class="col-12 text-center text-muted py-5"><?= te('dash.no_vlans') ?></div>
        <?php endif; ?>
    </div>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<?php renderFooterReal(); ?>
</body>
</html>
