<?php
include('auth.php');
$db = db();

$totalVlans   = $db->query("SELECT COUNT(*) FROM vlans")->fetchColumn();
$totalIps     = $db->query("SELECT COUNT(*) FROM ips")->fetchColumn();
$totalServers = $db->query("SELECT COUNT(*) FROM ips WHERE tag='serveur'")->fetchColumn();

$search = trim($_GET['q'] ?? '');
if ($search !== '') {
    $stmt = $db->prepare("SELECT * FROM vlans WHERE name LIKE ? OR CAST(vid AS TEXT) LIKE ? OR subnet LIKE ? ORDER BY vid ASC");
    $like = "%$search%";
    $stmt->execute([$like, $like, $like]);
} else {
    $stmt = $db->query("SELECT * FROM vlans ORDER BY vid ASC");
}
$vlans = $stmt->fetchAll();
?>
<!DOCTYPE html>
<html lang="<?= e(siteLang()) ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css">
    <?php renderThemeCSS(); ?>
    <title><?= e(siteName()) ?> — <?= te('nav.dashboard') ?></title>
    <style>
        .navbar-brand { letter-spacing:.5px; }
        .stat-card { border-radius:12px; border:none; }
        .vlan-row:hover { background-color:rgba(0,0,0,.02); }
        .tag-badge { font-size:.7rem; }
    </style>
</head>
<body>

<!-- NAVBAR -->
<nav class="navbar ipam-navbar shadow-sm px-3">
    <div class="container-fluid">
        <a class="navbar-brand fw-bold" href="index.php" style="color:var(--ipam-navbar-text)">
            <i class="bi bi-<?= e(siteIcon()) ?> me-2" style="color:var(--ipam-accent)"></i><?= e(siteName()) ?>
        </a>
        <div class="d-flex align-items-center gap-2">
            <span class="small me-1" style="color:var(--ipam-navbar-text);opacity:.8">
                <i class="bi bi-person-circle me-1"></i><?= e($_SESSION['user']) ?>
                <span class="badge <?= roleBadgeClass($_SESSION['role'] ?? 'viewer') ?> ms-1 tag-badge">
                    <?= te('role.' . ($_SESSION['role'] ?? 'viewer')) ?>
                </span>
            </span>
            <a href="my_password.php" class="btn btn-sm btn-outline-secondary" title="<?= te('nav.my_password') ?>">
                <i class="bi bi-key"></i>
            </a>
            <?php if ($isAdmin): ?>
                <a href="admin_tags.php" class="btn btn-sm" style="background:var(--ipam-accent);color:var(--ipam-accent-text);border-color:var(--ipam-accent)">
                    <i class="bi bi-tags-fill me-1"></i><?= te('nav.tags') ?>
                </a>
            <?php endif; ?>
            <?php if ($isSysAdmin): ?>
                <a href="settings.php" class="btn btn-sm btn-outline-secondary">
                    <i class="bi bi-gear-fill me-1"></i><?= te('nav.settings') ?>
                </a>
            <?php endif; ?>
            <a href="logout.php" class="btn btn-sm btn-outline-danger" title="<?= te('nav.logout') ?>">
                <i class="bi bi-box-arrow-right"></i>
            </a>
        </div>
    </div>
</nav>

<div class="container-fluid py-4 px-4">

    <?php flash(); ?>

    <?php $welcome = siteWelcome(); if ($welcome): ?>
    <div class="alert border-0 shadow-sm d-flex align-items-center gap-2 mb-4 py-2"
         style="background:var(--ipam-accent);color:var(--ipam-accent-text)" role="alert">
        <i class="bi bi-info-circle-fill flex-shrink-0"></i>
        <span><?= e($welcome) ?></span>
    </div>
    <?php endif; ?>

    <!-- STATS -->
    <div class="row g-3 mb-4">
        <div class="col-sm-4">
            <div class="card stat-card shadow-sm h-100">
                <div class="card-body d-flex align-items-center gap-3">
                    <div class="rounded-3 p-3" style="background:color-mix(in srgb,var(--ipam-accent) 12%,transparent)">
                        <i class="bi bi-diagram-3-fill fs-3" style="color:var(--ipam-accent)"></i>
                    </div>
                    <div>
                        <div class="text-muted small"><?= te('dash.vlans') ?></div>
                        <div class="fw-bold fs-3"><?= $totalVlans ?></div>
                    </div>
                </div>
            </div>
        </div>
        <div class="col-sm-4">
            <div class="card stat-card shadow-sm h-100">
                <div class="card-body d-flex align-items-center gap-3">
                    <div class="bg-success bg-opacity-10 rounded-3 p-3">
                        <i class="bi bi-hdd-network-fill text-success fs-3"></i>
                    </div>
                    <div>
                        <div class="text-muted small"><?= te('dash.ips') ?></div>
                        <div class="fw-bold fs-3"><?= $totalIps ?></div>
                    </div>
                </div>
            </div>
        </div>
        <div class="col-sm-4">
            <div class="card stat-card shadow-sm h-100">
                <div class="card-body d-flex align-items-center gap-3">
                    <div class="bg-danger bg-opacity-10 rounded-3 p-3">
                        <i class="bi bi-server text-danger fs-3"></i>
                    </div>
                    <div>
                        <div class="text-muted small"><?= te('dash.servers') ?></div>
                        <div class="fw-bold fs-3"><?= $totalServers ?></div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- BARRE ACTIONS -->
    <div class="d-flex justify-content-between align-items-center mb-3 gap-2 flex-wrap">
        <form class="d-flex gap-2 flex-grow-1" style="max-width:420px">
            <input type="text" name="q" class="form-control form-control-sm"
                   placeholder="<?= te('dash.search_placeholder') ?>"
                   value="<?= e($search) ?>">
            <button class="btn btn-sm btn-outline-secondary" type="submit">
                <i class="bi bi-search me-1"></i><?= te('dash.search_btn') ?>
            </button>
            <?php if ($search): ?>
                <a href="index.php" class="btn btn-sm btn-outline-danger"><i class="bi bi-x"></i></a>
            <?php endif; ?>
        </form>
        <?php if ($isAdmin): ?>
            <button class="btn btn-primary btn-sm" data-bs-toggle="modal" data-bs-target="#modalAddVlan">
                <i class="bi bi-plus-lg me-1"></i><?= te('dash.add_vlan') ?>
            </button>
        <?php endif; ?>
    </div>

    <!-- TABLE VLANs -->
    <div class="card shadow-sm border-0">
        <div class="table-responsive">
            <table class="table table-hover align-middle mb-0">
                <thead class="table-dark">
                    <tr>
                        <th style="width:80px"><?= te('vlan.id') ?></th>
                        <th><?= te('vlan.name') ?></th>
                        <th><?= te('vlan.subnet') ?></th>
                        <th><?= te('vlan.description') ?></th>
                        <th style="width:60px" class="text-center"><?= te('vlan.ip_count') ?></th>
                        <th class="text-end pe-3" style="width:140px"><?= te('vlan.actions') ?></th>
                    </tr>
                </thead>
                <tbody>
                <?php if (empty($vlans)): ?>
                    <tr><td colspan="6" class="text-center text-muted py-4">
                        <?= te($search ? 'dash.no_results' : 'dash.no_vlans') ?>
                    </td></tr>
                <?php endif; ?>
                <?php foreach ($vlans as $v):
                    $ipCount = db()->prepare("SELECT COUNT(*) FROM ips WHERE vlan_id=?");
                    $ipCount->execute([$v['id']]);
                    $cnt = $ipCount->fetchColumn();
                ?>
                <tr class="vlan-row">
                    <td><span class="badge bg-secondary">#<?= e($v['vid']) ?></span></td>
                    <td class="fw-semibold"><?= e($v['name']) ?></td>
                    <td><code><?= e($v['subnet']) ?></code></td>
                    <td class="text-muted small"><?= e($v['description'] ?? '') ?></td>
                    <td class="text-center">
                        <span class="badge <?= $cnt > 0 ? 'bg-success' : 'bg-light text-dark' ?>"><?= $cnt ?></span>
                    </td>
                    <td class="text-end pe-3">
                        <div class="btn-group btn-group-sm">
                            <a href="vlan_detail.php?id=<?= $v['id'] ?>" class="btn btn-outline-primary" title="<?= te('vlan.ip_count') ?>">
                                <i class="bi bi-eye"></i>
                            </a>
                            <?php if ($isAdmin): ?>
                                <button class="btn btn-outline-warning" data-bs-toggle="modal"
                                        data-bs-target="#modalEditVlan<?= $v['id'] ?>" title="<?= te('action.edit') ?>">
                                    <i class="bi bi-pencil"></i>
                                </button>
                                <a href="vlan_action.php?delete=<?= $v['id'] ?>" class="btn btn-outline-danger"
                                   title="<?= te('action.delete') ?>"
                                   onclick="return confirm('<?= te('vlan.delete_confirm') ?>')">
                                    <i class="bi bi-trash"></i>
                                </a>
                            <?php endif; ?>
                        </div>
                    </td>
                </tr>

                <!-- MODAL EDIT -->
                <?php if ($isAdmin): ?>
                <div class="modal fade" id="modalEditVlan<?= $v['id'] ?>" tabindex="-1">
                    <div class="modal-dialog"><div class="modal-content">
                        <form action="vlan_action.php" method="POST">
                            <input type="hidden" name="id" value="<?= $v['id'] ?>">
                            <div class="modal-header">
                                <h5 class="modal-title"><?= te('vlan.edit_title') ?> #<?= e($v['vid']) ?></h5>
                                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                            </div>
                            <div class="modal-body row g-3">
                                <div class="col-md-4">
                                    <label class="form-label small fw-semibold"><?= te('vlan.vid_label') ?></label>
                                    <input type="number" name="vid" class="form-control form-control-sm" value="<?= e($v['vid']) ?>" required min="1" max="4094">
                                </div>
                                <div class="col-md-8">
                                    <label class="form-label small fw-semibold"><?= te('vlan.name_label') ?></label>
                                    <input type="text" name="name" class="form-control form-control-sm" value="<?= e($v['name']) ?>" required>
                                </div>
                                <div class="col-12">
                                    <label class="form-label small fw-semibold"><?= te('vlan.subnet_label') ?></label>
                                    <input type="text" name="subnet" class="form-control form-control-sm" value="<?= e($v['subnet']) ?>" required placeholder="ex: 192.168.1.0/24">
                                </div>
                                <div class="col-12">
                                    <label class="form-label small fw-semibold"><?= te('vlan.desc_label') ?></label>
                                    <input type="text" name="description" class="form-control form-control-sm" value="<?= e($v['description'] ?? '') ?>">
                                </div>
                            </div>
                            <div class="modal-footer">
                                <button type="button" class="btn btn-secondary btn-sm" data-bs-dismiss="modal"><?= te('action.cancel') ?></button>
                                <button type="submit" name="edit_vlan" class="btn btn-warning btn-sm">
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

</div>

<!-- MODAL ADD VLAN -->
<?php if ($isAdmin): ?>
<div class="modal fade" id="modalAddVlan" tabindex="-1">
    <div class="modal-dialog"><div class="modal-content">
        <form action="vlan_action.php" method="POST">
            <div class="modal-header text-white" style="background:var(--ipam-accent)">
                <h5 class="modal-title"><i class="bi bi-plus-circle me-2"></i><?= te('vlan.add_title') ?></h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body row g-3">
                <div class="col-md-4">
                    <label class="form-label small fw-semibold"><?= te('vlan.vid_label') ?> <span class="text-danger">*</span></label>
                    <input type="number" name="vid" class="form-control form-control-sm" placeholder="ex: 10" required min="1" max="4094">
                </div>
                <div class="col-md-8">
                    <label class="form-label small fw-semibold"><?= te('vlan.name_label') ?> <span class="text-danger">*</span></label>
                    <input type="text" name="name" class="form-control form-control-sm" placeholder="ex: WIFI_GUEST" required>
                </div>
                <div class="col-12">
                    <label class="form-label small fw-semibold"><?= te('vlan.subnet_label') ?> <span class="text-danger">*</span></label>
                    <input type="text" name="subnet" class="form-control form-control-sm" placeholder="ex: 192.168.1.0/24" required>
                </div>
                <div class="col-12">
                    <label class="form-label small fw-semibold"><?= te('vlan.desc_label') ?></label>
                    <input type="text" name="description" class="form-control form-control-sm">
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary btn-sm" data-bs-dismiss="modal"><?= te('action.cancel') ?></button>
                <button type="submit" name="add_vlan" class="btn btn-primary btn-sm">
                    <i class="bi bi-plus-lg me-1"></i><?= te('action.create') ?>
                </button>
            </div>
        </form>
    </div></div>
</div>
<?php endif; ?>

<!-- CHANGELOG -->
<?php
$changelog = unserialize(APP_CHANGELOG);
$latest    = $changelog[0];
$typeIcons = ['new' => 'bi-plus-circle-fill text-success', 'fix' => 'bi-bug-fill text-danger', 'improve' => 'bi-arrow-up-circle-fill text-primary'];
?>
<div class="container-fluid mt-4 pb-2">
    <div class="d-flex align-items-center gap-2 mb-3">
        <h6 class="mb-0 fw-semibold text-muted small">
            <i class="bi bi-clock-history me-1"></i><?= te('dash.changelog') ?>
        </h6>
        <button class="btn btn-link btn-sm text-muted p-0 ms-auto small"
                data-bs-toggle="collapse" data-bs-target="#changelogFull">
            <?= te('dash.changelog_all') ?> <i class="bi bi-chevron-down"></i>
        </button>
    </div>
    <div class="card border-0 shadow-sm mb-2">
        <div class="card-body py-2 px-3">
            <div class="d-flex align-items-center gap-2 mb-2">
                <span class="badge bg-<?= $latest['label'] ?>">v<?= e($latest['version']) ?></span>
                <span class="fw-semibold small"><?= e($latest['title']) ?></span>
                <span class="text-muted ms-auto" style="font-size:.75rem"><?= e($latest['date']) ?></span>
            </div>
            <ul class="list-unstyled mb-0">
                <?php foreach ($latest['changes'] as $c): ?>
                <li class="py-1 border-bottom d-flex align-items-start gap-2" style="font-size:.8rem">
                    <i class="bi <?= $typeIcons[$c['type']] ?? 'bi-dot text-muted' ?> mt-1 flex-shrink-0"></i>
                    <span><?= e($c['text']) ?></span>
                </li>
                <?php endforeach; ?>
            </ul>
        </div>
    </div>
    <div class="collapse" id="changelogFull">
        <?php foreach (array_slice($changelog, 1) as $entry): ?>
        <div class="card border-0 shadow-sm mb-2">
            <div class="card-body py-2 px-3">
                <div class="d-flex align-items-center gap-2 mb-2">
                    <span class="badge bg-<?= e($entry['label']) ?>">v<?= e($entry['version']) ?></span>
                    <span class="fw-semibold small"><?= e($entry['title']) ?></span>
                    <span class="text-muted ms-auto" style="font-size:.75rem"><?= e($entry['date']) ?></span>
                </div>
                <ul class="list-unstyled mb-0">
                    <?php foreach ($entry['changes'] as $c): ?>
                    <li class="py-1 border-bottom d-flex align-items-start gap-2" style="font-size:.8rem">
                        <i class="bi <?= $typeIcons[$c['type']] ?? 'bi-dot text-muted' ?> mt-1 flex-shrink-0"></i>
                        <span><?= e($c['text']) ?></span>
                    </li>
                    <?php endforeach; ?>
                </ul>
            </div>
        </div>
        <?php endforeach; ?>
    </div>
</div>

</div><!-- /container-fluid -->

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<?php renderFooterReal(); ?>
</body>
</html>
