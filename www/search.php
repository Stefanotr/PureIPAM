<?php
include('auth.php');
$db = db();

$query = trim($_GET['q'] ?? '');
$results = [];
$searchDone = false;

if ($query !== '') {
    $searchDone = true;
    audit('search.global', $query, 'Recherche globale');
    $like = "%$query%";
    // Recherche dans IPs + jointure VLAN
    $stmt = $db->prepare("
        SELECT i.*, v.vid, v.name AS vlan_name, v.subnet, v.id AS vlan_id
        FROM ips i
        JOIN vlans v ON v.id = i.vlan_id
        WHERE i.ip_address LIKE ?
           OR i.hostname    LIKE ?
           OR i.domain      LIKE ?
           OR i.description LIKE ?
           OR v.name        LIKE ?
           OR CAST(v.vid AS TEXT) LIKE ?
        ORDER BY i.ip_address ASC
        LIMIT 200
    ");
    $stmt->execute([$like,$like,$like,$like,$like,$like]);
    $results = $stmt->fetchAll();
}

$allTags     = getTags();
$statusColors = ['used'=>'success','free'=>'light','reserved'=>'warning'];
?>
<!DOCTYPE html>
<html lang="<?= e(siteLang()) ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css">
    <?php renderThemeCSS(); ?>
    <title><?= e(siteName()) ?> — <?= te('search.title') ?></title>
    <style>
        .highlight { background: var(--ipam-accent); color: var(--ipam-accent-text); border-radius: 2px; padding: 0 2px; }
    </style>
</head>
<body>

<nav class="navbar ipam-navbar shadow-sm px-3">
    <div class="container-fluid">
        <a class="navbar-brand fw-bold" href="index.php">
            <i class="bi bi-<?= e(siteIcon()) ?> me-2" style="color:var(--ipam-accent)"></i><?= e(siteName()) ?>
        </a>
        <div class="d-flex align-items-center gap-2">
            <span class="text-secondary small">
                <i class="bi bi-person-circle me-1"></i><?= e($_SESSION['user']) ?>
            </span>
            <a href="logout.php" class="btn btn-outline-danger btn-sm"><i class="bi bi-box-arrow-right"></i></a>
        </div>
    </div>
</nav>

<div class="container-fluid py-4 px-4">

    <!-- BARRE DE RECHERCHE PRINCIPALE -->
    <div class="row justify-content-center mb-4">
        <div class="col-md-8">
            <form method="GET" class="d-flex gap-2">
                <div class="input-group input-group-lg">
                    <span class="input-group-text" style="background:var(--ipam-accent);color:var(--ipam-accent-text);border-color:var(--ipam-accent)">
                        <i class="bi bi-search"></i>
                    </span>
                    <input type="text" name="q" class="form-control form-control-lg"
                           placeholder="<?= te('search.placeholder') ?>"
                           value="<?= e($query) ?>" autofocus>
                    <button class="btn btn-primary" type="submit"><?= te('search.btn') ?></button>
                    <?php if ($query): ?>
                        <a href="search.php" class="btn btn-outline-secondary"><i class="bi bi-x-lg"></i></a>
                    <?php endif; ?>
                </div>
            </form>
            <p class="text-muted small mt-2 mb-0">
                <i class="bi bi-info-circle me-1"></i><?= te('search.hint') ?>
            </p>
        </div>
    </div>

    <?php if ($searchDone): ?>
    <!-- RÉSULTATS -->
    <div class="d-flex align-items-center mb-3 gap-2">
        <h5 class="mb-0">
            <?php if (empty($results)): ?>
                <i class="bi bi-search text-muted me-2"></i><?= te('search.no_results', ['q'=>e($query)]) ?>
            <?php else: ?>
                <i class="bi bi-check-circle text-success me-2"></i>
                <?= te('search.results_count', ['n'=>count($results),'q'=>e($query)]) ?>
            <?php endif; ?>
        </h5>
    </div>

    <?php if (!empty($results)): ?>
    <div class="card shadow-sm border-0">
        <div class="table-responsive">
            <table class="table table-hover align-middle mb-0">
                <thead class="table-dark">
                    <tr>
                        <th><?= te('ip.address') ?></th>
                        <th><?= te('ip.hostname') ?></th>
                        <th>VLAN</th>
                        <th><?= te('vlan.subnet') ?></th>
                        <th><?= te('ip.tag') ?></th>
                        <th><?= te('ip.status') ?></th>
                        <th><?= te('ip.description') ?></th>
                        <th></th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($results as $r):
                    $tagData     = getTag($r['tag']);
                    $statusColor = $statusColors[$r['status']] ?? 'secondary';
                    // Surligner la correspondance
                    $hl = function(string $text) use ($query): string {
                        if (!$query) return e($text);
                        return preg_replace('/(' . preg_quote(e($query), '/') . ')/i',
                            '<mark class="highlight p-0">$1</mark>', e($text));
                    };
                ?>
                <tr>
                    <td><code class="fw-semibold"><?= $hl($r['ip_address']) ?></code></td>
                    <td><?= $hl($r['hostname']) ?></td>
                    <td>
                        <span class="badge bg-secondary me-1">#<?= e($r['vid']) ?></span>
                        <span class="fw-semibold"><?= $hl($r['vlan_name']) ?></span>
                    </td>
                    <td class="text-muted small"><code><?= e($r['subnet']) ?></code></td>
                    <td>
                        <span class="badge bg-<?= e($tagData['color']) ?> <?= $tagData['color']==='light'?'text-dark border':'' ?>" style="font-size:.7rem">
                            <i class="bi bi-<?= e($tagData['icon']) ?> me-1"></i><?= strtoupper(e($r['tag'])) ?>
                        </span>
                    </td>
                    <td>
                        <span class="badge bg-<?= $statusColor ?> <?= $statusColor==='light'?'text-dark border':'' ?>" style="font-size:.7rem">
                            <?= te('ip.status.'.$r['status']) ?>
                        </span>
                    </td>
                    <td class="small text-muted"><?= $hl($r['description']) ?></td>
                    <td>
                        <a href="vlan_detail.php?id=<?= $r['vlan_id'] ?>" class="btn btn-sm btn-outline-primary" title="Voir le VLAN">
                            <i class="bi bi-arrow-right"></i>
                        </a>
                    </td>
                </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
    <?php if (count($results) >= 200): ?>
        <div class="alert alert-warning mt-3 py-2 small">
            <i class="bi bi-exclamation-triangle me-1"></i><?= te('search.limit_warning') ?>
        </div>
    <?php endif; ?>
    <?php endif; ?>

    <?php else: ?>
    <!-- PAGE VIERGE — inviter à chercher -->
    <div class="text-center py-5 text-muted">
        <i class="bi bi-search" style="font-size:3rem;opacity:.3"></i>
        <p class="mt-3"><?= te('search.intro') ?></p>
    </div>
    <?php endif; ?>

</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<?php renderFooterReal(); ?>
</body>
</html>
