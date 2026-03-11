<?php
include('auth.php');
requireAdmin();
if (!$isAdmin) redirect('index.php', 'Accès réservé aux administrateurs.', 'danger');

$db     = db();
$errors = [];

// ─── CSRF ─────────────────────────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrfVerify('admin_tags.php');
}

// Couleurs Bootstrap disponibles
$availableColors = [
    'primary'   => 'Bleu',
    'secondary' => 'Gris',
    'success'   => 'Vert',
    'danger'    => 'Rouge',
    'warning'   => 'Jaune',
    'info'      => 'Cyan',
    'dark'      => 'Noir',
    'light'     => 'Blanc',
];

// Icônes Bootstrap Icons suggérées
$availableIcons = [
    'tag', 'server', 'pc', 'router', 'hdd-network', 'globe', 'printer',
    'telephone', 'camera-video', 'wifi', 'shield', 'lightning', 'cpu',
    'database', 'cloud', 'broadcast', 'box', 'tools',
];

// ─── AJOUTER ────────────────────────────────────────────────────────────────
if (isset($_POST['add_tag'])) {
    $name  = strtolower(trim(preg_replace('/[^a-zA-Z0-9_\-]/', '', $_POST['name'] ?? '')));
    $color = array_key_exists($_POST['color'] ?? '', $availableColors) ? $_POST['color'] : 'secondary';
    $icon  = trim($_POST['icon'] ?? 'tag');
    $icon  = preg_replace('/[^a-zA-Z0-9\-]/', '', $icon) ?: 'tag';

    if (strlen($name) < 2) {
        $errors[] = "Le nom doit faire au moins 2 caractères (lettres, chiffres, - ou _).";
    } else {
        try {
            $db->prepare("INSERT INTO tags (name, color, icon) VALUES (?,?,?)")->execute([$name, $color, $icon]);
            redirect('admin_tags.php', "Étiquette « $name » créée.");
        } catch (Exception $e) {
            $errors[] = "Une étiquette « $name » existe déjà.";
        }
    }
}

// ─── MODIFIER ───────────────────────────────────────────────────────────────
if (isset($_POST['edit_tag'])) {
    $id    = (int)($_POST['id'] ?? 0);
    $color = array_key_exists($_POST['color'] ?? '', $availableColors) ? $_POST['color'] : 'secondary';
    $icon  = preg_replace('/[^a-zA-Z0-9\-]/', '', trim($_POST['icon'] ?? 'tag')) ?: 'tag';

    $db->prepare("UPDATE tags SET color=?, icon=? WHERE id=?")->execute([$color, $icon, $id]);
    redirect('admin_tags.php', "Étiquette mise à jour.");
}

// ─── SUPPRIMER ──────────────────────────────────────────────────────────────
if (isset($_GET['delete'])) {
    $id  = (int)$_GET['delete'];
    $tag = $db->prepare("SELECT * FROM tags WHERE id=?");
    $tag->execute([$id]);
    $t = $tag->fetch();

    if (!$t) redirect('admin_tags.php', 'Étiquette introuvable.', 'danger');

    // Compter les IPs utilisant ce tag
    $ipCount = $db->prepare("SELECT COUNT(*) FROM ips WHERE tag=?");
    $ipCount->execute([$t['name']]);
    $cnt = $ipCount->fetchColumn();

    if ($cnt > 0 && !isset($_GET['force'])) {
        redirect('admin_tags.php', "L'étiquette « {$t['name']} » est utilisée par $cnt IP(s). Confirmez la suppression en cliquant à nouveau.", 'warning');
    }

    // Si force=1, on remet les IPs en tag 'client' (ou premier tag dispo)
    if ($cnt > 0) {
        $fallback = $db->prepare("SELECT name FROM tags WHERE id != ? ORDER BY id ASC LIMIT 1");
        $fallback->execute([$id]);
        $fb = $fallback->fetchColumn() ?: 'client';
        $db->prepare("UPDATE ips SET tag=? WHERE tag=?")->execute([$fb, $t['name']]);
    }

    $db->prepare("DELETE FROM tags WHERE id=?")->execute([$id]);
    redirect('admin_tags.php', "Étiquette « {$t['name']} » supprimée" . ($cnt > 0 ? " ($cnt IP(s) réaffectée(s))." : "."));
}

$tags = $db->query("SELECT t.*, COUNT(i.id) as ip_count
    FROM tags t LEFT JOIN ips i ON i.tag = t.name
    GROUP BY t.id ORDER BY t.name ASC")->fetchAll();
?>
<!DOCTYPE html>
<html lang="<?= e(siteLang()) ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css">
    <?php renderThemeCSS(); ?>
    
    <style>
        
        .tag-preview { font-size: .75rem; }
        .icon-grid { display: grid; grid-template-columns: repeat(6, 1fr); gap: 6px; max-height: 160px; overflow-y: auto; }
        .icon-option { cursor: pointer; border: 2px solid transparent; border-radius: 6px; padding: 4px; text-align: center; transition: all .15s; }
        .icon-option:hover, .icon-option.selected { border-color: #0d6efd; background: #e8f0fe; }
        .icon-option i { font-size: 1.1rem; display: block; }
        .icon-option span { font-size: .6rem; color: #666; }
    </style>
</head>
<body>

<nav class="navbar ipam-navbar shadow-sm px-3">
    <div class="container-fluid">
        <a class="navbar-brand fw-bold" href="index.php" style="color:var(--ipam-navbar-text)">
            <i class="bi bi-<?= e(siteIcon()) ?> me-2" style="color:var(--ipam-accent)"></i><?= e(siteName()) ?>
        </a>
        <a href="logout.php" class="btn btn-outline-danger btn-sm"><i class="bi bi-box-arrow-right"></i></a>
    </div>
</nav>

<div class="container py-4" style="max-width:900px">

    <div class="d-flex align-items-center gap-3 mb-4">
        <a href="index.php" class="btn btn-sm btn-outline-secondary">
            <i class="bi bi-arrow-left me-1"></i>Retour
        </a>
        <h4 class="mb-0 fw-bold">
            <i class="bi bi-tags-fill me-2 text-primary"></i>Gestion des étiquettes
        </h4>
    </div>

    <?php flash(); ?>

    <?php if (!empty($errors)): ?>
        <div class="alert alert-danger py-2 small">
            <?php foreach ($errors as $err): ?><div><i class="bi bi-exclamation-circle me-1"></i><?= e($err) ?></div><?php endforeach; ?>
        </div>
    <?php endif; ?>

    <!-- ─── CRÉER UNE ÉTIQUETTE ──────────────────────────────────────────── -->
    <div class="card shadow-sm border-0 mb-4">
        <div class="card-header bg-light fw-semibold small py-2">
            <i class="bi bi-plus-circle me-1 text-success"></i>Créer une nouvelle étiquette
        </div>
        <div class="card-body">
            <form method="POST">
                <?php csrfField(); ?>
                    <div class="col-md-4">
                        <label class="form-label small fw-semibold">Nom <span class="text-danger">*</span></label>
                        <input type="text" name="name" id="newTagName" class="form-control form-control-sm"
                               placeholder="ex: firewall" required
                               pattern="[a-zA-Z0-9_\-]+" title="Lettres, chiffres, tirets uniquement">
                        <div class="form-text" style="font-size:.7rem">Lettres, chiffres, - ou _ uniquement</div>
                    </div>
                    <div class="col-md-4">
                        <label class="form-label small fw-semibold">Couleur</label>
                        <select name="color" id="newTagColor" class="form-select form-select-sm">
                            <?php foreach ($availableColors as $val => $label): ?>
                                <option value="<?= $val ?>"><?= $label ?></option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div class="col-md-4">
                        <label class="form-label small fw-semibold">Aperçu</label>
                        <div>
                            <span id="tagPreview" class="badge bg-secondary tag-preview">
                                <i class="bi bi-tag me-1"></i><span id="previewName">nouvelle</span>
                            </span>
                        </div>
                    </div>
                    <div class="col-12">
                        <label class="form-label small fw-semibold">Icône</label>
                        <input type="hidden" name="icon" id="newTagIcon" value="tag">
                        <div class="icon-grid mt-1" id="iconGrid">
                            <?php foreach ($availableIcons as $ico): ?>
                                <div class="icon-option <?= $ico === 'tag' ? 'selected' : '' ?>"
                                     data-icon="<?= $ico ?>" onclick="selectIcon(this)">
                                    <i class="bi bi-<?= $ico ?>"></i>
                                    <span><?= $ico ?></span>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    </div>
                    <div class="col-12 d-flex justify-content-end">
                        <button type="submit" name="add_tag" class="btn btn-success btn-sm px-4">
                            <i class="bi bi-plus-lg me-1"></i>Créer l'étiquette
                        </button>
                    </div>
                </div>
            </form>
        </div>
    </div>

    <!-- ─── LISTE DES ÉTIQUETTES ─────────────────────────────────────────── -->
    <div class="card shadow-sm border-0">
        <div class="card-header bg-light fw-semibold small py-2">
            <i class="bi bi-list-ul me-1"></i><?= count($tags) ?> étiquette<?= count($tags) > 1 ? 's' : '' ?> configurée<?= count($tags) > 1 ? 's' : '' ?>
        </div>
        <div class="table-responsive">
            <table class="table table-hover align-middle mb-0">
                <thead class="table-dark">
                    <tr>
                        <th>Aperçu</th>
                        <th>Nom</th>
                        <th>Couleur</th>
                        <th>Icône</th>
                        <th class="text-center">IPs associées</th>
                        <th class="text-end pe-3">Actions</th>
                    </tr>
                </thead>
                <tbody>
                <?php if (empty($tags)): ?>
                    <tr><td colspan="6" class="text-center text-muted py-4">Aucune étiquette.</td></tr>
                <?php endif; ?>
                <?php foreach ($tags as $t): ?>
                <tr>
                    <td>
                        <span class="badge bg-<?= e($t['color']) ?> <?= $t['color'] === 'light' ? 'text-dark border' : '' ?> tag-preview">
                            <i class="bi bi-<?= e($t['icon']) ?> me-1"></i><?= e($t['name']) ?>
                        </span>
                    </td>
                    <td class="fw-semibold"><?= e($t['name']) ?></td>
                    <td>
                        <span class="badge bg-<?= e($t['color']) ?> <?= $t['color'] === 'light' ? 'text-dark border' : '' ?>">
                            <?= e($availableColors[$t['color']] ?? $t['color']) ?>
                        </span>
                    </td>
                    <td class="text-muted small"><i class="bi bi-<?= e($t['icon']) ?> me-1"></i><?= e($t['icon']) ?></td>
                    <td class="text-center">
                        <span class="badge <?= $t['ip_count'] > 0 ? 'bg-primary' : 'bg-light text-dark border' ?>">
                            <?= $t['ip_count'] ?>
                        </span>
                    </td>
                    <td class="text-end pe-3">
                        <div class="btn-group btn-group-sm">
                            <button class="btn btn-outline-warning" data-bs-toggle="modal"
                                    data-bs-target="#modalEdit<?= $t['id'] ?>" title="Modifier">
                                <i class="bi bi-pencil"></i>
                            </button>
                            <a href="?delete=<?= $t['id'] ?>" class="btn btn-outline-danger" title="Supprimer"
                               onclick="return confirm('Supprimer l\'étiquette « <?= e($t['name']) ?> » ?\n<?= $t['ip_count'] > 0 ? $t['ip_count'].' IP(s) seront réaffectées.' : '' ?>')">
                                <i class="bi bi-trash"></i>
                            </a>
                        </div>
                    </td>
                </tr>

                <!-- MODAL EDIT -->
                <div class="modal fade" id="modalEdit<?= $t['id'] ?>" tabindex="-1">
                    <div class="modal-dialog"><div class="modal-content">
                        <form method="POST">
                            <?php csrfField(); ?>
                            <input type="hidden" name="id" value="<?= $t['id'] ?>">
                            <div class="modal-header">
                                <h6 class="modal-title">Modifier « <?= e($t['name']) ?> »</h6>
                                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                            </div>
                            <div class="modal-body row g-3">
                                <div class="col-md-6">
                                    <label class="form-label small fw-semibold">Couleur</label>
                                    <select name="color" class="form-select form-select-sm edit-color-<?= $t['id'] ?>"
                                            onchange="updateEditPreview(<?= $t['id'] ?>)">
                                        <?php foreach ($availableColors as $val => $label): ?>
                                            <option value="<?= $val ?>" <?= $t['color'] === $val ? 'selected' : '' ?>><?= $label ?></option>
                                        <?php endforeach; ?>
                                    </select>
                                </div>
                                <div class="col-md-6">
                                    <label class="form-label small fw-semibold">Aperçu</label>
                                    <div>
                                        <span id="editPreview<?= $t['id'] ?>" class="badge bg-<?= e($t['color']) ?> tag-preview">
                                            <i class="bi bi-<?= e($t['icon']) ?> me-1" id="editPreviewIcon<?= $t['id'] ?>"></i><?= e($t['name']) ?>
                                        </span>
                                    </div>
                                </div>
                                <div class="col-12">
                                    <label class="form-label small fw-semibold">Icône</label>
                                    <input type="hidden" name="icon" id="editTagIcon<?= $t['id'] ?>" value="<?= e($t['icon']) ?>">
                                    <div class="icon-grid mt-1">
                                        <?php foreach ($availableIcons as $ico): ?>
                                            <div class="icon-option <?= $ico === $t['icon'] ? 'selected' : '' ?>"
                                                 data-icon="<?= $ico ?>"
                                                 onclick="selectEditIcon(this, <?= $t['id'] ?>)">
                                                <i class="bi bi-<?= $ico ?>"></i>
                                                <span><?= $ico ?></span>
                                            </div>
                                        <?php endforeach; ?>
                                    </div>
                                </div>
                            </div>
                            <div class="modal-footer">
                                <button type="button" class="btn btn-secondary btn-sm" data-bs-dismiss="modal"><?= te('action.cancel') ?></button>
                                <button type="submit" name="edit_tag" class="btn btn-warning btn-sm">
                                    <i class="bi bi-floppy me-1"></i><?= te('action.save') ?>
                                </button>
                            </div>
                        </form>
                    </div></div>
                </div>

                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<?php renderFooterReal(); ?>
<script>
// ─── Aperçu live pour la création ────────────────────────────────────────────
const nameInput  = document.getElementById('newTagName');
const colorSel   = document.getElementById('newTagColor');
const preview    = document.getElementById('tagPreview');
const previewNm  = document.getElementById('previewName');
const iconInput  = document.getElementById('newTagIcon');

function updatePreview() {
    const name  = nameInput.value || 'nouvelle';
    const color = colorSel.value;
    const icon  = iconInput.value || 'tag';
    preview.className = `badge bg-${color} tag-preview${color === 'light' ? ' text-dark border' : ''}`;
    previewNm.textContent = name;
    preview.querySelector('i').className = `bi bi-${icon} me-1`;
}

nameInput.addEventListener('input',  updatePreview);
colorSel.addEventListener('change',  updatePreview);

function selectIcon(el) {
    document.querySelectorAll('#iconGrid .icon-option').forEach(x => x.classList.remove('selected'));
    el.classList.add('selected');
    iconInput.value = el.dataset.icon;
    updatePreview();
}

// ─── Aperçu live pour l'édition ──────────────────────────────────────────────
function updateEditPreview(id) {
    const color = document.querySelector(`.edit-color-${id}`).value;
    const icon  = document.getElementById(`editTagIcon${id}`).value;
    const el    = document.getElementById(`editPreview${id}`);
    el.className = `badge bg-${color} tag-preview${color === 'light' ? ' text-dark border' : ''}`;
    document.getElementById(`editPreviewIcon${id}`).className = `bi bi-${icon} me-1`;
}

function selectEditIcon(el, id) {
    el.closest('.icon-grid').querySelectorAll('.icon-option').forEach(x => x.classList.remove('selected'));
    el.classList.add('selected');
    document.getElementById(`editTagIcon${id}`).value = el.dataset.icon;
    updateEditPreview(id);
}
</script>
</body>
</html>
