<?php
/**
 * IPAM Light — Configuration globale
 */

// ─── VERSION ─────────────────────────────────────────────────────────────────
define('APP_NAME',    'IPAM Light');
define('APP_VERSION', '1.7.0');
define('APP_BUILD',   '2026.03.10');
define('APP_AUTHOR',  'Stefano');

// ─── CHANGELOG ───────────────────────────────────────────────────────────────
define('APP_CHANGELOG', serialize([
    [
        'version' => '1.7.0',
        'date'    => '2026-03-11',
        'label'   => 'danger',
        'title'   => 'Politique de mots de passe & sécurité avancée',
        'changes' => [
            ['type' => 'new',     'text' => 'Politique de mots de passe configurable : longueur min/max, complexité (4 niveaux), expiration'],
            ['type' => 'new',     'text' => 'Onglet Sécurité dans les paramètres pour gérer la politique mdp'],
            ['type' => 'new',     'text' => 'Sysadmin peut définir un mdp à partir de 4 caractères (indépendant de la politique utilisateur)'],
            ['type' => 'new',     'text' => 'Forçage de changement de mdp à la connexion (par utilisateur ou automatique à l\'expiration)'],
            ['type' => 'new',     'text' => 'Bouton "Définir mot de passe" par utilisateur avec toggle "Forcer changement à la connexion"'],
            ['type' => 'new',     'text' => 'Badge 🔑 sur les utilisateurs devant changer leur mot de passe'],
            ['type' => 'new',     'text' => 'Page "Mon mot de passe" : barre de force visuelle 4 niveaux + vérification correspondance temps réel'],
            ['type' => 'new',     'text' => 'Colonne Statut dans le tableau utilisateurs : Connecté / Bloqué / Xmin / Actif'],
            ['type' => 'improve', 'text' => 'Onglet Utilisateurs entièrement refondu : interface claire, actions sans doublons'],
            ['type' => 'improve', 'text' => 'Création d\'utilisateur avec toggle "Forcer changement mdp" dès la création'],
            ['type' => 'improve', 'text' => 'i18n complète de l\'onglet Paramètres (onglets, labels, messages) — +47 clés FR/EN'],
            ['type' => 'fix',     'text' => 'login_otp.php : must_change_password et password_expires_at maintenant mis en session après 2FA'],
            ['type' => 'fix',     'text' => 'admin_tags.php : restriction d\'accès manquante corrigée (requireAdmin ajouté)'],
            ['type' => 'fix',     'text' => 'portal.php / launch.php : résidus SSO supprimés'],
            ['type' => 'fix',     'text' => 'lang/fr.php : apostrophe non echappee dans Journal d\'audit corrigee'],
            ['type' => 'security','text' => 'Forçage mdp dans auth.php avec liste blanche des pages exemptées (settings, db_init, logout)'],
            ['type' => 'security','text' => 'Maximum absolu de 64 caractères pour les mots de passe (non modifiable)'],
        ],
    ],
    [
        'version' => '1.6.0',
        'date'    => '2025-11-14',
        'label'   => 'warning',
        'title'   => 'Double authentification TOTP & gestion avancée des utilisateurs',
        'changes' => [
            ['type' => 'new',     'text' => 'Double authentification TOTP (Google Authenticator, Aegis) par utilisateur'],
            ['type' => 'new',     'text' => 'QR code 2FA généré en PHP pur via bacon/bacon-qr-code (offline, secret jamais exposé)'],
            ['type' => 'new',     'text' => 'Blocage / Déblocage manuel des utilisateurs par le Sysadmin'],
            ['type' => 'new',     'text' => 'Journal d\'audit avec pagination et filtre par utilisateur/action'],
            ['type' => 'new',     'text' => 'Protection du fichier ipam.db et vendor/ via router.php (PHP built-in server)'],
            ['type' => 'improve', 'text' => 'Migration TOTP vers spomky-labs/otphp (maintenu, RFC 6238) — abandon de sonata-project'],
            ['type' => 'fix',     'text' => 'Boucle de redirection ERR_TOO_MANY_REDIRECTS résolue (auth.php réécrit)'],
            ['type' => 'fix',     'text' => 'Icône bi-ip-network inexistante remplacée par bi-hdd-network-fill'],
            ['type' => 'security','text' => 'SSO PixelPass entièrement supprimé du code'],
        ],
    ],
    [
        'version' => '1.5.0',
        'date'    => '2025-08-20',
        'label'   => 'success',
        'title'   => 'Thèmes, internationalisation & CSRF',
        'changes' => [
            ['type' => 'new',     'text' => '8 thèmes visuels via CSS custom properties'],
            ['type' => 'new',     'text' => 'Système de traductions FR/EN avec t()/te()'],
            ['type' => 'new',     'text' => 'Protection CSRF sur tous les formulaires POST'],
            ['type' => 'new',     'text' => 'Rate limiting login : blocage automatique après 5 échecs (15 min)'],
            ['type' => 'new',     'text' => 'Timeout de session automatique après 1 heure d\'inactivité'],
            ['type' => 'new',     'text' => 'Journal d\'audit : toutes les actions CRUD enregistrées (utilisateur, cible, IP source)'],
            ['type' => 'fix',     'text' => 'Requête N+1 corrigée dans le dashboard'],
            ['type' => 'improve', 'text' => 'admin_users.php redirigé vers settings.php'],
        ],
    ],
    [
        'version' => '1.4.0',
        'date'    => '2025-05-03',
        'label'   => 'primary',
        'title'   => 'Rôles, paramètres site & sécurité DB',
        'changes' => [
            ['type' => 'new',  'text' => 'Nouveau rôle Sysadmin : accès total (users, paramètres, licence, DB, tags, VLANs)'],
            ['type' => 'new',  'text' => 'Page Paramètres unifiée avec onglets : Utilisateurs, Licence, Site, Base de données'],
            ['type' => 'new',  'text' => 'Onglet Site : nom, icône, couleur principale, message d\'accueil et langue personnalisables'],
            ['type' => 'new',  'text' => 'Page "Mon mot de passe" accessible à tous les rôles'],
            ['type' => 'new',  'text' => 'db_init.php protégé : accessible uniquement aux Sysadmins connectés'],
            ['type' => 'new',  'text' => 'Export CSV et JSON des IPs par VLAN'],
            ['type' => 'new',  'text' => 'Import CSV d\'IPs avec validation CIDR'],
            ['type' => 'new',  'text' => 'Recherche globale cross-VLAN (IP, hostname, VLAN)'],
            ['type' => 'new',  'text' => 'Ping AJAX par IP : test de disponibilité en un clic'],
            ['type' => 'fix',  'text' => 'Migration automatique des anciens admins vers sysadmin au premier lancement'],
        ],
    ],
    [
        'version' => '1.3.0',
        'date'    => '2025-02-17',
        'label'   => 'info',
        'title'   => 'Édition IPs & validation CIDR renforcée',
        'changes' => [
            ['type' => 'fix',  'text' => 'Validation stricte du masque CIDR IPv4 — les masques > /32 sont refusés'],
            ['type' => 'fix',  'text' => 'Validation améliorée des subnets IPv6 (masque max /128)'],
            ['type' => 'new',  'text' => 'Édition complète des IPs via modal (adresse, hostname, domaine, tag, statut, description)'],
            ['type' => 'new',  'text' => 'Pagination sur vlan_detail.php (25/50/100/200 par page)'],
        ],
    ],
    [
        'version' => '1.2.0',
        'date'    => '2024-11-08',
        'label'   => 'warning',
        'title'   => 'Gestion des étiquettes',
        'changes' => [
            ['type' => 'new',  'text' => 'Page admin dédiée à la gestion des étiquettes (tags)'],
            ['type' => 'new',  'text' => 'Création d\'étiquettes avec nom, couleur Bootstrap et icône Bootstrap Icons'],
            ['type' => 'new',  'text' => 'Aperçu live du badge lors de la création ou modification d\'une étiquette'],
            ['type' => 'new',  'text' => 'Suppression d\'étiquette avec réaffectation automatique des IPs orphelines'],
        ],
    ],
    [
        'version' => '1.1.0',
        'date'    => '2024-09-25',
        'label'   => 'secondary',
        'title'   => 'Système de licence & versioning',
        'changes' => [
            ['type' => 'new',  'text' => 'Page d\'activation de licence obligatoire après le premier login'],
            ['type' => 'new',  'text' => 'Clés de licence avec checksum SHA-256 intégré'],
            ['type' => 'new',  'text' => 'Footer affichant la version, le build et le statut de la licence'],
            ['type' => 'new',  'text' => 'Gestion de la licence (révocation, réactivation) dans la page paramètres'],
        ],
    ],
    [
        'version' => '1.0.0',
        'date'    => '2024-07-10',
        'label'   => 'dark',
        'title'   => 'Version initiale',
        'changes' => [
            ['type' => 'new',  'text' => 'Gestion des VLANs (CRUD complet avec validation CIDR)'],
            ['type' => 'new',  'text' => 'Gestion des adresses IP par VLAN avec tags et statuts'],
            ['type' => 'new',  'text' => 'Authentification avec rôles admin / viewer'],
            ['type' => 'new',  'text' => 'Mots de passe hashés en bcrypt, migrations DB sans perte de données'],
            ['type' => 'new',  'text' => 'Interface Bootstrap 5 responsive'],
        ],
    ],
]));

// ─── CLÉS DE LICENCE VALIDES ─────────────────────────────────────────────────
// Format : XXXX-XXXX-XXXX-XXXX  (16 caractères alphanumériques + tirets)
// Pour générer une nouvelle clé valide, on vérifie la signature interne.
// Les clés sont hashées en SHA-256 avec un sel interne pour éviter le brute-force.
define('LICENSE_SALT', 'ipam-light-v160-voyager3');

/**
 * Vérifie si une clé de licence est valide.
 * Format attendu : XXXX-XXXX-XXXX-XXXX
 * La dernière section est un checksum des 3 premières + sel.
 */
function validateLicenseKey(string $key): bool {
    $key = strtoupper(trim($key));

    // Format basique
    if (!preg_match('/^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/', $key)) {
        return false;
    }

    $parts = explode('-', $key);
    $payload  = $parts[0] . $parts[1] . $parts[2];
    $checksum = $parts[3];

    // Calcul du checksum attendu : premiers 4 chars du hash SHA256(payload+sel)
    $expected = strtoupper(substr(hash('sha256', $payload . LICENSE_SALT), 0, 4));

    return $checksum === $expected;
}

/**
 * Génère une clé de licence valide (pour l'admin/outil interne).
 * Appelé via ?generate_key=1 en mode debug uniquement.
 */
function generateLicenseKey(): string {
    $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // sans 0,O,I,1 pour lisibilité
    $parts = [];
    for ($i = 0; $i < 3; $i++) {
        $part = '';
        for ($j = 0; $j < 4; $j++) $part .= $chars[random_int(0, strlen($chars) - 1)];
        $parts[] = $part;
    }
    $payload  = implode('', $parts);
    $checksum = strtoupper(substr(hash('sha256', $payload . LICENSE_SALT), 0, 4));
    $parts[]  = $checksum;
    return implode('-', $parts);
}

/**
 * Retourne la valeur d'un paramètre site depuis la table settings.
 * Retourne $default si le paramètre n'existe pas.
 */
function getSetting(string $key, string $default = ''): string {
    try {
        $db = db();
        $db->exec("CREATE TABLE IF NOT EXISTS settings (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL DEFAULT ''
        )");
        $stmt = $db->prepare("SELECT value FROM settings WHERE key=?");
        $stmt->execute([$key]);
        $row = $stmt->fetch();
        return $row ? $row['value'] : $default;
    } catch (Exception $e) {
        return $default;
    }
}

/**
 * Enregistre un paramètre site.
 */
function setSetting(string $key, string $value): void {
    try {
        $db = db();
        $db->exec("CREATE TABLE IF NOT EXISTS settings (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL DEFAULT ''
        )");
        $db->prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?,?)")
           ->execute([$key, $value]);
    } catch (Exception $e) {}
}

/**
 * Retourne le nom du site (depuis DB ou APP_NAME par défaut).
 */
function siteName(): string {
    return getSetting('site_name', APP_NAME);
}

/**
 * Retourne l'icône du site (Bootstrap Icons slug).
 */
function siteIcon(): string {
    return getSetting('site_icon', 'hdd-network-fill');
}

/**
 * Retourne la couleur principale du site (classe Bootstrap sans "bg-").
 */
function siteColor(): string {
    return getSetting('site_color', 'primary');
}

/**
 * Retourne le message d'accueil affiché sur le dashboard.
 */
function siteWelcome(): string {
    return getSetting('site_welcome', '');
}

/**
 * Retourne la langue de l'interface.
 */
function siteLang(): string {
    return getSetting('site_lang', 'fr');
}

// ─── THÈMES ───────────────────────────────────────────────────────────────────
// Chaque thème définit des CSS custom properties appliquées globalement.
// Conventions : --ipam-* = variables propres à IPAM, séparées de Bootstrap.
define('IPAM_THEMES', serialize([
    'default' => [
        'label'       => 'IPAM Default',
        'emoji'       => '🔵',
        '--ipam-navbar-bg'      => '#212529',
        '--ipam-navbar-text'    => '#ffffff',
        '--ipam-body-bg'        => '#f0f2f5',
        '--ipam-accent'         => '#0d6efd',
        '--ipam-accent-hover'   => '#0b5ed7',
        '--ipam-accent-text'    => '#ffffff',
        '--ipam-thead-bg'       => '#212529',
        '--ipam-thead-text'     => '#ffffff',
        '--ipam-card-border'    => 'rgba(0,0,0,.08)',
        '--ipam-link'           => '#0d6efd',
        '--ipam-focus-ring'     => 'rgba(13,110,253,.25)',
        '--ipam-badge-bg'       => '#0d6efd',
    ],
    'dark_navy' => [
        'label'       => 'Dark Navy',
        'emoji'       => '🌑',
        '--ipam-navbar-bg'      => '#0d1b2a',
        '--ipam-navbar-text'    => '#e0e6f0',
        '--ipam-body-bg'        => '#111827',
        '--ipam-accent'         => '#3b82f6',
        '--ipam-accent-hover'   => '#2563eb',
        '--ipam-accent-text'    => '#ffffff',
        '--ipam-thead-bg'       => '#1e293b',
        '--ipam-thead-text'     => '#94a3b8',
        '--ipam-card-border'    => 'rgba(255,255,255,.06)',
        '--ipam-link'           => '#60a5fa',
        '--ipam-focus-ring'     => 'rgba(59,130,246,.35)',
        '--ipam-badge-bg'       => '#3b82f6',
        'dark_mode'             => true,
    ],
    'green_tech' => [
        'label'       => 'Green Tech',
        'emoji'       => '🟢',
        '--ipam-navbar-bg'      => '#0a2e1a',
        '--ipam-navbar-text'    => '#d1fae5',
        '--ipam-body-bg'        => '#f0fdf4',
        '--ipam-accent'         => '#16a34a',
        '--ipam-accent-hover'   => '#15803d',
        '--ipam-accent-text'    => '#ffffff',
        '--ipam-thead-bg'       => '#14532d',
        '--ipam-thead-text'     => '#bbf7d0',
        '--ipam-card-border'    => 'rgba(22,163,74,.15)',
        '--ipam-link'           => '#16a34a',
        '--ipam-focus-ring'     => 'rgba(22,163,74,.25)',
        '--ipam-badge-bg'       => '#16a34a',
    ],
    'red_alert' => [
        'label'       => 'Red Alert',
        'emoji'       => '🔴',
        '--ipam-navbar-bg'      => '#3b0a0a',
        '--ipam-navbar-text'    => '#fecaca',
        '--ipam-body-bg'        => '#fff5f5',
        '--ipam-accent'         => '#dc2626',
        '--ipam-accent-hover'   => '#b91c1c',
        '--ipam-accent-text'    => '#ffffff',
        '--ipam-thead-bg'       => '#7f1d1d',
        '--ipam-thead-text'     => '#fecaca',
        '--ipam-card-border'    => 'rgba(220,38,38,.15)',
        '--ipam-link'           => '#dc2626',
        '--ipam-focus-ring'     => 'rgba(220,38,38,.25)',
        '--ipam-badge-bg'       => '#dc2626',
    ],
    'purple_haze' => [
        'label'       => 'Purple Haze',
        'emoji'       => '🟣',
        '--ipam-navbar-bg'      => '#1e0a3c',
        '--ipam-navbar-text'    => '#e9d5ff',
        '--ipam-body-bg'        => '#faf5ff',
        '--ipam-accent'         => '#7c3aed',
        '--ipam-accent-hover'   => '#6d28d9',
        '--ipam-accent-text'    => '#ffffff',
        '--ipam-thead-bg'       => '#3b0764',
        '--ipam-thead-text'     => '#d8b4fe',
        '--ipam-card-border'    => 'rgba(124,58,237,.15)',
        '--ipam-link'           => '#7c3aed',
        '--ipam-focus-ring'     => 'rgba(124,58,237,.25)',
        '--ipam-badge-bg'       => '#7c3aed',
    ],
    'ocean' => [
        'label'       => 'Ocean',
        'emoji'       => '🌊',
        '--ipam-navbar-bg'      => '#0c3547',
        '--ipam-navbar-text'    => '#bae6fd',
        '--ipam-body-bg'        => '#f0f9ff',
        '--ipam-accent'         => '#0284c7',
        '--ipam-accent-hover'   => '#0369a1',
        '--ipam-accent-text'    => '#ffffff',
        '--ipam-thead-bg'       => '#0c4a6e',
        '--ipam-thead-text'     => '#bae6fd',
        '--ipam-card-border'    => 'rgba(2,132,199,.15)',
        '--ipam-link'           => '#0284c7',
        '--ipam-focus-ring'     => 'rgba(2,132,199,.25)',
        '--ipam-badge-bg'       => '#0284c7',
    ],
    'sunset' => [
        'label'       => 'Sunset',
        'emoji'       => '🌅',
        '--ipam-navbar-bg'      => '#431407',
        '--ipam-navbar-text'    => '#fed7aa',
        '--ipam-body-bg'        => '#fff7ed',
        '--ipam-accent'         => '#ea580c',
        '--ipam-accent-hover'   => '#c2410c',
        '--ipam-accent-text'    => '#ffffff',
        '--ipam-thead-bg'       => '#7c2d12',
        '--ipam-thead-text'     => '#fed7aa',
        '--ipam-card-border'    => 'rgba(234,88,12,.15)',
        '--ipam-link'           => '#ea580c',
        '--ipam-focus-ring'     => 'rgba(234,88,12,.25)',
        '--ipam-badge-bg'       => '#ea580c',
    ],
    'slate' => [
        'label'       => 'Slate',
        'emoji'       => '⚫',
        '--ipam-navbar-bg'      => '#1e293b',
        '--ipam-navbar-text'    => '#cbd5e1',
        '--ipam-body-bg'        => '#f8fafc',
        '--ipam-accent'         => '#475569',
        '--ipam-accent-hover'   => '#334155',
        '--ipam-accent-text'    => '#ffffff',
        '--ipam-thead-bg'       => '#1e293b',
        '--ipam-thead-text'     => '#94a3b8',
        '--ipam-card-border'    => 'rgba(71,85,105,.12)',
        '--ipam-link'           => '#475569',
        '--ipam-focus-ring'     => 'rgba(71,85,105,.25)',
        '--ipam-badge-bg'       => '#475569',
    ],
]));

/**
 * Retourne le thème actif (slug depuis DB, défaut : 'default').
 */
function siteTheme(): string {
    $themes = unserialize(IPAM_THEMES);
    $t = getSetting('site_theme', 'default');
    return isset($themes[$t]) ? $t : 'default';
}

function siteAccent(): string {
    return getTheme()['accent'] ?? '#0d6efd';
}

/**
 * Retourne les données d'un thème.
 */
function getTheme(string $slug = ''): array {
    $themes = unserialize(IPAM_THEMES);
    $slug   = $slug ?: siteTheme();
    return $themes[$slug] ?? $themes['default'];
}

/**
 * Génère et retourne le bloc <style> CSS avec toutes les custom properties du thème actif.
 * À inclure dans le <head> de chaque page, APRÈS Bootstrap.
 */
function renderThemeCSS(): void {
    $theme   = getTheme();
    $isDark  = !empty($theme['dark_mode']);
    $vars    = '';
    foreach ($theme as $k => $v) {
        if (str_starts_with($k, '--')) {
            $vars .= "    $k: " . htmlspecialchars($v, ENT_QUOTES) . ";\n";
        }
    }
    $darkOverride = $isDark ? '
        body { color: #e2e8f0; }
        .card { background:#1e293b; border-color:var(--ipam-card-border) !important; color:#e2e8f0; }
        .table { color:#e2e8f0; }
        .table-hover>tbody>tr:hover>* { background-color: rgba(255,255,255,.04); }
        .form-control, .form-select { background:#111827; border-color:#374151; color:#e2e8f0; }
        .form-control:focus, .form-select:focus { background:#1e293b; color:#e2e8f0; }
        .input-group-text { background:#1e293b; border-color:#374151; color:#94a3b8; }
        .modal-content { background:#1e293b; color:#e2e8f0; }
        .modal-header, .modal-footer { border-color:#374151; }
        .bg-light { background:#1e293b !important; }
        .text-muted { color:#94a3b8 !important; }
        .border-top, .border-bottom { border-color:#374151 !important; }
        .alert { background:#1e293b; }
        .list-group-item { background:#1e293b; border-color:#374151; color:#e2e8f0; }
        .dropdown-menu { background:#1e293b; border-color:#374151; }
    ' : '';

    echo <<<CSS
    <style>
    :root {
    $vars}

    /* ── Navbar ── */
    .ipam-navbar {
        background-color: var(--ipam-navbar-bg) !important;
    }
    .ipam-navbar .navbar-brand,
    .ipam-navbar .nav-link,
    .ipam-navbar .text-secondary {
        color: var(--ipam-navbar-text) !important;
    }

    /* ── Body ── */
    body {
        background-color: var(--ipam-body-bg) !important;
    }

    /* ── Boutons principaux ── */
    .btn-primary,
    .btn-ipam {
        background-color: var(--ipam-accent) !important;
        border-color: var(--ipam-accent) !important;
        color: var(--ipam-accent-text) !important;
    }
    .btn-primary:hover,
    .btn-ipam:hover {
        background-color: var(--ipam-accent-hover) !important;
        border-color: var(--ipam-accent-hover) !important;
    }
    .btn-primary:focus,
    .btn-ipam:focus {
        box-shadow: 0 0 0 .25rem var(--ipam-focus-ring) !important;
    }
    .btn-outline-primary {
        color: var(--ipam-accent) !important;
        border-color: var(--ipam-accent) !important;
    }
    .btn-outline-primary:hover {
        background-color: var(--ipam-accent) !important;
        color: var(--ipam-accent-text) !important;
    }

    /* ── En-têtes de tableaux ── */
    .table-dark,
    thead.table-dark tr,
    .table > thead {
        background-color: var(--ipam-thead-bg) !important;
        color: var(--ipam-thead-text) !important;
    }
    .table-dark th {
        background-color: var(--ipam-thead-bg) !important;
        color: var(--ipam-thead-text) !important;
        border-color: rgba(255,255,255,.08) !important;
    }

    /* ── Liens ── */
    a:not(.btn):not(.nav-link):not(.navbar-brand) {
        color: var(--ipam-link);
    }
    a:not(.btn):not(.nav-link):not(.navbar-brand):hover {
        color: var(--ipam-accent-hover);
    }

    /* ── Focus rings ── */
    .form-control:focus,
    .form-select:focus {
        border-color: var(--ipam-accent) !important;
        box-shadow: 0 0 0 .25rem var(--ipam-focus-ring) !important;
    }

    /* ── Badges accent ── */
    .badge.bg-primary { background-color: var(--ipam-badge-bg) !important; }

    /* ── Nav tabs active ── */
    .nav-tabs .nav-link.active {
        color: var(--ipam-accent) !important;
        border-bottom-color: var(--ipam-accent) !important;
    }

    /* ── Rôle sysadmin ── */
    .role-sysadmin {
        background: linear-gradient(135deg,#6f42c1,#0d6efd);
        color: #fff;
    }

    $darkOverride
    </style>
    CSS;
}

// ─── TRADUCTIONS ─────────────────────────────────────────────────────────────
/**
 * Charge et retourne le tableau de traductions pour la langue active.
 * Cache statique — chargé une seule fois par requête.
 */
function loadLang(): array {
    static $strings = null;
    if ($strings !== null) return $strings;
    $lang = siteLang(); // 'fr' ou 'en'
    $file = __DIR__ . "/lang/{$lang}.php";
    if (!file_exists($file)) $file = __DIR__ . '/lang/fr.php';
    $strings = file_exists($file) ? require $file : [];
    return $strings;
}

/**
 * Retourne la traduction d'une clé.
 * Supporte les variables : t('vlan.deleted', ['name' => 'PROD']) remplace {name}.
 */
function t(string $key, array $vars = []): string {
    $strings = loadLang();
    $str     = $strings[$key] ?? $key; // fallback = la clé elle-même
    foreach ($vars as $k => $v) {
        $str = str_replace('{' . $k . '}', htmlspecialchars((string)$v, ENT_QUOTES, 'UTF-8'), $str);
    }
    return $str;
}

/**
 * Comme t() mais échappe le résultat pour affichage HTML sécurisé.
 */
function te(string $key, array $vars = []): string {
    return htmlspecialchars(t($key, $vars), ENT_QUOTES, 'UTF-8');
}

// ─── LICENCE ─────────────────────────────────────────────────────────────────
function getLicense(): ?array {
    try {
        $db = db();
        $db->exec("CREATE TABLE IF NOT EXISTS license (
            id         INTEGER PRIMARY KEY CHECK (id = 1),
            key        TEXT NOT NULL,
            owner      TEXT NOT NULL DEFAULT '',
            activated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )");
        $row = $db->query("SELECT * FROM license WHERE id=1")->fetch();
        return $row ?: null;
    } catch (Exception $e) {
        return null;
    }
}

// ─── POLITIQUE MOT DE PASSE ──────────────────────────────────────────────────
function getPwPolicy(): array {
    static $policy = null;
    if ($policy !== null) return $policy;
    try {
        $db = db();
        $rows = $db->query("SELECT key, value FROM settings WHERE key LIKE 'pw_%'")->fetchAll();
        $map  = array_column($rows, 'value', 'key');
    } catch (Exception $e) { $map = []; }
    $policy = [
        'min'        => max(1,  (int)($map['pw_min_length']  ?? 8)),
        'max'        => min(64, (int)($map['pw_max_length']  ?? 64)),
        'complexity' => (int)($map['pw_complexity']  ?? 0),
        'expiry'     => (int)($map['pw_expiry_days'] ?? 0),
    ];
    // Sanity : min <= max
    if ($policy['min'] > $policy['max']) $policy['min'] = $policy['max'];
    return $policy;
}

function validatePassword(string $pw, bool $isSysadminSet = false): array {
    $errors = [];
    $p = getPwPolicy();
    $min = $isSysadminSet ? 4 : $p['min'];
    $max = 64; // toujours 64 max absolu
    if (strlen($pw) < $min)
        $errors[] = "Minimum $min caractères requis.";
    if (strlen($pw) > $max)
        $errors[] = "Maximum $max caractères autorisés.";
    if (!$isSysadminSet) {
        if ($p['complexity'] >= 1 && (!preg_match('/[A-Z]/', $pw) || !preg_match('/[a-z]/', $pw)))
            $errors[] = "Doit contenir une majuscule et une minuscule.";
        if ($p['complexity'] >= 2 && !preg_match('/[0-9]/', $pw))
            $errors[] = "Doit contenir au moins un chiffre.";
        if ($p['complexity'] >= 3 && !preg_match('/[^A-Za-z0-9]/', $pw))
            $errors[] = "Doit contenir au moins un caractère spécial.";
    }
    return $errors;
}


// ─── FOOTER ──────────────────────────────────────────────────────────────────
function renderFooterReal(): void {
    $lic   = getLicense();
    $v     = APP_VERSION;
    $b     = APP_BUILD;
    $a     = APP_AUTHOR;
    $name  = htmlspecialchars(siteName(), ENT_QUOTES, 'UTF-8');
    $icon  = htmlspecialchars(siteIcon(), ENT_QUOTES, 'UTF-8');
    $theme = getTheme();
    $accentColor = $theme['--ipam-accent'] ?? '#0d6efd';

    $licText = $lic
        ? '<i class="bi bi-patch-check-fill text-success me-1"></i>' . te('footer.licensed_to') . ' — <strong>' . htmlspecialchars($lic['owner']) . '</strong>'
        : '<i class="bi bi-patch-exclamation-fill text-warning me-1"></i><span class="text-warning">' . te('footer.unlicensed') . '</span>';

    echo <<<HTML
    <footer class="text-center text-muted small py-3 mt-4 border-top" style="background:var(--ipam-body-bg)">
        <span class="me-2">
            <i class="bi bi-{$icon} me-1" style="color:{$accentColor}"></i>
            <strong>{$name}</strong>
            <span class="badge bg-secondary ms-1" style="font-size:.65rem">v{$v}</span>
            <span class="text-muted ms-1">build {$b}</span>
        </span>
        <span class="mx-2 text-muted">·</span>
        <span>{$licText}</span>
        <span class="mx-2 text-muted">·</span>
        <span>&copy; {$a}</span>
    </footer>
    HTML;
}
// Alias
function renderFooter(): void { renderFooterReal(); }

// ─── CSRF ─────────────────────────────────────────────────────────────────────
/**
 * Génère (ou réutilise) le token CSRF de la session.
 */
function csrfToken(): string {
    if (session_status() === PHP_SESSION_NONE) session_start();
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/**
 * Affiche le champ caché CSRF à insérer dans tout formulaire POST.
 */
function csrfField(): void {
    echo '<input type="hidden" name="csrf_token" value="' . htmlspecialchars(csrfToken(), ENT_QUOTES) . '">';
}

/**
 * Vérifie le token CSRF soumis. Redirige si invalide.
 */
function csrfVerify(string $back = 'index.php'): void {
    $submitted = $_POST['csrf_token'] ?? '';
    if (!hash_equals(csrfToken(), $submitted)) {
        if (function_exists('redirect')) {
            redirect($back, 'Requête invalide (CSRF). Veuillez réessayer.', 'danger');
        } else {
            session_start();
            $_SESSION['flash'] = ['msg' => 'Requête invalide (CSRF).', 'type' => 'danger'];
            header("Location: $back");
            exit;
        }
    }
}
