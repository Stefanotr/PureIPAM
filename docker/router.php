<?php
/**
 * Router PHP built-in — remplace .htaccess pour php -S
 * Bloque l'accès direct aux fichiers sensibles
 */

$uri  = $_SERVER['REQUEST_URI'];
$path = parse_url($uri, PHP_URL_PATH);
$file = __DIR__ . $path;

// ─── FICHIERS BLOQUÉS ────────────────────────────────────────────────────────
$blocked = [
    // Fichiers sensibles à la racine
    '/ipam.db', '/composer.json', '/composer.lock',
    // Répertoires entiers (tout ce qui commence par)
    '/vendor/', '/lang/', '/docker/',
];

foreach ($blocked as $b) {
    if (str_ends_with($b, '/')) {
        // Blocage de répertoire
        if (str_starts_with($path, $b)) {
            http_response_code(403);
            echo '403 Forbidden';
            return true;
        }
    } else {
        // Blocage de fichier exact
        if ($path === $b) {
            http_response_code(403);
            echo '403 Forbidden';
            return true;
        }
    }
}

// ─── FICHIERS STATIQUES ───────────────────────────────────────────────────────
// Laisser PHP servir les fichiers statiques qui existent (.css, .js, .png, etc.)
if ($path !== '/' && file_exists($file) && !is_dir($file)) {
    return false; // PHP built-in gère le fichier statique
}

// ─── ROUTING PHP ─────────────────────────────────────────────────────────────
// Si le fichier PHP demandé existe, le servir
if (file_exists($file . '.php')) {
    $_SERVER['SCRIPT_FILENAME'] = $file . '.php';
    include $file . '.php';
    return true;
}

// Laisser le serveur built-in gérer (servira le .php si présent)
return false;
