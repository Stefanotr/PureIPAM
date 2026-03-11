<?php
// Fonctions déplacées dans auth.php
// Ce fichier est conservé pour la compatibilité.
if (!function_exists('validateIpInSubnet')) {
    require_once __DIR__ . '/auth.php';
}
