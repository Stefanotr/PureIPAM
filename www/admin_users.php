<?php
/**
 * admin_users.php — Redirigé vers settings.php (onglet Utilisateurs)
 * Ce fichier est conservé pour la compatibilité avec d'éventuels bookmarks.
 */
include('auth.php');
redirect('settings.php?tab=users');
