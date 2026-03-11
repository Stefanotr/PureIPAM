<?php
// Compatibilité – les anciennes requêtes POST vers vlan_add.php sont redirigées
include('auth.php');
if (!$isAdmin) redirect('index.php', 'Accès refusé.', 'danger');
if (isset($_POST['vid'])) {
    $_POST['add_vlan'] = '1';
    include('vlan_action.php');
} else {
    redirect('index.php');
}
