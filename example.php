<?php 

// --- Esempio di Utilizzo ---

require_once("SpfDmarcCheck.php");

if (php_sapi_name() == "cli") {
    $options = getopt("d:s:h", ["domain:", "server:", "help"]);
    if (isset($options['h']) || isset($options['help']) || empty($options['d']) && empty($options['domain'])) {
        echo "Usage: php " . basename(__FILE__) . " -d <domain> [-s <dns_server>]\n";
        echo "  -d, --domain   Domain to analyze (e.g., gmail.com)\n";
        echo "  -s, --server   DNS server to use (optional, overrides rotation, e.g., 8.8.8.8)\n";
        echo "  -h, --help     Show this help\n\n";
        exit;
    }
    $dominioDaAnalizzare = $options['d'] ?? $options['domain'];
    $serverDnsSpecifico = $options['s'] ?? $options['server'] ?? null;
    if ($serverDnsSpecifico) {
        echo "Analyzing domain: $dominioDaAnalizzare using DNS server: $serverDnsSpecifico (override)\n\n";
    } else {
        echo "Analyzing domain: $dominioDaAnalizzare using rotated public DNS servers (if 'dig' is available) or system DNS\n\n";
    }
} else { // Web
    $dominioDaAnalizzare = $_GET['domain'] ?? 'gmail.com';
    $serverDnsSpecifico = $_GET['dns_server'] ?? null;
    if (isset($_GET['domain'])) echo "<pre>"; 
}

if (!empty($dominioDaAnalizzare)) {
    $checker = new SpfDmarcCheck($dominioDaAnalizzare, $serverDnsSpecifico);
    $reportAuth = $checker->getReport();

    if (php_sapi_name() != "cli") header('Content-Type: application/json');
    echo json_encode($reportAuth, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);

} elseif (php_sapi_name() == "cli" && !(isset($options['h']) || isset($options['help']))) {
     echo "No domain specified.\n";
}


if (php_sapi_name() == "cli") {
    echo "\n";
} else {
    if (isset($_GET['domain'])) echo "</pre>";
    else echo "Please specify a 'domain' parameter in the query string (e.g., ?domain=example.com&dns_server=8.8.8.8)";
}
