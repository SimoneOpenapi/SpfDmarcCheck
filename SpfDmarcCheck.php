<?php

// NOTA: Questo è un esempio concettuale e ALTAMENTE SEMPLIFICATO.
// Una implementazione completa e robusta è significativamente più complessa
// e dovrebbe aderire strettamente alle RFC 7208 (SPF) e RFC 7489 (DMARC).
// L'uso di 'dig' tramite shell_exec introduce una dipendenza esterna.

define('MAX_DNS_LOOKUPS_MECHANISMS', 10); // Limite RFC per meccanismi e redirect SPF
define('MAX_RECURSION_DEPTH', 10);       // Protezione aggiuntiva per la profondità di include/redirect SPF
define('MAX_VOID_LOOKUPS', 2);           // Limite RFC per lookup nulli SPF (RFC 7208, Sezione 4.6.4)

// --- Custom Exception Classes ---
class SpfException extends \Exception {}
class SpfDnsException extends SpfException {} 
class SpfDnsTempErrorException extends SpfDnsException {} 
class SpfDnsPermErrorException extends SpfDnsException {} 
class SpfNoRecordException extends SpfException {}
class SpfMultipleRecordsException extends SpfException {}
class SpfProcessingException extends SpfException {} 
class SpfLimitExceededException extends SpfProcessingException {} 
class SpfSyntaxException extends SpfProcessingException {}
class DigCommandNotFoundException extends SpfException {}

class DmarcException extends \Exception {}
class DmarcNoRecordException extends DmarcException {}
class DmarcSyntaxException extends DmarcException {}


class SpfDmarcCheck {
    private string $domain;
    private ?string $initialDnsServerOverride;
    private array $report;

    // Lista di server DNS pubblici per la rotazione
    private static array $publicDnsServers = [
        '1.1.1.1',    // Cloudflare
        '1.0.0.1',    // Cloudflare Secondary
        '8.8.8.8',    // Google Public DNS
        '8.8.4.4',    // Google Public DNS Secondary
        '9.9.9.9',    // Quad9
        '149.112.112.112', // Quad9 Secondary
        '208.67.222.222', // OpenDNS
        '208.67.220.220', // OpenDNS Secondary
    ];
    private static int $currentDnsServerIndex = 0;

    public function __construct(string $domain, ?string $dnsServerOverride = null) {
        $this->domain = $domain;
        $this->initialDnsServerOverride = $dnsServerOverride;
        $this->report = $this->_analyzeEmailAuthentication();
    }

    public function getReport(): array {
        // Pulisce gli array di IP per una migliore leggibilità e rimuove duplicati
        if (isset($this->report['spfDetails']['collectedIpAddresses'])) {
            foreach ($this->report['spfDetails']['collectedIpAddresses'] as $key => $ips) {
                if (is_array($ips)) $this->report['spfDetails']['collectedIpAddresses'][$key] = array_values(array_unique($ips));
            }
        }
        if (isset($this->report['spfDetails']['parsedMechanisms'])) { 
            self::_cleanMechanismIpsRecursive($this->report['spfDetails']['parsedMechanisms']);
        }
        return $this->report;
    }

    /**
     * Seleziona il prossimo server DNS dalla lista pubblica per la rotazione.
     */
    private static function _getNextPublicDnsServer(): string {
        $selectedServer = self::$publicDnsServers[self::$currentDnsServerIndex];
        self::$currentDnsServerIndex = (self::$currentDnsServerIndex + 1) % count(self::$publicDnsServers);
        return $selectedServer;
    }

    /**
     * Esegue una query DNS.
     */
    private function _performDnsQuery(string $hostname, string $typeStr, ?string &$dnsServerToUseRef = null): array|false {
        $results = [];
        $serverForThisQuery = $dnsServerToUseRef; 

        if ($serverForThisQuery) { 
            $digPath = trim(@shell_exec('command -v dig'));
            if (empty($digPath) || !is_executable($digPath)) {
                throw new DigCommandNotFoundException("Command 'dig' not found or not executable, but a specific DNS server was requested ($serverForThisQuery).");
            }
            $command = "dig @" . escapeshellarg($serverForThisQuery) . " " . escapeshellarg($hostname) . " " . escapeshellarg($typeStr) . " +short +norrcomments +nocmd +noquestion +nocomments +nostats";
            $output = @shell_exec($command);
            if ($output === null || $output === false) { if (trim($output ?? '') === '') return []; throw new SpfDnsTempErrorException("Execution of 'dig' failed or no output for $hostname ($typeStr) on server $serverForThisQuery.");}
            $lines = explode("\n", trim($output));
            if (empty(trim($output)) && count($lines) === 1 && $lines[0] === '') return [];
            foreach ($lines as $line) { 
                $line = trim($line); if (empty($line)) continue;
                switch (strtoupper($typeStr)) {
                    case 'TXT': $results[] = ['txt' => str_replace('"', '', $line)]; break;
                    case 'A': if (filter_var($line, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) $results[] = ['ip' => $line]; break;
                    case 'AAAA': if (filter_var($line, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) $results[] = ['ipv6' => $line]; break;
                    case 'MX': $parts = explode(" ", $line); if (count($parts) == 2 && is_numeric($parts[0])) $results[] = ['pri' => intval($parts[0]), 'target' => rtrim($parts[1], '.')]; break;
                }
            }
        } else { 
            $canUseDig = false;
            $digPath = trim(@shell_exec('command -v dig'));
            if (!empty($digPath) && is_executable($digPath)) $canUseDig = true;

            if ($canUseDig) {
                $serverForThisQuery = self::_getNextPublicDnsServer();
                $dnsServerToUseRef = $serverForThisQuery; // Aggiorna per il report
                $command = "dig @" . escapeshellarg($serverForThisQuery) . " " . escapeshellarg($hostname) . " " . escapeshellarg($typeStr) . " +short +norrcomments +nocmd +noquestion +nocomments +nostats";
                $output = @shell_exec($command);
                if ($output === null || $output === false) { if (trim($output ?? '') === '') return []; throw new SpfDnsTempErrorException("Execution of 'dig' failed or no output for $hostname ($typeStr) on rotated server $serverForThisQuery.");}
                $lines = explode("\n", trim($output));
                if (empty(trim($output)) && count($lines) === 1 && $lines[0] === '') return [];
                foreach ($lines as $line) { 
                    $line = trim($line); if (empty($line)) continue;
                    switch (strtoupper($typeStr)) {
                        case 'TXT': $results[] = ['txt' => str_replace('"', '', $line)]; break;
                        case 'A': if (filter_var($line, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) $results[] = ['ip' => $line]; break;
                        case 'AAAA': if (filter_var($line, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) $results[] = ['ipv6' => $line]; break;
                        case 'MX': $parts = explode(" ", $line); if (count($parts) == 2 && is_numeric($parts[0])) $results[] = ['pri' => intval($parts[0]), 'target' => rtrim($parts[1], '.')]; break;
                    }
                }
            } else { 
                $dnsServerToUseRef = null; 
                $phpRecordType = match (strtoupper($typeStr)) {
                    'A' => DNS_A, 'AAAA' => DNS_AAAA, 'MX' => DNS_MX, 'TXT' => DNS_TXT, default => 0 
                };
                if ($phpRecordType === 0) { error_log("Unsupported DNS type in _performDnsQuery: " . $typeStr); return false; }
                $dnsRecs = @dns_get_record($hostname, $phpRecordType);
                if ($dnsRecs === false) return [];
                return $dnsRecs; 
            }
        }
        return $results;
    }

    /**
     * Funzione principale interna per l'analisi SPF.
     */
    private function _analyzeDomainSpfInternal(?string &$dnsServerUsedForReport): array {
        $spfDetails = [
            'domain' => $this->domain,
            'dnsServerUsed' => $dnsServerUsedForReport,
            'queriedDnsForTxt' => false, 'selectedSpfRecord' => null,
            'formalValidity' => ['startsWithVspf1' => false, 'hasValidAllMechanism' => false, 'dnsMechanismLookupCount' => 0, 'maxDnsMechanismLookups' => MAX_DNS_LOOKUPS_MECHANISMS, 'voidLookupCount' => 0, 'maxVoidLookups' => MAX_VOID_LOOKUPS, 'hasRedirectModifier' => false, 'redirectDomain' => null, 'syntaxErrors' => [], 'warnings' => [], 'explanationDomain' => null,],
            'parsedMechanisms' => [], 'allMechanismDetails' => null,
            'collectedIpAddresses' => ['ip4' => [], 'ip6' => [], 'fromA' => [], 'fromMx' => []],
            'summary' => ['totalDnsMechanismLookupsUsed' => 0, 'finalProcessingResult' => 'NEUTRAL', 'evaluationLog' => []]
        ];
        $dnsMechanismLookupCount = 0; $voidLookupCount = 0;
        $currentQueryDnsServer = $dnsServerUsedForReport;

        try {
            $txtQueryResults = $this->_performDnsQuery($this->domain, 'TXT', $currentQueryDnsServer);
            $spfDetails['dnsServerUsed'] = $currentQueryDnsServer; 
            $spfDetails['queriedDnsForTxt'] = true;
            if ($txtQueryResults === false) throw new SpfDnsTempErrorException("Initial DNS query for TXT records failed for domain '{$this->domain}'.");
            $spfRecordStrings = [];
            if (!empty($txtQueryResults)) foreach ($txtQueryResults as $record) if (($record['txt'] ?? null) && preg_match('/^v=spf1/i', $record['txt'])) $spfRecordStrings[] = $record['txt'];
            if (empty($spfRecordStrings)) throw new SpfNoRecordException("No SPF record (v=spf1) found for '{$this->domain}'.");
            if (count($spfRecordStrings) > 1) throw new SpfMultipleRecordsException("Multiple SPF records found for '{$this->domain}'.");
            $spfDetails['selectedSpfRecord'] = $spfRecordStrings[0];
            $spfDetails['formalValidity']['startsWithVspf1'] = true;
            $this->_processSpfRecordSegment($spfDetails, $this->domain, $spfDetails['selectedSpfRecord'], $dnsMechanismLookupCount, $voidLookupCount, 0, $currentQueryDnsServer);
            if ($spfDetails['summary']['finalProcessingResult'] !== 'PERMERROR' && $spfDetails['summary']['finalProcessingResult'] !== 'TEMPERROR') {
                if ($spfDetails['allMechanismDetails'] !== null) $spfDetails['summary']['finalProcessingResult'] = self::_mapQualifierToResult($spfDetails['allMechanismDetails']['qualifier']);
                elseif ($spfDetails['formalValidity']['hasRedirectModifier']) { if ($spfDetails['summary']['finalProcessingResult'] === 'NEUTRAL' && empty($spfDetails['allMechanismDetails'])) $spfDetails['summary']['finalProcessingResult'] = 'NEUTRAL';}
                else $spfDetails['summary']['finalProcessingResult'] = 'NEUTRAL'; 
            }
        } catch (SpfException $e) { // Cattura tutte le eccezioni SPF e DNS correlate
            $spfDetails['formalValidity']['syntaxErrors'][] = $e->getMessage();
            if ($e instanceof SpfNoRecordException) $spfDetails['summary']['finalProcessingResult'] = 'NONE';
            elseif ($e instanceof SpfMultipleRecordsException || $e instanceof SpfLimitExceededException || $e instanceof SpfSyntaxException || $e instanceof SpfDnsPermErrorException || $e instanceof SpfProcessingException) $spfDetails['summary']['finalProcessingResult'] = 'PERMERROR';
            else $spfDetails['summary']['finalProcessingResult'] = 'TEMPERROR'; // SpfDnsTempErrorException, DigCommandNotFoundException, Exception generica
        }
        $spfDetails['summary']['totalDnsMechanismLookupsUsed'] = $dnsMechanismLookupCount;
        $spfDetails['formalValidity']['dnsMechanismLookupCount'] = $dnsMechanismLookupCount;
        $spfDetails['formalValidity']['voidLookupCount'] = $voidLookupCount;
        $dnsServerUsedForReport = $spfDetails['dnsServerUsed'];
        return $spfDetails;
    }

    /** Funzione interna ricorsiva per processare un segmento di record SPF. */
    private function _processSpfRecordSegment(array &$reportRef, string $currentDomain, string $spfString, int &$dnsMechanismLookupCount, int &$voidLookupCount, int $recursionDepth, ?string $dnsServer) {
        if ($recursionDepth >= MAX_RECURSION_DEPTH) throw new SpfLimitExceededException("Maximum recursion depth ($MAX_RECURSION_DEPTH) exceeded for include/redirect on domain '$currentDomain'.");
        $spfContent = preg_replace('/^v=spf1\s+/i', '', $spfString);
        $terms = preg_split('/\s+/', trim($spfContent));
        $redirectModifierEncountered = false;

        foreach ($terms as $term) {
            if (empty($term)) continue;
            if ($redirectModifierEncountered) { $reportRef['formalValidity']['warnings'][] = "Term '$term' ignored (follows 'redirect=')."; continue; }
            $parsedMechanism = ['term' => $term, 'mechanism' => '', 'value' => '', 'qualifier' => '+', 'lookupCost' => 0, 'isVoidLookup' => false, 'ipsFound' => [], 'effectiveResultIfMatched' => 'NEUTRAL'];
            if (in_array($term[0], ['+', '-', '~', '?'])) { $parsedMechanism['qualifier'] = $term[0]; $termPart = substr($term, 1); } else { $termPart = $term; }
            $parsedMechanism['effectiveResultIfMatched'] = self::_mapQualifierToResult($parsedMechanism['qualifier']);
            if (strpos($termPart, '=') !== false && preg_match('/^(redirect|exp)=(.+)/i', $termPart, $modifierMatches)) { $parsedMechanism['mechanism'] = strtolower($modifierMatches[1]); $parsedMechanism['value'] = $modifierMatches[2]; }
            elseif (strpos($termPart, ':') !== false) { list($mech, $val) = explode(':', $termPart, 2); $parsedMechanism['mechanism'] = strtolower($mech); $parsedMechanism['value'] = $val; }
            else { $parsedMechanism['mechanism'] = strtolower($termPart); }
            
            try {
                $currentQueryDnsServerForMech = $dnsServer;
                switch ($parsedMechanism['mechanism']) {
                    case 'all': $reportRef['formalValidity']['hasValidAllMechanism'] = true; $reportRef['allMechanismDetails'] = ['term' => $parsedMechanism['qualifier'] . $parsedMechanism['mechanism'], 'qualifier' => $parsedMechanism['qualifier'], 'result' => $parsedMechanism['effectiveResultIfMatched']]; $reportRef['summary']['evaluationLog'][] = "Mechanism 'all': {$parsedMechanism['effectiveResultIfMatched']}"; break;
                    case 'ip4': case 'ip6': $ipToCheck = explode('/', $parsedMechanism['value'])[0]; $flag = $parsedMechanism['mechanism'] == 'ip4' ? FILTER_FLAG_IPV4 : FILTER_FLAG_IPV6; if (filter_var($ipToCheck, FILTER_VALIDATE_IP, $flag)) { $parsedMechanism['ipsFound'][] = $parsedMechanism['value']; $reportRef['collectedIpAddresses'][$parsedMechanism['mechanism']][] = $parsedMechanism['value']; } else { throw new SpfSyntaxException("Invalid IP: {$parsedMechanism['mechanism']}:{$parsedMechanism['value']}."); } break;
                    case 'a': case 'mx':
                        if ($dnsMechanismLookupCount >= MAX_DNS_LOOKUPS_MECHANISMS) throw new SpfLimitExceededException("DNS lookup limit reached at '{$term}'.");
                        $dnsMechanismLookupCount++; $parsedMechanism['lookupCost'] = 1; $lookupDomain = !empty($parsedMechanism['value']) ? self::_macroExpand($parsedMechanism['value'], $currentDomain, [], $currentQueryDnsServerForMech) : $currentDomain; $ipsFromMech = []; $isVoidThisMechanism = true;
                        if ($parsedMechanism['mechanism'] == 'a') {
                            $dnsRecordsA = $this->_performDnsQuery($lookupDomain, 'A', $currentQueryDnsServerForMech); if ($currentQueryDnsServerForMech !== $reportRef['dnsServerUsed'] && $reportRef['dnsServerUsed'] === null) $reportRef['dnsServerUsed'] = $currentQueryDnsServerForMech;
                            if ($dnsRecordsA) foreach ($dnsRecordsA as $r) if(isset($r['ip'])) {$ipsFromMech[] = $r['ip']; $isVoidThisMechanism = false;}
                            $dnsRecordsAAAA = $this->_performDnsQuery($lookupDomain, 'AAAA', $currentQueryDnsServerForMech); if ($currentQueryDnsServerForMech !== $reportRef['dnsServerUsed'] && $reportRef['dnsServerUsed'] === null) $reportRef['dnsServerUsed'] = $currentQueryDnsServerForMech;
                            if ($dnsRecordsAAAA) foreach ($dnsRecordsAAAA as $r) if(isset($r['ipv6'])) {$ipsFromMech[] = $r['ipv6']; $isVoidThisMechanism = false;}
                            if (!empty($ipsFromMech)) $reportRef['collectedIpAddresses']['fromA'] = array_merge($reportRef['collectedIpAddresses']['fromA'], $ipsFromMech);
                        } else { // mx
                            $mxHosts = $this->_performDnsQuery($lookupDomain, 'MX', $currentQueryDnsServerForMech); if ($currentQueryDnsServerForMech !== $reportRef['dnsServerUsed'] && $reportRef['dnsServerUsed'] === null) $reportRef['dnsServerUsed'] = $currentQueryDnsServerForMech;
                            if ($mxHosts) { $isVoidThisMechanism = false; uasort($mxHosts, fn($a,$b) => ($a['pri']??INF)<=>($b['pri']??INF));
                                foreach ($mxHosts as $mx) { if (!isset($mx['target'])) continue; if ($dnsMechanismLookupCount >= MAX_DNS_LOOKUPS_MECHANISMS) throw new SpfLimitExceededException("DNS lookup limit at MX host '{$mx['target']}'.");
                                    $dnsMechanismLookupCount++; $parsedMechanism['lookupCost']++; $isMxHostVoid = true; $mxTargetDomain = self::_macroExpand($mx['target'], $currentDomain, [], $currentQueryDnsServerForMech);
                                    $mx_arecords = $this->_performDnsQuery($mxTargetDomain, 'A', $currentQueryDnsServerForMech); if ($currentQueryDnsServerForMech !== $reportRef['dnsServerUsed'] && $reportRef['dnsServerUsed'] === null) $reportRef['dnsServerUsed'] = $currentQueryDnsServerForMech;
                                    if ($mx_arecords) foreach ($mx_arecords as $r) if(isset($r['ip'])) {$ipsFromMech[] = $r['ip']; $isMxHostVoid = false;}
                                    $mx_aaaa_records = $this->_performDnsQuery($mxTargetDomain, 'AAAA', $currentQueryDnsServerForMech); if ($currentQueryDnsServerForMech !== $reportRef['dnsServerUsed'] && $reportRef['dnsServerUsed'] === null) $reportRef['dnsServerUsed'] = $currentQueryDnsServerForMech;
                                    if ($mx_aaaa_records) foreach ($mx_aaaa_records as $r) if(isset($r['ipv6'])) {$ipsFromMech[] = $r['ipv6']; $isMxHostVoid = false;}
                                    if ($isMxHostVoid) { $voidLookupCount++; if ($voidLookupCount > MAX_VOID_LOOKUPS) throw new SpfLimitExceededException("Void lookup limit at MX host '{$mxTargetDomain}'."); }
                                } if (!empty($ipsFromMech)) $reportRef['collectedIpAddresses']['fromMx'] = array_merge($reportRef['collectedIpAddresses']['fromMx'], $ipsFromMech);
                            }
                        } $parsedMechanism['ipsFound'] = $ipsFromMech; if ($isVoidThisMechanism) $voidLookupCount++; $parsedMechanism['isVoidLookup'] = $isVoidThisMechanism; if ($voidLookupCount > MAX_VOID_LOOKUPS) throw new SpfLimitExceededException("Void lookup limit at '{$term}'."); break;
                    case 'include':
                        if ($dnsMechanismLookupCount >= MAX_DNS_LOOKUPS_MECHANISMS) throw new SpfLimitExceededException("DNS lookup limit at 'include:{$parsedMechanism['value']}'.");
                        $dnsMechanismLookupCount++; $parsedMechanism['lookupCost'] = 1; $includeDomain = self::_macroExpand($parsedMechanism['value'], $currentDomain, [], $currentQueryDnsServerForMech);
                        $txtRecordsInclude = $this->_performDnsQuery($includeDomain, 'TXT', $currentQueryDnsServerForMech); if ($currentQueryDnsServerForMech !== $reportRef['dnsServerUsed'] && $reportRef['dnsServerUsed'] === null) $reportRef['dnsServerUsed'] = $currentQueryDnsServerForMech;
                        $selectedIncludedSpf = null; $isIncludeVoid = true;
                        if ($txtRecordsInclude) { $spfStringsInclude = []; foreach($txtRecordsInclude as $r) if (isset($r['txt']) && preg_match('/^v=spf1/i', $r['txt'])) $spfStringsInclude[] = $r['txt']; if (count($spfStringsInclude) === 1) { $selectedIncludedSpf = $spfStringsInclude[0]; $isIncludeVoid = false; } elseif (count($spfStringsInclude) > 1) throw new SpfSyntaxException("Included domain '$includeDomain' has multiple SPF records."); }
                        if ($isIncludeVoid) $voidLookupCount++; if ($voidLookupCount > MAX_VOID_LOOKUPS) throw new SpfLimitExceededException("Void lookup limit at 'include:{$includeDomain}'.");
                        if ($selectedIncludedSpf) {
                            $parsedMechanism['includedReport'] = ['domain' => $includeDomain, 'selectedSpfRecord' => $selectedIncludedSpf, 'formalValidity' => ['dnsMechanismLookupCount' => 0, 'voidLookupCount' => 0, 'maxVoidLookups' => MAX_VOID_LOOKUPS, 'syntaxErrors' => [], 'warnings' => [], 'dnsServerUsed' => $currentQueryDnsServerForMech], 'parsedMechanisms' => [], 'allMechanismDetails' => null, 'collectedIpAddresses' => ['ip4' => [], 'ip6' => [], 'fromA' => [], 'fromMx' => []], 'summary' => ['finalProcessingResult' => 'NEUTRAL']];
                            $this->_processSpfRecordSegment($parsedMechanism['includedReport'], $includeDomain, $selectedIncludedSpf, $dnsMechanismLookupCount, $voidLookupCount, $recursionDepth + 1, $currentQueryDnsServerForMech);
                            foreach (['ip4', 'ip6', 'fromA', 'fromMx'] as $type) if(isset($parsedMechanism['includedReport']['collectedIpAddresses'][$type])) $reportRef['collectedIpAddresses'][$type] = array_unique(array_merge($reportRef['collectedIpAddresses'][$type], $parsedMechanism['includedReport']['collectedIpAddresses'][$type]));
                            $includeResult = $parsedMechanism['includedReport']['summary']['finalProcessingResult']; if ($includeResult === 'PERMERROR' || $includeResult === 'TEMPERROR') throw new SpfProcessingException("Include of '$includeDomain' resulted in $includeResult.", 0, $includeResult === 'PERMERROR' ? new SpfDnsPermErrorException("Error in included domain $includeDomain") : new SpfDnsTempErrorException("Error in included domain $includeDomain"));
                        } else { throw new SpfSyntaxException("No valid SPF record for 'include:{$includeDomain}'. PermError for mechanism.");} break;
                    case 'redirect':
                        if ($dnsMechanismLookupCount >= MAX_DNS_LOOKUPS_MECHANISMS) throw new SpfLimitExceededException("DNS lookup limit at 'redirect={$parsedMechanism['value']}'.");
                        $dnsMechanismLookupCount++; $parsedMechanism['lookupCost'] = 1; $reportRef['formalValidity']['hasRedirectModifier'] = true; $redirectDomain = self::_macroExpand($parsedMechanism['value'], $currentDomain, [], $currentQueryDnsServerForMech); $reportRef['formalValidity']['redirectDomain'] = $redirectDomain; $redirectModifierEncountered = true;
                        $txtRecordsRedirect = $this->_performDnsQuery($redirectDomain, 'TXT', $currentQueryDnsServerForMech); if ($currentQueryDnsServerForMech !== $reportRef['dnsServerUsed'] && $reportRef['dnsServerUsed'] === null) $reportRef['dnsServerUsed'] = $currentQueryDnsServerForMech;
                        $selectedRedirectSpf = null; $isRedirectVoid = true;
                        if ($txtRecordsRedirect) { $spfStringsRedirect = []; foreach($txtRecordsRedirect as $r) if (isset($r['txt']) && preg_match('/^v=spf1/i', $r['txt'])) $spfStringsRedirect[] = $r['txt']; if (count($spfStringsRedirect) === 1) { $selectedRedirectSpf = $spfStringsRedirect[0]; $isRedirectVoid = false; } elseif (count($spfStringsRedirect) > 1) throw new SpfSyntaxException("Redirect domain '$redirectDomain' has multiple SPF records."); }
                        if ($isRedirectVoid) $voidLookupCount++; if ($voidLookupCount > MAX_VOID_LOOKUPS) throw new SpfLimitExceededException("Void lookup limit at 'redirect={$redirectDomain}'.");
                        if ($selectedRedirectSpf) {
                            $parsedMechanism['redirectedReport'] = ['domain' => $redirectDomain, 'selectedSpfRecord' => $selectedRedirectSpf, 'formalValidity' => ['dnsMechanismLookupCount' => 0, 'voidLookupCount' => 0, 'maxVoidLookups' => MAX_VOID_LOOKUPS, 'syntaxErrors' => [], 'warnings' => [], 'dnsServerUsed' => $currentQueryDnsServerForMech], 'parsedMechanisms' => [], 'allMechanismDetails' => null, 'summary' => ['finalProcessingResult' => 'NEUTRAL']];
                            $this->_processSpfRecordSegment($parsedMechanism['redirectedReport'], $redirectDomain, $selectedRedirectSpf, $dnsMechanismLookupCount, $voidLookupCount, $recursionDepth + 1, $currentQueryDnsServerForMech);
                            $reportRef['summary']['finalProcessingResult'] = $parsedMechanism['redirectedReport']['summary']['finalProcessingResult']; if ($parsedMechanism['redirectedReport']['allMechanismDetails']) $reportRef['allMechanismDetails'] = $parsedMechanism['redirectedReport']['allMechanismDetails'];
                        } else { throw new SpfSyntaxException("No valid SPF record for 'redirect={$redirectDomain}'."); }
                        $reportRef['parsedMechanisms'][] = $parsedMechanism; return; 
                    case 'exists':
                        if ($dnsMechanismLookupCount >= MAX_DNS_LOOKUPS_MECHANISMS) throw new SpfLimitExceededException("DNS lookup limit at 'exists:{$parsedMechanism['value']}'.");
                        $dnsMechanismLookupCount++; $parsedMechanism['lookupCost'] = 1; $existsDomain = self::_macroExpand($parsedMechanism['value'], $currentDomain, [], $currentQueryDnsServerForMech);
                        $exists_arecords = $this->_performDnsQuery($existsDomain, 'A', $currentQueryDnsServerForMech); if ($currentQueryDnsServerForMech !== $reportRef['dnsServerUsed'] && $reportRef['dnsServerUsed'] === null) $reportRef['dnsServerUsed'] = $currentQueryDnsServerForMech;
                        if (!$exists_arecords || empty($exists_arecords)) { $voidLookupCount++; $parsedMechanism['isVoidLookup'] = true; }
                        if ($voidLookupCount > MAX_VOID_LOOKUPS) throw new SpfLimitExceededException("Void lookup limit at 'exists:{$existsDomain}'."); break;
                    case 'ptr': $reportRef['formalValidity']['warnings'][] = "PTR mechanism used ({$term}). Discouraged. Not implemented."; break;
                    case 'exp': $reportRef['formalValidity']['explanationDomain'] = self::_macroExpand($parsedMechanism['value'], $currentDomain, [], $currentQueryDnsServerForMech); break;
                    default: throw new SpfSyntaxException("Unknown mechanism/modifier: '{$parsedMechanism['term']}'.");
                }
            } catch (SpfException $e) { $reportRef['parsedMechanisms'][] = $parsedMechanism; throw $e; }
            $reportRef['parsedMechanisms'][] = $parsedMechanism;
        }
    }

    /** Mappa un qualificatore SPF al risultato testuale. */
    private static function _mapQualifierToResult(string $qualifier): string {
        return match ($qualifier) { '+' => 'PASS', '-' => 'FAIL', '~' => 'SOFTFAIL', '?' => 'NEUTRAL', default => 'NEUTRAL' };
    }

    /** Espande le macro SPF (semplificato). */
    private static function _macroExpand(string $value, string $domain, array $emailContext = [], ?string $dnsServer = null): string {
        $ip = $emailContext['ip'] ?? '127.0.0.1'; $sender = $emailContext['sender'] ?? 'postmaster@unknown.example.com'; $heloDomain = $emailContext['helo_domain'] ?? $domain; 
        list($localPart, $senderDomain) = explode('@', $sender, 2) + [null, $domain]; 
        $macros = ['%{s}' => $sender, '%{l}' => $localPart, '%{o}' => $senderDomain, '%{d}' => $domain, '%{i}' => $ip, '%{h}' => $heloDomain, '%{c}' => $ip, '%{r}' => php_uname('n'), '%{t}' => time()];
        return str_replace(array_keys($macros), array_values($macros), $value);
    }

    /**
     * Analizza il record DMARC per un dominio.
     */
    private function _analyzeDomainDmarcInternal(?string &$dnsServerUsedForReport): array {
        $dmarcDetails = [
            'recordFound' => false, 'record' => null, 'dnsQueryDomain' => '_dmarc.' . $this->domain, 'dnsServerUsed' => $dnsServerUsedForReport,
            'policy' => null, 'subdomainPolicy' => null, 'alignmentDkim' => 'r', 'alignmentSpf' => 'r',  
            'percentage' => 100, 'reportingUrisAggregate' => [], 'reportingUrisFailure' => [],
            'failureOptions' => [], 'errors' => [], 'warnings' => []
        ];
        $dmarcQueryDomain = $dmarcDetails['dnsQueryDomain'];
        $currentQueryDnsServer = $dnsServerUsedForReport;

        try {
            $txtRecords = $this->_performDnsQuery($dmarcQueryDomain, 'TXT', $currentQueryDnsServer);
            $dmarcDetails['dnsServerUsed'] = $currentQueryDnsServer;
            $dmarcRecordString = null;
            if ($txtRecords) foreach ($txtRecords as $record) if (($record['txt'] ?? null) && stripos($record['txt'], 'v=DMARC1') === 0) { if ($dmarcRecordString !== null) throw new DmarcSyntaxException("Multiple DMARC records for '$dmarcQueryDomain'."); $dmarcRecordString = $record['txt']; }
            if ($dmarcRecordString) {
                $dmarcDetails['recordFound'] = true; $dmarcDetails['record'] = $dmarcRecordString;
                $tags = explode(';', $dmarcRecordString);
                foreach ($tags as $tag) { $tag = trim($tag); if (empty($tag)) continue; $parts = explode('=', $tag, 2);
                    if (count($parts) === 2) { $key = strtolower(trim($parts[0])); $value = trim($parts[1]);
                        switch ($key) {
                            case 'v': if (strtolower($value) !== 'dmarc1') $dmarcDetails['warnings'][] = "DMARC version not 'DMARC1': $value"; break;
                            case 'p': $dmarcDetails['policy'] = strtolower($value); if (!in_array($dmarcDetails['policy'], ['none', 'quarantine', 'reject'])) $dmarcDetails['warnings'][] = "Invalid DMARC policy (p=): $value"; break;
                            case 'sp': $dmarcDetails['subdomainPolicy'] = strtolower($value); if (!in_array($dmarcDetails['subdomainPolicy'], ['none', 'quarantine', 'reject'])) $dmarcDetails['warnings'][] = "Invalid DMARC subdomain policy (sp=): $value"; break;
                            case 'adkim': $dmarcDetails['alignmentDkim'] = strtolower($value); if (!in_array($dmarcDetails['alignmentDkim'], ['r', 's'])) $dmarcDetails['warnings'][] = "Invalid DKIM alignment (adkim=): $value"; break;
                            case 'aspf': $dmarcDetails['alignmentSpf'] = strtolower($value); if (!in_array($dmarcDetails['alignmentSpf'], ['r', 's'])) $dmarcDetails['warnings'][] = "Invalid SPF alignment (aspf=): $value"; break;
                            case 'pct': if (is_numeric($value) && $value >= 0 && $value <= 100) $dmarcDetails['percentage'] = intval($value); else $dmarcDetails['warnings'][] = "Invalid percentage (pct=): $value"; break;
                            case 'rua': $dmarcDetails['reportingUrisAggregate'] = array_map('trim', explode(',', $value)); break;
                            case 'ruf': $dmarcDetails['reportingUrisFailure'] = array_map('trim', explode(',', $value)); break;
                            case 'fo': $dmarcDetails['failureOptions'] = array_map('trim', explode(':', strtolower($value))); break;
                        }
                    } else { if (!empty($tag) && strpos($tag, '=') === false && strlen($tag) > 1 && $tag !== 'v') $dmarcDetails['warnings'][] = "Malformed DMARC tag: '$tag'"; elseif (strpos($tag, '=') !== false && empty(trim(explode('=', $tag, 2)[1]))) $dmarcDetails['warnings'][] = "DMARC tag with empty value: '$tag'";}
                } if ($dmarcDetails['policy'] === null) $dmarcDetails['warnings'][] = "Mandatory DMARC policy (p=) missing.";
            } else throw new DmarcNoRecordException("No DMARC record (v=DMARC1) for '$dmarcQueryDomain'.");
        } catch (DmarcException $e) { $dmarcDetails['errors'][] = $e->getMessage();
        } catch (SpfDnsException $e) { $dmarcDetails['errors'][] = "DNS error for $dmarcQueryDomain: " . $e->getMessage();
        } catch (\Exception $e) { $dmarcDetails['errors'][] = "Error querying DMARC for $dmarcQueryDomain: " . $e->getMessage(); }
        $dnsServerUsedForReport = $dmarcDetails['dnsServerUsed'];
        return $dmarcDetails;
    }

    /**
     * Analizza SPF e DMARC per un dominio.
     */
    private function _analyzeEmailAuthentication(): array {
        $spfAnalysisDetails = []; 
        $dmarcAnalysisDetails = []; 
        $validSpf = false; $validDmarc = false;
        $digCommandError = null; 
        $dnsServerForSpf = $this->initialDnsServerOverride; 

        try {
            $spfReport = $this->_analyzeDomainSpfInternal($dnsServerForSpf); // Passa per riferimento
            $spfAnalysisDetails = $spfReport;
            if (!in_array($spfReport['summary']['finalProcessingResult'], ['PERMERROR', 'TEMPERROR', 'NONE'])) $validSpf = true; 
        } catch (DigCommandNotFoundException $e) { 
            $digCommandError = $e->getMessage(); 
            $spfAnalysisDetails['formalValidity']['syntaxErrors'][] = "Configuration error for SPF: " . $digCommandError;
            $spfAnalysisDetails['summary']['finalProcessingResult'] = 'TEMPERROR';
        } catch (\Exception $e) {
            if (!isset($spfAnalysisDetails['formalValidity'])) $spfAnalysisDetails['formalValidity'] = ['syntaxErrors' => []];
            if (!isset($spfAnalysisDetails['summary'])) $spfAnalysisDetails['summary'] = [];
            $spfAnalysisDetails['formalValidity']['syntaxErrors'][] = "Unexpected error during SPF analysis: " . $e->getMessage();
            $spfAnalysisDetails['summary']['finalProcessingResult'] = 'TEMPERROR';
        }
        
        // Il server DNS per DMARC sarà l'override iniziale se fornito, altrimenti DMARC gestirà la sua rotazione.
        $dnsServerForDmarc = $this->initialDnsServerOverride;

        if ($digCommandError) {
            if (!isset($dmarcAnalysisDetails['errors'])) $dmarcAnalysisDetails['errors'] = [];
            $dmarcAnalysisDetails['errors'][] = "DMARC check skipped due to Dig configuration error: " . $digCommandError;
        } else {
            try {
                $dmarcReport = $this->_analyzeDomainDmarcInternal($dnsServerForDmarc); // Passa per riferimento
                $dmarcAnalysisDetails = $dmarcReport;
                if ($dmarcReport['recordFound'] && !empty($dmarcReport['policy']) && empty($dmarcReport['errors'])) $validDmarc = true; 
            } catch (DigCommandNotFoundException $e) { 
                if (!isset($dmarcAnalysisDetails['errors'])) $dmarcAnalysisDetails['errors'] = [];
                $dmarcAnalysisDetails['errors'][] = "Configuration error for DMARC: " . $e->getMessage();
            } catch (\Exception $e) {
                if (!isset($dmarcAnalysisDetails['errors'])) $dmarcAnalysisDetails['errors'] = [];
                $dmarcAnalysisDetails['errors'][] = "Unexpected error during DMARC analysis: " . $e->getMessage();
            }
        }
        
        if (empty($spfAnalysisDetails)) $spfAnalysisDetails = ['domain' => $this->domain, 'dnsServerUsed' => $dnsServerForSpf, 'summary' => ['finalProcessingResult' => 'TEMPERROR'], 'formalValidity' => ['syntaxErrors' => ['SPF analysis could not be performed.']]];
        if (empty($dmarcAnalysisDetails)) $dmarcAnalysisDetails = ['domain' => $this->domain, 'dnsServerUsed' => $dnsServerForDmarc, 'errors' => ['DMARC analysis could not be performed.']];

        return [
            'domainAnalyzed' => $this->domain,
            'dnsServerUsedGlobalOverride' => $this->initialDnsServerOverride, 
            'validSpf' => $validSpf,
            'spfDetails' => $spfAnalysisDetails,
            'validDmarc' => $validDmarc,
            'dmarcDetails' => $dmarcAnalysisDetails
        ];
    }

    /**
     * Pulisce ricorsivamente gli array di IP nei meccanismi SPF.
     */
    private static function _cleanMechanismIpsRecursive(array &$mechanisms): void { 
        if (!is_array($mechanisms)) return;
        foreach ($mechanisms as &$mech) { 
            if (isset($mech['ipsFound']) && is_array($mech['ipsFound'])) $mech['ipsFound'] = array_values(array_unique($mech['ipsFound']));
            if (isset($mech['includedReport']['parsedMechanisms'])) self::_cleanMechanismIpsRecursive($mech['includedReport']['parsedMechanisms']);
            if (isset($mech['redirectedReport']['parsedMechanisms'])) self::_cleanMechanismIpsRecursive($mech['redirectedReport']['parsedMechanisms']);
            if (isset($mech['includedReport']['collectedIpAddresses'])) foreach ($mech['includedReport']['collectedIpAddresses'] as $key => $ips) if (is_array($ips)) $mech['includedReport']['collectedIpAddresses'][$key] = array_values(array_unique($ips));
            if (isset($mech['redirectedReport']['collectedIpAddresses'])) foreach ($mech['redirectedReport']['collectedIpAddresses'] as $key => $ips) if (is_array($ips)) $mech['redirectedReport']['collectedIpAddresses'][$key] = array_values(array_unique($ips));
        }
    }
}


// --- Esempio di Utilizzo ---
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

?>
