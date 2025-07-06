<?php
function getDnsRecords($domain) {
    $results = [];


    if (empty($domain)) {
        return ['error' => 'Please enter a domain name.'];
    }

    $domain = filter_var($domain, FILTER_SANITIZE_URL);


    if (!preg_match('/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$/i', $domain)) {
        return ['error' => 'Invalid domain name format.'];
    }

    
    $a_records = dns_get_record($domain, DNS_A);
    if ($a_records !== false) {
        $results['A'] = array_map(function($record) {
            return $record['ip'];
        }, $a_records);
    } else {
        $results['A'] = 'No A records found or DNS query failed.';
    }

    
    $mx_records = dns_get_record($domain, DNS_MX);
    if ($mx_records !== false) {
       
        usort($mx_records, function($a, $b) {
            return $a['pri'] <=> $b['pri'];
        });
        $results['MX'] = array_map(function($record) {
            return ['priority' => $record['pri'], 'target' => $record['target']];
        }, $mx_records);
    } else {
        $results['MX'] = 'No MX records found or DNS query failed.';
    }

    
    $ns_records = dns_get_record($domain, DNS_NS);
    if ($ns_records !== false) {
        $results['NS'] = array_map(function($record) {
            return $record['target'];
        }, $ns_records);
    } else {
        $results['NS'] = 'No NS records found or DNS query failed.';
    }
 
    $cname_records = dns_get_record($domain, DNS_CNAME);
    if ($cname_records !== false) {
        $results['CNAME'] = array_map(function($record) {
            return $record['target'];
        }, $cname_records);
    } else {
        $results['CNAME'] = 'No CNAME records found or DNS query failed.';
    }

   
    $txt_records = dns_get_record($domain, DNS_TXT);
    if ($txt_records !== false) {
        $results['TXT'] = array_map(function($record) {
            return $record['txt'];
        }, $txt_records);
    } else {
        $results['TXT'] = 'No TXT records found or DNS query failed.';
    }

    return $results;
}


$domain_to_scan = '';
$scan_results = null;
$error_message = '';

// Process form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $domain_to_scan = isset($_POST['domain']) ? trim($_POST['domain']) : '';
    $scan_results = getDnsRecords($domain_to_scan);

    if (isset($scan_results['error'])) {
        $error_message = $scan_results['error'];
        $scan_results = null; // Clear results if there's an error
    }
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DNS Scanner - Dev by Antonius (www.indodev.asia)</title>
    <link rel="stylesheet" type="text/css" href="css/indodev.css">
</head>
<body class="p-4">
    <div class="container">
        <h1 class="text-3xl font-bold text-center mb-6 text-gray-800">DNS Scanner - by Antonius (<a href="https://www.indodev.asia">www.indodev.asia</a>)</h1>

        <form method="POST" class="mb-8">
            <div class="flex flex-col sm:flex-row gap-4 items-center">
                <input
                    type="text"
                    name="domain"
                    placeholder="Enter domain name (e.g., example.com)"
                    value="<?php echo htmlspecialchars($domain_to_scan); ?>"
                    class="input-field flex-grow"
                    required
                >
                <br><br>
                <button type="submit" class="button w-full sm:w-auto">Scan DNS</button>
            </div>
        </form>

        <?php if ($error_message): ?>
            <div class="error-message">
                <p><?php echo htmlspecialchars($error_message); ?></p>
            </div>
        <?php endif; ?>

        <?php if ($scan_results): ?>
            <div class="results-section">
                <h2 class="text-2xl font-semibold mb-4 text-gray-700">DNS Records for "<?php echo htmlspecialchars($domain_to_scan); ?>"</h2>

                <?php foreach ($scan_results as $type => $records): ?>
                    <div class="mb-6">
                        <h3 class="record-type"><?php echo htmlspecialchars($type); ?> Records:</h3>
                        <?php if (is_array($records) && !empty($records)): ?>
                            <div class="space-y-2">
                                <?php foreach ($records as $record): ?>
                                    <div class="record-item">
                                        <?php
                                            if ($type === 'MX') {
                                                echo 'Priority: ' . htmlspecialchars($record['priority']) . ', Target: ' . htmlspecialchars($record['target']);
                                            } else {
                                                echo htmlspecialchars($record);
                                            }
                                        ?>
                                    </div>
                                <?php endforeach; ?>
                            </div>
                        <?php else: ?>
                            <div class="record-item text-gray-500">
                                <?php echo htmlspecialchars($records); // This will display "No X records found..." or similar ?>
                            </div>
                        <?php endif; ?>
                    </div>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>
    </div>
</body>
</html>
