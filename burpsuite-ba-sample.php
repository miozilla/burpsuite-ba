<?php

// test cmd
// sudo php burpsuite-ba-sample.php

// === CONFIGURATION ===
$base_url = "http://127.0.0.1/mutillidae/index.php?page=resetpassword.php"; // Target page
$payload = "<script>alert('XSS')</script>"; // XSS payload
$params_to_test = ['email', 'token', 'username']; // Common reset params
$output_file = "/root/altemail"; // File to write results

// === Prepare output
file_put_contents($output_file, "[*] XSS Scan Results for resetpassword.php\n\n");

foreach ($params_to_test as $param) {
    echo "\n[*] Testing parameter: $param\n";
    $test_url = $base_url . "&" . $param . "=" . urlencode($payload);
    echo "[*] Requesting URL: $test_url\n";

    $response = @file_get_contents($test_url);

    if ($response === false) {
        echo "[!] Failed to connect or load page.\n";
        file_put_contents($output_file, "[!] Failed to load $test_url\n", FILE_APPEND);
        continue;
    }

    if (strpos($response, $payload) !== false) {
        echo "[-] Potential XSS in parameter: '$param'\n";
        file_put_contents($output_file, "[-] XSS possible in parameter: '$param'\n", FILE_APPEND);
    } else {
        echo "[✓] No XSS in parameter: '$param'\n";
        file_put_contents($output_file, "[✓] No XSS in parameter: '$param'\n", FILE_APPEND);
    }
}

echo "\n[✓] Results saved to $output_file\n";
?>

