/*
Enterprise-Grade YARA Rules for Advanced Malware Detection
==========================================================
This file contains sophisticated detection rules used by enterprise antivirus solutions.
Rules are categorized by malware families, attack techniques, and file types.
*/

// ============================================================================
// MALWARE FAMILY DETECTION RULES
// ============================================================================

rule Malware_Family_Emotet {
    meta:
        description = "Detects Emotet banking trojan variants"
        author = "Enterprise AV Team"
        date = "2024-01-01"
        version = "1.0"
        severity = "Critical"
        family = "Emotet"
        mitre_attck = "T1071.001, T1059.001, T1083"
        confidence = "High"
    strings:
        $emotet_string1 = "emotet" nocase
        $emotet_string2 = "geodo" nocase
        $emotet_string3 = "heodo" nocase
        $emotet_c2 = /https?:\/\/[a-zA-Z0-9.-]+\/gate\.php/ nocase
        $emotet_payload = /powershell.*-enc.*[A-Za-z0-9+/]{20,}/ nocase
        $emotet_registry = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
    condition:
        (2 of ($emotet_string*)) or ($emotet_c2 and $emotet_payload) or ($emotet_registry and $emotet_payload)
}

rule Malware_Family_Ryuk {
    meta:
        description = "Detects Ryuk ransomware variants"
        author = "Enterprise AV Team"
        date = "2024-01-01"
        version = "1.0"
        severity = "Critical"
        family = "Ryuk"
        mitre_attck = "T1486, T1489, T1490"
        confidence = "High"
    strings:
        $ryuk_string1 = "ryuk" nocase
        $ryuk_string2 = "ryuk_encrypted" nocase
        $ryuk_extension = ".ryuk" nocase
        $ryuk_note = "RYUK_README.txt" nocase
        $ryuk_encryption = "AES-256" nocase
        $ryuk_ransom = "pay the ransom" nocase
    condition:
        (2 of ($ryuk_string*)) or ($ryuk_extension and $ryuk_note) or ($ryuk_encryption and $ryuk_ransom)
}

rule Malware_Family_TrickBot {
    meta:
        description = "Detects TrickBot banking trojan"
        author = "Enterprise AV Team"
        date = "2024-01-01"
        version = "1.0"
        severity = "Critical"
        family = "TrickBot"
        mitre_attck = "T1071.001, T1059.001, T1083"
        confidence = "High"
    strings:
        $trickbot_string1 = "trickbot" nocase
        $trickbot_string2 = "trick" nocase
        $trickbot_c2 = /https?:\/\/[a-zA-Z0-9.-]+\/post\.php/ nocase
        $trickbot_injection = "VirtualAllocEx" nocase
        $trickbot_banking = "banking" nocase
    condition:
        (2 of ($trickbot_string*)) or ($trickbot_c2 and $trickbot_injection) or ($trickbot_banking and $trickbot_injection)
}

// ============================================================================
// ATTACK TECHNIQUE DETECTION RULES
// ============================================================================

rule Technique_Process_Injection {
    meta:
        description = "Detects process injection techniques"
        author = "Enterprise AV Team"
        date = "2024-01-01"
        version = "1.0"
        severity = "High"
        technique = "Process Injection"
        mitre_attck = "T1055"
        confidence = "Medium"
    strings:
        $virtual_alloc = "VirtualAllocEx" nocase
        $write_process = "WriteProcessMemory" nocase
        $create_remote = "CreateRemoteThread" nocase
        $nt_unmap = "NtUnmapViewOfSection" nocase
        $nt_allocate = "NtAllocateVirtualMemory" nocase
        $nt_write = "NtWriteVirtualMemory" nocase
        $nt_create = "NtCreateThreadEx" nocase
    condition:
        3 of them
}

rule Technique_Code_Injection {
    meta:
        description = "Detects code injection patterns"
        author = "Enterprise AV Team"
        date = "2024-01-01"
        version = "1.0"
        severity = "High"
        technique = "Code Injection"
        mitre_attck = "T1055.001"
        confidence = "Medium"
    strings:
        $shellcode = /\\x[0-9a-fA-F]{2}/ nocase
        $base64_payload = /[A-Za-z0-9+/]{50,}={0,2}/ nocase
        $hex_payload = /[0-9a-fA-F]{100,}/ nocase
        $xor_key = /xor.*[0-9a-fA-F]{2,}/ nocase
    condition:
        2 of them
}

rule Technique_Privilege_Escalation {
    meta:
        description = "Detects privilege escalation attempts"
        author = "Enterprise AV Team"
        date = "2024-01-01"
        version = "1.0"
        severity = "High"
        technique = "Privilege Escalation"
        mitre_attck = "T1068"
        confidence = "Medium"
    strings:
        $uac_bypass = "UAC bypass" nocase
        $token_manipulation = "Token Manipulation" nocase
        $se_debug = "SeDebugPrivilege" nocase
        $se_tcb = "SeTcbPrivilege" nocase
        $runas = "runas" nocase
        $elevate = "elevate" nocase
    condition:
        2 of them
}

rule Technique_Persistence {
    meta:
        description = "Detects persistence mechanisms"
        author = "Enterprise AV Team"
        date = "2024-01-01"
        version = "1.0"
        severity = "High"
        technique = "Persistence"
        mitre_attck = "T1547"
        confidence = "Medium"
    strings:
        $run_key = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $run_once = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase
        $startup_folder = "Startup" nocase
        $task_scheduler = "schtasks" nocase
        $service_install = "sc create" nocase
        $wmi_event = "WMI" nocase
    condition:
        2 of them
}

// ============================================================================
// FILE TYPE SPECIFIC RULES
// ============================================================================

rule PDF_Malware {
    meta:
        description = "Detects malicious PDF files"
        author = "Enterprise AV Team"
        date = "2024-01-01"
        version = "1.0"
        severity = "High"
        file_type = "PDF"
        confidence = "Medium"
    strings:
        $pdf_header = "%PDF-"
        $javascript = "/JS" nocase
        $launch = "/Launch" nocase
        $embedded_file = "/EmbeddedFile" nocase
        $action = "/Action" nocase
        $uri = "/URI" nocase
        $base64_pdf = /[A-Za-z0-9+/]{100,}={0,2}/ nocase
    condition:
        $pdf_header and (2 of ($javascript, $launch, $embedded_file, $action, $uri)) or ($base64_pdf and $javascript)
}

rule Office_Macro_Malware_Advanced {
    meta:
        description = "Detects advanced Office macro malware"
        author = "Enterprise AV Team"
        date = "2024-01-01"
        version = "1.0"
        severity = "High"
        file_type = "Office"
        confidence = "Medium"
    strings:
        $vba_start = "VBA" nocase
        $auto_open = "Auto_Open" nocase
        $auto_close = "Auto_Close" nocase
        $document_open = "Document_Open" nocase
        $shell_execute = "Shell.Application" nocase
        $wscript_shell = "WScript.Shell" nocase
        $powershell = "powershell" nocase
        $cmd_exec = "cmd.exe" nocase
        $download_string = "DownloadString" nocase
        $invoke_expression = "Invoke-Expression" nocase
    condition:
        $vba_start and (($auto_open or $auto_close or $document_open) and (2 of ($shell_execute, $wscript_shell, $powershell, $cmd_exec, $download_string, $invoke_expression)))
}

rule JavaScript_Malware {
    meta:
        description = "Detects malicious JavaScript"
        author = "Enterprise AV Team"
        date = "2024-01-01"
        version = "1.0"
        severity = "High"
        file_type = "JavaScript"
        confidence = "Medium"
    strings:
        $eval = "eval(" nocase
        $unescape = "unescape(" nocase
        $from_char_code = "fromCharCode" nocase
        $atob = "atob(" nocase
        $btoa = "btoa(" nocase
        $document_write = "document.write" nocase
        $inner_html = "innerHTML" nocase
        $base64_decode = /[A-Za-z0-9+/]{20,}={0,2}/ nocase
        $hex_decode = /[0-9a-fA-F]{20,}/ nocase
    condition:
        (2 of ($eval, $unescape, $from_char_code, $atob, $btoa)) or ($document_write and $base64_decode) or ($inner_html and $hex_decode)
}

// ============================================================================
// NETWORK AND C2 DETECTION RULES
// ============================================================================

rule C2_Communication {
    meta:
        description = "Detects command and control communication"
        author = "Enterprise AV Team"
        date = "2024-01-01"
        version = "1.0"
        severity = "High"
        technique = "C2 Communication"
        mitre_attck = "T1071"
        confidence = "Medium"
    strings:
        $http_get = "GET /" nocase
        $http_post = "POST /" nocase
        $user_agent = "User-Agent:" nocase
        $content_type = "Content-Type:" nocase
        $cookie = "Cookie:" nocase
        $authorization = "Authorization:" nocase
        $beacon = "beacon" nocase
        $heartbeat = "heartbeat" nocase
        $checkin = "checkin" nocase
    condition:
        (2 of ($http_get, $http_post, $user_agent, $content_type)) and (1 of ($beacon, $heartbeat, $checkin))
}

rule DNS_Tunneling {
    meta:
        description = "Detects DNS tunneling attempts"
        author = "Enterprise AV Team"
        date = "2024-01-01"
        version = "1.0"
        severity = "Medium"
        technique = "DNS Tunneling"
        mitre_attck = "T1071.004"
        confidence = "Low"
    strings:
        $dns_query = "nslookup" nocase
        $dns_resolve = "Resolve-DnsName" nocase
        $long_subdomain = /[a-zA-Z0-9]{50,}\./ nocase
        $base64_dns = /[A-Za-z0-9+/]{20,}\./ nocase
        $hex_dns = /[0-9a-fA-F]{20,}\./ nocase
    condition:
        ($dns_query or $dns_resolve) and (1 of ($long_subdomain, $base64_dns, $hex_dns))
}

// ============================================================================
// EVASION TECHNIQUE DETECTION RULES
// ============================================================================

rule Anti_VM_Techniques {
    meta:
        description = "Detects anti-VM and anti-debugging techniques"
        author = "Enterprise AV Team"
        date = "2024-01-01"
        version = "1.0"
        severity = "Medium"
        technique = "Anti-VM"
        mitre_attck = "T1497"
        confidence = "Medium"
    strings:
        $vmware = "VMware" nocase
        $virtualbox = "VirtualBox" nocase
        $vbox = "VBox" nocase
        $xen = "Xen" nocase
        $qemu = "QEMU" nocase
        $sandbox = "sandbox" nocase
        $debugger = "debugger" nocase
        $is_debugger = "IsDebuggerPresent" nocase
        $check_remote = "CheckRemoteDebuggerPresent" nocase
    condition:
        2 of them
}

rule Code_Obfuscation {
    meta:
        description = "Detects code obfuscation techniques"
        author = "Enterprise AV Team"
        date = "2024-01-01"
        version = "1.0"
        severity = "Medium"
        technique = "Code Obfuscation"
        mitre_attck = "T1027"
        confidence = "Low"
    strings:
        $base64_long = /[A-Za-z0-9+/]{100,}={0,2}/ nocase
        $hex_long = /[0-9a-fA-F]{100,}/ nocase
        $xor_pattern = /xor.*[0-9a-fA-F]{2,}/ nocase
        $rot13 = /[A-Za-z]{20,}/ nocase
        $unicode_escape = /\\u[0-9a-fA-F]{4}/ nocase
        $null_bytes = /\\x00/ nocase
    condition:
        2 of them
}

// ============================================================================
// CRYPTOMINING DETECTION RULES
// ============================================================================

rule Cryptominer_Detection {
    meta:
        description = "Detects cryptocurrency mining malware"
        author = "Enterprise AV Team"
        date = "2024-01-01"
        version = "1.0"
        severity = "Medium"
        family = "Cryptominer"
        mitre_attck = "T1496"
        confidence = "Medium"
    strings:
        $xmr = "XMRig" nocase
        $monero = "monero" nocase
        $cryptonight = "cryptonight" nocase
        $pool = "pool" nocase
        $wallet = "wallet" nocase
        $hashrate = "hashrate" nocase
        $mining = "mining" nocase
        $stratum = "stratum" nocase
    condition:
        3 of them
}

// ============================================================================
// RANSOMWARE DETECTION RULES
// ============================================================================

rule Ransomware_Generic {
    meta:
        description = "Detects generic ransomware patterns"
        author = "Enterprise AV Team"
        date = "2024-01-01"
        version = "1.0"
        severity = "Critical"
        family = "Ransomware"
        mitre_attck = "T1486"
        confidence = "Medium"
    strings:
        $encrypted = "encrypted" nocase
        $ransom = "ransom" nocase
        $bitcoin = "bitcoin" nocase
        $payment = "payment" nocase
        $decrypt = "decrypt" nocase
        $key = "key" nocase
        $extension = /\.(encrypted|locked|crypto|ransom)$/ nocase
        $readme = "README" nocase
        $note = "NOTE" nocase
    condition:
        (2 of ($encrypted, $ransom, $bitcoin, $payment)) or ($extension and $readme) or ($decrypt and $key)
}

// ============================================================================
// ADVANCED HEURISTIC RULES
// ============================================================================

rule Suspicious_Behavior_Combination {
    meta:
        description = "Detects suspicious behavior combinations"
        author = "Enterprise AV Team"
        date = "2024-01-01"
        version = "1.0"
        severity = "High"
        technique = "Multiple Techniques"
        confidence = "Medium"
    strings:
        $network_activity = /https?:\/\/[a-zA-Z0-9.-]+/ nocase
        $file_creation = "CreateFile" nocase
        $registry_modification = "RegSetValue" nocase
        $process_creation = "CreateProcess" nocase
        $memory_allocation = "VirtualAlloc" nocase
        $suspicious_apis = /(VirtualAlloc|WriteProcessMemory|CreateRemoteThread|NtCreateThreadEx)/ nocase
    condition:
        $network_activity and (2 of ($file_creation, $registry_modification, $process_creation, $memory_allocation)) and $suspicious_apis
}

rule Advanced_Persistence_Detection {
    meta:
        description = "Detects advanced persistence mechanisms"
        author = "Enterprise AV Team"
        date = "2024-01-01"
        version = "1.0"
        severity = "High"
        technique = "Persistence"
        mitre_attck = "T1547"
        confidence = "Medium"
    strings:
        $registry_keys = /HKEY_[A-Z_]+\\Software\\Microsoft\\Windows\\CurrentVersion\\Run/ nocase
        $scheduled_tasks = "schtasks" nocase
        $services = "sc create" nocase
        $wmi = "WMI" nocase
        $startup_folder = "Startup" nocase
        $browser_extensions = "extension" nocase
        $autorun = "autorun" nocase
    condition:
        3 of them
}

// ============================================================================
// FILE INTEGRITY AND PACKING DETECTION
// ============================================================================

rule Packed_Executable {
    meta:
        description = "Detects packed or obfuscated executables"
        author = "Enterprise AV Team"
        date = "2024-01-01"
        version = "1.0"
        severity = "Medium"
        technique = "Packing"
        mitre_attck = "T1027"
        confidence = "Low"
    strings:
        $upx = "UPX" nocase
        $aspack = "ASPack" nocase
        $upack = "UPack" nocase
        $petite = "Petite" nocase
        $winupack = "WinUpack" nocase
        $themida = "Themida" nocase
        $vmprotect = "VMProtect" nocase
        $packer = "packer" nocase
    condition:
        1 of them
}

rule Suspicious_File_Structure {
    meta:
        description = "Detects suspicious file structure anomalies"
        author = "Enterprise AV Team"
        date = "2024-01-01"
        version = "1.0"
        severity = "Medium"
        technique = "File Structure"
        confidence = "Low"
    strings:
        $pe_header = "MZ"
        $dos_stub = "This program cannot be run in DOS mode"
        $rich_header = "Rich"
        $overlay_data = /.{1000,}/ nocase
        $suspicious_sections = /\.(data|rdata|text|code)$/ nocase
    condition:
        $pe_header and not $dos_stub or ($overlay_data and $suspicious_sections)
} 