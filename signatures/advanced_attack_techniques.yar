/*
Advanced Attack Technique Detection Rules
=========================================
Enterprise-grade detection rules for sophisticated attack techniques
*/

rule Technique_Advanced_Process_Injection {
    meta:
        description = "Detects advanced process injection techniques"
        author = "Enterprise AV Team"
        date = "2024-01-01"
        version = "2.0"
        severity = "High"
        technique = "Process Injection"
        mitre_attck = "T1055"
        confidence = "Medium"
        variants = "VirtualAllocEx, NtCreateSection, SetWindowsHookEx"
    strings:
        $virtual_alloc = "VirtualAllocEx" nocase
        $write_process = "WriteProcessMemory" nocase
        $create_remote = "CreateRemoteThread" nocase
        $nt_unmap = "NtUnmapViewOfSection" nocase
        $nt_allocate = "NtAllocateVirtualMemory" nocase
        $nt_write = "NtWriteVirtualMemory" nocase
        $nt_create = "NtCreateThreadEx" nocase
        $nt_create_section = "NtCreateSection" nocase
        $nt_map_view = "NtMapViewOfSection" nocase
        $set_windows_hook = "SetWindowsHookEx" nocase
        $queue_user_apc = "QueueUserAPC" nocase
        $nt_test_alert = "NtTestAlert" nocase
    condition:
        4 of them
}

rule Technique_Code_Cave_Injection {
    meta:
        description = "Detects code cave injection technique"
        author = "Enterprise AV Team"
        date = "2024-01-01"
        version = "1.0"
        severity = "High"
        technique = "Code Cave Injection"
        mitre_attck = "T1055.012"
        confidence = "Medium"
    strings:
        $code_cave = "code cave" nocase
        $section_header = ".text" nocase
        $unused_space = /[\\x00]{100,}/ nocase
        $injection_point = "injection point" nocase
        $section_alignment = "SectionAlignment" nocase
        $file_alignment = "FileAlignment" nocase
    condition:
        ($code_cave and $section_header) or ($unused_space and $injection_point) or ($section_alignment and $file_alignment)
}

rule Technique_Thread_Hijacking {
    meta:
        description = "Detects thread hijacking technique"
        author = "Enterprise AV Team"
        date = "2024-01-01"
        version = "1.0"
        severity = "High"
        technique = "Thread Hijacking"
        mitre_attck = "T1055.003"
        confidence = "Medium"
    strings:
        $suspend_thread = "SuspendThread" nocase
        $get_thread_context = "GetThreadContext" nocase
        $set_thread_context = "SetThreadContext" nocase
        $resume_thread = "ResumeThread" nocase
        $nt_suspend = "NtSuspendThread" nocase
        $nt_get_context = "NtGetContextThread" nocase
        $nt_set_context = "NtSetContextThread" nocase
    condition:
        3 of them
}

rule Technique_Advanced_Persistence {
    meta:
        description = "Detects advanced persistence mechanisms"
        author = "Enterprise AV Team"
        date = "2024-01-01"
        version = "2.0"
        severity = "High"
        technique = "Persistence"
        mitre_attck = "T1547"
        confidence = "Medium"
        methods = "Registry, Scheduled Tasks, Services, WMI, COM"
    strings:
        $registry_run = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $registry_runonce = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase
        $registry_services = "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services" nocase
        $scheduled_tasks = "schtasks" nocase
        $task_scheduler = "Task Scheduler" nocase
        $wmi_event = "WMI" nocase
        $com_object = "COM" nocase
        $startup_folder = "Startup" nocase
        $autorun = "autorun" nocase
        $browser_extensions = "extension" nocase
        $group_policy = "Group Policy" nocase
        $logon_script = "logon script" nocase
    condition:
        3 of them
}

rule Technique_Privilege_Escalation_Advanced {
    meta:
        description = "Detects advanced privilege escalation techniques"
        author = "Enterprise AV Team"
        date = "2024-01-01"
        version = "2.0"
        severity = "High"
        technique = "Privilege Escalation"
        mitre_attck = "T1068"
        confidence = "Medium"
        methods = "UAC Bypass, Token Manipulation, Process Injection"
    strings:
        $uac_bypass = "UAC bypass" nocase
        $token_manipulation = "Token Manipulation" nocase
        $se_debug = "SeDebugPrivilege" nocase
        $se_tcb = "SeTcbPrivilege" nocase
        $se_backup = "SeBackupPrivilege" nocase
        $se_restore = "SeRestorePrivilege" nocase
        $se_take_ownership = "SeTakeOwnershipPrivilege" nocase
        $runas = "runas" nocase
        $elevate = "elevate" nocase
        $admin_privileges = "administrator privileges" nocase
        $system_privileges = "SYSTEM privileges" nocase
        $token_stealing = "token stealing" nocase
    condition:
        3 of them
}

rule Technique_Defense_Evasion_Advanced {
    meta:
        description = "Detects advanced defense evasion techniques"
        author = "Enterprise AV Team"
        date = "2024-01-01"
        version = "2.0"
        severity = "Medium"
        technique = "Defense Evasion"
        mitre_attck = "T1562"
        confidence = "Medium"
        methods = "Disable Security Tools, Modify Registry, Obfuscation"
    strings:
        $disable_av = "disable antivirus" nocase
        $disable_firewall = "disable firewall" nocase
        $disable_defender = "disable defender" nocase
        $modify_registry = "modify registry" nocase
        $obfuscation = "obfuscation" nocase
        $encryption = "encryption" nocase
        $packing = "packing" nocase
        $anti_debug = "anti debug" nocase
        $anti_vm = "anti vm" nocase
        $anti_sandbox = "anti sandbox" nocase
        $timing_attack = "timing attack" nocase
        $sleep_obfuscation = "sleep obfuscation" nocase
    condition:
        3 of them
}

rule Technique_Network_Evasion {
    meta:
        description = "Detects network traffic evasion techniques"
        author = "Enterprise AV Team"
        date = "2024-01-01"
        version = "1.0"
        severity = "Medium"
        technique = "Network Evasion"
        mitre_attck = "T1071"
        confidence = "Medium"
        methods = "DNS Tunneling, HTTP Tunneling, Custom Protocols"
    strings:
        $dns_tunneling = "dns tunneling" nocase
        $http_tunneling = "http tunneling" nocase
        $custom_protocol = "custom protocol" nocase
        $port_hopping = "port hopping" nocase
        $domain_generation = "domain generation" nocase
        $fast_flux = "fast flux" nocase
        $cdn_abuse = "cdn abuse" nocase
        $ssl_tunneling = "ssl tunneling" nocase
        $icmp_tunneling = "icmp tunneling" nocase
    condition:
        2 of them
}

rule Technique_Memory_Manipulation {
    meta:
        description = "Detects memory manipulation techniques"
        author = "Enterprise AV Team"
        date = "2024-01-01"
        version = "1.0"
        severity = "High"
        technique = "Memory Manipulation"
        mitre_attck = "T1055"
        confidence = "Medium"
        methods = "Memory Patching, API Hooking, DLL Injection"
    strings:
        $memory_patch = "memory patch" nocase
        $api_hook = "api hook" nocase
        $dll_injection = "dll injection" nocase
        $iat_hook = "iat hook" nocase
        $inline_hook = "inline hook" nocase
        $detour = "detour" nocase
        $trampoline = "trampoline" nocase
        $memory_scan = "memory scan" nocase
        $memory_protection = "memory protection" nocase
    condition:
        3 of them
}

rule Technique_File_System_Evasion {
    meta:
        description = "Detects file system evasion techniques"
        author = "Enterprise AV Team"
        date = "2024-01-01"
        version = "1.0"
        severity = "Medium"
        technique = "File System Evasion"
        mitre_attck = "T1564"
        confidence = "Medium"
        methods = "Hidden Files, Alternate Data Streams, File Attributes"
    strings:
        $hidden_file = "hidden file" nocase
        $alternate_stream = "alternate data stream" nocase
        $file_attributes = "file attributes" nocase
        $system_file = "system file" nocase
        $readonly_file = "readonly file" nocase
        $archive_file = "archive file" nocase
        $compressed_file = "compressed file" nocase
        $encrypted_file = "encrypted file" nocase
        $offline_file = "offline file" nocase
    condition:
        3 of them
}

rule Technique_Process_Evasion {
    meta:
        description = "Detects process evasion techniques"
        author = "Enterprise AV Team"
        date = "2024-01-01"
        version = "1.0"
        severity = "Medium"
        technique = "Process Evasion"
        mitre_attck = "T1055"
        confidence = "Medium"
        methods = "Process Hollowing, Process Doppelganging, Thread Local Storage"
    strings:
        $process_hollowing = "process hollowing" nocase
        $process_doppelganging = "process doppelganging" nocase
        $thread_local_storage = "thread local storage" nocase
        $process_suspension = "process suspension" nocase
        $process_termination = "process termination" nocase
        $process_creation = "process creation" nocase
        $process_injection = "process injection" nocase
        $process_migration = "process migration" nocase
    condition:
        3 of them
}

rule Technique_Registry_Evasion {
    meta:
        description = "Detects registry evasion techniques"
        author = "Enterprise AV Team"
        date = "2024-01-01"
        version = "1.0"
        severity = "Medium"
        technique = "Registry Evasion"
        mitre_attck = "T1112"
        confidence = "Medium"
        methods = "Registry Hiding, Registry Virtualization, Registry Redirection"
    strings:
        $registry_hiding = "registry hiding" nocase
        $registry_virtualization = "registry virtualization" nocase
        $registry_redirection = "registry redirection" nocase
        $registry_reflection = "registry reflection" nocase
        $registry_impersonation = "registry impersonation" nocase
        $registry_encryption = "registry encryption" nocase
        $registry_compression = "registry compression" nocase
        $registry_backup = "registry backup" nocase
    condition:
        3 of them
} 