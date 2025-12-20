/* Standard YARA Rules File 
   Place this in backend/analyzer/rules.yar
*/

rule High_Risk_Command_Exec {
    meta:
        description = "Detects attempts to execute system commands"
        severity = "High"
    strings:
        $a = "os.system" nocase
        $b = "subprocess.call" nocase
        $c = "cmd.exe" nocase
        $d = "/bin/sh" nocase
        $e = "powershell" nocase
    condition:
        any of them
}

rule Network_Exfiltration {
    meta:
        description = "Detects network communication attempts"
        severity = "Medium"
    strings:
        $a = "requests.post" nocase
        $b = "socket.socket" nocase
        $c = "http://" nocase
        $d = "https://" nocase
        $e = "urllib" nocase
    condition:
        any of them
}

rule Ransomware_Behavior {
    meta:
        description = "Detects cryptographic operations common in ransomware"
        severity = "Critical"
    strings:
        $a = "AES.new"
        $b = ".encrypt("
        $c = "ransom" nocase
        $d = "bitcoin" nocase
    condition:
        any of them
}