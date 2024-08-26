rule Suspicious_Persistence_Indicators
{
    meta:
        description = "Detects suspicious persistence mechanisms via registry, shortcuts, and scripts"
        author = "aycagl - Ayca Gul"
        date = "2024-08-15"
        reference = "XWorm V5.6"

    strings:
    $scheduled = "schtasks.exe" fullword wide
        $task_highest = "/create /f /RL HIGHEST /sc minute /mo 1 /tn \"" fullword wide
        $task_basic = "/create /f /sc minute /mo 1 /tn \"" fullword wide
        $registry_run = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" fullword wide
        $wscript_shell = "WScript.Shell" fullword wide
        $create_shortcut = "CreateShortcut" fullword wide
        $target_path = "TargetPath" fullword wide
        $working_directory = "WorkingDirectory" fullword wide

    condition:
        6 of them
}

rule XWorm_Indicators
{
    meta:
        description = "Detects the XWorm malware's send_infos method that sends system information via a Telegram bot"
        author = "aycagl - Ayca Gul"
        date = "2024-08-15"
        reference = "XWorm V5.6"

    strings:
        $xworm_version = "XWorm V" fullword wide
        $new_client = "New Clinet :" fullword wide
        $username = "UserName :" fullword wide
        $os_fullname = "OSFullName :" fullword wide
        $usb = "USB :" fullword wide
        $cpu = "CPU :" fullword wide
        $gpu = "GPU :" fullword wide
        $ram = "RAM :" fullword wide
        $group = "Groub :" fullword wide
        $telegram_api = "https://api.telegram.org/bot" fullword wide
        $send_message = "/sendMessage?chat_id=" fullword wide
        $webclient_function = {00735600000A0C08026F5700000A0ADE2D}

    condition:
        6 of them
}

rule Malware_Information_Queries {
    meta:
        description = "Detects malware performing system information queries and persistence setup."
        author = "aycagl - Ayca Gul"
        date = "2024-08-15"
        reference = "XWorm V5.6"

    strings:
        $query_antivirus = "\\root\\SecurityCenter2" fullword wide
        $query_antivirus_product = "Select * from AntivirusProduct" fullword wide
        $query_display_name = "displayName" fullword wide
        $query_video_controller = "SELECT * FROM Win32_VideoController" fullword wide
        $query_processor = "Win32_Processor.deviceid" fullword wide

    condition:
        4 of them
}

rule Malware_Command_Detection {
    meta:
        description = "Detects specific malware command and function strings"
        author = "aycagl - Ayca Gul"
        date = "2024-08-15"
        reference = "XWorm V5.6"

    strings:
        $s1 = "pong" fullword wide
        $s2 = "CLOSE" fullword wide
        $s3 = "uninstall" fullword wide
        $s4 = "update" fullword wide
        $s5 = "Urlopen" fullword wide
        $s6 = "Urlhide" fullword wide
        $s7 = "PCShutdown" fullword wide
        $s8 = "shutdown.exe /f /s /t 0" fullword wide
        $s9 = "PCRestart" fullword wide
        $s10 = "shutdown.exe /f /r /t 0" fullword wide
        $s11 = "PCLogoff" fullword wide
        $s12 = "shutdown.exe -L" fullword wide
        $s13 = "RunShell" fullword wide
        $s14 = "StartDDos" fullword wide
        $s15 = "StopDDos" fullword wide
        $s16 = "StartReport" fullword wide
        $s17 = "StopReport" fullword wide
        $s18 = "Xchat" fullword wide
        $s19 = "Hosts" fullword wide
        $s20 = "\\drivers\\etc\\hosts" fullword wide
        $s21 = "Shosts" fullword wide
        $s22 = "HostsMSG" fullword wide
        $s23 = "Modified successfully!" fullword wide
        $s24 = "HostsErr" fullword wide
        $s25 = "DDos" fullword wide
        $s26 = "plugin" fullword wide
        $s27 = "sendPlugin" fullword wide
        $s28 = "savePlugin" fullword wide
        $s29 = "RemovePlugins" fullword wide
        $s30 = "Plugins Removed!" fullword wide
        $s31 = "OfflineGet" fullword wide
        $s32 = "OfflineKeylogger Not Enabled" fullword wide
        $s33 = "Plugin" fullword wide
        $s34 = "Invoke" fullword wide
        $s35 = "RunRecovery" fullword wide
        $s36 = "Recovery" fullword wide


    condition:
        15 of ($s*)
}

