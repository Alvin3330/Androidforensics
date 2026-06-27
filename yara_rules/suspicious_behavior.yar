
rule Hidden_App {
  meta:
    description = "App with hidden/obfuscated package name"
    risk = "high"
    author = "Android Forensics"
  strings:
    $pattern1 = /[a-z]{1,3}.[a-z]{1,3}.[a-z]{1,3}/
    $hidden = "hidden" nocase
    $obf = "obf" nocase
    $spy = "spy" nocase
  condition:
    ($pattern1 and any of ($hidden, $obf, $spy))
}

rule Location_Tracking {
  meta:
    description = "App requesting fine location + internet + no UI"
    risk = "high"
    author = "Android Forensics"
  strings:
    $perm1 = "ACCESS_FINE_LOCATION"
    $perm2 = "INTERNET"
    $perm3 = "ACCESS_BACKGROUND_LOCATION" nocase
  condition:
    all of them
}

rule Call_Interception {
  meta:
    description = "Suspicious call interception setup"
    risk = "critical"
    author = "Android Forensics"
  strings:
    $perm1 = "CALL_PHONE"
    $perm2 = "READ_CALL_LOG"
    $perm3 = "PROCESS_OUTGOING_CALLS"
    $call_hook = "CallHandler" nocase
    $intercept = "intercept" nocase
  condition:
    (all of ($perm*)) or ($call_hook and $intercept)
}

rule SMS_Stealer {
  meta:
    description = "SMS interception and forwarding"
    risk = "critical"
    author = "Android Forensics"
  strings:
    $perm1 = "READ_SMS"
    $perm2 = "RECEIVE_SMS"
    $perm3 = "SEND_SMS"
    $sms_forward = "SMS_RECEIVED" 
    $content_uri = "sms" nocase
  condition:
    (all of ($perm*)) or ($sms_forward and $content_uri)
}

rule Audio_Recording {
  meta:
    description = "Audio/call recording capability"
    risk = "high"
    author = "Android Forensics"
  strings:
    $perm1 = "RECORD_AUDIO"
    $perm2 = "MODIFY_AUDIO_SETTINGS"
    $record_class = "MediaRecorder" nocase
  condition:
    all of them
}

rule Data_Exfiltration {
  meta:
    description = "Suspicious data exfiltration pattern"
    risk = "high"
    author = "Android Forensics"
  strings:
    $read1 = "READ_CONTACTS"
    $read2 = "READ_CALL_LOG"
    $read3 = "READ_SMS"
    $send_perm = "INTERNET"
    $command_host = /http://[a-z0-9-]+.[a-z]{2,}/ nocase
  condition:
    (2 of ($read*) and $send_perm) or $command_host
}

rule Persistence_Mechanism {
  meta:
    description = "App persistence after device reboot"
    risk = "high"
    author = "Android Forensics"
  strings:
    $boot = "BOOT_COMPLETED"
    $receiver = "BroadcastReceiver" nocase
    $start_service = "startService" nocase
  condition:
    all of them
}
      