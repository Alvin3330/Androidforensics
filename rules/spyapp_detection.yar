/*
 * YARA Rules for Android Spy App Detection
 */
rule KnownSpyware {
    meta:
        description = "Detects known spyware"
        severity = "critical"
    strings:
        $spy1 = "com.spybubble" nocase
        $spy2 = "com.mspy" nocase
        $spy3 = "com.flexispy" nocase
    condition:
        any of ($spy*)
}
rule HiddenApp {
    meta:
        description = "Hidden/obfuscated apps"
        severity = "high"
    strings:
        $hidden1 = "com.hidden" nocase
        $hidden2 = "com.spy" nocase
    condition:
        any of ($hidden*)
}
rule LocationTracking {
    meta:
        description = "Location tracking"
        severity = "high"
    strings:
        $loc1 = "com.gps" nocase
        $loc2 = "com.location" nocase
    condition:
        any of ($loc*)
}
