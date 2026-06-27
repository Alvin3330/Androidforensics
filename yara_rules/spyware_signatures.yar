
rule SpyBubble {
  meta:
    description = "SpyBubble spyware detection"
    risk = "critical"
    author = "Android Forensics"
  strings:
    $s1 = "com.spyapp"
    $s2 = "com.bubble.spy"
    $s3 = "spybubble" nocase
  condition:
    any of them
}

rule mSpy {
  meta:
    description = "mSpy spyware - call interception & location tracking"
    risk = "critical"
    author = "Android Forensics"
  strings:
    $s1 = "com.mspy"
    $s2 = "com.hidden.mspy"
    $s3 = "mspy" nocase
    $s4 = "callmonitor" nocase
  condition:
    2 of them
}

rule Pegasus {
  meta:
    description = "Pegasus NSO spyware - advanced exploitation"
    risk = "critical"
    author = "Android Forensics"
  strings:
    $s1 = "com.nso.pegasus"
    $s2 = "pegasus" nocase
    $s3 = "zero_day" nocase
    $s4 = "NSO" 
  condition:
    any of them
}

rule FlexiSPY {
  meta:
    description = "FlexiSPY - keystroke logging, call recording"
    risk = "critical"
    author = "Android Forensics"
  strings:
    $s1 = "com.flexi.spy"
    $s2 = "com.flexispy"
    $s3 = "flexispy" nocase
    $s4 = "callrecorder" nocase
  condition:
    any of them
}

rule XMod_Games {
  meta:
    description = "XMod Games trojan disguised as game mod"
    risk = "high"
    author = "Android Forensics"
  strings:
    $s1 = "com.xmodgames"
    $s2 = "xmod" nocase
    $s3 = "game.mod" nocase
  condition:
    any of them
}
      