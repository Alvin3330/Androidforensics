// modules/yara-scanner.js
// YARA Rule Integration for Advanced Spyware Detection
// (This is a Node.js wrapper around YARA CLI since yara-js has limited support)

const fs = require('fs');
const path = require('path');
const { exec, execSync } = require('child_process');

class YaraScanner {
  constructor() {
    this.rulesDir = path.join(__dirname, '../yara_rules');
    this.ensureRulesDir();
  }

  // ============================================================
  // Initialize YARA Rules Directory
  // ============================================================
  ensureRulesDir() {
    if (!fs.existsSync(this.rulesDir)) {
      fs.mkdirSync(this.rulesDir, { recursive: true });
      this.createDefaultRules();
    }
  }

  // ============================================================
  // Create Default YARA Rules
  // ============================================================
  createDefaultRules() {
    const defaultRules = {
      spyware_signatures: `
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
      `,
      
      suspicious_behavior: `
rule Hidden_App {
  meta:
    description = "App with hidden/obfuscated package name"
    risk = "high"
    author = "Android Forensics"
  strings:
    $pattern1 = /[a-z]{1,3}\.[a-z]{1,3}\.[a-z]{1,3}/
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
    $command_host = /http:\/\/[a-z0-9\-]+\.[a-z]{2,}/ nocase
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
      `,

      financial_malware: `
rule Banking_Trojan {
  meta:
    description = "Banking malware - credential theft"
    risk = "critical"
    author = "Android Forensics"
  strings:
    $bank_keyword = /bank|payment|paypal|credit|debit|wallet|crypto/i
    $hook = "Xposed" nocase
    $inject = "injectCode" nocase
    $overlay = "SYSTEM_ALERT_WINDOW"
  condition:
    $bank_keyword and any of ($hook, $inject, $overlay)
}

rule Ransomware {
  meta:
    description = "Ransomware - file encryption/extortion"
    risk = "critical"
    author = "Android Forensics"
  strings:
    $encrypt = "encrypt" nocase
    $ransom = "ransom" nocase
    $demand = "pay" nocase
    $lock = "LOCK_SCREEN" nocase
  condition:
    2 of them
}
      `,
    };

    // Write default rules
    Object.entries(defaultRules).forEach(([name, content]) => {
      const filePath = path.join(this.rulesDir, `${name}.yar`);
      if (!fs.existsSync(filePath)) {
        fs.writeFileSync(filePath, content);
      }
    });
  }

  // ============================================================
  // Scan Package Against YARA Rules
  // ============================================================
  scanPackage(packageName, metadata = {}) {
    try {
      // Compile all YARA rules
      const rulesFiles = fs.readdirSync(this.rulesDir).filter(f => f.endsWith('.yar'));
      
      if (rulesFiles.length === 0) {
        return { matches: [], score: 0 };
      }

      const rulesPath = path.join(this.rulesDir, '*.yar');
      
      // Check if yara command exists
      try {
        execSync('which yara', { stdio: 'ignore' });
      } catch {
        // YARA not installed, use fallback matching
        return this.fallbackScan(packageName, metadata);
      }

      // Create temp file with package metadata
      const tempFile = `/tmp/${packageName}_metadata.txt`;
      fs.writeFileSync(tempFile, `${packageName}\n${JSON.stringify(metadata)}`);

      // Run YARA scan
      try {
        const result = execSync(`yara -r ${this.rulesDir}/*.yar ${tempFile}`, {
          encoding: 'utf8',
          stdio: ['pipe', 'pipe', 'pipe'],
        });

        fs.unlinkSync(tempFile);
        return this.parseYaraOutput(result);
      } catch (error) {
        // No matches (yara exits with 1 if no matches)
        fs.unlinkSync(tempFile);
        return { matches: [], score: 0 };
      }
    } catch (error) {
      console.error('YARA scan error:', error.message);
      return this.fallbackScan(packageName, metadata);
    }
  }

  // ============================================================
  // Fallback: Pattern-based matching without YARA
  // ============================================================
  fallbackScan(packageName, metadata = {}) {
    const matches = [];
    const keywords = {
      CRITICAL: ['spy', 'spybubble', 'mspy', 'pegasus', 'flexispy', 'xmod', 'trojan', 'ransomware'],
      HIGH: ['hidden', 'obf', 'monitor', 'tracker', 'logger', 'intercept', 'steal'],
      MEDIUM: ['api', 'service', 'helper', 'util'],
    };

    // Check package name
    Object.entries(keywords).forEach(([level, kws]) => {
      kws.forEach(kw => {
        if (packageName.toLowerCase().includes(kw)) {
          matches.push({
            rule: `Pattern_${kw.toUpperCase()}`,
            risk: level,
            match: `Package name contains "${kw}"`,
          });
        }
      });
    });

    // Check metadata
    if (metadata.permissions) {
      const suspicious = ['READ_SMS', 'RECORD_AUDIO', 'ACCESS_FINE_LOCATION', 'READ_CALL_LOG'];
      const foundPerms = metadata.permissions.filter(p => 
        suspicious.some(s => p.includes(s))
      );
      
      if (foundPerms.length >= 3) {
        matches.push({
          rule: 'Suspicious_Permissions',
          risk: 'HIGH',
          match: `Multiple suspicious permissions: ${foundPerms.slice(0, 3).join(', ')}`,
        });
      }
    }

    // Calculate risk score (0-100)
    const criticalCount = matches.filter(m => m.risk === 'CRITICAL').length;
    const highCount = matches.filter(m => m.risk === 'HIGH').length;
    const score = Math.min(100, (criticalCount * 40) + (highCount * 20));

    return { matches, score, method: 'fallback' };
  }

  // ============================================================
  // Parse YARA Output
  // ============================================================
  parseYaraOutput(output) {
    const matches = [];
    const lines = output.trim().split('\n');

    lines.forEach(line => {
      // YARA output format: rulename filename offset(s)
      const parts = line.split(/\s+/);
      if (parts.length >= 2) {
        const ruleName = parts[0];
        
        matches.push({
          rule: ruleName,
          risk: this.getRiskFromRule(ruleName),
          match: line,
        });
      }
    });

    // Calculate score
    const criticalCount = matches.filter(m => m.risk === 'CRITICAL').length;
    const highCount = matches.filter(m => m.risk === 'HIGH').length;
    const score = Math.min(100, (criticalCount * 40) + (highCount * 20));

    return { matches, score, method: 'yara' };
  }

  // ============================================================
  // Determine Risk Level from Rule Name
  // ============================================================
  getRiskFromRule(ruleName) {
    const criticalRules = ['SpyBubble', 'mSpy', 'Pegasus', 'FlexiSPY', 'Banking_Trojan', 'Ransomware', 'Call_Interception', 'SMS_Stealer'];
    const highRules = ['XMod_Games', 'Hidden_App', 'Location_Tracking', 'Audio_Recording', 'Data_Exfiltration', 'Persistence_Mechanism'];

    if (criticalRules.some(r => ruleName.includes(r))) return 'CRITICAL';
    if (highRules.some(r => ruleName.includes(r))) return 'HIGH';
    return 'MEDIUM';
  }

  // ============================================================
  // Upload Custom YARA Rule
  // ============================================================
  uploadRule(ruleName, ruleContent) {
    const rulePath = path.join(this.rulesDir, `${ruleName}.yar`);
    
    // Basic validation
    if (!ruleContent.includes('rule ') || !ruleContent.includes('condition:')) {
      throw new Error('Invalid YARA rule format');
    }

    fs.writeFileSync(rulePath, ruleContent);
    return { message: `Rule ${ruleName} uploaded`, path: rulePath };
  }

  // ============================================================
  // List Available Rules
  // ============================================================
  listRules() {
    const rules = fs.readdirSync(this.rulesDir)
      .filter(f => f.endsWith('.yar'))
      .map(f => ({
        name: f.replace('.yar', ''),
        path: path.join(this.rulesDir, f),
        size: fs.statSync(path.join(this.rulesDir, f)).size,
      }));

    return rules;
  }

  // ============================================================
  // Delete Rule
  // ============================================================
  deleteRule(ruleName) {
    const rulePath = path.join(this.rulesDir, `${ruleName}.yar`);
    
    if (!fs.existsSync(rulePath)) {
      throw new Error('Rule not found');
    }

    fs.unlinkSync(rulePath);
    return { message: `Rule ${ruleName} deleted` };
  }
}

module.exports = new YaraScanner();