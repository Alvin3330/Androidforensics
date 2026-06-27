// modules/forensicsAnalyzer.js
// Forensics Analysis Engine - Risk Assessment & Threat Detection
// Combines YARA results, permissions analysis, and behavioral patterns

class ForensicsAnalyzer {
  constructor() {
    this.suspiciousPermissions = {
      CRITICAL: [
        'android.permission.READ_SMS',
        'android.permission.SEND_SMS',
        'android.permission.RECEIVE_SMS',
        'android.permission.RECORD_AUDIO',
        'android.permission.ACCESS_FINE_LOCATION',
        'android.permission.PROCESS_OUTGOING_CALLS',
        'android.permission.CALL_PHONE',
        'android.permission.READ_CALL_LOG',
        'android.permission.WRITE_CALL_LOG',
      ],
      HIGH: [
        'android.permission.INTERNET',
        'android.permission.ACCESS_COARSE_LOCATION',
        'android.permission.READ_CONTACTS',
        'android.permission.WRITE_CONTACTS',
        'android.permission.GET_ACCOUNTS',
        'android.permission.MODIFY_AUDIO_SETTINGS',
        'android.permission.CAMERA',
      ],
      MEDIUM: [
        'android.permission.CHANGE_WIFI_STATE',
        'android.permission.ACCESS_NETWORK_STATE',
        'android.permission.CHANGE_NETWORK_STATE',
      ],
    };

    this.systemPackagePrefixes = [
      'com.android',
      'com.google',
      'android',
      'com.samsung',
      'com.sec',
    ];
  }

  // ============================================================
  // Analyze single app for threat level
  // ============================================================
  analyzeApp(appData) {
    const {
      packageName,
      permissions = [],
      yaraMatches = [],
      fileSize = 0,
      installTime = null,
      apkMetadata = {},
    } = appData;

    let riskScore = 0;
    const findings = [];
    const flags = [];

    // ---- YARA Signature Matches ----
    if (yaraMatches && yaraMatches.length > 0) {
      const criticalMatches = yaraMatches.filter(m => m.risk === 'CRITICAL').length;
      const highMatches = yaraMatches.filter(m => m.risk === 'HIGH').length;

      if (criticalMatches > 0) {
        riskScore += criticalMatches * 25;
        flags.push(`CRITICAL: ${criticalMatches} malware signature(s) detected`);
      }
      if (highMatches > 0) {
        riskScore += highMatches * 15;
        flags.push(`HIGH: ${highMatches} suspicious signature(s) detected`);
      }

      findings.push({
        category: 'YARA_SIGNATURES',
        risk: criticalMatches > 0 ? 'CRITICAL' : 'HIGH',
        details: yaraMatches,
      });
    }

    // ---- Permission Analysis ----
    const permissionRisks = this.analyzePermissions(permissions);
    if (permissionRisks.criticalPerms.length > 0) {
      riskScore += permissionRisks.criticalPerms.length * 15;
      flags.push(`CRITICAL: ${permissionRisks.criticalPerms.length} dangerous permission(s)`);
    }
    if (permissionRisks.highPerms.length > 0) {
      riskScore += permissionRisks.highPerms.length * 8;
    }

    if (permissionRisks.criticalPerms.length > 0 || permissionRisks.highPerms.length > 0) {
      findings.push({
        category: 'PERMISSIONS',
        risk: permissionRisks.criticalPerms.length > 0 ? 'CRITICAL' : 'HIGH',
        criticalPerms: permissionRisks.criticalPerms,
        highPerms: permissionRisks.highPerms,
      });
    }

    // ---- Package Name Analysis ----
    const nameRisk = this.analyzePackageName(packageName);
    if (nameRisk.risk) {
      riskScore += nameRisk.score;
      flags.push(nameRisk.message);
      findings.push({
        category: 'PACKAGE_NAME',
        risk: nameRisk.risk,
        details: nameRisk.message,
      });
    }

    // ---- Behavioral Patterns ----
    const behaviorRisk = this.analyzeBehavior(permissions, yaraMatches);
    if (behaviorRisk.risks.length > 0) {
      riskScore += behaviorRisk.score;
      behaviorRisk.risks.forEach(r => flags.push(r));
      findings.push({
        category: 'BEHAVIORAL_PATTERNS',
        risk: behaviorRisk.topRisk,
        patterns: behaviorRisk.risks,
      });
    }

    // ---- Size Anomaly ----
    if (fileSize > 100 * 1024 * 1024) { // > 100MB
      riskScore += 5;
      flags.push('WARNING: Unusually large file size');
      findings.push({
        category: 'FILE_SIZE_ANOMALY',
        risk: 'LOW',
        size: fileSize,
      });
    }

    // ---- System App Check ----
    const isSystemApp = this.isSystemApp(packageName);
    if (!isSystemApp && !this.isLikelyLegitimate(packageName)) {
      riskScore += 3;
    }

    // Cap score at 100
    riskScore = Math.min(100, riskScore);

    // Determine threat level
    let threatLevel = 'CLEAN';
    if (riskScore >= 80) threatLevel = 'CRITICAL';
    else if (riskScore >= 60) threatLevel = 'HIGH';
    else if (riskScore >= 40) threatLevel = 'MEDIUM';
    else if (riskScore >= 20) threatLevel = 'LOW';

    return {
      packageName,
      threatLevel,
      riskScore,
      flags,
      findings,
      metadata: {
        isSystemApp,
        fileSize,
        installTime,
        permissionCount: permissions.length,
      },
    };
  }

  // ============================================================
  // Analyze Permission Combinations
  // ============================================================
  analyzePermissions(permissions) {
    const criticalPerms = [];
    const highPerms = [];
    const mediumPerms = [];

    permissions.forEach(perm => {
      if (this.suspiciousPermissions.CRITICAL.includes(perm)) {
        criticalPerms.push(perm);
      } else if (this.suspiciousPermissions.HIGH.includes(perm)) {
        highPerms.push(perm);
      } else if (this.suspiciousPermissions.MEDIUM.includes(perm)) {
        mediumPerms.push(perm);
      }
    });

    // Check for spyware-specific combos
    const hasSMSAccess = criticalPerms.some(p => 
      p.includes('READ_SMS') || p.includes('SEND_SMS') || p.includes('RECEIVE_SMS')
    );
    const hasLocationAccess = criticalPerms.some(p => p.includes('ACCESS_FINE_LOCATION'));
    const hasCallAccess = criticalPerms.some(p => 
      p.includes('CALL_PHONE') || p.includes('READ_CALL_LOG') || p.includes('PROCESS_OUTGOING_CALLS')
    );
    const hasInternet = highPerms.includes('android.permission.INTERNET');
    const hasAudioAccess = criticalPerms.includes('android.permission.RECORD_AUDIO');

    const riskScore = (criticalPerms.length * 15) + (highPerms.length * 8) + (mediumPerms.length * 2);

    return {
      criticalPerms,
      highPerms,
      mediumPerms,
      riskScore,
      spywareIndicators: {
        canStealSMS: hasSMSAccess && hasInternet,
        canTrackLocation: hasLocationAccess && hasInternet,
        canInterceptCalls: hasCallAccess && hasInternet,
        canRecordAudio: hasAudioAccess && hasInternet,
      },
    };
  }

  // ============================================================
  // Analyze Package Name for Suspicious Patterns
  // ============================================================
  analyzePackageName(packageName) {
    const suspiciousPatterns = {
      CRITICAL: [
        /spy|spyware|tracker|monitor|stalker|keylog/i,
        /malware|trojan|ransomware|botnet/i,
      ],
      HIGH: [
        /^[a-z]{1,2}\.[a-z]{1,2}(\.[a-z]{1,2})?$/, // Obfuscated names (a.b.c)
        /hidden|obf|encrypt|crypto/i,
      ],
    };

    // Check critical patterns
    for (const pattern of suspiciousPatterns.CRITICAL) {
      if (pattern.test(packageName)) {
        return {
          risk: 'CRITICAL',
          score: 30,
          message: `Package name matches spyware pattern: ${pattern}`,
        };
      }
    }

    // Check high patterns
    for (const pattern of suspiciousPatterns.HIGH) {
      if (pattern.test(packageName)) {
        return {
          risk: 'HIGH',
          score: 15,
          message: `Package name appears obfuscated or suspicious`,
        };
      }
    }

    return { risk: null, score: 0, message: null };
  }

  // ============================================================
  // Analyze Behavioral Patterns
  // ============================================================
  analyzeBehavior(permissions, yaraMatches = []) {
    const risks = [];
    let score = 0;

    // SMS Stealing Behavior
    if (permissions.includes('android.permission.READ_SMS') &&
        permissions.includes('android.permission.RECEIVE_SMS') &&
        permissions.includes('android.permission.INTERNET')) {
      risks.push('Likely SMS interception capability');
      score += 25;
    }

    // Call Interception
    if (permissions.includes('android.permission.PROCESS_OUTGOING_CALLS') &&
        permissions.includes('android.permission.CALL_PHONE') &&
        permissions.includes('android.permission.INTERNET')) {
      risks.push('Likely call interception capability');
      score += 25;
    }

    // Location Tracking
    if (permissions.includes('android.permission.ACCESS_FINE_LOCATION') &&
        permissions.includes('android.permission.INTERNET')) {
      risks.push('Real-time location tracking capability');
      score += 20;
    }

    // Audio/Video Surveillance
    if (permissions.includes('android.permission.RECORD_AUDIO') &&
        permissions.includes('android.permission.CAMERA') &&
        permissions.includes('android.permission.INTERNET')) {
      risks.push('Audio and video surveillance capability');
      score += 25;
    }

    // Contact/Data Exfiltration
    if (permissions.includes('android.permission.READ_CONTACTS') &&
        permissions.includes('android.permission.READ_CALL_LOG') &&
        permissions.includes('android.permission.INTERNET')) {
      risks.push('Contact and call history exfiltration capability');
      score += 15;
    }

    // Persistence (stays even after reboot)
    if (yaraMatches && yaraMatches.some(m => m.rule && m.rule.includes('Persistence'))) {
      risks.push('Persistence mechanism detected (survives reboot)');
      score += 10;
    }

    const topRisk = score >= 25 ? 'CRITICAL' : score >= 15 ? 'HIGH' : 'MEDIUM';

    return { risks, score, topRisk };
  }

  // ============================================================
  // Check if package is a system app
  // ============================================================
  isSystemApp(packageName) {
    return this.systemPackagePrefixes.some(prefix => 
      packageName.startsWith(prefix)
    );
  }

  // ============================================================
  // Check if package is likely legitimate
  // ============================================================
  isLikelyLegitimate(packageName) {
    const knownLegit = [
      'whatsapp',
      'telegram',
      'facebook',
      'instagram',
      'tiktok',
      'chrome',
      'firefox',
      'opera',
      'gmail',
      'outlook',
      'microsoft',
      'adobe',
      'spotify',
      'netflix',
      'youtube',
      'amazon',
      'paypal',
    ];

    return knownLegit.some(app => packageName.toLowerCase().includes(app));
  }

  // ============================================================
  // Analyze Full Device
  // ============================================================
  analyzeDevice(deviceData) {
    const {
      deviceInfo = {},
      installedApps = [],
      appAnalyses = [],
    } = deviceData;

    const threatSummary = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      CLEAN: 0,
    };

    let totalRiskScore = 0;
    const topThreats = [];

    appAnalyses.forEach(app => {
      threatSummary[app.threatLevel]++;
      totalRiskScore += app.riskScore;

      if (app.threatLevel === 'CRITICAL' || app.threatLevel === 'HIGH') {
        topThreats.push({
          packageName: app.packageName,
          threatLevel: app.threatLevel,
          riskScore: app.riskScore,
          flags: app.flags.slice(0, 2), // Top 2 flags
        });
      }
    });

    // Sort by risk score
    topThreats.sort((a, b) => b.riskScore - a.riskScore);

    // Device-level risk score (average of all apps)
    const avgDeviceRisk = appAnalyses.length > 0 
      ? Math.round(totalRiskScore / appAnalyses.length) 
      : 0;

    // Determine device threat status
    let deviceThreatStatus = 'CLEAN';
    if (threatSummary.CRITICAL > 0) deviceThreatStatus = 'CRITICAL';
    else if (threatSummary.HIGH > 2) deviceThreatStatus = 'HIGH';
    else if (threatSummary.HIGH > 0) deviceThreatStatus = 'MEDIUM';

    return {
      deviceInfo,
      threatSummary,
      deviceThreatStatus,
      averageDeviceRisk: avgDeviceRisk,
      totalAppsScanned: appAnalyses.length,
      topThreats: topThreats.slice(0, 10), // Top 10
      recommendations: this.generateRecommendations(threatSummary, deviceThreatStatus),
      scanTimestamp: new Date().toISOString(),
    };
  }

  // ============================================================
  // Generate Remediation Recommendations
  // ============================================================
  generateRecommendations(threatSummary, deviceStatus) {
    const recommendations = [];

    if (threatSummary.CRITICAL > 0) {
      recommendations.push({
        priority: 'CRITICAL',
        action: 'Isolate device from network immediately',
        reason: `${threatSummary.CRITICAL} critical threat(s) detected`,
      });
      recommendations.push({
        priority: 'CRITICAL',
        action: 'Factory reset device after backing up data',
        reason: 'Advanced malware may require full reset',
      });
    }

    if (threatSummary.HIGH > 0) {
      recommendations.push({
        priority: 'HIGH',
        action: 'Uninstall suspicious apps immediately',
        reason: `${threatSummary.HIGH} high-risk app(s) detected`,
      });
      recommendations.push({
        priority: 'HIGH',
        action: 'Change all sensitive passwords from another device',
        reason: 'Potential credential theft from spyware',
      });
    }

    if (threatSummary.MEDIUM > 0) {
      recommendations.push({
        priority: 'MEDIUM',
        action: 'Review and revoke unnecessary permissions',
        reason: 'Several apps have suspicious permission combinations',
      });
    }

    // General recommendations
    recommendations.push({
      priority: 'ONGOING',
      action: 'Enable Unknown Sources protection',
      reason: 'Prevent side-loading of malicious APKs',
    });
    recommendations.push({
      priority: 'ONGOING',
      action: 'Keep Android OS and apps updated',
      reason: 'Security patches close known vulnerabilities',
    });

    return recommendations;
  }
}

module.exports = new ForensicsAnalyzer();