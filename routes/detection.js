// routes/detection.js
// Detection and Scanning Routes - Uses ADB Service + YARA Scanner + Forensics Analyzer

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const adbService = require('../modules/adbService');
const yaraScanner = require('../modules/yara-scanner');
const forensicsAnalyzer = require('../modules/forensicsAnalyzer');

const router = express.Router();

// Initialize database
const db = new sqlite3.Database('./forensics.db');

// ============================================================
// GET /api/detection/devices
// List all connected ADB devices
// ============================================================
router.get('/devices', (req, res) => {
  try {
    const devices = adbService.listDevices();
    res.json({ 
      success: true,
      devices,
      count: devices.length 
    });
  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: error.message 
    });
  }
});

// ============================================================
// POST /api/detection/connect
// Connect to a specific device
// ============================================================
router.post('/connect', (req, res) => {
  try {
    const { deviceIp } = req.body;

    if (!deviceIp) {
      return res.status(400).json({ error: 'Device Ip required' });
    }

    const result = adbService.connectDevice(deviceIp);
    res.json({ success: true, result });
  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: error.message 
    });
  }
});

// ============================================================
// POST /api/detection/device-info
// Get detailed device information
// ============================================================
router.post('/device-info', (req, res) => {
  try {
    const { deviceIp } = req.body;

    if (!deviceIp) {
      return res.status(400).json({ error: 'Device Ip required' });
    }

    const deviceInfo = adbService.getDeviceInfo(deviceIp);
    res.json({ success: true, deviceInfo });
  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: error.message 
    });
  }
});

// ============================================================
// POST /api/detection/scan
// Full device scan - packages + YARA rules + forensic analysis
// ============================================================
router.post('/scan', (req, res) => {
  try {
    const { caseId, deviceIp } = req.body;

    if (!deviceIp) {
      return res.status(400).json({ error: 'Device ID required' });
    }

    if (!caseId) {
      return res.status(400).json({ error: 'Case ID required' });
    }

    // Step 1: Get device info
    console.log(`[SCAN] Getting device info for ${deviceIp}`);
    const deviceInfo = adbService.getDeviceInfo(deviceIp);

    // Step 2: List installed packages
    console.log(`[SCAN] Listing installed packages...`);
    const packages = adbService.listInstalledPackages(deviceIp);
    console.log(`[SCAN] Found ${packages.length} packages`);

    // Step 3: Analyze each package
    console.log(`[SCAN] Analyzing packages...`);
    const appAnalyses = [];
    const detectedThreats = [];

    packages.forEach((pkg, index) => {
      if (index % 50 === 0) console.log(`[SCAN] Progress: ${index}/${packages.length}`);

      // Get permissions
      const permissions = adbService.getAppPermissions(pkg, deviceIp);

      // Get YARA matches
      const yaraResults = yaraScanner.scanPackage(pkg, { permissions });

      // Analyze app
      const analysis = forensicsAnalyzer.analyzeApp({
        packageName: pkg,
        permissions,
        yaraMatches: yaraResults.matches || [],
        fileSize: adbService.getAPKSize(pkg, deviceIp) || 0,
        installTime: adbService.getAppInstallTime(pkg, deviceIp),
      });

      appAnalyses.push(analysis);

      // Store detected threats in database
      if (analysis.threatLevel !== 'CLEAN') {
        const app = {
          case_id: caseId,
          package_name: pkg,
          app_name: pkg.split('.').pop(),
          risk_level: analysis.threatLevel.toLowerCase(),
          is_hidden: analysis.flags.some(f => f.includes('obfuscated')) ? 1 : 0,
          permissions: JSON.stringify(analysis.metadata.permissionCount > 0 ? permissions : []),
        };

        db.run(
          `INSERT INTO detected_apps (case_id, package_name, app_name, risk_level, is_hidden, permissions) 
           VALUES (?, ?, ?, ?, ?, ?)`,
          [app.case_id, app.package_name, app.app_name, app.risk_level, app.is_hidden, app.permissions],
          (err) => {
            if (!err) detectedThreats.push(app);
          }
        );
      }
    });

    // Step 4: Device-level analysis
    console.log(`[SCAN] Generating device-level analysis...`);
    const deviceAnalysis = forensicsAnalyzer.analyzeDevice({
      deviceInfo,
      installedApps: packages,
      appAnalyses,
    });

    console.log(`[SCAN] Scan complete. Threats detected: ${detectedThreats.length}`);

    res.json({
      success: true,
      scanResult: {
        deviceInfo,
        totalPackagesScanned: packages.length,
        threatsDetected: detectedThreats.length,
        deviceAnalysis,
        topThreats: deviceAnalysis.topThreats,
        deviceThreatStatus: deviceAnalysis.deviceThreatStatus,
        recommendations: deviceAnalysis.recommendations,
      },
    });

  } catch (error) {
    console.error(`[SCAN] Error: ${error.message}`);
    res.status(500).json({ 
      success: false,
      error: error.message 
    });
  }
});

// ============================================================
// POST /api/detection/quick-scan
// Fast scan - only high-risk packages
// ============================================================
router.post('/quick-scan', (req, res) => {
  try {
    const { deviceIp } = req.body;

    if (!deviceIp) {
      return res.status(400).json({ error: 'Device Ip required' });
    }

    console.log(`[QUICK-SCAN] Starting quick scan on ${deviceIp}`);
    
    const deviceInfo = adbService.getDeviceInfo(deviceIp);
    const packages = adbService.listInstalledPackages(deviceIp);

    // Only scan suspicious packages
    const suspiciousPkgs = packages.filter(pkg => 
      /spy|tracker|monitor|hidden|secret|stealth|trojan|ransomware/i.test(pkg)
    );

    console.log(`[QUICK-SCAN] Found ${suspiciousPkgs.length} potentially suspicious packages`);

    const threats = suspiciousPkgs.map(pkg => {
      const permissions = adbService.getAppPermissions(pkg, deviceIp);
      const yaraResults = yaraScanner.scanPackage(pkg, { permissions });
      
      return forensicsAnalyzer.analyzeApp({
        packageName: pkg,
        permissions,
        yaraMatches: yaraResults.matches || [],
      });
    }).filter(a => a.threatLevel !== 'CLEAN');

    res.json({
      success: true,
      quickScanResult: {
        deviceInfo,
        totalPackagesScanned: packages.length,
        suspiciousPackagesFound: suspiciousPkgs.length,
        threatsDetected: threats.length,
        threats: threats,
      },
    });

  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: error.message 
    });
  }
});

// ============================================================
// GET /api/detection/yara-rules
// List available YARA rules
// ============================================================
router.get('/yara-rules', (req, res) => {
  try {
    const rules = yaraScanner.listRules();
    res.json({ 
      success: true,
      rules,
      count: rules.length 
    });
  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: error.message 
    });
  }
});

// ============================================================
// POST /api/detection/upload-rule
// Upload custom YARA rule
// ============================================================
router.post('/upload-rule', (req, res) => {
  try {
    const { ruleName, ruleContent } = req.body;

    if (!ruleName || !ruleContent) {
      return res.status(400).json({ error: 'Rule name and content required' });
    }

    const result = yaraScanner.uploadRule(ruleName, ruleContent);
    res.json({ success: true, result });
  } catch (error) {
    res.status(400).json({ 
      success: false,
      error: error.message 
    });
  }
});

// ============================================================
// DELETE /api/detection/rule/:ruleName
// Delete YARA rule
// ============================================================
router.delete('/rule/:ruleName', (req, res) => {
  try {
    const { ruleName } = req.params;
    const result = yaraScanner.deleteRule(ruleName);
    res.json({ success: true, result });
  } catch (error) {
    res.status(400).json({ 
      success: false,
      error: error.message 
    });
  }
});

module.exports = router;