/**
 * Android Forensics Backend - With SQLite Persistence
 * File: routes/android-forensics.js
 *
 * Uses SQLite for permanent data storage
 */

const express = require('express');
const { execSync } = require('child_process');
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const router = express.Router();

// ============================================
// CONFIG
// ============================================
const DEFAULT_INVESTIGATOR_ID = process.env.DEFAULT_INVESTIGATOR_ID || 'INV-001';

// ============================================
// DATABASE SETUP
// ============================================
const db = new sqlite3.Database('./db/forensics.db', (err) => {
    if (err) console.error('Database connection error:', err);
    else console.log('Connected to forensics.db');
});

const dbRun = (sql, params = []) => {
    return new Promise((resolve, reject) => {
        db.run(sql, params, function (err) {
            if (err) reject(err);
            else resolve({ lastID: this.lastID, changes: this.changes });
        });
    });
};

const dbGet = (sql, params = []) => {
    return new Promise((resolve, reject) => {
        db.get(sql, params, (err, row) => {
            if (err) reject(err);
            else resolve(row);
        });
    });
};

const dbAll = (sql, params = []) => {
    return new Promise((resolve, reject) => {
        db.all(sql, params, (err, rows) => {
            if (err) reject(err);
            else resolve(rows || []);
        });
    });
};

// ============================================
// INPUT VALIDATION HELPERS
// ============================================

/**
 * Validate an IPv4 address string.
 */
function isValidIP(ip) {
    return /^(\d{1,3}\.){3}\d{1,3}$/.test(ip) &&
        ip.split('.').every(octet => parseInt(octet, 10) <= 255);
}

/**
 * Validate a device ID (serial number or IP:port).
 * Allows alphanumerics, dots, colons, hyphens, and underscores only.
 */
function isValidDeviceId(id) {
    return /^[a-zA-Z0-9.:_-]+$/.test(id);
}

/**
 * Safely run an adb shell command for a given device ID.
 * Throws if deviceId fails validation.
 */
function adbShell(deviceId, shellCmd, timeoutMs = 5000) {
    if (!isValidDeviceId(deviceId)) {
        throw new Error(`Invalid device ID: ${deviceId}`);
    }
    return execSync(`adb -s ${deviceId} shell ${shellCmd}`, {
        encoding: 'utf-8',
        timeout: timeoutMs,
    });
}

// ============================================
// GET /api/android/devices
// List all connected ADB devices (with DB history)
// ============================================
router.get('/devices', async (req, res) => {
    try {
        const output = execSync('adb devices -l', { encoding: 'utf-8' });
        const lines = output
            .split('\n')
            .filter(line => line.trim() && !line.includes('List'));

        const devices = [];

        for (const line of lines) {
            const parts = line.trim().split(/\s+/);
            if (parts.length < 2) continue;

            const deviceId = parts[0];
            const state = parts[1];

            // Validate device ID before using it in shell commands
            if (!isValidDeviceId(deviceId)) {
                console.warn(`Skipping device with invalid ID: ${deviceId}`);
                continue;
            }

            if (state === 'device') {
                try {
                    const name = adbShell(deviceId, 'getprop ro.product.model').trim();
                    const androidVersion = adbShell(deviceId, 'getprop ro.build.version.release').trim();

                    let ip = 'USB';
                    if (deviceId.includes(':')) {
                        ip = deviceId.split(':')[0];
                    }

                    const dbDevice = await dbGet(
                        'SELECT * FROM devices WHERE id = ?',
                        [deviceId]
                    );

                    if (!dbDevice) {
                        await dbRun(
                            `INSERT INTO devices (id, deviceName, deviceModel, androidVersion, ip, status)
                             VALUES (?, ?, ?, ?, ?, 'connected')`,
                            [deviceId, name, name, androidVersion, ip]
                        );
                    } else {
                        await dbRun(
                            'UPDATE devices SET lastConnected = CURRENT_TIMESTAMP, status = ? WHERE id = ?',
                            ['connected', deviceId]
                        );
                    }

                    devices.push({
                        id: deviceId,
                        name: name || 'Unknown Device',
                        model: name,
                        ip,
                        state,
                        androidVersion: androidVersion || 'Unknown',
                        connected: true,
                    });
                } catch (e) {
                    console.error(`Error getting info for ${deviceId}:`, e.message);
                }
            }
        }

        // Also return DB history (including previously seen / disconnected devices)
        const dbDevices = await dbAll(
            'SELECT * FROM devices ORDER BY lastConnected DESC LIMIT 20'
        );

        res.json({
            success: true,
            currentDevices: devices,
            allDevices: dbDevices,
            message: `Found ${devices.length} connected device(s)`,
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Failed to list devices',
            details: error.message,
        });
    }
});

// ============================================
// POST /api/android/connect
// Connect a device and save it to the DB
//
// Body:
//   method       {string}  'manual' | 'wifi' | 'usb'
//   ip           {string}  Required for method='manual'
//   port         {number}  Optional, defaults to 5555
//   investigatorId {string}
//   caseId       {string}
// ============================================
router.post('/connect', async (req, res) => {
    const { method, ip, port = 5555, investigatorId, caseId } = req.body;
    const invId = investigatorId || DEFAULT_INVESTIGATOR_ID;

    if (!method) {
        return res.status(400).json({ error: 'Connection method required (manual | wifi | usb)' });
    }

    try {
        let deviceId;

        // ----------------------------------------------------------
        // MANUAL  — caller supplies an explicit IP address
        // ----------------------------------------------------------
        if (method === 'manual') {
            if (!ip) {
                return res.status(400).json({ error: 'IP address required for manual connection' });
            }

            // Validate IP to prevent command injection
            if (!isValidIP(ip)) {
                return res.status(400).json({ error: 'Invalid IP address format' });
            }

            const adbPort = parseInt(port, 10);
            if (isNaN(adbPort) || adbPort < 1 || adbPort > 65535) {
                return res.status(400).json({ error: 'Invalid port number' });
            }

            const connectOutput = execSync(`adb connect ${ip}:${adbPort}`, {
                encoding: 'utf-8',
                timeout: 10000,
            });

            if (connectOutput.includes('failed') || connectOutput.includes('refused')) {
                return res.status(400).json({
                    error: 'Connection failed',
                    details: connectOutput.trim(),
                });
            }

            deviceId = `${ip}:${adbPort}`;

        // ----------------------------------------------------------
        // WIFI  — pick the first already-paired WiFi ADB device
        // Matches any IP:PORT format (not just :5555)
        // ----------------------------------------------------------
        } else if (method === 'wifi') {
            const adbOutput = execSync('adb devices', { encoding: 'utf-8' });
            const wifiDevices = adbOutput
                .split('\n')
                .filter(line => {
                    const trimmed = line.trim();
                    // WiFi devices have IP:PORT format e.g. 192.168.100.7:40741
                    return trimmed &&
                        !trimmed.startsWith('List') &&
                        /^\d+\.\d+\.\d+\.\d+:\d+/.test(trimmed) &&
                        trimmed.includes('device');
                })
                .map(line => line.split(/\s+/)[0]);

            if (wifiDevices.length === 0) {
                return res.status(400).json({ error: 'No WiFi ADB devices found. Pair the device first.' });
            }

            deviceId = wifiDevices[0];

        // ----------------------------------------------------------
        // USB  — pick the first USB-attached device
        // ----------------------------------------------------------
        } else if (method === 'usb') {
            const adbOutput = execSync('adb devices', { encoding: 'utf-8' });
            const usbDevices = adbOutput
                .split('\n')
                .filter(line => {
                    const trimmed = line.trim();
                    // USB serials don't contain ':' (WiFi ones do)
                    return (
                        trimmed &&
                        !trimmed.startsWith('List') &&
                        trimmed.endsWith('device') &&
                        !trimmed.includes(':')
                    );
                })
                .map(line => line.split(/\s+/)[0]);

            if (usbDevices.length === 0) {
                return res.status(400).json({ error: 'No USB ADB devices found. Check the cable and enable USB debugging.' });
            }

            deviceId = usbDevices[0];

        // ----------------------------------------------------------
        // UNKNOWN method
        // ----------------------------------------------------------
        } else {
            return res.status(400).json({
                error: `Unknown connection method "${method}". Use manual, wifi, or usb.`,
            });
        }

        // Validate the resolved device ID before any further shell calls
        if (!isValidDeviceId(deviceId)) {
            return res.status(500).json({ error: 'Resolved device ID is invalid' });
        }

        // Verify the device is actually reachable
        adbShell(deviceId, 'echo connected');

        // Gather device metadata
        const deviceName = adbShell(deviceId, 'getprop ro.product.model').trim();
        const androidVersion = adbShell(deviceId, 'getprop ro.build.version.release').trim();
        const serialNumber = adbShell(deviceId, 'getprop ro.serialno').trim();

        const deviceIp =
            method === 'manual'
                ? ip
                : deviceId.includes(':')
                ? deviceId.split(':')[0]
                : 'USB';

        // Persist / update device record
        await dbRun(
            `INSERT OR REPLACE INTO devices
             (id, deviceName, deviceModel, androidVersion, ip, serialNumber, connectionMethod, status, lastConnected, investigatorId, caseId)
             VALUES (?, ?, ?, ?, ?, ?, ?, 'connected', CURRENT_TIMESTAMP, ?, ?)`,
            [deviceId, deviceName, deviceName, androidVersion, deviceIp, serialNumber, method, invId, caseId || null]
        );

        // Audit log
        await dbRun(
            `INSERT INTO audit_logs (id, investigatorId, action, resource, resourceId, details)
             VALUES (?, ?, ?, ?, ?, ?)`,
            [
                crypto.randomUUID(),
                invId,
                'device_connected',
                'device',
                deviceId,
                `${deviceName} (${androidVersion}) connected via ${method}`,
            ]
        );

        res.json({
            success: true,
            device: {
                id: deviceId,
                name: deviceName,
                model: deviceName,
                androidVersion,
                serialNumber,
                ip: deviceIp,
                connectionMethod: method,
            },
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Connection failed',
            details: error.message,
        });
    }
});

// ============================================
// POST /api/android/disconnect
// Disconnect a device and update DB status
// ============================================
router.post('/disconnect', async (req, res) => {
    const { deviceId, investigatorId } = req.body;
    const invId = investigatorId || DEFAULT_INVESTIGATOR_ID;

    if (!deviceId) {
        return res.status(400).json({ error: 'deviceId is required' });
    }

    if (!isValidDeviceId(deviceId)) {
        return res.status(400).json({ error: 'Invalid device ID format' });
    }

    try {
        if (deviceId.includes(':')) {
            execSync(`adb disconnect ${deviceId}`, { encoding: 'utf-8', timeout: 5000 });
        }

        await dbRun(
            'UPDATE devices SET status = ?, lastConnected = CURRENT_TIMESTAMP WHERE id = ?',
            ['disconnected', deviceId]
        );

        await dbRun(
            `INSERT INTO audit_logs (id, investigatorId, action, resource, resourceId, details)
             VALUES (?, ?, ?, ?, ?, ?)`,
            [crypto.randomUUID(), invId, 'device_disconnected', 'device', deviceId, `Device ${deviceId} disconnected`]
        );

        res.json({ success: true, message: `Device ${deviceId} disconnected` });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Disconnect failed', details: error.message });
    }
});

// ============================================
// POST /api/android/scan
// Execute a scan and save results to the DB
// ============================================
router.post('/scan', async (req, res) => {
    const { deviceIp, scanType, options, investigatorId, caseId } = req.body;
    const invId = investigatorId || DEFAULT_INVESTIGATOR_ID;

    if (!deviceIp || !scanType) {
        return res.status(400).json({ error: 'deviceIp and scanType are required' });
    }

    if (!isValidDeviceId(deviceIp)) {
        return res.status(400).json({ error: 'Invalid deviceIp format' });
    }

    // FIX: guard against missing options object
    const opts = options || {};

    const scanId = `scan_${Date.now()}_${crypto.randomUUID().split('-')[0]}`;

    try {
        const startTime = Date.now();
        const results = [];

        await dbRun(
            `INSERT INTO scans
             (id, deviceId, caseId, investigatorId, scanType, status, startedAt, extractedApks, capturedMemory, analyzedStorage)
             VALUES (?, ?, ?, ?, ?, 'running', CURRENT_TIMESTAMP, ?, ?, ?)`,
            [
                scanId,
                deviceIp,
                caseId || null,
                invId,
                scanType,
                opts.extractApks ? 1 : 0,
                opts.captureMemory ? 1 : 0,
                opts.analyzeStorage ? 1 : 0,
            ]
        );

        if (['quick', 'deep', 'forensic'].includes(scanType)) {
            const packages = adbShell(deviceIp, 'pm list packages -3', 15000);

            const appList = packages
                .split('\n')
                .filter(line => line.startsWith('package:'))
                .map(line => line.replace('package:', '').trim());

            for (const pkg of appList) {
                try {
                    const permissions = await checkAppPermissions(deviceIp, pkg);
                    const threats = detectThreats({ packageName: pkg }, permissions);

                    for (const threat of threats) {
                        const threatId = `threat_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

                        await dbRun(
                            `INSERT INTO detected_threats
                             (id, scanId, deviceId, packageName, threatName, severity, detectionMethod, description, detectedAt)
                             VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
                            [
                                threatId,
                                scanId,
                                deviceIp,
                                pkg,
                                threat.name,
                                threat.severity,
                                threat.detectionMethod,
                                threat.description,
                            ]
                        );

                        results.push({ ...threat, packageName: pkg, id: threatId });
                    }
                } catch (e) {
                    console.error(`Error scanning ${pkg}:`, e.message);
                }
            }
        }

        const duration = Date.now() - startTime;
        const criticalCount = results.filter(r => r.severity === 'critical').length;
        const warningCount = results.filter(r => r.severity === 'warning').length;
        const infoCount = results.filter(r => r.severity === 'info').length;

        await dbRun(
            `UPDATE scans
             SET status = 'completed', completedAt = CURRENT_TIMESTAMP, durationMs = ?,
                 totalThreats = ?, criticalThreats = ?, warningThreats = ?, infoThreats = ?
             WHERE id = ?`,
            [duration, results.length, criticalCount, warningCount, infoCount, scanId]
        );

        await dbRun(
            `INSERT INTO audit_logs (id, investigatorId, action, resource, resourceId, details)
             VALUES (?, ?, ?, ?, ?, ?)`,
            [
                crypto.randomUUID(),
                invId,
                'scan_completed',
                'scan',
                scanId,
                `Found ${results.length} threats (${criticalCount} critical)`,
            ]
        );

        res.json({
            success: true,
            scanId,
            results,
            summary: {
                total: results.length,
                critical: criticalCount,
                warning: warningCount,
                info: infoCount,
                duration,
            },
        });
    } catch (error) {
        await dbRun('UPDATE scans SET status = ? WHERE id = ?', ['failed', scanId]);

        res.status(500).json({
            success: false,
            error: 'Scan failed',
            details: error.message,
        });
    }
});

// ============================================
// GET /api/android/statistics
// Dashboard statistics
// ============================================
router.get('/statistics', async (req, res) => {
    try {
        const stats = {
            totalDevices: (await dbGet('SELECT COUNT(*) as count FROM devices')).count,
            connectedDevices: (await dbGet('SELECT COUNT(*) as count FROM devices WHERE status = ?', ['connected'])).count,
            totalScans: (await dbGet('SELECT COUNT(*) as count FROM scans')).count,
            totalThreats: (await dbGet('SELECT COUNT(*) as count FROM detected_threats')).count,
            criticalThreats: (await dbGet('SELECT COUNT(*) as count FROM detected_threats WHERE severity = ?', ['critical'])).count,
            totalInvestigators: (await dbGet('SELECT COUNT(*) as count FROM investigators')).count,
            totalCases: (await dbGet('SELECT COUNT(*) as count FROM cases')).count,

            // FIX: LEFT JOIN so scans without a matching device record are not dropped
            recentScans: await dbAll(`
                SELECT s.*, d.deviceName, d.deviceModel
                FROM scans s
                LEFT JOIN devices d ON s.deviceId = d.id
                ORDER BY s.startedAt DESC
                LIMIT 10
            `),

            topThreats: await dbAll(`
                SELECT threatName, severity, COUNT(*) as count
                FROM detected_threats
                GROUP BY threatName
                ORDER BY count DESC
                LIMIT 10
            `),

            threatsBySeverity: await dbAll(`
                SELECT severity, COUNT(*) AS count
                FROM detected_threats
                GROUP BY severity
            `),
        };

        res.json({ success: true, stats });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============================================
// GET /api/android/threats
// All detected threats with optional filtering
// ============================================
router.get('/threats', async (req, res) => {
    try {
        const { severity, deviceId, scanId, limit = 100 } = req.query;

        let sql = 'SELECT * FROM detected_threats WHERE 1=1';
        const params = [];

        if (severity) {
            sql += ' AND severity = ?';
            params.push(severity);
        }
        if (deviceId) {
            sql += ' AND deviceId = ?';
            params.push(deviceId);
        }
        if (scanId) {
            sql += ' AND scanId = ?';
            params.push(scanId);
        }

        const parsedLimit = parseInt(limit, 10);
        sql += ' ORDER BY detectedAt DESC LIMIT ?';
        params.push(isNaN(parsedLimit) || parsedLimit < 1 ? 100 : parsedLimit);

        const threats = await dbAll(sql, params);

        res.json({ success: true, threats });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============================================
// GET /api/android/scan/:scanId
// Specific scan details with threats and chain-of-custody
// ============================================
router.get('/scan/:scanId', async (req, res) => {
    try {
        const { scanId } = req.params;

        const scan = await dbGet('SELECT * FROM scans WHERE id = ?', [scanId]);
        if (!scan) {
            return res.status(404).json({ error: 'Scan not found' });
        }

        const threats = await dbAll(
            'SELECT * FROM detected_threats WHERE scanId = ? ORDER BY severity DESC',
            [scanId]
        );
        const chainOfCustody = await dbAll(
            'SELECT * FROM chain_of_custody WHERE scanId = ?',
            [scanId]
        );

        res.json({ success: true, scan, threats, chainOfCustody });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============================================
// GET /api/android/scans
// List all scans with optional ?status= filter
// ============================================
router.get('/scans', async (req, res) => {
    try {
        const { status, deviceId, limit = 50 } = req.query;

        let sql = `
            SELECT s.*, d.deviceName, d.deviceModel
            FROM scans s
            LEFT JOIN devices d ON s.deviceId = d.id
            WHERE 1=1
        `;
        const params = [];

        if (status) {
            sql += ' AND s.status = ?';
            params.push(status);
        }
        if (deviceId) {
            sql += ' AND s.deviceId = ?';
            params.push(deviceId);
        }

        const parsedLimit = parseInt(limit, 10);
        sql += ' ORDER BY s.startedAt DESC LIMIT ?';
        params.push(isNaN(parsedLimit) || parsedLimit < 1 ? 50 : parsedLimit);

        const scans = await dbAll(sql, params);

        res.json({ success: true, scans });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ============================================
// GET /api/android/investigators
// List all investigators from the DB
// ============================================
router.get('/investigators', async (req, res) => {
    try {
        // The investigators table lives in the shared DB (created by server.js).
        // We select only non-sensitive columns — never return password_hash.
        const investigators = await dbAll(`
            SELECT investigator_id, name, email, created_at
            FROM investigators
            ORDER BY created_at DESC
        `);

        res.json({ success: true, investigators });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ============================================
// GET /api/android/audit
// List audit log entries with optional filters
// Query params: investigatorId, action, limit
// ============================================
router.get('/audit', async (req, res) => {
    try {
        const { investigatorId, action, limit = 100 } = req.query;

        let sql = 'SELECT * FROM audit_logs WHERE 1=1';
        const params = [];

        if (investigatorId) {
            sql += ' AND investigatorId = ?';
            params.push(investigatorId);
        }
        if (action) {
            sql += ' AND action = ?';
            params.push(action);
        }

        const parsedLimit = parseInt(limit, 10);
        sql += ' ORDER BY timestamp DESC LIMIT ?';
        params.push(isNaN(parsedLimit) || parsedLimit < 1 ? 100 : parsedLimit);

        const logs = await dbAll(sql, params);

        res.json({ success: true, logs });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ============================================
// HELPER FUNCTIONS
// ============================================

async function checkAppPermissions(deviceId, packageName) {
    try {
        // packageName comes from `pm list packages` output — validate it
        if (!/^[a-zA-Z0-9._]+$/.test(packageName)) {
            return [];
        }
        const output = adbShell(deviceId, `cmd appops get ${packageName}`);
        return output.split('\n').filter(line => line.trim());
    } catch (error) {
        return [];
    }
}

function detectThreats(appInfo, permissions) {
    const threats = [];

    const redFlags = {
        RECORD_AUDIO: { severity: 'critical', desc: 'Unauthorized audio recording' },
        CAMERA: { severity: 'critical', desc: 'Unauthorized camera access' },
        READ_SMS: { severity: 'critical', desc: 'SMS interception capability' },
        READ_CALL_LOG: { severity: 'warning', desc: 'Call log access' },
        ACCESS_FINE_LOCATION: { severity: 'critical', desc: 'GPS tracking enabled' },
        READ_CONTACTS: { severity: 'warning', desc: 'Contact list access' },
        SEND_SMS: { severity: 'critical', desc: 'Unauthorized SMS sending' },
    };

    permissions.forEach(perm => {
        Object.keys(redFlags).forEach(flag => {
            if (perm.includes(flag)) {
                threats.push({
                    name: redFlags[flag].desc,
                    severity: redFlags[flag].severity,
                    detectionMethod: 'Permission Analysis',
                    description: `App has ${flag} permission active`,
                });
            }
        });
    });

    return threats;
}

module.exports = router;