const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { execSync, exec } = require('child_process');
require('dotenv').config();

const reportRoutes = require('./routes/reports');
const detectionRoutes = require('./routes/detection');
const androidForensicsRouter = require('./routes/android-forensics'); // FIX: consistent name

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'forensic-secret-key-change-in-production';

// ============================================
// INPUT VALIDATION HELPERS
// ============================================

/**
 * Validate a device serial / ADB device ID.
 * Allows alphanumerics, dots, colons, hyphens, underscores only.
 */
function isValidDeviceSerial(serial) {
    return typeof serial === 'string' && /^[a-zA-Z0-9.:_-]+$/.test(serial);
}

// ============================================
// MIDDLEWARE
// ============================================
app.use(express.json());
app.use(express.static('public'));
app.use(cors());

// ============================================
// ROUTES — registered AFTER middleware
// FIX: removed duplicate /api/reports registration
// FIX: use the correctly imported variable name
// ============================================
app.use('/api/reports', reportRoutes);
app.use('/api/detection', detectionRoutes);
app.use('/api/android', androidForensicsRouter);

// ============================================
// DATABASE — single shared path
// FIX: was './forensics.db' here vs './db/forensics.db' in android-forensics.js
// Both files now use the same path via DB_PATH env var (default: ./db/forensics.db)
// ============================================
const DB_PATH = process.env.DB_PATH || './db/forensics.db';

// Ensure the db directory exists
const dbDir = path.dirname(DB_PATH);
if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
}

const db = new sqlite3.Database(DB_PATH, (err) => {
    if (err) {
        console.error('Database error:', err);
    } else {
        console.log('✅ SQLite connected at', DB_PATH);
        // WAL mode: safer for concurrent access, prevents corruption on crash
        db.run('PRAGMA journal_mode=WAL', (err) => {
            if (err) console.error('Failed to set WAL mode:', err.message);
            else console.log('✅ WAL journal mode enabled');
        });
        // Enforce foreign key constraints (SQLite disables them by default)
        db.run('PRAGMA foreign_keys=ON', (err) => {
            if (err) console.error('Failed to enable foreign keys:', err.message);
            else console.log('✅ Foreign keys enabled');
        });
        // Reduce risk of corruption on power loss
        db.run('PRAGMA synchronous=NORMAL');
    }
});

// ============================================
// DATABASE SCHEMA
// ============================================
const initializeDB = () => {
    db.serialize(() => {
        db.run(`
            CREATE TABLE IF NOT EXISTS investigators (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                investigator_id TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `);

        db.run(`
            CREATE TABLE IF NOT EXISTS cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_number TEXT UNIQUE NOT NULL,
                investigator_id TEXT NOT NULL,
                device_model TEXT,
                device_serial TEXT,
                description TEXT,
                status TEXT DEFAULT 'pending',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (investigator_id) REFERENCES investigators(investigator_id)
            )
        `);

        db.run(`
            CREATE TABLE IF NOT EXISTS forensic_images (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL,
                image_path TEXT NOT NULL,
                image_type TEXT,
                acquisition_method TEXT,
                hash_md5 TEXT,
                hash_sha256 TEXT,
                file_size TEXT,
                acquisition_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (case_id) REFERENCES cases(id)
            )
        `);

        db.run(`
            CREATE TABLE IF NOT EXISTS detected_apps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL,
                package_name TEXT NOT NULL,
                app_name TEXT,
                risk_level TEXT,
                installation_date DATETIME,
                last_active DATETIME,
                permissions TEXT,
                is_hidden BOOLEAN,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (case_id) REFERENCES cases(id)
            )
        `);

        db.run(`
            CREATE TABLE IF NOT EXISTS artifacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                app_id INTEGER NOT NULL,
                artifact_type TEXT,
                artifact_data TEXT,
                extracted_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (app_id) REFERENCES detected_apps(id)
            )
        `);

        db.run(`
            CREATE TABLE IF NOT EXISTS chain_of_custody (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                investigator_id TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                hash_value TEXT,
                FOREIGN KEY (case_id) REFERENCES cases(id),
                FOREIGN KEY (investigator_id) REFERENCES investigators(investigator_id)
            )
        `);


        // Devices table — used by android-forensics.js
        db.run(`
            CREATE TABLE IF NOT EXISTS devices (
                id TEXT PRIMARY KEY,
                deviceName TEXT,
                deviceModel TEXT,
                androidVersion TEXT,
                ip TEXT,
                serialNumber TEXT,
                connectionMethod TEXT,
                status TEXT DEFAULT 'disconnected',
                lastConnected DATETIME DEFAULT CURRENT_TIMESTAMP,
                investigatorId TEXT,
                caseId TEXT,
                createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Scans table — used by android-forensics.js
        db.run(`
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                deviceIp TEXT NOT NULL,
                caseId TEXT,
                investigatorId TEXT,
                scanType TEXT,
                status TEXT DEFAULT 'pending',
                startedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
                completedAt DATETIME,
                durationMs INTEGER,
                totalThreats INTEGER DEFAULT 0,
                criticalThreats INTEGER DEFAULT 0,
                warningThreats INTEGER DEFAULT 0,
                infoThreats INTEGER DEFAULT 0,
                extractedApks INTEGER DEFAULT 0,
                capturedMemory INTEGER DEFAULT 0,
                analyzedStorage INTEGER DEFAULT 0
            )
        `);

        // Detected threats table — used by android-forensics.js
        db.run(`
            CREATE TABLE IF NOT EXISTS detected_threats (
                id TEXT PRIMARY KEY,
                scanId TEXT,
                deviceIp TEXT,
                packageName TEXT,
                threatName TEXT,
                severity TEXT,
                detectionMethod TEXT,
                description TEXT,
                detectedAt DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Audit logs table — used by android-forensics.js
        db.run(`
            CREATE TABLE IF NOT EXISTS audit_logs (
                id TEXT PRIMARY KEY,
                investigatorId TEXT,
                action TEXT,
                resource TEXT,
                resourceId TEXT,
                details TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `);

        console.log('✅ Database schema initialized');
    });
};

initializeDB();

// ============================================
// JWT MIDDLEWARE
// FIX: moved ABOVE all route definitions so it is
//      defined before any route handler references it.
// ============================================
const verifyToken = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ error: 'Invalid token' });
        }
        req.investigator = decoded;
        next();
    });
};

// ============================================
// AUTH ROUTES
// ============================================

app.post('/api/auth/register', async (req, res) => {
    const { investigator_id, name, email, password } = req.body;

    if (!investigator_id || !name || !email || !password) {
        return res.status(400).json({ error: 'All fields required' });
    }

    try {
        const hashed = await bcrypt.hash(password, 10);

        db.run(
            `INSERT INTO investigators (investigator_id, name, email, password_hash)
             VALUES (?, ?, ?, ?)`,
            [investigator_id, name, email, hashed],
            (err) => {
                if (err) {
                    return res.status(400).json({ error: 'Investigator ID already exists' });
                }
                res.status(201).json({ message: 'Registered successfully' });
            }
        );
    } catch (error) {
        res.status(500).json({ error: 'Registration failed' });
    }
});

app.post('/api/auth/login', (req, res) => {
    const { investigator_id, password } = req.body;

    if (!investigator_id || !password) {
        return res.status(400).json({ error: 'ID and password required' });
    }

    db.get(
        `SELECT * FROM investigators WHERE investigator_id = ?`,
        [investigator_id],
        async (err, row) => {
            if (err || !row) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }

            const validPassword = await bcrypt.compare(password, row.password_hash);
            if (!validPassword) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }

            const token = jwt.sign(
                { investigator_id: row.investigator_id, name: row.name },
                JWT_SECRET,
                { expiresIn: '24h' }
            );

            res.json({ token, investigator_id: row.investigator_id, name: row.name });
        }
    );
});

// ============================================
// ADB ROUTES
// FIX: validate deviceSerial before all shell commands
// ============================================

app.get('/api/adb/devices', verifyToken, (req, res) => {
    exec('adb devices', (error, stdout) => {
        if (error) {
            return res.status(500).json({ error: 'ADB not available' });
        }

        const lines = stdout.split('\n').slice(1).filter(line => line.trim());
        const devices = lines.map(line => {
            const [serial, status] = line.split('\t');
            return { serial: serial?.trim(), status: status?.trim() };
        }).filter(d => d.serial && d.status);

        res.json({ devices });
    });
});

app.post('/api/adb/device-info', verifyToken, (req, res) => {
    const { deviceSerial } = req.body;

    // FIX: validate before use
    if (!deviceSerial || !isValidDeviceSerial(deviceSerial)) {
        return res.status(400).json({ error: 'Invalid or missing device serial' });
    }

    try {
        const device_info = {
            model: execSync(`adb -s ${deviceSerial} shell getprop ro.product.model`, { encoding: 'utf-8' }).trim() || 'Unknown',
            android_version: execSync(`adb -s ${deviceSerial} shell getprop ro.build.version.release`, { encoding: 'utf-8' }).trim() || 'Unknown',
            serial: execSync(`adb -s ${deviceSerial} shell getprop ro.serialno`, { encoding: 'utf-8' }).trim() || 'Unknown',
            brand: execSync(`adb -s ${deviceSerial} shell getprop ro.product.brand`, { encoding: 'utf-8' }).trim() || 'Unknown',
        };

        res.json({ device_info });
    } catch (error) {
        res.status(500).json({ error: 'Failed to get device info. Device may be disconnected or locked.' });
    }
});

app.post('/api/adb/packages', verifyToken, (req, res) => {
    const { deviceSerial } = req.body;

    // FIX: validate before use
    if (!deviceSerial || !isValidDeviceSerial(deviceSerial)) {
        return res.status(400).json({ error: 'Invalid or missing device serial' });
    }

    exec(`adb -s ${deviceSerial} shell pm list packages`, (error, stdout) => {
        if (error) {
            return res.status(500).json({ error: 'Failed to get packages' });
        }

        const packages = stdout
            .split('\n')
            .filter(line => line.startsWith('package:'))
            .map(line => line.replace('package:', '').trim());

        res.json({ packages, count: packages.length });
    });
});

// ============================================
// CASE ROUTES
// ============================================

app.post('/api/cases', verifyToken, (req, res) => {
     console.log('CREATE CASE - body:', req.body);        // ← add this
    console.log('CREATE CASE - user:', req.investigator);
    
    const { device_model, device_serial, description } = req.body;
    const investigator_id = req.investigator.investigator_id;

    // Auto-generate a unique case number if not provided
    const case_number = req.body.case_number && req.body.case_number.trim()
        ? req.body.case_number.trim()
        : `CASE-${Date.now()}-${Math.random().toString(36).substr(2, 5).toUpperCase()}`;

    if (!device_model && !device_serial && !description) {
        return res.status(400).json({ error: 'At least one of device_model, device_serial, or description is required' });
    }

    db.run(
        `INSERT INTO cases (case_number, investigator_id, device_model, device_serial, description)
         VALUES (?, ?, ?, ?, ?)`,
        [case_number, investigator_id, device_model, device_serial, description],
        function (err) {
            if (err) {
                if (err.message && err.message.includes('UNIQUE constraint failed')) {
                    // Case number collision — append timestamp and retry once
                    const fallback = `${case_number}-${Date.now()}`;
                    db.run(
                        `INSERT INTO cases (case_number, investigator_id, device_model, device_serial, description)
                         VALUES (?, ?, ?, ?, ?)`,
                        [fallback, investigator_id, device_model, device_serial, description],
                        function (err2) {
                            if (err2) {
                                return res.status(400).json({
                                    error: `Case number "${case_number}" already exists. Please use a different case number.`
                                });
                            }
                            res.status(201).json({
                                case_id: this.lastID,
                                case_number: fallback,
                                message: 'Case created (auto-renamed to avoid duplicate)'
                            });
                        }
                    );
                } else {
                    return res.status(500).json({ error: 'Failed to create case', details: err.message });
                }
            } else {
                res.status(201).json({ case_id: this.lastID, case_number, message: 'Case created' });
            }
        }
    );
});

app.get('/api/cases', verifyToken, (req, res) => {
    const investigator_id = req.investigator.investigator_id;

    db.all(
        `SELECT * FROM cases WHERE investigator_id = ? ORDER BY created_at DESC`,
        [investigator_id],
        (err, rows) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            res.json({ cases: rows });
        }
    );
});

// FIX: promisified helper for cleaner nested DB calls
const dbAll = (sql, params = []) =>
    new Promise((resolve, reject) =>
        db.all(sql, params, (err, rows) => (err ? reject(err) : resolve(rows || [])))
    );

const dbGet = (sql, params = []) =>
    new Promise((resolve, reject) =>
        db.get(sql, params, (err, row) => (err ? reject(err) : resolve(row)))
    );

const dbRun = (sql, params = []) =>
    new Promise((resolve, reject) =>
        db.run(sql, params, function (err) {
            if (err) reject(err);
            else resolve({ lastID: this.lastID, changes: this.changes });
        })
    );

app.get('/api/cases/:caseId', verifyToken, async (req, res) => {
    const { caseId } = req.params;

    try {
        // FIX: properly handle errors from both DB calls
        const caseData = await dbGet('SELECT * FROM cases WHERE id = ?', [caseId]);
        if (!caseData) {
            return res.status(404).json({ error: 'Case not found' });
        }

        const [images, apps] = await Promise.all([
            dbAll('SELECT * FROM forensic_images WHERE case_id = ?', [caseId]),
            dbAll('SELECT * FROM detected_apps WHERE case_id = ?', [caseId]),
        ]);

        res.json({ case: caseData, images, apps });
    } catch (err) {
        res.status(500).json({ error: 'Database error', details: err.message });
    }
});

app.delete('/api/cases/:caseId', verifyToken, async (req, res) => {
    const { caseId } = req.params;
    const investigator_id = req.investigator?.investigator_id || req.investigator?.id;

    if (!investigator_id) {
        return res.status(401).json({ error: 'Invalid token' });
    }

    try {
        const caseData = await dbGet(
            'SELECT * FROM cases WHERE id = ? AND investigator_id = ?',
            [caseId, investigator_id]
        );

        if (!caseData) {
            return res.status(404).json({ error: 'Case not found or not authorized' });
        }

        // FIX: use a transaction so all deletes succeed or none do
        await dbRun('BEGIN TRANSACTION');

        await dbRun(
            'DELETE FROM artifacts WHERE app_id IN (SELECT id FROM detected_apps WHERE case_id = ?)',
            [caseId]
        );
        await dbRun('DELETE FROM detected_apps WHERE case_id = ?', [caseId]);
        await dbRun('DELETE FROM forensic_images WHERE case_id = ?', [caseId]);
        await dbRun('DELETE FROM chain_of_custody WHERE case_id = ?', [caseId]);
        await dbRun('DELETE FROM cases WHERE id = ?', [caseId]);

        await dbRun('COMMIT');

        res.json({ message: 'Case deleted successfully' });
    } catch (err) {
        await dbRun('ROLLBACK').catch(() => {});
        res.status(500).json({ error: 'Failed to delete case', details: err.message });
    }
});

// ============================================
// DETECTION ROUTE
// FIX: validate deviceSerial before shell use
// ============================================
const rulesPath = path.join(__dirname, 'rules/spyapp_detection.yar');

app.post('/api/detection/scan', verifyToken, (req, res) => {
    const { caseId, deviceSerial } = req.body;

    if (!deviceSerial || !isValidDeviceSerial(deviceSerial)) {
        return res.status(400).json({ error: 'Invalid or missing device serial' });
    }

    try {
        const packages = execSync(`adb -s ${deviceSerial} shell pm list packages`, { encoding: 'utf-8' })
            .split('\n')
            .filter(line => line.startsWith('package:'))
            .map(line => line.replace('package:', '').trim());

        const detectedApps = [];
        const tempFile = `/tmp/packages_${Date.now()}.txt`;
        fs.writeFileSync(tempFile, packages.join('\n'));

        const riskMap = {
            KnownSpyware: 'critical',
            RemoteCommand: 'critical',
            Keylogging: 'critical',
            DataExfiltration: 'critical',
            C2Communication: 'critical',
            HiddenApp: 'high',
            LocationTracking: 'high',
            CallMonitoring: 'high',
            SMSInterception: 'high',
            Persistence: 'medium',
        };

        const processPackages = (yaraMatches, detectionMethod) => {
            packages.forEach(pkg => {
                let matchedRules = [];
                let risk_level = 'low';

                if (yaraMatches) {
                    yaraMatches.forEach(match => {
                        const ruleName = match.split(' ')[0];
                        if (match.includes(tempFile)) {
                            matchedRules.push(ruleName);
                            const ruleRisk = riskMap[ruleName] || 'medium';
                            const order = ['low', 'medium', 'high', 'critical'];
                            if (order.indexOf(ruleRisk) > order.indexOf(risk_level)) {
                                risk_level = ruleRisk;
                            }
                        }
                    });
                }

                const suspiciousName = pkg.includes('hidden') || pkg.includes('spy') || pkg.includes('tracker');
                if (matchedRules.length === 0 && suspiciousName) {
                    matchedRules.push('PatternMatch');
                    risk_level = 'high';
                }

                if (matchedRules.length > 0) {
                    const app = {
                        case_id: caseId,
                        package_name: pkg,
                        app_name: pkg.split('.').pop(),
                        risk_level,
                        is_hidden: suspiciousName ? 1 : 0,
                        permissions: JSON.stringify(matchedRules),
                    };

                    detectedApps.push(app);

                    db.run(
                        `INSERT INTO detected_apps (case_id, package_name, app_name, risk_level, is_hidden, permissions)
                         VALUES (?, ?, ?, ?, ?, ?)`,
                        [app.case_id, app.package_name, app.app_name, app.risk_level, app.is_hidden, app.permissions],
                        (err) => { if (err) console.error('Insert error:', err.message); }
                    );
                }
            });

            try { fs.unlinkSync(tempFile); } catch (e) {}

            res.json({
                detected_count: detectedApps.length,
                apps: detectedApps,
                detection_method: detectionMethod,
                scanned_packages: packages.length,
            });
        };

        try {
            const yaraOutput = execSync(`yara -r ${rulesPath} ${tempFile}`, { encoding: 'utf-8' });
            const yaraMatches = yaraOutput.split('\n').filter(line => line.trim());
            processPackages(yaraMatches, 'YARA Rules');
        } catch (yaraError) {
            // YARA not installed or no matches — fall back to pattern matching
            processPackages(null, 'Pattern Matching (YARA unavailable)');
        }

    } catch (error) {
        console.error('Detection error:', error);
        res.status(500).json({ error: 'Device scan failed: ' + error.message });
    }
});

// ============================================
// HEALTH CHECK
// ============================================
app.get('/api/health', (req, res) => {
    res.json({ status: 'Backend running ✅', db: DB_PATH });
});

// ============================================
// START SERVER
// ============================================
app.listen(PORT, () => {
    console.log(`
╔═══════════════════════════════════════════╗
║  Android Forensics Backend                ║
║  Running on http://localhost:${PORT}        ║
║  Status: Ready for acquisition 🔍         ║
╚═══════════════════════════════════════════╝
    `);
});

module.exports = app;