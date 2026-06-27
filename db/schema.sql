/**
 * Android Forensics Database Schema
 * File: db/schema.sql
 * 
 * Run with: sqlite3 forensics.db < schema.sql
 */

-- ============================================
-- USERS & INVESTIGATORS TABLE
-- ============================================
CREATE TABLE IF NOT EXISTS investigators (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT UNIQUE,
    department TEXT,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    lastActive DATETIME,
    role TEXT DEFAULT 'investigator' -- investigator, admin, viewer
);

-- ============================================
-- CASES TABLE
-- ============================================
CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    investigatorId TEXT NOT NULL,
    status TEXT DEFAULT 'open', -- open, closed, archived
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    closedAt DATETIME,
    FOREIGN KEY (investigatorId) REFERENCES investigators(id)
);

-- ============================================
-- CONNECTED DEVICES TABLE
-- ============================================
CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    deviceName TEXT NOT NULL,
    deviceModel TEXT,
    androidVersion TEXT,
    ip TEXT,
    connectionMethod TEXT, -- wifi, usb, manual
    status TEXT DEFAULT 'connected', -- connected, disconnected, error
    firstSeen DATETIME DEFAULT CURRENT_TIMESTAMP,
    lastConnected DATETIME,
    investigatorId TEXT,
    caseId TEXT,
    FOREIGN KEY (investigatorId) REFERENCES investigators(id),
    FOREIGN KEY (caseId) REFERENCES cases(id)
);

-- ============================================
-- FORENSIC SCANS TABLE
-- ============================================
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    deviceId TEXT NOT NULL,
    caseId TEXT,
    investigatorId TEXT NOT NULL,
    scanType TEXT NOT NULL, -- quick, deep, network, forensic
    status TEXT DEFAULT 'completed', -- running, completed, failed
    startedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    completedAt DATETIME,
    durationMs INTEGER,
    
    -- Scan options
    extractedApks BOOLEAN DEFAULT 0,
    capturedMemory BOOLEAN DEFAULT 0,
    analyzedStorage BOOLEAN DEFAULT 0,
    
    -- Summary counts
    totalThreats INTEGER DEFAULT 0,
    criticalThreats INTEGER DEFAULT 0,
    warningThreats INTEGER DEFAULT 0,
    infoThreats INTEGER DEFAULT 0,
    
    -- Notes
    notes TEXT,
    
    FOREIGN KEY (deviceId) REFERENCES devices(id),
    FOREIGN KEY (caseId) REFERENCES cases(id),
    FOREIGN KEY (investigatorId) REFERENCES investigators(id)
);

-- ============================================
-- DETECTED THREATS TABLE
-- ============================================
CREATE TABLE IF NOT EXISTS detected_threats (
    id TEXT PRIMARY KEY,
    scanId TEXT NOT NULL,
    deviceId TEXT NOT NULL,
    packageName TEXT,
    threatName TEXT NOT NULL,
    severity TEXT NOT NULL, -- critical, warning, info
    detectionMethod TEXT, -- Permission Analysis, YARA, Network, Process, etc.
    description TEXT,
    appLabel TEXT,
    appIcon BLOB,
    
    -- Additional context
    permissions TEXT, -- JSON array of permissions
    networks TEXT,    -- JSON array of network connections
    processes TEXT,   -- JSON array of suspicious processes
    
    detectedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    falsePositive BOOLEAN DEFAULT 0,
    reviewed BOOLEAN DEFAULT 0,
    reviewedBy TEXT,
    
    FOREIGN KEY (scanId) REFERENCES scans(id),
    FOREIGN KEY (deviceId) REFERENCES devices(id)
);

-- ============================================
-- CHAIN OF CUSTODY TABLE
-- ============================================
CREATE TABLE IF NOT EXISTS chain_of_custody (
    id TEXT PRIMARY KEY,
    caseId TEXT NOT NULL,
    scanId TEXT,
    deviceId TEXT,
    action TEXT NOT NULL, -- connected, scanned, exported, archived
    investigatorId TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    details TEXT,
    
    FOREIGN KEY (caseId) REFERENCES cases(id),
    FOREIGN KEY (scanId) REFERENCES scans(id),
    FOREIGN KEY (deviceId) REFERENCES devices(id),
    FOREIGN KEY (investigatorId) REFERENCES investigators(id)
);

-- ============================================
-- EXPORTED REPORTS TABLE
-- ============================================
CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY,
    caseId TEXT NOT NULL,
    scanId TEXT,
    investigatorId TEXT NOT NULL,
    reportType TEXT, -- summary, detailed, evidence
    exportFormat TEXT, -- pdf, csv, json
    exportedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    fileName TEXT,
    fileSize INTEGER,
    filePath TEXT,
    
    FOREIGN KEY (caseId) REFERENCES cases(id),
    FOREIGN KEY (scanId) REFERENCES scans(id),
    FOREIGN KEY (investigatorId) REFERENCES investigators(id)
);

-- ============================================
-- SCAN ARTIFACTS TABLE
-- ============================================
CREATE TABLE IF NOT EXISTS artifacts (
    id TEXT PRIMARY KEY,
    scanId TEXT NOT NULL,
    deviceId TEXT NOT NULL,
    artifactType TEXT, -- apk, image, log, config
    fileName TEXT NOT NULL,
    fileSize INTEGER,
    hash TEXT,
    storagePath TEXT,
    extractedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (scanId) REFERENCES scans(id),
    FOREIGN KEY (deviceId) REFERENCES devices(id)
);

-- ============================================
-- AUDIT LOG TABLE
-- ============================================
CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    investigatorId TEXT,
    action TEXT NOT NULL,
    resource TEXT, -- device, scan, threat, case
    resourceId TEXT,
    details TEXT,
    ipAddress TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (investigatorId) REFERENCES investigators(id)
);

-- ============================================
-- INDEXES FOR PERFORMANCE
-- ============================================
CREATE INDEX idx_scans_deviceId ON scans(deviceId);
CREATE INDEX idx_scans_caseId ON scans(caseId);
CREATE INDEX idx_scans_investigatorId ON scans(investigatorId);
CREATE INDEX idx_scans_startedAt ON scans(startedAt);

CREATE INDEX idx_threats_scanId ON detected_threats(scanId);
CREATE INDEX idx_threats_deviceId ON detected_threats(deviceId);
CREATE INDEX idx_threats_severity ON detected_threats(severity);
CREATE INDEX idx_threats_detectedAt ON detected_threats(detectedAt);

CREATE INDEX idx_devices_investigatorId ON devices(investigatorId);
CREATE INDEX idx_devices_caseId ON devices(caseId);

CREATE INDEX idx_cases_investigatorId ON cases(investigatorId);
CREATE INDEX idx_cases_status ON cases(status);

CREATE INDEX idx_audit_investigatorId ON audit_logs(investigatorId);
CREATE INDEX idx_audit_timestamp ON audit_logs(timestamp);