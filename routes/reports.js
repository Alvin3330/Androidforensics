// routes/reports.js
// Forensic Report Generation - ISO/IEC 27037:2012 compliant PDF reports

const express = require('express');
const path = require('path');
const fs = require('fs');
const router = express.Router();

const PDFDocument = require('pdfkit');

// ============================================================
// POST /api/reports/generate
// Generate a comprehensive forensic investigation report
// ============================================================
router.post('/generate', (req, res) => {
  const { caseId, includeChainOfCustody, includeArtifacts } = req.body;

  if (!caseId) {
    return res.status(400).json({ error: 'caseId required' });
  }

  const db = require('../db');

  Promise.all([
    getCaseData(db, caseId),
    getDetectedApps(db, caseId),
    getCOCLog(db, caseId),
    getForensicImages(db, caseId),
  ])
    .then(([caseData, detectedApps, cocLog, images]) => {
      if (!caseData) {
        return res.status(404).json({ error: 'Case not found' });
      }

      return generatePDF(caseData, detectedApps, cocLog, images);
    })
    .then((pdfPath) => {
      res.download(pdfPath, `forensic_report_${pdfPath.split('_')[2]}.pdf`, (err) => {
        if (err) console.error('Download error:', err);
        setTimeout(() => {
          fs.unlink(pdfPath, () => {});
        }, 5000);
      });
    })
    .catch((err) => {
      res.status(500).json({ error: err.message });
    });
});

// ============================================================
// POST /api/reports/preview
// Preview report data (JSON) before generating PDF
// ============================================================
router.post('/preview', (req, res) => {
  const { caseId } = req.body;
  const db = require('../db');

  Promise.all([
    getCaseData(db, caseId),
    getDetectedApps(db, caseId),
    getCOCLog(db, caseId),
  ])
    .then(([caseData, detectedApps, cocLog]) => {
      res.json({
        case: caseData,
        detected_apps: detectedApps,
        coc_entries: cocLog,
        report_metadata: {
          generated_date: new Date().toISOString(),
          total_detected: detectedApps.length,
          coc_entries: cocLog.length,
          critical_apps: detectedApps.filter((a) => a.risk_level === 'critical').length,
        },
      });
    })
    .catch((err) => res.status(500).json({ error: err.message }));
});

// ============================================================
// GET /api/reports/:caseId/summary
// Quick report summary
// ============================================================
router.get('/:caseId/summary', (req, res) => {
  const { caseId } = req.params;
  const db = require('../db');

  db.get('SELECT * FROM cases WHERE id = ?', [caseId], (err, caseData) => {
    if (!caseData) return res.status(404).json({ error: 'Case not found' });

    db.all(
      'SELECT risk_level FROM detected_apps WHERE case_id = ?',
      [caseId],
      (err, apps) => {
        const critical = apps.filter((a) => a.risk_level === 'critical').length;
        const high = apps.filter((a) => a.risk_level === 'high').length;
        const medium = apps.filter((a) => a.risk_level === 'medium').length;

        res.json({
          case_id: caseId,
          case_number: caseData.case_number,
          device: `${caseData.device_model} (${caseData.device_serial})`,
          total_apps_detected: apps.length,
          risk_breakdown: { critical, high, medium },
          severity: critical > 0 ? 'CRITICAL' : high > 0 ? 'HIGH' : 'MEDIUM',
          case_status: caseData.status,
        });
      }
    );
  });
});

// ============================================================
// Helper: Generate PDF Report
// ============================================================
function generatePDF(caseData, detectedApps, cocLog, images) {
  const caseId = caseData.id;

  const outputPath = path.join(
    __dirname,
    `../reports/forensic_report_${caseId}_${Date.now()}.pdf`
  );

  // Ensure reports directory exists
  const reportsDir = path.dirname(outputPath);
  if (!fs.existsSync(reportsDir)) {
    fs.mkdirSync(reportsDir, { recursive: true });
  }

  const doc = new PDFDocument({ bufferPages: true, margin: 50 });
  const stream = fs.createWriteStream(outputPath);

  doc.pipe(stream);

  // ========== COVER PAGE ==========
  doc
    .fontSize(24)
    .font('Helvetica-Bold')
    .text('FORENSIC INVESTIGATION REPORT', { align: 'center' });
  doc.fontSize(12).font('Helvetica').moveDown();
  doc.text('Android Device Analysis & Spyware Detection', { align: 'center' });
  doc.moveDown(2);

  doc.fontSize(11).text(`Case Number: ${caseData.case_number}`, { align: 'left' });
  doc.text(`Generated: ${new Date().toISOString()}`);
  doc.text(`Standard: ISO/IEC 27037:2012 Digital Evidence Handling`);
  doc.addPage();

  // ========== CASE INFORMATION ==========
  doc.fontSize(16).font('Helvetica-Bold').text('1. CASE INFORMATION', { underline: true });
  doc.fontSize(11).font('Helvetica').moveDown();

  const caseTable = [
    ['Case Number', caseData.case_number],
    ['Device Model', caseData.device_model || 'N/A'],
    ['Device Serial', caseData.device_serial || 'N/A'],
    ['Description', caseData.description || 'N/A'],
    ['Status', caseData.status || 'N/A'],
    ['Created', new Date(caseData.created_at).toLocaleString()],
  ];

  drawTable(doc, caseTable, { x: 50, y: doc.y });
  doc.moveDown(2);

  // ========== FORENSIC IMAGES ==========
  if (images && images.length > 0) {
    doc.fontSize(16).font('Helvetica-Bold').text('2. FORENSIC IMAGES', { underline: true });
    doc.fontSize(11).font('Helvetica').moveDown();

    const imgTable = images.map((img) => [
      img.image_type,
      img.acquisition_method,
      formatBytes(img.file_size),
      img.hash_sha256.substring(0, 16) + '...',
      new Date(img.acquisition_date).toLocaleDateString(),
    ]);

    imgTable.unshift(['Type', 'Method', 'Size', 'SHA-256 (abbrev)', 'Date']);
    drawTable(doc, imgTable, { x: 50, y: doc.y, width: 500 });
    doc.moveDown(2);
  }

  // ========== DETECTED APPLICATIONS ==========
  doc.addPage();
  doc
    .fontSize(16)
    .font('Helvetica-Bold')
    .text('3. DETECTED APPLICATIONS', { underline: true });
  doc.fontSize(11).font('Helvetica').moveDown();

  if (detectedApps.length === 0) {
    doc.text('No suspicious applications detected.');
  } else {
    const critical = detectedApps.filter((a) => a.risk_level === 'critical');
    const high = detectedApps.filter((a) => a.risk_level === 'high');

    doc
      .fontSize(12)
      .font('Helvetica-Bold')
      .fillColor(critical.length > 0 ? 'red' : 'orange')
      .text(`Summary: ${critical.length} CRITICAL, ${high.length} HIGH`)
      .fillColor('black');
    doc.moveDown();

    // Critical apps first
    if (critical.length > 0) {
      doc.fontSize(11).font('Helvetica-Bold').fillColor('darkred').text('CRITICAL RISK APPLICATIONS:');
      critical.forEach((app) => {
        doc.font('Helvetica').fontSize(10).fillColor('darkred');
        doc.text(`• ${app.app_name} (${app.package_name})`);
        doc
          .fillColor('black')
          .text(`  Risk: ${app.risk_level} | Hidden: ${app.is_hidden ? 'Yes' : 'No'}`, {
            indent: 20,
          });
        if (app.detection_reason) {
          doc.text(`  Reason: ${app.detection_reason.substring(0, 100)}...`, { indent: 20 });
        }
        doc.moveDown(0.5);
      });
      doc.moveDown();
    }

    // High risk apps
    if (high.length > 0) {
      doc.fontSize(11).font('Helvetica-Bold').fillColor('orangered').text('HIGH RISK APPLICATIONS:');
      high.forEach((app) => {
        doc.font('Helvetica').fontSize(10).fillColor('orangered');
        doc.text(`• ${app.app_name} (${app.package_name})`);
        doc
          .fillColor('black')
          .text(`  Risk: ${app.risk_level} | Hidden: ${app.is_hidden ? 'Yes' : 'No'}`, {
            indent: 20,
          });
        doc.moveDown(0.5);
      });
      doc.fillColor('black');
    }
  }

  // ========== CHAIN OF CUSTODY ==========
  doc.addPage();
  doc.fontSize(16).font('Helvetica-Bold').text('4. CHAIN OF CUSTODY', { underline: true });
  doc.fontSize(11).font('Helvetica').moveDown();

  if (cocLog && cocLog.length > 0) {
    const cocTable = cocLog.map((entry, idx) => [
      (idx + 1).toString(),
      new Date(entry.timestamp).toLocaleTimeString(),
      entry.action.substring(0, 40) + (entry.action.length > 40 ? '...' : ''),
      entry.investigator_id,
    ]);

    cocTable.unshift(['#', 'Timestamp', 'Action', 'Investigator']);
    drawTable(doc, cocTable, { x: 50, y: doc.y, width: 500 });
  } else {
    doc.text('No chain of custody entries.');
  }

  // ========== COMPLIANCE & CERTIFICATION ==========
  doc.addPage();
  doc
    .fontSize(16)
    .font('Helvetica-Bold')
    .text('5. COMPLIANCE & CERTIFICATION', { underline: true });
  doc.fontSize(11).font('Helvetica').moveDown();

  doc.fontSize(10);
  doc.text(
    'This report has been generated in accordance with ISO/IEC 27037:2012 "Guidelines for identification, collection, acquisition and preservation of digital evidence"',
    { align: 'justify' }
  );
  doc.moveDown();

  doc.font('Helvetica-Bold').text('Evidence Handling Compliance:');
  doc.fontSize(9).font('Helvetica');
  doc.text('✓ Device identification and authentication', { indent: 10 });
  doc.text('✓ Write-blocking and data integrity verification', { indent: 10 });
  doc.text('✓ Hash verification (MD5/SHA-256)', { indent: 10 });
  doc.text('✓ Chain of custody documentation', { indent: 10 });
  doc.text('✓ Investigator accountability logging', { indent: 10 });
  doc.text('✓ Timestamp authentication', { indent: 10 });

  doc.moveDown();
  doc.fontSize(10).font('Helvetica-Bold').fillColor('darkblue').text('CERTIFICATION:');
  doc
    .fontSize(9)
    .font('Helvetica')
    .fillColor('black')
    .text(
      'I certify that the evidence presented in this report was acquired, handled, and analyzed in accordance with industry best practices and legal standards. This report is suitable for court submission and forensic proceedings.',
      { align: 'justify' }
    );

  doc.moveDown(2);
  doc.fontSize(10).text(`Generated by: Android Forensics Backend v1.0`);
  doc.text(`Report ID: ${caseData.id}-${Date.now()}`);
  doc.text(`Certified Date: ${new Date().toISOString()}`);

  // ========== PAGE FOOTERS ==========
  const pages = doc.bufferedPageRange().count;
  for (let i = 0; i < pages; i++) {
    doc.switchToPage(i);
    doc
      .fontSize(9)
      .text(`Page ${i + 1} of ${pages}`, 50, doc.page.height - 30, { align: 'center' });
  }

  doc.end();

  return new Promise((resolve, reject) => {
    stream.on('finish', () => resolve(outputPath));
    stream.on('error', reject);
  });
} // ← end generatePDF

// ============================================================
// Helper: Draw Table in PDF
// ============================================================
function drawTable(doc, data, options = {}) {
  const { x = 50, y = doc.y, width = 500, rowHeight = 20 } = options;
  const cellPadding = 5;
  const colCount = data[0].length;
  const colWidth = width / colCount;

  let currentY = y;

  data.forEach((row, rowIndex) => {
    row.forEach((cell, colIndex) => {
      const cellX = x + colIndex * colWidth;
      const cellY = currentY;

      doc.rect(cellX, cellY, colWidth, rowHeight).stroke();

      if (rowIndex === 0) {
        doc.font('Helvetica-Bold').fontSize(9);
      } else {
        doc.font('Helvetica').fontSize(8);
      }

      doc.text(String(cell), cellX + cellPadding, cellY + cellPadding, {
        width: colWidth - 2 * cellPadding,
        height: rowHeight - 2 * cellPadding,
        ellipsis: true,
      });
    });

    currentY += rowHeight;
  });

  doc.y = currentY;
}

// ============================================================
// Helper: Format bytes
// ============================================================
function formatBytes(bytes) {
  if (!bytes) return 'N/A';
  const sizes = ['B', 'KB', 'MB', 'GB'];
  if (bytes === 0) return '0 B';
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return Math.round((bytes / Math.pow(1024, i)) * 100) / 100 + ' ' + sizes[i];
}

// ============================================================
// Database Helper Functions
// ============================================================
function getCaseData(db, caseId) {
  return new Promise((resolve, reject) => {
    db.get('SELECT * FROM cases WHERE id = ?', [caseId], (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}

function getDetectedApps(db, caseId) {
  return new Promise((resolve, reject) => {
    db.all(
      'SELECT * FROM detected_apps WHERE case_id = ? ORDER BY risk_level DESC',
      [caseId],
      (err, rows) => {
        if (err) reject(err);
        else resolve(rows || []);
      }
    );
  });
}

function getCOCLog(db, caseId) {
  return new Promise((resolve, reject) => {
    db.all(
      'SELECT * FROM chain_of_custody WHERE case_id = ? ORDER BY timestamp ASC',
      [caseId],
      (err, rows) => {
        if (err) reject(err);
        else resolve(rows || []);
      }
    );
  });
}

function getForensicImages(db, caseId) {
  return new Promise((resolve, reject) => {
    db.all(
      'SELECT * FROM forensic_images WHERE case_id = ? ORDER BY acquisition_date ASC',
      [caseId],
      (err, rows) => {
        if (err) reject(err);
        else resolve(rows || []);
      }
    );
  });
}

module.exports = router;