// modules/adbService.js
// ADB (Android Debug Bridge) Service - Device Interaction & File Extraction
// Uses execSync for reliable command execution on Kali Linux

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

class ADBService {
  constructor() {
    this.adbPath = '/usr/bin/adb'; // Standard path on Linux
    this.connectedDevice = null;
    this.tempDir = path.join(os.tmpdir(), 'android-forensics');
    this.ensureTempDir();
  }

  // ============================================================
  // Ensure temp directory exists
  // ============================================================
  ensureTempDir() {
    if (!fs.existsSync(this.tempDir)) {
      fs.mkdirSync(this.tempDir, { recursive: true });
    }
  }

  // ============================================================
  // Check if ADB is installed
  // ============================================================
  checkAdbInstalled() {
    try {
      execSync(`${this.adbPath} version`, { encoding: 'utf8' });
      return true;
    } catch (error) {
      throw new Error('ADB not installed. Install: apt install android-tools-adb');
    }
  }

  // ============================================================
  // List connected devices
  // ============================================================
  listDevices() {
    try {
      const output = execSync(`${this.adbPath} devices -l`, { 
        encoding: 'utf8',
        stdio: ['pipe', 'pipe', 'pipe'],
      });

      const lines = output.trim().split('\n').slice(1); // Skip header
      const devices = [];

      lines.forEach(line => {
        if (line.trim()) {
          const [deviceIp, status, ...rest] = line.split(/\s+/);
          if (deviceIp && status) {
            devices.push({
              id: deviceIp,
              status: status,
              info: rest.join(' '),
            });
          }
        }
      });

      return devices;
    } catch (error) {
      throw new Error(`Failed to list devices: ${error.message}`);
    }
  }

  // ============================================================
  // Connect to device
  // ============================================================
  connectDevice(deviceIp) {
    try {
      const output = execSync(`${this.adbPath} connect ${deviceIp}`, { 
        encoding: 'utf8',
        stdio: ['pipe', 'pipe', 'pipe'],
      });

      this.connectedDevice = deviceIp;
      return { 
        success: true, 
        device: deviceIp, 
        message: output.trim() 
      };
    } catch (error) {
      throw new Error(`Failed to connect to ${deviceIp}: ${error.message}`);
    }
  }

  // ============================================================
  // Get device properties (model, SDK version, etc.)
  // ============================================================
  getDeviceInfo(deviceIp = this.connectedDevice) {
    if (!deviceIp) throw new Error('No device connected');

    try {
      const model = execSync(`${this.adbPath} -s ${deviceIp} shell getprop ro.product.model`, { 
        encoding: 'utf8' 
      }).trim();

      const sdk = execSync(`${this.adbPath} -s ${deviceIp} shell getprop ro.build.version.sdk`, { 
        encoding: 'utf8' 
      }).trim();

      const android = execSync(`${this.adbPath} -s ${deviceIp} shell getprop ro.build.version.release`, { 
        encoding: 'utf8' 
      }).trim();

      const buildId = execSync(`${this.adbPath} -s ${deviceIp} shell getprop ro.build.id`, { 
        encoding: 'utf8' 
      }).trim();

      return {
        model,
        sdk,
        androidVersion: android,
        buildId,
        deviceIp,
      };
    } catch (error) {
      throw new Error(`Failed to get device info: ${error.message}`);
    }
  }

  // ============================================================
  // List all installed packages
  // ============================================================
  listInstalledPackages(deviceIp = this.connectedDevice) {
    if (!deviceIp) throw new Error('No device connected');

    try {
      const output = execSync(`${this.adbPath} -s ${deviceIp} shell pm list packages`, { 
        encoding: 'utf8',
        maxBuffer: 10 * 1024 * 1024, // 10MB buffer for large output
      });

      const packages = output
        .trim()
        .split('\n')
        .filter(line => line.startsWith('package:'))
        .map(line => line.replace('package:', '').trim());

      return packages;
    } catch (error) {
      throw new Error(`Failed to list packages: ${error.message}`);
    }
  }

  // ============================================================
  // Get app permissions
  // ============================================================
  getAppPermissions(packageName, deviceIp = this.connectedDevice) {
    if (!deviceIp) throw new Error('No device connected');

    try {
      const output = execSync(`${this.adbPath} -s ${deviceIp} shell dumpsys package ${packageName}`, { 
        encoding: 'utf8',
        maxBuffer: 5 * 1024 * 1024,
      });

      const permissionsMatch = output.match(/granted permissions:[\s\S]*?requested permissions:/);
      const permissions = [];

      if (permissionsMatch) {
        const permLines = permissionsMatch[0].split('\n');
        permLines.forEach(line => {
          const perm = line.match(/android\.permission\.\w+/);
          if (perm) permissions.push(perm[0]);
        });
      }

      return permissions;
    } catch (error) {
      return []; // Return empty if package not found
    }
  }

  // ============================================================
  // Get app installation path and APK location
  // ============================================================
  getAppPath(packageName, deviceIp = this.connectedDevice) {
    if (!deviceIp) throw new Error('No device connected');

    try {
      const output = execSync(`${this.adbPath} -s ${deviceIp} shell pm path ${packageName}`, { 
        encoding: 'utf8' 
      }).trim();

      // Output format: package:/path/to/app.apk
      const match = output.match(/package:(.+)/);
      return match ? match[1] : null;
    } catch (error) {
      return null;
    }
  }

  // ============================================================
  // Pull APK file to forensics directory
  // ============================================================
  pullAPK(packageName, deviceIp = this.connectedDevice) {
    if (!deviceIp) throw new Error('No device connected');

    try {
      const apkPath = this.getAppPath(packageName, deviceIp);
      if (!apkPath) throw new Error(`APK path not found for ${packageName}`);

      const localPath = path.join(this.tempDir, `${packageName}.apk`);

      execSync(`${this.adbPath} -s ${deviceIp} pull ${apkPath} ${localPath}`, {
        encoding: 'utf8',
        stdio: ['pipe', 'pipe', 'pipe'],
      });

      return { 
        success: true, 
        packageName, 
        localPath,
        size: fs.statSync(localPath).size,
      };
    } catch (error) {
      throw new Error(`Failed to pull APK: ${error.message}`);
    }
  }

  // ============================================================
  // Extract APK metadata (AndroidManifest parsing)
  // ============================================================
  extractAPKMetadata(apkPath) {
    try {
      // Verify APK exists
      if (!fs.existsSync(apkPath)) {
        throw new Error(`APK not found: ${apkPath}`);
      }

      // Extract AndroidManifest.xml from APK (ZIP format)
      const unzipCmd = `unzip -p ${apkPath} AndroidManifest.xml 2>/dev/null || echo ""`;
      const manifest = execSync(unzipCmd, { encoding: 'utf8' });

      if (!manifest) {
        return { error: 'Could not extract manifest' };
      }

      // Parse permissions (basic regex extraction)
      const permRegex = /permission["\s]*android:name\s*=\s*"([^"]+)"/g;
      const permissions = [];
      let match;

      while ((match = permRegex.exec(manifest)) !== null) {
        permissions.push(match[1]);
      }

      return {
        hasManifest: true,
        permissions,
        manifestSize: manifest.length,
      };
    } catch (error) {
      console.error(`Metadata extraction error: ${error.message}`);
      return { error: error.message };
    }
  }

  // ============================================================
  // Get app file size
  // ============================================================
  getAPKSize(packageName, deviceIp = this.connectedDevice) {
    if (!deviceIp) throw new Error('No device connected');

    try {
      const apkPath = this.getAppPath(packageName, deviceIp);
      if (!apkPath) return null;

      const output = execSync(`${this.adbPath} -s ${deviceIp} shell ls -la ${apkPath}`, { 
        encoding: 'utf8' 
      }).trim();

      const parts = output.split(/\s+/);
      return parts[4] ? parseInt(parts[4]) : null;
    } catch (error) {
      return null;
    }
  }

  // ============================================================
  // Get app install time
  // ============================================================
  getAppInstallTime(packageName, deviceIp = this.connectedDevice) {
    if (!deviceIp) throw new Error('No device connected');

    try {
      const output = execSync(`${this.adbPath} -s ${deviceIp} shell stat ${this.getAppPath(packageName, deviceIp)}`, { 
        encoding: 'utf8' 
      }).trim();

      // Extract modification time
      const match = output.match(/Modify: (.+)/);
      return match ? match[1] : null;
    } catch (error) {
      return null;
    }
  }

  // ============================================================
  // Create full device image (backup of all data)
  // ============================================================
  createDeviceBackup(outputDir, deviceIp = this.connectedDevice) {
    if (!deviceIp) throw new Error('No device connected');

    try {
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const backupName = `android-backup-${deviceIp}-${timestamp}.ab`;
      const backupPath = path.join(outputDir, backupName);

      console.log(`Creating backup: ${backupPath}`);
      
      // Android backup command (requires confirmation on device)
      execSync(`${this.adbPath} -s ${deviceIp} backup -all -f ${backupPath}`, {
        encoding: 'utf8',
        stdio: 'inherit', // Show output to user
      });

      return {
        success: true,
        backupPath,
        size: fs.statSync(backupPath).size,
      };
    } catch (error) {
      throw new Error(`Backup failed: ${error.message}`);
    }
  }

  // ============================================================
  // Clean up temp directory
  // ============================================================
  cleanup() {
    try {
      if (fs.existsSync(this.tempDir)) {
        const files = fs.readdirSync(this.tempDir);
        files.forEach(file => {
          fs.unlinkSync(path.join(this.tempDir, file));
        });
      }
    } catch (error) {
      console.error(`Cleanup error: ${error.message}`);
    }
  }
}

module.exports = new ADBService();