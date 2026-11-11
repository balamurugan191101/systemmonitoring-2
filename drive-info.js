const fs = require('fs');

const DRIVE_TYPES = { 2: 'Removable', 3: 'Local disk', 4: 'Network', 5: 'CD/DVD' };

function parseDisks(json) {
  const map = {};
  for (const d of [].concat(JSON.parse(json || '[]'))) {
    map[`${d.DeviceID}\\`] = {
      label: d.VolumeName || '',
      fileSystem: d.FileSystem || '',
      type: DRIVE_TYPES[d.DriveType] || 'Drive',
    };
  }
  return map;
}

function readDriveInfo() {
  if (process.platform !== 'win32') return {};
  try {
    const out = require('child_process').execFileSync(
      'powershell',
      ['-NoProfile', '-Command', 'Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID,VolumeName,FileSystem,DriveType | ConvertTo-Json'],
      { encoding: 'utf8', timeout: 8000, windowsHide: true },
    );
    return parseDisks(out);
  } catch {
    return {};
  }
}

function readDrives() {
  const roots = process.platform === 'win32' ? 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.split('').map((d) => `${d}:\\`) : ['/'];
  const info = readDriveInfo();
  return roots.flatMap((root) => {
    try {
      const stat = fs.statfsSync(root);
      const total = stat.blocks * stat.bsize;
      const free = stat.bavail * stat.bsize;
      if (total <= 0) return [];
      const disk = info[root] || {};
      const letter = root.replace('\\', '');
      const label = disk.label || (disk.type === 'Removable' ? 'Removable Disk' : disk.type === 'Network' ? 'Network Drive' : 'Local Disk');
      return [{
        drive: root,
        name: process.platform === 'win32' ? `${label} (${letter})` : root,
        fileSystem: disk.fileSystem || '',
        type: disk.type || 'Drive',
        total,
        free,
        used: total - free,
      }];
    } catch {
      return [];
    }
  });
}

module.exports = { readDrives };
