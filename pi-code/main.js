const { app, BrowserWindow } = require('electron');
const path = require('path');

// Disable GPU hardware acceleration on Pi (use software rendering)
app.disableHardwareAcceleration();
app.commandLine.appendSwitch('disable-gpu');
app.commandLine.appendSwitch('disable-gpu-compositing');

// Start the contact server for QR code add-contact feature
try {
  require('./server.js');
  console.log('Contact server started');
} catch (err) {
  console.error('Failed to start contact server:', err.message);
}

function createWindow() {
  // Detect if running on the actual Pi touchscreen or via HDMI/VNC
  const isProduction = process.argv.includes('--kiosk');

  const winOptions = {
    backgroundColor: '#FDFAF5',
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
      enableRemoteModule: true
    }
  };

  if (isProduction) {
    // Production: fullscreen kiosk on the 10.1" touchscreen
    winOptions.fullscreen = true;
    winOptions.kiosk = true;
  } else {
    // Development: fixed 600x1024 portrait window (matches touchscreen ratio)
    winOptions.width = 600;
    winOptions.height = 1024;
    winOptions.resizable = false;
    winOptions.useContentSize = true;
  }

  const win = new BrowserWindow(winOptions);

  win.loadFile('index.html');
  win.setMenuBarVisibility(false);

  // Log renderer console messages and errors to stdout
  win.webContents.on('console-message', (event, level, message, line, sourceId) => {
    const levels = ['LOG', 'WARN', 'ERROR'];
    console.log(`[RENDERER ${levels[level] || level}] ${message} (line ${line})`);
  });

  // Force window to front and focus (kiosk: always on top)
  win.once('ready-to-show', () => {
    win.show();
    win.focus();
    if (isProduction) {
      win.setAlwaysOnTop(true, 'screen-saver');
    }
  });

  // Re-focus on any click/touch that might go to root window
  win.on('blur', () => {
    if (isProduction) {
      setTimeout(() => { win.focus(); win.setAlwaysOnTop(true, 'screen-saver'); }, 100);
    }
  });

  // Expose window for screen capture (used by server.js for HQ remote viewing)
  global.kenWindow = win;

  console.log('The Ken window loaded');
}

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
  // On macOS, keep app running even when windows closed
  // On Linux/Pi, quit when windows closed
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});
