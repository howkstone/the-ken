const { app, BrowserWindow } = require('electron');
const path = require('path');

// Disable GPU acceleration on Pi (prevents crash)
app.disableHardwareAcceleration();
app.commandLine.appendSwitch('disable-gpu');
app.commandLine.appendSwitch('disable-software-rasterizer');

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

  // Expose window for screen capture (used by server.js for HQ remote viewing)
  global.kenWindow = win;

  // Open DevTools in development (comment out in production)
  // win.webContents.openDevTools();

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
