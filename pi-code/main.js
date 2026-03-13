const { app, BrowserWindow } = require('electron');
const path = require('path');

function createWindow() {
  const win = new BrowserWindow({
    fullscreen: true,
    kiosk: true,
    backgroundColor: '#FDFAF5',
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
      enableRemoteModule: true
    }
  });

  win.loadFile('index.html');
  win.setMenuBarVisibility(false);

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
