const fs = require('fs');

module.exports = {
  log: (msg) => console.log(`[LOG] ${msg}`),
  error: (msg) => console.error(`[ERROR] ${msg}`),
  info: (msg) => console.log(`[INFO] ${msg}`)
};