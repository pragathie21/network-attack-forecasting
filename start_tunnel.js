const localtunnel = require('localtunnel');
const fs = require('fs');

(async () => {
  try {
    console.log('Opening localtunnel to port 8000...');
    const tunnel = await localtunnel({ port: 8000 });
    console.log('PUBLIC_URL=' + tunnel.url);
    fs.writeFileSync('public_url.txt', tunnel.url, 'utf8');

    tunnel.on('close', () => {
      console.log('Tunnel closed');
    });

    tunnel.on('error', (err) => {
      console.error('Tunnel error:', err);
    });
  } catch (err) {
    console.error('Failed to create tunnel:', err);
  }
})();
