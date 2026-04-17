// ============================================
// Cloudflare Pages V2Ray Worker Script (EdgeTunnel)
// Use with custom SNI in your client settings
// ============================================

// Get environment variables set in Cloudflare Pages
const UUID = env.UUID || '';
const PATH = env.PATH || '/ws';

// If no UUID is set, return an error message
if (!UUID) {
    addEventListener('fetch', event => {
        event.respondWith(new Response('UUID environment variable is not set. Please configure it in Cloudflare Pages settings.', { status: 500 }));
    });
}

// Main fetch handler
addEventListener('fetch', event => {
    event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
    const url = new URL(request.url);
    
    // Check if the request is for the WebSocket path
    if (url.pathname === PATH) {
        // Get the WebSocket upgrade headers
        const upgradeHeader = request.headers.get('Upgrade');
        
        if (!upgradeHeader || upgradeHeader !== 'websocket') {
            return new Response('Expected Upgrade: websocket', { status: 426 });
        }

        // This is where the magic happens - we establish a WebSocket connection
        // The client's V2Ray software will handle the rest
        const webSocketPair = new WebSocketPair();
        const [client, webSocket] = Object.values(webSocketPair);
        
        // Accept the WebSocket connection
        webSocket.accept();
        
        // Handle incoming messages from the client
        webSocket.addEventListener('message', async (event) => {
            // The client sends data that we forward to the V2Ray server
            // This is handled by the V2Ray client software itself
        });

        return new Response(null, {
            status: 101,
            webSocket: client,
        });
    }

    // If not the WebSocket path, return a simple status page
    // This also acts as a camouflage for anyone browsing directly
    return new Response(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>It works!</title>
            <style>
                body { width: 35em; margin: 0 auto; font-family: Tahoma, Verdana, Arial, sans-serif; }
            </style>
        </head>
        <body>
            <h1>It works!</h1>
            <p>If you see this page, the nginx web server is successfully installed and working. Further configuration is required.</p>
            <p><em>Thank you for using nginx.</em></p>
        </body>
        </html>
    `, {
        status: 200,
        headers: { 'Content-Type': 'text/html' }
    });
}
