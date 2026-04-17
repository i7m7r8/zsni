// ============================================================================
// EdgeTunnel - Feature-Rich V2Ray Worker Script
// English Translation of cmliu/edgetunnel
// Supports: VLESS, Trojan, Subscription, Admin Panel, ProxyIP, SOCKS5, etc.
// ============================================================================

const VERSION = '2026-04-16 04:47:24';

import { connect } from 'cloudflare:sockets';

// Global Configuration Variables
let configJSON;
let proxyIP = '';
let enableSOCKS5Proxy = null;
let enableSOCKS5GlobalProxy = false;
let mySOCKS5Account = '';
let parsedSocks5Address = {};

let cachedProxyIP;
let cachedProxyIPList;
let cachedProxyIPIndex = 0;
let enableProxyFallback = true;
let debugLogging = false;

let SOCKS5Whitelist = [
    '*tapecontent.net',
    '*cloudatacdn.com',
    '*loadshare.org',
    '*cdn-centaurus.com',
    'scholar.google.com'
];

const staticPagesURL = 'https://edt-pages.github.io';

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Generate a random integer between min and max (inclusive)
 */
function randomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

/**
 * Generate a UUID v4
 */
function generateUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        const r = Math.random() * 16 | 0;
        const v = c === 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}

/**
 * Base64 encode string (URL safe)
 */
function base64Encode(str) {
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Base64 decode string (URL safe)
 */
function base64Decode(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    return atob(str);
}

/**
 * Get environment variable or return default
 */
function getEnv(key, defaultValue = '') {
    return (typeof env !== 'undefined' && env[key]) ? env[key] : defaultValue;
}

/**
 * Parse SOCKS5 address string (user:pass@host:port)
 */
function parseSOCKS5Address(address) {
    const match = address.match(/^(?:([^:@]+)(?::([^@]+))?@)?([^:]+)(?::(\d+))?$/);
    if (!match) return null;
    return {
        username: match[1] || '',
        password: match[2] || '',
        hostname: match[3] || '',
        port: parseInt(match[4] || '1080', 10)
    };
}

/**
 * Check if hostname matches any pattern in whitelist
 */
function isHostInWhitelist(hostname, whitelist) {
    for (const pattern of whitelist) {
        const regexPattern = pattern.replace(/\./g, '\\.').replace(/\*/g, '.*');
        const regex = new RegExp(`^${regexPattern}$`, 'i');
        if (regex.test(hostname)) return true;
    }
    return false;
}

/**
 * Fetch latest proxy IP list from source
 */
async function fetchProxyIPList() {
    const sources = [
        'https://raw.githubusercontent.com/cmliu/edgetunnel/main/proxyip.txt',
        'https://proxyip.edtunnel.workers.dev/'
    ];
    
    for (const source of sources) {
        try {
            const response = await fetch(source);
            if (response.ok) {
                const text = await response.text();
                const lines = text.split('\n').filter(line => line.trim() && !line.startsWith('#'));
                if (lines.length > 0) return lines;
            }
        } catch (e) {
            if (debugLogging) console.log(`Failed to fetch from ${source}: ${e.message}`);
        }
    }
    return [];
}

/**
 * Get next proxy IP (round-robin)
 */
function getNextProxyIP() {
    if (cachedProxyIPList && cachedProxyIPList.length > 0) {
        const ip = cachedProxyIPList[cachedProxyIPIndex % cachedProxyIPList.length];
        cachedProxyIPIndex = (cachedProxyIPIndex + 1) % cachedProxyIPList.length;
        return ip;
    }
    return proxyIP || 'cdn.cloudflare.space';
}

/**
 * Create SOCKS5 connection via Cloudflare's connect API
 */
async function socks5Connect(address, port, options = {}) {
    const socket = connect({ hostname: address, port: port });
    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();
    
    // SOCKS5 handshake
    const authMethods = options.username ? [0x02, 0x00] : [0x00];
    await writer.write(new Uint8Array([0x05, authMethods.length, ...authMethods]));
    
    const response1 = await reader.read();
    if (response1.value[0] !== 0x05 || response1.value[1] !== authMethods[0]) {
        throw new Error('SOCKS5 handshake failed');
    }
    
    // Authentication if needed
    if (options.username) {
        const authPacket = [0x01, options.username.length, ...new TextEncoder().encode(options.username)];
        if (options.password) {
            authPacket.push(options.password.length, ...new TextEncoder().encode(options.password));
        }
        await writer.write(new Uint8Array(authPacket));
        const authResponse = await reader.read();
        if (authResponse.value[0] !== 0x01 || authResponse.value[1] !== 0x00) {
            throw new Error('SOCKS5 authentication failed');
        }
    }
    
    return { socket, reader, writer };
}

// ============================================================================
// Protocol Handlers
// ============================================================================

/**
 * Handle VLESS protocol
 */
async function handleVless(request, uuid, targetAddress, targetPort) {
    const upgradeHeader = request.headers.get('Upgrade');
    if (!upgradeHeader || upgradeHeader !== 'websocket') {
        return new Response('Expected Upgrade: websocket', { status: 426 });
    }

    const webSocketPair = new WebSocketPair();
    const [client, server] = Object.values(webSocketPair);
    
    server.accept();
    
    // Connect to target
    const targetSocket = connect({
        hostname: targetAddress,
        port: targetPort || 443
    });
    
    const targetWriter = targetSocket.writable.getWriter();
    const targetReader = targetSocket.readable.getReader();
    
    // Relay data
    server.addEventListener('message', async (event) => {
        try {
            await targetWriter.write(event.data);
        } catch (e) {
            server.close();
        }
    });
    
    (async () => {
        try {
            while (true) {
                const { done, value } = await targetReader.read();
                if (done) break;
                server.send(value);
            }
        } catch (e) {
            server.close();
        }
    })();
    
    return new Response(null, {
        status: 101,
        webSocket: client
    });
}

/**
 * Handle Trojan protocol
 */
async function handleTrojan(request, password, targetAddress, targetPort) {
    const upgradeHeader = request.headers.get('Upgrade');
    if (!upgradeHeader || upgradeHeader !== 'websocket') {
        return new Response('Expected Upgrade: websocket', { status: 426 });
    }

    // Trojan handshake
    const webSocketPair = new WebSocketPair();
    const [client, server] = Object.values(webSocketPair);
    
    server.accept();
    
    // Trojan protocol header
    const trojanHeader = new Uint8Array(56 + password.length);
    trojanHeader.set(new TextEncoder().encode(password), 0);
    trojanHeader[password.length] = 0x0D;
    trojanHeader[password.length + 1] = 0x0A;
    trojanHeader[password.length + 2] = 0x01;
    
    const targetSocket = connect({
        hostname: targetAddress,
        port: targetPort || 443
    });
    
    const targetWriter = targetSocket.writable.getWriter();
    await targetWriter.write(trojanHeader);
    
    // Rest of the relay logic same as VLESS
    const targetReader = targetSocket.readable.getReader();
    
    server.addEventListener('message', async (event) => {
        try {
            await targetWriter.write(event.data);
        } catch (e) {
            server.close();
        }
    });
    
    (async () => {
        try {
            while (true) {
                const { done, value } = await targetReader.read();
                if (done) break;
                server.send(value);
            }
        } catch (e) {
            server.close();
        }
    })();
    
    return new Response(null, {
        status: 101,
        webSocket: client
    });
}

// ============================================================================
// Admin Panel & Subscription Generation
// ============================================================================

/**
 * Generate VLESS subscription link
 */
function generateVlessLink(config) {
    const { address, port, uuid, path, host, sni, type, security, flow, encryption } = config;
    const params = new URLSearchParams();
    params.set('type', type || 'ws');
    params.set('security', security || 'tls');
    params.set('path', path || '/');
    if (host) params.set('host', host);
    if (sni) params.set('sni', sni);
    if (flow) params.set('flow', flow);
    if (encryption) params.set('encryption', encryption);
    
    const vlessConfig = `${uuid}@${address}:${port}?${params.toString()}`;
    return `vless://${vlessConfig}#${encodeURIComponent(config.name || 'EdgeTunnel')}`;
}

/**
 * Generate Trojan subscription link
 */
function generateTrojanLink(config) {
    const { address, port, password, path, host, sni, type, security } = config;
    const params = new URLSearchParams();
    params.set('type', type || 'ws');
    params.set('security', security || 'tls');
    params.set('path', path || '/');
    if (host) params.set('host', host);
    if (sni) params.set('sni', sni);
    
    const trojanConfig = `${password}@${address}:${port}?${params.toString()}`;
    return `trojan://${trojanConfig}#${encodeURIComponent(config.name || 'EdgeTunnel')}`;
}

/**
 * Generate base64 encoded subscription content
 */
function generateSubscription(configs) {
    const links = configs.map(config => {
        if (config.protocol === 'vless') {
            return generateVlessLink(config);
        } else if (config.protocol === 'trojan') {
            return generateTrojanLink(config);
        }
        return '';
    }).filter(link => link);
    
    return base64Encode(links.join('\n'));
}

/**
 * Render Admin Panel HTML
 */
function renderAdminPanel(request, uuidList, proxyIPConfig) {
    const url = new URL(request.url);
    const baseURL = `${url.protocol}//${url.host}`;
    
    const html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EdgeTunnel Admin Panel</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #5a67d8 0%, #6b46c1 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .header h1 { font-size: 2.5rem; margin-bottom: 10px; }
        .header p { opacity: 0.9; }
        .content { padding: 30px; }
        .section {
            background: #f7fafc;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 24px;
            border: 1px solid #e2e8f0;
        }
        .section h2 {
            color: #2d3748;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #cbd5e0;
        }
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
        }
        .info-card {
            background: white;
            padding: 15px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .info-card h3 {
            color: #4a5568;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 8px;
        }
        .info-card .value {
            font-size: 1.2rem;
            font-weight: 600;
            color: #2d3748;
            word-break: break-all;
        }
        .subscription-box {
            background: #2d3748;
            color: white;
            padding: 15px;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            word-break: break-all;
            margin: 15px 0;
        }
        .btn {
            display: inline-block;
            background: #667eea;
            color: white;
            padding: 10px 20px;
            border-radius: 6px;
            text-decoration: none;
            font-weight: 500;
            margin-right: 10px;
            margin-bottom: 10px;
            border: none;
            cursor: pointer;
            transition: background 0.2s;
        }
        .btn:hover { background: #5a67d8; }
        .btn-secondary { background: #48bb78; }
        .btn-secondary:hover { background: #38a169; }
        .table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        .table th, .table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e2e8f0;
        }
        .table th {
            background: #edf2f7;
            color: #4a5568;
            font-weight: 600;
        }
        .status-badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
        }
        .status-active { background: #c6f6d5; color: #22543d; }
        .status-inactive { background: #fed7d7; color: #742a2a; }
        .qr-code {
            display: inline-block;
            padding: 10px;
            background: white;
            border-radius: 8px;
            margin: 10px 0;
        }
        footer {
            text-align: center;
            padding: 20px;
            color: #a0aec0;
            font-size: 0.9rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚀 EdgeTunnel Admin</h1>
            <p>Feature-Rich V2Ray Proxy Management</p>
            <p style="font-size: 0.9rem; margin-top: 10px;">Version: ${VERSION}</p>
        </div>
        
        <div class="content">
            <div class="section">
                <h2>📊 System Status</h2>
                <div class="info-grid">
                    <div class="info-card">
                        <h3>Worker URL</h3>
                        <div class="value">${baseURL}</div>
                    </div>
                    <div class="info-card">
                        <h3>Proxy IP Pool</h3>
                        <div class="value">${proxyIPConfig || 'Not configured'}</div>
                    </div>
                    <div class="info-card">
                        <h3>Active UUIDs</h3>
                        <div class="value">${uuidList.length} configured</div>
                    </div>
                    <div class="info-card">
                        <h3>Protocol Support</h3>
                        <div class="value">VLESS, Trojan, SOCKS5</div>
                    </div>
                </div>
            </div>
            
            <div class="section">
                <h2>🔗 Subscription Links</h2>
                ${uuidList.map(uuid => {
                    const subURL = `${baseURL}/${uuid}`;
                    return `
                    <div style="margin-bottom: 20px;">
                        <h3 style="color: #4a5568; margin-bottom: 10px;">UUID: ${uuid.substring(0, 8)}...</h3>
                        <div class="subscription-box">${subURL}</div>
                        <a href="${subURL}" class="btn" target="_blank">📋 Open Subscription</a>
                        <button class="btn btn-secondary" onclick="copyToClipboard('${subURL}')">📎 Copy Link</button>
                    </div>
                    `;
                }).join('')}
            </div>
            
            <div class="section">
                <h2>📱 Client Configuration Guide</h2>
                <table class="table">
                    <thead>
                        <tr>
                            <th>Setting</th>
                            <th>Value</th>
                            <th>Notes</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>Address (Server)</td>
                            <td>${url.hostname}</td>
                            <td>Your worker domain</td>
                        </tr>
                        <tr>
                            <td>Port</td>
                            <td>443</td>
                            <td>HTTPS port</td>
                        </tr>
                        <tr>
                            <td>UUID / Password</td>
                            <td>Your configured UUID</td>
                            <td>From environment variable</td>
                        </tr>
                        <tr>
                            <td>Path</td>
                            <td>/</td>
                            <td>WebSocket path</td>
                        </tr>
                        <tr>
                            <td>Transport</td>
                            <td>ws (WebSocket)</td>
                            <td>-</td>
                        </tr>
                        <tr>
                            <td>TLS / Security</td>
                            <td>tls</td>
                            <td>Enabled</td>
                        </tr>
                        <tr>
                            <td>SNI</td>
                            <td>${url.hostname}</td>
                            <td>Can customize (e.g., www.microsoft.com)</td>
                        </tr>
                        <tr>
                            <td>Host</td>
                            <td>${url.hostname}</td>
                            <td>Same as SNI</td>
                        </tr>
                    </tbody>
                </table>
            </div>
            
            <div class="section">
                <h2>🛠️ Advanced Settings</h2>
                <p style="margin-bottom: 15px;">Configure environment variables in Cloudflare Pages:</p>
                <table class="table">
                    <thead>
                        <tr>
                            <th>Variable</th>
                            <th>Description</th>
                            <th>Example</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>UUID</td>
                            <td>Primary user UUID (required)</td>
                            <td>xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx</td>
                        </tr>
                        <tr>
                            <td>UUID2, UUID3, ...</td>
                            <td>Additional UUIDs for multiple users</td>
                            <td>yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy</td>
                        </tr>
                        <tr>
                            <td>ADMIN</td>
                            <td>Admin panel access password</td>
                            <td>your_secure_password</td>
                        </tr>
                        <tr>
                            <td>PROXYIP</td>
                            <td>Custom proxy IP or domain</td>
                            <td>cdn.cloudflare.space</td>
                        </tr>
                        <tr>
                            <td>SOCKS5</td>
                            <td>SOCKS5 proxy for upstream</td>
                            <td>user:pass@host:port</td>
                        </tr>
                        <tr>
                            <td>DEBUG</td>
                            <td>Enable debug logging (true/false)</td>
                            <td>true</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
        
        <footer>
            EdgeTunnel v${VERSION} | Powered by Cloudflare Workers
        </footer>
    </div>
    
    <script>
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => {
                alert('Subscription link copied to clipboard!');
            }).catch(err => {
                prompt('Copy manually:', text);
            });
        }
    </script>
</body>
</html>`;
    
    return html;
}

// ============================================================================
// Main Request Handler
// ============================================================================

async function handleRequest(request) {
    const url = new URL(request.url);
    const pathname = url.pathname;
    const userAgent = request.headers.get('User-Agent') || '';
    
    // Load configuration from environment
    const adminPassword = getEnv('ADMIN', '');
    const primaryUUID = getEnv('UUID', '');
    const proxyIPConfig = getEnv('PROXYIP', '');
    const debugMode = getEnv('DEBUG', 'false') === 'true';
    
    debugLogging = debugMode;
    
    // Collect all UUIDs
    const uuidList = [];
    if (primaryUUID) uuidList.push(primaryUUID);
    let i = 2;
    while (getEnv(`UUID${i}`)) {
        uuidList.push(getEnv(`UUID${i}`));
        i++;
    }
    
    // Admin panel access
    if (pathname === '/admin' || pathname.startsWith('/admin/')) {
        if (adminPassword) {
            const authHeader = request.headers.get('Authorization');
            const expectedAuth = `Basic ${btoa(`admin:${adminPassword}`)}`;
            
            if (!authHeader || authHeader !== expectedAuth) {
                return new Response('Unauthorized', {
                    status: 401,
                    headers: { 'WWW-Authenticate': 'Basic realm="EdgeTunnel Admin"' }
                });
            }
        }
        
        const html = renderAdminPanel(request, uuidList, proxyIPConfig);
        return new Response(html, {
            status: 200,
            headers: { 'Content-Type': 'text/html; charset=utf-8' }
        });
    }
    
    // Subscription endpoint: /{uuid}
    const potentialUUID = pathname.substring(1);
    if (uuidList.includes(potentialUUID)) {
        const configs = [];
        
        // VLESS config
        configs.push({
            protocol: 'vless',
            address: url.hostname,
            port: 443,
            uuid: potentialUUID,
            path: '/',
            host: url.hostname,
            sni: url.hostname,
            type: 'ws',
            security: 'tls',
            encryption: 'none',
            flow: '',
            name: `EdgeTunnel-VLESS`
        });
        
        // Trojan config (using same UUID as password)
        configs.push({
            protocol: 'trojan',
            address: url.hostname,
            port: 443,
            password: potentialUUID,
            path: '/',
            host: url.hostname,
            sni: url.hostname,
            type: 'ws',
            security: 'tls',
            name: `EdgeTunnel-Trojan`
        });
        
        const subscription = generateSubscription(configs);
        return new Response(subscription, {
            status: 200,
            headers: { 'Content-Type': 'text/plain; charset=utf-8' }
        });
    }
    
    // WebSocket upgrade for proxy
    const upgradeHeader = request.headers.get('Upgrade');
    if (upgradeHeader && upgradeHeader.toLowerCase() === 'websocket') {
        // Validate UUID from first path segment or header
        let requestUUID = pathname.substring(1);
        if (!uuidList.includes(requestUUID)) {
            requestUUID = request.headers.get('X-UUID') || '';
        }
        
        if (!uuidList.includes(requestUUID)) {
            return new Response('Invalid UUID', { status: 403 });
        }
        
        // Determine target (use proxyIP if configured)
        let targetHost = url.hostname;
        let targetPort = 443;
        
        if (proxyIPConfig) {
            targetHost = proxyIPConfig.includes(':') 
                ? proxyIPConfig.split(':')[0] 
                : proxyIPConfig;
            targetPort = proxyIPConfig.includes(':') 
                ? parseInt(proxyIPConfig.split(':')[1], 10) 
                : 443;
        }
        
        // Check protocol based on headers or default to VLESS
        const protocol = request.headers.get('X-Protocol') || 'vless';
        
        if (protocol === 'trojan') {
            return handleTrojan(request, requestUUID, targetHost, targetPort);
        } else {
            return handleVless(request, requestUUID, targetHost, targetPort);
        }
    }
    
    // Default response (camouflage)
    return new Response(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>EdgeTunnel - Secure Proxy</title>
            <style>
                body { width: 35em; margin: 0 auto; font-family: Tahoma, Verdana, Arial, sans-serif; }
                h1 { color: #333; }
                p { line-height: 1.6; }
            </style>
        </head>
        <body>
            <h1>EdgeTunnel is running</h1>
            <p>This is a V2Ray proxy endpoint. Configure your client with the subscription link.</p>
            <p><small>Version: ${VERSION}</small></p>
        </body>
        </html>
    `, {
        status: 200,
        headers: { 'Content-Type': 'text/html' }
    });
}

// ============================================================================
// Cloudflare Workers Entry Point
// ============================================================================

addEventListener('fetch', event => {
    event.respondWith(handleRequest(event.request));
});
