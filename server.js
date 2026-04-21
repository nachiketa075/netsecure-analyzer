const express = require('express');
const fs      = require('fs');
const path    = require('path');

const app      = express();
const PORT     = 3000;
const LOG_FILE = path.join(__dirname, 'ids_log.json');

// Serve public folder (index.html, style.css, app.js)
app.use(express.static(path.join(__dirname, 'public')));

// Parse ids_log.json
function parseLogs() {
    const packets     = [];
    const alerts      = [];
    let   summary     = {};
    const protoCounts = {};
    const ipCounts    = {};
    const timeline    = {};

    if (!fs.existsSync(LOG_FILE)) {
        return { packets, alerts, summary, protoCounts, ipCounts, timeline };
    }

    const lines = fs.readFileSync(LOG_FILE, 'utf8').split('\n');

    for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) continue;

        let obj;
        try { obj = JSON.parse(trimmed); }
        catch { continue; }

        if (obj.event === 'SUMMARY') {
            // Final summary block
            summary = obj;

        } else if (obj.level === 'ALERT') {
            // Alert from raiseAlert() — fields: severity, msg, time
            alerts.push({
                severity:  obj.severity,
                message:   obj.msg || obj.message || '',
                timestamp: obj.time || obj.timestamp || '',
            });

        } else if (obj.proto) {
            // Packet from logPacket() — fields: proto, src, dst, size, flags, time
            const src_ip   = (obj.src || '').split(':')[0];
            const src_port = parseInt((obj.src || '').split(':')[1]) || 0;
            const dst_ip   = (obj.dst || '').split(':')[0];
            const dst_port = parseInt((obj.dst || '').split(':')[1]) || 0;

            packets.push({
                protocol:    obj.proto,
                src_ip,
                src_port,
                dst_ip,
                dst_port,
                packet_size: obj.size  || 0,
                flags:       obj.flags || '',
                timestamp:   obj.time  || '',
            });

            protoCounts[obj.proto]   = (protoCounts[obj.proto]   || 0) + 1;
            ipCounts[src_ip]         = (ipCounts[src_ip]         || 0) + 1;
            const ts                 = (obj.time || '').slice(0, 16);
            timeline[ts]             = (timeline[ts]             || 0) + 1;
        }
    }

    return { packets, alerts, summary, protoCounts, ipCounts, timeline };
}

// API endpoint
app.get('/api/stats', (req, res) => {
    const { packets, alerts, summary, protoCounts, ipCounts, timeline } = parseLogs();

    const topIPs = Object.entries(ipCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .map(([ip, count]) => ({ ip, count }));

    const timelineSorted = Object.entries(timeline)
        .sort((a, b) => a[0].localeCompare(b[0]))
        .slice(-30)
        .map(([time, count]) => ({ time, count }));

    res.json({
        total_packets:  packets.length,
        total_alerts:   alerts.length,
        summary,
        protocols:      protoCounts,
        top_ips:        topIPs,
        timeline:       timelineSorted,
        recent_alerts:  alerts.slice(-20).reverse(),
        recent_packets: packets.slice(-15).reverse(),
    });
});

app.listen(PORT, () => {
    console.log(`\n✅ IDS Dashboard  →  http://localhost:${PORT}`);
    console.log(`📄 Log file       →  ${LOG_FILE}`);
    console.log(`🔴 Press Ctrl+C to stop\n`);
});