const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const path = require('path');
const mongoose = require('mongoose');

const app = express();
const server = http.createServer(app);

app.use(cors());
app.use(express.json());
app.use(express.static('public')); // Serves the web dashboard

const io = new Server(server, { cors: { origin: "*" } });

// --- MONGODB ATLAS CLOUD CONNECTION ---
const ATLAS_URI = "mongodb+srv://deepakdesignservice_db_user:sbxaKM7S76opDWQj@cluster0.5rijrxo.mongodb.net/antivirus_db?retryWrites=true&w=majority&appName=Cluster0";

mongoose.connect(ATLAS_URI)
    .then(() => console.log('🛡️ Cloud Threat Database Connected to MongoDB Atlas!'))
    .catch(err => console.error('❌ MongoDB Connection Error:', err));

// --- SCHEMAS ---
// 1. Historic Threat Logs
const ThreatLog = mongoose.model('ThreatLog', new mongoose.Schema({
    agentId: String,
    hostname: String,
    fileName: String,
    fileHash: String,
    actionTaken: String,
    timestamp: String
}));

// 2. Dynamic Malicious Hashes (NEW!)
const MaliciousHash = mongoose.model('MaliciousHash', new mongoose.Schema({
    hash: { type: String, unique: true, required: true },
    description: String,
    createdAt: { type: String, default: () => new Date().toLocaleTimeString() }
}));

// Active Agents Tracking (RAM)
let connectedAgents = new Map();

// --- API ENDPOINTS FOR CLIENT AGENT ---

// 1. Agent Registration / Heartbeat
app.post(['/api/register', '/register'], (req, res) => {
    const { agentId, os, hostname } = req.body;
    connectedAgents.set(agentId, {
        os: os || "Windows",
        hostname: hostname || "Unknown Host",
        lastCheckIn: new Date().toLocaleTimeString()
    });
    io.emit('agent_update', Array.from(connectedAgents.entries()));
    res.json({ status: "registered", interval: 5000 });
});

// 2. Scan Endpoint / Dynamic Verdict Engine
app.post(['/api/scan', '/scan'], async (req, res) => {
    const { agentId, hostname, file_name, hash } = req.body;
    console.log(`[Scan Request] Agent: ${agentId} | File: ${file_name} | Hash: ${hash}`);

    try {
        // DYNAMIC CHECK: Look up the hash inside MongoDB instead of a hardcoded array!
        const isMalicious = await MaliciousHash.findOne({ hash: hash.toLowerCase().trim() });
        let verdict = "safe";

        if (isMalicious) {
            verdict = "malicious";
            const currentTime = new Date().toLocaleTimeString();
            
            const newLog = new ThreatLog({
                agentId: agentId,
                hostname: hostname || "Unknown",
                fileName: file_name,
                fileHash: hash,
                actionTaken: "Quarantined",
                timestamp: currentTime
            });
            await newLog.save();
            
            io.emit('security_alert', {
                agentId,
                file_name,
                hash,
                timestamp: currentTime,
                action: "Quarantined"
            });
        }
        res.json({ status: verdict });
    } catch (err) {
        console.error("❌ Scan engine database error:", err);
        res.json({ status: "safe" }); // Fallback safe on DB failure
    }
});

// --- MANAGEMENT ENDPOINTS FOR THE DASHBOARD UI ---

// Get all historical threat logs
app.get('/api/logs', async (req, res) => {
    try {
        const historicalLogs = await ThreatLog.find().sort({ _id: -1 }).limit(50);
        res.json(historicalLogs);
    } catch (err) {
        res.status(500).json({ error: "Failed to fetch logs" });
    }
});

// Get all dynamic threat hashes (NEW!)
app.get('/api/hashes', async (req, res) => {
    try {
        const hashes = await MaliciousHash.find().sort({ _id: -1 });
        res.json(hashes);
    } catch (err) {
        res.status(500).json({ error: "Failed to fetch hashes" });
    }
});

// Add a new signature hash to MongoDB (NEW!)
app.post('/api/hashes', async (req, res) => {
    const { hash, description } = req.body;
    if (!hash) return res.status(400).json({ error: "Hash is required" });

    try {
        const newSignature = new MaliciousHash({
            hash: hash.toLowerCase().trim(),
            description: description || "Manual Admin Blocklist entry"
        });
        await newSignature.save();
        
        // Push full updated list via sockets so UI updates automatically
        const allHashes = await MaliciousHash.find().sort({ _id: -1 });
        io.emit('hash_list_update', allHashes);

        res.json({ success: true, message: "Hash registered successfully into cloud intelligence." });
    } catch (err) {
        res.status(400).json({ error: "Hash already exists or format is invalid" });
    }
});

// --- SOCKET CONFIGURATION ---
io.on('connection', async (socket) => {
    console.log('Dashboard user connected');
    socket.emit('agent_update', Array.from(connectedAgents.entries()));
    
    // Send existing hashes to the dashboard when it opens
    try {
        const initialHashes = await MaliciousHash.find().sort({ _id: -1 });
        socket.emit('hash_list_update', initialHashes);
    } catch (e) { console.error(e); }
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`🚀 Console running on port ${PORT}`));