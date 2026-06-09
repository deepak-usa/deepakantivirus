const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const path = require('path');
const mongoose = require('mongoose');

const app = express();
const server = http.createServer(app);

// Enable CORS so the agent and UI can communicate across local ports
app.use(cors());
app.use(express.json());
app.use(express.static('public')); // Serves the web dashboard

// Initialize WebSockets
const io = new Server(server, {
    cors: { origin: "*" }
});

// --- MONGODB ATLAS CLOUD CONNECTION ---
const ATLAS_URI = "mongodb+srv://deepakdesignservice_db_user:sbxaKM7S76opDWQj@cluster0.5rijrxo.mongodb.net/antivirus_db?retryWrites=true&w=majority&appName=Cluster0";

mongoose.connect(ATLAS_URI)
    .then(() => console.log('🛡️ Cloud Threat Database Connected to MongoDB Atlas!'))
    .catch(err => console.error('❌ MongoDB Connection Error:', err));

// Define a Schema to log every security incident permanently
const ThreatLogSchema = new mongoose.Schema({
    agentId: String,
    hostname: String,
    fileName: String,
    fileHash: String,
    actionTaken: String,
    timestamp: String
});
const ThreatLog = mongoose.model('ThreatLog', ThreatLogSchema);

// --- STATIC MALICIOUS SIGNATURE DATABASE ---
const MALICIOUS_HASHES = [
    "5e884167ac263c947107475d128523ddb292030c50650254e2da3481b7a1d4f4", // Example hash (password)
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"  // Empty file hash
];

// Active Agents tracking memory (Keep heartbeats in RAM)
let connectedAgents = new Map();


// --- API ENDPOINTS FOR THE CLIENT AGENT ---

// 1. Agent Registration / Heartbeat (Accepts both /api/register and /register)
app.post(['/api/register', '/register'], (req, res) => {
    const { agentId, os, hostname } = req.body;
    
    connectedAgents.set(agentId, {
        os: os || "Windows",
        hostname: hostname || "Unknown Host",
        lastCheckIn: new Date().toLocaleTimeString()
    });

    // Notify the UI dashboard that an agent checked in
    io.emit('agent_update', Array.from(connectedAgents.entries()));
    
    res.json({ status: "registered", interval: 5000 });
});

// 2. Scan Endpoint / Verdict Engine (Accepts both /api/scan and /scan)
app.post(['/api/scan', '/scan'], async (req, res) => {
    const { agentId, hostname, file_name, hash } = req.body;
    console.log(`[Scan Request] Agent: ${agentId} | File: ${file_name} | Hash: ${hash}`);

    let verdict = "safe";

    // Check if the hash exists in our malicious signature database
    if (MALICIOUS_HASHES.includes(hash)) {
        verdict = "malicious";
        const currentTime = new Date().toLocaleTimeString();
        
        try {
            // Save the incident data to MongoDB Atlas permanently
            const newLog = new ThreatLog({
                agentId: agentId,
                hostname: hostname || "Unknown",
                fileName: file_name,
                fileHash: hash,
                actionTaken: "Quarantined",
                timestamp: currentTime
            });
            await newLog.save();
            console.log(`✨ Threat logged to cloud database: ${file_name}`);
        } catch (dbErr) {
            console.error("❌ Failed to log threat to MongoDB:", dbErr);
        }
        
        // Broadcast this alert to the Web Dashboard immediately
        io.emit('security_alert', {
            agentId,
            file_name,
            hash,
            timestamp: currentTime,
            action: "Quarantined"
        });
    }

    res.json({ status: verdict });
});

// 3. UI Dashboard Historic Logs Restorer
app.get('/api/logs', async (req, res) => {
    try {
        const historicalLogs = await ThreatLog.find().sort({ _id: -1 }).limit(50);
        res.json(historicalLogs);
    } catch (err) {
        res.status(500).json({ error: "Failed to fetch historical database logs" });
    }
});


// --- WEBSOCKET CONNECTION FOR DASHBOARD UI ---
io.on('connection', (socket) => {
    console.log('Dashboard user connected');
    
    // Immediately send the list of active agents to the newly opened dashboard
    socket.emit('agent_update', Array.from(connectedAgents.entries()));

    socket.on('disconnect', () => {
        console.log('Dashboard user disconnected');
    });
});

// Start Server on Port 5000
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
    console.log(`🚀 Console running on port ${PORT}`);
});