console.log("🚀 Starting server...");

const express = require("express");
const axios = require("axios");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
require("dotenv").config();

const MISTRAL_API_KEY = process.env.MISTRAL_API_KEY;

if (!MISTRAL_API_KEY) {
    console.error("❌ MISTRAL_API_KEY is not set in environment variables.");
    process.exit(1); // Exit if API key is missing
}

const app = express();
app.use(express.json());
app.use(cors({ origin: ["https://your-frontend.com"] })); // ✅ Restrict CORS to trusted domains

// Rate limiting to prevent abuse
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per window
    message: "Too many requests, please try again later.",
});

app.use(limiter);

// Logging middleware
app.use((req, res, next) => {
    console.log(`✅ Received request: ${req.method} ${req.url}`);
    next();
});

// Endpoint to generate tweets
app.post("/generate-tweets", async (req, res) => {
    console.log("✅ Received a request on /generate-tweets");

    const { topic } = req.body;
    if (!topic || typeof topic !== "string" || topic.trim().length < 2) {
        return res.status(400).json({ error: "Invalid 'topic' provided" });
    }

    const url = "https://api.mistral.ai/v1/completions";
    const headers = {
        Authorization: `Bearer ${MISTRAL_API_KEY}`,
        "Content-Type": "application/json",
    };
    const data = {
        model: "mistral-7b-instruct",
        messages: [
            { role: "system", content: "You are a helpful assistant." },
            { role: "user", content: `Write 5 tweets about ${topic}.` }
        ],
        max_tokens: 200,
    };

    try {
        const response = await axios.post(url, data, { headers, timeout: 5000 }); // ✅ Added timeout
        res.json(response.data);
    } catch (error) {
        console.error("❌ Error:", error.response ? error.response.data : error.message);
        res.status(500).json({ error: "Internal server error" });
    }
});

// Health check endpoint
app.get("/", (req, res) => {
    res.json({ message: "🚀 Server is running!", status: "✅ Online" });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`✅ Server running on http://localhost:${PORT}`);
});