console.log("🚀 Starting server...");
console.log("Tweets to send:");

const fs = require("fs");
const express = require("express");
const path = require("path");
const axios = require("axios");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
require("dotenv").config();
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

// Make our server
const app = express();
app.set('trust proxy', 1);
app.use(express.json());

// Middleware to verify token
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1]; // Expect "Bearer <token>"
    if (!token) return res.status(401).json({ error: "Access denied. Please sign up or log in." });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded; // Attach user info to request
        next();
    } catch (error) {
        res.status(403).json({ error: "Invalid token. Please log in again." });
    }
};

// Get the secret key for OpenAI
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;

if (!OPENAI_API_KEY) {
    console.error("❌ No OPENAI_API_KEY! Add it to your .env file like OPENAI_API_KEY=your-key-here");
    process.exit(1);
}

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/tweetspark')
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    marketingOpt: { type: Boolean, default: false }
});
const User = mongoose.model('User', userSchema);

// Serve static files
const projectDir = path.join(__dirname, 'public');
app.use(express.static(projectDir));

app.get("/", (req, res) => {
    try {
        res.sendFile(path.join(projectDir, "index.html"));
        console.log(`Serving welcome page at / from ${path.join(projectDir, "index.html")}`);
    } catch (err) {
        console.error(`Error serving index.html: ${err.message}`);
        res.status(404).send("Welcome page not found.");
    }
});

app.get("/tweet_generator.html", (req, res) => {
    try {
        res.sendFile(path.join(projectDir, "tweet_generator.html"));
        console.log(`Serving tweet generator at /tweet_generator.html from ${path.join(projectDir, "tweet_generator.html")}`);
    } catch (err) {
        console.error(`Error serving tweet_generator.html: ${err.message}`);
        res.status(404).send("Tweet generator page not found.");
    }
});

app.get("/login.html", (req, res) => {
    try {
        res.sendFile(path.join(projectDir, "login.html"));
        console.log(`Serving login page at /login.html from ${path.join(projectDir, "login.html")}`);
    } catch (err) {
        console.error(`Error serving login.html: ${err.message}`);
        res.status(404).send("Login page not found.");
    }
});

// CORS configuration
app.use(cors({
    origin: [
        'http://localhost:3003',
        'http://127.0.0.1:3003',
        'https://*.app.github.dev',
        'https://adaistra-k8kn.onrender.com' // Add Render frontend origin
    ],
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
    optionsSuccessStatus: 208
}));

app.options('*', cors());

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: "Too many requests! Please wait and try again later.",
});
app.use(limiter);

// Log requests
app.use((req, res, next) => {
    console.log(`🔍 [${new Date().toISOString()}] ${req.method} ${req.url} from ${req.ip} (Origin: ${req.get('origin') || 'unknown'}, Host: ${req.get('host') || 'unknown'}, User-Agent: ${req.get('user-agent') || 'unknown'}, Referer: ${req.get('referer') || 'unknown'})`);
    next();
});

// Generate tweets
app.post("/generate-tweets", authenticateToken, async (req, res) => {
    console.log("✅ Someone wants tweets! Raw headers:", req.headers);

    // Log the raw request body to debug parsing
    console.log("Raw request body:", JSON.stringify(req.body, null, 2));

    const rawBody = req.body;
    const { mode, topic, tone, sampleTweet, customPrompt, tweetLength } = rawBody;
    const userEmail = req.user.email;

    console.log(`Received request from user: ${userEmail}`, "Destructured:", { mode, topic, tone, sampleTweet, customPrompt, tweetLength }, "Type of tweetLength before parsing:", typeof tweetLength);

    if (!topic || topic.trim().length === 0) {
        console.log("❌ No topic provided! Topic is required.");
        return res.status(400).json({ error: "Please provide a topic (Enter any topic you want)." });
    }

    if (sampleTweet && sampleTweet.length > 280) {
        return res.status(400).json({ error: "Tweet sample must be 280 characters or fewer." });
    }

    let requestedLength = 10; // Default to 10 for Tweet Mode
    console.log("Initial mode value:", mode, "Type of mode:", typeof mode, "Trimmed mode:", mode ? mode.trim() : 'undefined');
    if (mode && typeof mode === 'string' && mode.trim().toLowerCase() === 'thread') {
        console.log("Mode is 'thread', proceeding with tweetLength validation");
        if (tweetLength === undefined || tweetLength === null) {
            console.error("❌ tweetLength is undefined or null:", tweetLength);
            return res.status(400).json({ error: "Thread length is required and must be a valid number." });
        }
        requestedLength = Number(tweetLength);
        console.log("Parsed tweetLength:", requestedLength, "Type after parsing:", typeof requestedLength, "Raw value:", JSON.stringify(tweetLength));
        if (isNaN(requestedLength)) {
            console.error("❌ tweetLength is NaN:", tweetLength, "Raw value:", JSON.stringify(tweetLength));
            return res.status(400).json({ error: "Thread length must be a valid number." });
        }
        if (requestedLength < 3 || requestedLength > 10) {
            console.error("❌ Invalid thread length:", requestedLength, "Raw value:", JSON.stringify(tweetLength));
            return res.status(400).json({ error: "Thread length must be a number between 3 and 10 tweets." });
        }
        console.log("Validated thread length:", requestedLength);
    } else {
        console.log("Mode is not 'thread' or invalid, using default length:", requestedLength, "Mode received:", JSON.stringify(mode));
    }

    // Tone instructions
    let toneInstructions = "";
    if (tone) {
        switch (tone.toLowerCase()) {
            case "impactful":
                toneInstructions = "Write a bold, impactful tweet under 500 chars, exposing a harsh reality or making an uncomfortable statement. Mimic the provocative, direct tone of: 'We all knew Zelenskyy is a dictator yet some leaders still defend him.' or 'EU leaders feast while men die in trenches—‘How many sons lost?’'. Keep it raw, gripping, and shareable, no quotes unless in examples, no hashtags, no emojis, ! or ? only if natural.";
                break;
            case "violent":
                toneInstructions = "Create 10 intense, confrontational tweets with no emojis at all !, each under 500 chars, vivid and aggressive like 'England is invaded by millions of Muslims and he thinks about fighting Russia. Real retard.' or 'People who want to replace this with mosques and burkas are legitimately insane. Keep Ireland Irish.' Be really extreme, direct language, no hashtags, no emojis, no emotes just words, ! or ? only in quotes, numbered (e.g., '1. Text').";
                break;
            case "neutral":
                toneInstructions = "Generate a factual, clear tweet like 'Wanting peace isn't being pro-Russian', objective, under 500 chars, no emojis just words, no hashtags, ! or ? only in quotes.";
                break;
            default:
                toneInstructions = "Produce a bold, critical tweet prioritizing the prompt’s intent, under 280 chars, like ‘Elon stumbles—‘Risk backfires!’’, quote optional, no hashtags, ! or ? only in quotes.";
        }
    } else {
        toneInstructions = "Default to a striking, engaging tweet under 500 chars, like ‘Elon’s gamble—‘Win big or bust!’’, prioritizing prompt intent, quote optional, no hashtags, no emojis, ! or ? only in quotes.";
    }

    const url = "https://api.openai.com/v1/chat/completions";
    const headers = {
        Authorization: `Bearer ${OPENAI_API_KEY}`,
        "Content-Type": "application/json",
    };

    let promptContent;
    if (mode && typeof mode === 'string' && mode.trim().toLowerCase() === 'tweet') {
        promptContent = `Topic: ${topic}\nGenerate 10 viral, engaging tweets under 500 chars, focusing on '${customPrompt || topic}', with a gripping hook and quote if specified, no hashtags, ! or ? only in quotes.`;
    } else {
        promptContent = `Topic: ${topic}\nGenerate ${requestedLength} viral, cohesive thread tweets (3-10), each under 280 chars (or 140 for 'impactful'), focusing on '${customPrompt || topic}', building a gripping narrative like @naval’s threads, with quotes in 2-3 tweets, numbered (e.g., '1. Text'), no hashtags, ! or ? only in quotes.`;
    }

    if (customPrompt && customPrompt.trim().length > 0) {
        promptContent += `\nCustom Prompt: ${customPrompt}`;
    }

    let additionalInstructions = (mode && typeof mode === 'string' && mode.trim().toLowerCase() === 'thread') 
        ? `Ensure a tight, chronological flow like @naval’s threads, each tweet hooking to the next, numbered (e.g., '1. Text'), no extra text beyond tweets.`
        : "";

    const data = {
        model: "gpt-3.5-turbo-0125",
        messages: [
            { 
                role: "system", 
                content: `You are a viral X post generator, crafting concise, engaging tweets under 1000 chars as a passionate user. No hashtags. No emojis. Mimic sample tweet’s style if given, else use topic, tone, and prompt for unique, shareable posts. Avoid dates—use 'recent'. Strictly follow: ${toneInstructions}. 'Impactful' under 500 chars, others under 500. Tweet Mode: 10 tweets. Threads Mode: ${requestedLength} tweets, cohesive and numbered (e.g., '1. Text'). ${additionalInstructions} Return only ${requestedLength} tweets, each on a new line, starting with number, period, space (e.g., '1. Text'), no extra text.` 
            },
            { 
                role: "user", 
                content: `${promptContent}${sampleTweet ? `\nTweet Sample: ${sampleTweet}` : ''}` 
            }
        ],
        max_tokens: 4096,
        temperature: 1.0,
    };

    try {
        console.log("🔍 Asking OpenAI for tweets with requested length:", requestedLength, "Prompt:", promptContent);
        const response = await axios.post(url, data, { headers, timeout: 360000 });
        console.log("✅ Got tweets from OpenAI - Raw Response:", JSON.stringify(response.data, null, 2));

        let tweets = [];
        if (response.data.choices && response.data.choices[0] && response.data.choices[0].message && response.data.choices[0].message.content) {
            console.log("Raw content from OpenAI:", response.data.choices[0].message.content);
            tweets = response.data.choices[0].message.content
                .split('\n')
                .map(line => line.trim())
                .filter(line => line.match(/^\d+\.\s/) || ((mode && typeof mode === 'string' && mode.trim().toLowerCase() === 'tweet') && line.length > 0))
                .map(line => line.replace(/^\d+\.\s/, '').trim())
                .filter(tweet => tweet.length <= 500 && !tweet.includes('#'));
        }

        console.log("Processed tweets before sending:", tweets);

        if (tweets.length === 0) {
            console.warn("⚠️ No valid tweets generated, using fallback.");
            tweets = (mode && typeof mode === 'string' && mode.trim().toLowerCase() === 'tweet') 
                ? ["No tweet generated—try again!"] 
                : Array(requestedLength).fill("Thread part failed—retry!");
        } else if (tweets.length < requestedLength) {
            console.warn(`⚠️ Generated ${tweets.length} tweets, padding to ${requestedLength}.`);
            while (tweets.length < requestedLength) {
                tweets.push("Continued—more to come!");
            }
        }

        const responseContent = tweets.join('\n');
        console.log("Final JSON response content:", responseContent);
        res.json({ choices: [{ message: { content: responseContent } }] });
    } catch (error) {
        console.error("❌ Error with OpenAI - Full Error:", {
            message: error.message,
            code: error.code,
            response: error.response ? error.response.data : 'No response data',
            stack: error.stack
        });
        if (error.code === 'ECONNABORTED') {
            console.error("❌ OpenAI took too long!");
            return res.status(504).json({ error: "Sorry, it’s taking too long—try again later!" });
        }
        res.status(500).json({ error: "Something broke—check server logs or OpenAI API key!" });
    }
});

// Health check
app.get("/health", (req, res) => {
    res.json({ message: "🚀 TweetSpark is alive!", status: "✅ Online" });
});

// Login endpoint
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    console.log(`🔍 Login attempt for ${email}`);
    try {
        const user = await User.findOne({ email });
        if (!user || !await bcrypt.compare(password, user.password)) 
            return res.status(401).json({ error: 'Invalid credentials' });
        const token = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
        console.log(`✅ Login successful for ${email}`);
        res.json({ token });
    } catch (error) {
        console.error(`❌ Login error: ${error.message}`);
        res.status(500).json({ error: 'Server error' });
    }
});

// Signup endpoint
app.post('/signup', async (req, res) => {
    const { name, email, password, marketingOpt } = req.body;
    console.log(`🔍 Signup attempt for ${email}, marketingOpt: ${marketingOpt}`);
    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(400).json({ error: 'Email already exists' });
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ name, email, password: hashedPassword, marketingOpt });
        await newUser.save();
        const token = jwt.sign({ id: newUser._id, email: newUser.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
        console.log(`✅ Signup successful for ${email}`);

        const logEntry = `${new Date().toISOString()} - ${email}\n`;
        const localFilePath = path.join(__dirname, 'users.txt');
        console.log(`Attempting to write to ${localFilePath}`);
        try {
            if (!fs.existsSync(localFilePath)) {
                fs.writeFileSync(localFilePath, '', { encoding: 'utf8', mode: 0o666 });
                console.log(`✅ Created ${localFilePath}`);
            }
            fs.appendFileSync(localFilePath, logEntry, { encoding: 'utf8' });
            console.log(`✅ Successfully logged email to ${localFilePath}: ${email}`);
        } catch (localErr) {
            console.error(`❌ Failed to write to ${localFilePath}: ${localErr.message}`);
            console.log(`🔧 Fallback log: ${logEntry}`);
        }

        res.json({ token });
    } catch (error) {
        console.error(`❌ Signup error: ${error.message}`);
        res.status(500).json({ error: 'Server error' });
    }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', (err) => {
    if (err) {
        console.error(`❌ Failed to start server on port ${PORT}:`, err);
    } else {
        console.log(`✅ Server is on at http://0.0.0.0:${PORT} (Render may use a different port)`);
    }
});
