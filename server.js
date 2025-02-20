console.log("🚀 Starting server...");
const express = require("express");
const app = express();

app.use(express.json());

app.get("/", (req, res) => {
    res.json({ message: "🚀 Server is running!", status: "✅ Online" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
