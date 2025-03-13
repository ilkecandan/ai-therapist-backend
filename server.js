const express = require("express");
const cors = require("cors");
const axios = require("axios");
const NodeCache = require("node-cache");
require("dotenv").config();

const app = express();
app.use(express.json());
app.use(cors());

const cache = new NodeCache({ stdTTL: 300 }); // Cache responses for 5 minutes

app.post("/api/chat", async (req, res) => {
    try {
        const userMessage = req.body.message;
        const partDetails = req.body.partDetails ? req.body.partDetails.slice(0, 200) : ""; // Trim to 200 chars
        const cacheKey = JSON.stringify({ userMessage, partDetails });

        // Check cache before making API call
        const cachedResponse = cache.get(cacheKey);
        if (cachedResponse) {
            return res.json({ response: cachedResponse });
        }

        const apiResponse = await axios.post(
            "https://api.openai.com/v1/chat/completions",
            {
                model: process.env.USE_GPT4 ? "gpt-4o" : "gpt-3.5-turbo", // Use GPT-3.5 for speed, GPT-4o if needed
                messages: [
                    {
                        role: "system",
                        content: `You are an AI therapist guiding the user through self-exploration. Give concise answers, keep a friendly, amusing, and supportive tone. Remember users' information. They are working with this part: ${partDetails}`,
                    },
                    { role: "user", content: userMessage }
                ],
                max_tokens: 150, // Limits response length for faster output
                temperature: 0.7,
                stream: false, // Change to `false` for debugging
            },
            {
                headers: { Authorization: `Bearer ${process.env.OPENAI_API_KEY}` },
            }
        );

        const fullResponse = apiResponse.data.choices[0]?.message?.content || "No response";

        // Cache the response
        cache.set(cacheKey, fullResponse);

        res.json({ response: fullResponse });

    } catch (error) {
        console.error("OpenAI API Error:", error.response ? error.response.data : error.message);
        res.status(500).json({ error: "Error connecting to OpenAI" });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
