const express = require("express");
const cors = require("cors");
const axios = require("axios");
require("dotenv").config();

const app = express();
app.use(express.json());
app.use(cors());

app.post("/api/chat", async (req, res) => {
    try {
        const userMessage = req.body.message;
        const partDetails = req.body.partDetails;

        const response = await axios.post(
            "https://api.openai.com/v1/chat/completions",
            {
                model: "gpt-4o",
                messages: [
                    { role: "system", content: `You are an AI therapist guiding the user through self-exploration. They are working with this part: ${partDetails}` },
                    { role: "user", content: userMessage }
                ],
            },
            {
                headers: { Authorization: `Bearer ${process.env.OPENAI_API_KEY}` },
            }
        );

        res.json({ response: response.data.choices[0].message.content });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Error connecting to OpenAI" });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
