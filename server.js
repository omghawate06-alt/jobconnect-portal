

const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");

const app = express();

app.use(cors());
app.use(express.json());

mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log("MongoDB connected successfully"))
  .catch((err) => console.error("MongoDB connection error:", err.message));

app.get("/", (req, res) => {
  res.send("JobConnect Portal Backend is Running!");
});

app.get("/api/jobs", async (req, res) => {
  try {
    const jobs = await mongoose.connection.db
      .collection("jobs")
      .find({})
      .toArray();

    res.json(jobs);
  } catch (error) {
    res.status(500).json({
      message: "Could not fetch jobs from MongoDB",
      error: error.message
    });
  }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
