

const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");

const app = express();

app.use(cors());
app.use(express.json());

// Application database model
const applicationSchema = new mongoose.Schema({
  applicantName: { type: String, required: true, trim: true },
  email: { type: String, required: true, trim: true, lowercase: true },
  jobTitle: { type: String, required: true, trim: true },
  appliedAt: { type: Date, default: Date.now }
});

const Application = mongoose.model("Application", applicationSchema);

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, {
  dbName: "jobconnect"
})
  .then(() => console.log("MongoDB connected successfully"))
  .catch((err) => console.error("MongoDB connection error:", err.message));

// Website homepage
app.get("/", (req, res) => {
  res.sendFile(__dirname + "/index.html");
});

// Get all jobs
app.get("/api/jobs", async (req, res) => {
  try {
    const jobs = await mongoose.connection.db
      .collection("jobs")
      .find({})
      .toArray();

    res.json(jobs);
  } catch (error) {
    res.status(500).json({
      message: "Could not fetch jobs from MongoDB"
    });
  }
});

// Submit a job application
app.post("/api/applications", async (req, res) => {
  try {
    const { applicantName, email, jobTitle } = req.body;

    if (
      typeof applicantName !== "string" ||
      !applicantName.trim() ||
      typeof email !== "string" ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim()) ||
      typeof jobTitle !== "string" ||
      !jobTitle.trim()
    ) {
      return res.status(400).json({
        message: "Enter a valid name, email, and job title."
      });
    }

    if (mongoose.connection.readyState !== 1) {
      return res.status(503).json({
        message: "Database is not ready. Please try again."
      });
    }

    const application = await Application.create({
      applicantName: applicantName.trim(),
      email: email.trim().toLowerCase(),
      jobTitle: jobTitle.trim()
    });

    res.status(201).json({
      message: "Application submitted successfully!",
      applicationId: application._id
    });
  } catch (error) {
    console.error("Application save error:", error.message);
    res.status(500).json({
      message: "Could not save application. Please try again."
    });
  }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

