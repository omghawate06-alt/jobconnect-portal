
const express = require("express");
const cors = require("cors");

const app = express();

app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
  res.send("JobConnect Portal Backend is Running!");
});

app.get("/api/jobs", (req, res) => {
  res.json([
    {
      id: 1,
      title: "Frontend Developer",
      company: "JobConnect",
      location: "Pune"
    },
    {
      id: 2,
      title: "Backend Developer",
      company: "JobConnect",
      location: "Mumbai"
    }
  ]);
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
