

const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const crypto = require("crypto");
const { promisify } = require("util");

const app = express();
const scrypt = promisify(crypto.scrypt);

app.use(cors());
app.use(express.json({ limit: "20kb" }));

// ---------------- SECURITY HELPERS ----------------

const JWT_SECRET = process.env.JWT_SECRET;

function createToken(user) {
  const now = Math.floor(Date.now() / 1000);

  const header = Buffer.from(
    JSON.stringify({ alg: "HS256", typ: "JWT" })
  ).toString("base64url");

  const payload = Buffer.from(
    JSON.stringify({
      sub: user._id.toString(),
      name: user.name,
      email: user.email,
      iat: now,
      exp: now + 7 * 24 * 60 * 60
    })
  ).toString("base64url");

  const content = `${header}.${payload}`;

  const signature = crypto
    .createHmac("sha256", JWT_SECRET)
    .update(content)
    .digest("base64url");

  return `${content}.${signature}`;
}

function requireLogin(req, res, next) {
  if (!JWT_SECRET) {
    return res.status(503).json({
      message: "Login security is not configured on the server."
    });
  }

  const authorization = req.headers.authorization || "";
  const parts = authorization.split(" ");

  if (parts.length !== 2 || parts[0] !== "Bearer") {
    return res.status(401).json({
      message: "Please log in first."
    });
  }

  const tokenParts = parts[1].split(".");

  if (tokenParts.length !== 3) {
    return res.status(401).json({
      message: "Invalid login token."
    });
  }

  try {
    const content = `${tokenParts[0]}.${tokenParts[1]}`;

    const expected = crypto
      .createHmac("sha256", JWT_SECRET)
      .update(content)
      .digest();

    const actual = Buffer.from(tokenParts[2], "base64url");

    if (
      actual.length !== expected.length ||
      !crypto.timingSafeEqual(actual, expected)
    ) {
      return res.status(401).json({
        message: "Invalid login token."
      });
    }

    const header = JSON.parse(
      Buffer.from(tokenParts[0], "base64url").toString()
    );

    const payload = JSON.parse(
      Buffer.from(tokenParts[1], "base64url").toString()
    );

    if (
      header.alg !== "HS256" ||
      header.typ !== "JWT" ||
      typeof payload.sub !== "string" ||
      typeof payload.exp !== "number" ||
      payload.exp <= Math.floor(Date.now() / 1000)
    ) {
      return res.status(401).json({
        message: "Your login has expired. Please log in again."
      });
    }

    req.userId = payload.sub;
    next();
  } catch (error) {
    return res.status(401).json({
      message: "Invalid login token."
    });
  }
}

// ---------------- DATABASE MODELS ----------------

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true,
    maxlength: 100
  },
  email: {
    type: String,
    required: true,
    trim: true,
    lowercase: true,
    unique: true,
    maxlength: 254
  },
  passwordHash: {
    type: String,
    required: true,
    select: false
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const User = mongoose.model("User", userSchema);

const applicationSchema = new mongoose.Schema({
  applicantName: {
    type: String,
    required: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    trim: true,
    lowercase: true
  },
  jobTitle: {
    type: String,
    required: true,
    trim: true
  },
  appliedAt: {
    type: Date,
    default: Date.now
  }
});

const Application = mongoose.model("Application", applicationSchema);

// ---------------- DATABASE CONNECTION ----------------

mongoose.connect(process.env.MONGODB_URI, {
  dbName: "jobconnect"
})
  .then(() => console.log("MongoDB connected successfully"))
  .catch((err) =>
    console.error("MongoDB connection error:", err.message)
  );

// ---------------- REGISTRATION ----------------

app.post("/api/auth/register", async (req, res) => {
  try {
    if (!JWT_SECRET) {
      return res.status(503).json({
        message: "Login security is not configured on the server."
      });
    }

    const { name, email, password } = req.body || {};

    if (
      typeof name !== "string" ||
      !name.trim() ||
      name.trim().length > 100 ||
      typeof email !== "string" ||
      email.length > 254 ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim()) ||
      typeof password !== "string" ||
      password.length < 8 ||
      password.length > 128
    ) {
      return res.status(400).json({
        message: "Enter a valid name and email. Password must be 8–128 characters."
      });
    }

    if (mongoose.connection.readyState !== 1) {
      return res.status(503).json({
        message: "Database is not ready. Please try again."
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const existingUser = await User.findOne({
      email: normalizedEmail
    });

    if (existingUser) {
      return res.status(409).json({
        message: "An account with this email already exists."
      });
    }

    const salt = crypto.randomBytes(16).toString("hex");

    const derivedKey = await scrypt(password, salt, 64);

    const passwordHash =
      salt + ":" + Buffer.from(derivedKey).toString("hex");

    const user = await User.create({
      name: name.trim(),
      email: normalizedEmail,
      passwordHash
    });

    res.status(201).json({
      message: "Registration successful! You can now log in.",
      user: {
        id: user._id,
        name: user.name,
        email: user.email
      }
    });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(409).json({
        message: "An account with this email already exists."
      });
    }

    console.error("Registration error:", error.message);
    res.status(500).json({
      message: "Could not register. Please try again."
    });
  }
});

// ---------------- LOGIN ----------------

app.post("/api/auth/login", async (req, res) => {
  try {
    if (!JWT_SECRET) {
      return res.status(503).json({
        message: "Login security is not configured on the server."
      });
    }

    const { email, password } = req.body || {};

    if (
      typeof email !== "string" ||
      email.length > 254 ||
      typeof password !== "string" ||
      password.length > 128
    ) {
      return res.status(400).json({
        message: "Enter a valid email and password."
      });
    }

    if (mongoose.connection.readyState !== 1) {
      return res.status(503).json({
        message: "Database is not ready. Please try again."
      });
    }

    const user = await User.findOne({
      email: email.trim().toLowerCase()
    }).select("+passwordHash");

    if (!user) {
      return res.status(401).json({
        message: "Invalid email or password."
      });
    }

    const [salt, storedHash] = user.passwordHash.split(":");

    const derivedKey = await scrypt(password, salt, 64);
    const actualHash = Buffer.from(derivedKey);
    const expectedHash = Buffer.from(storedHash, "hex");

    if (
      actualHash.length !== expectedHash.length ||
      !crypto.timingSafeEqual(actualHash, expectedHash)
    ) {
      return res.status(401).json({
        message: "Invalid email or password."
      });
    }

    res.json({
      message: "Login successful!",
      token: createToken(user),
      user: {
        id: user._id,
        name: user.name,
        email: user.email
      }
    });
  } catch (error) {
    console.error("Login error:", error.message);
    res.status(500).json({
      message: "Could not log in. Please try again."
    });
  }
});

// ---------------- CURRENT USER ----------------

app.get("/api/auth/me", requireLogin, async (req, res) => {
  try {
    const user = await User.findById(req.userId);

    if (!user) {
      return res.status(401).json({
        message: "Account not found. Please log in again."
      });
    }

    res.json({
      user: {
        id: user._id,
        name: user.name,
        email: user.email
      }
    });
  } catch (error) {
    res.status(500).json({
      message: "Could not load your account."
    });
  }
});

// ---------------- WEBSITE HOMEPAGE ----------------

app.get("/", (req, res) => {
  res.sendFile(__dirname + "/index.html");
});

// ---------------- GET JOBS ----------------

app.get("/api/jobs", async (req, res) => {
  try {
    if (mongoose.connection.readyState !== 1) {
      return res.status(503).json({
        message: "Database is not ready."
      });
    }

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

// ---------------- SUBMIT APPLICATION ----------------

app.post("/api/applications", async (req, res) => {
  try {
    const { applicantName, email, jobTitle } = req.body || {};

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

// ---------------- START SERVER ----------------

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

