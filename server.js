

const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const crypto = require("crypto");
const { promisify } = require("util");

const app = express();
const scrypt = promisify(crypto.scrypt);

app.use(cors());
app.use(express.json({ limit: "20kb" }));

// SECURITY
const JWT_SECRET =
  typeof process.env.JWT_SECRET === "string"
    ? process.env.JWT_SECRET.trim()
    : "";

console.log("JWT_SECRET configured:", JWT_SECRET.length >= 32);

function createToken(user) {
  const now = Math.floor(Date.now() / 1000);

  const header = Buffer.from(
    JSON.stringify({ alg: "HS256", typ: "JWT" })
  ).toString("base64url");

  const payload = Buffer.from(
    JSON.stringify({
      sub: user._id.toString(),
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
  if (JWT_SECRET.length < 32) {
    return res.status(503).json({
      message: "Login security is not configured."
    });
  }

  const parts = (req.headers.authorization || "").split(" ");

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
        message: "Login expired. Please log in again."
      });
    }

    req.userId = payload.sub;
    next();
  } catch {
    return res.status(401).json({
      message: "Invalid login token."
    });
  }
}

// DATABASE MODELS
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
  role: {
    type: String,
    enum: ["user", "admin"],
    default: "user"
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const User = mongoose.model("User", userSchema);

const APPLICATION_STATUSES = [
  "Submitted",
  "Under Review",
  "Shortlisted",
  "Rejected",
  "Accepted"
];

const applicationSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
    index: true
  },
  applicantName: {
    type: String,
    required: true,
    trim: true,
    maxlength: 100
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
    trim: true,
    maxlength: 200
  },
  status: {
    type: String,
    enum: APPLICATION_STATUSES,
    default: "Submitted"
  },
  appliedAt: {
    type: Date,
    default: Date.now
  },
  statusUpdatedAt: {
    type: Date,
    default: Date.now
  }
});

const Application = mongoose.model("Application", applicationSchema);

// DATABASE CONNECTION
if (!process.env.MONGODB_URI) {
  console.error("MONGODB_URI is missing in Render Environment.");
} else {
  mongoose
    .connect(process.env.MONGODB_URI, { dbName: "jobconnect" })
    .then(() => console.log("MongoDB connected successfully"))
    .catch(err =>
      console.error("MongoDB connection error:", err.message)
    );
}

// REGISTER
app.post("/api/auth/register", async (req, res) => {
  try {
    if (JWT_SECRET.length < 32) {
      return res.status(503).json({
        message: "Login security is not configured."
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
        message: "Database is not ready."
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    if (await User.findOne({ email: normalizedEmail })) {
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

// LOGIN
app.post("/api/auth/login", async (req, res) => {
  try {
    if (JWT_SECRET.length < 32) {
      return res.status(503).json({
        message: "Login security is not configured."
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
        message: "Database is not ready."
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

// CURRENT USER
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
  } catch {
    res.status(500).json({
      message: "Could not load your account."
    });
  }
});

// HOMEPAGE
app.get("/", (req, res) => {
  res.sendFile(__dirname + "/index.html");
});

// JOBS
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
    console.error("Fetch jobs error:", error.message);
    res.status(500).json({
      message: "Could not fetch jobs from MongoDB."
    });
  }
});

// ADMIN CHECK
async function requireAdmin(req, res, next) {
  try {
    const user = await User.findById(req.userId);

    if (!user || user.role !== "admin") {
      return res.status(403).json({
        message: "Administrator access required."
      });
    }

    next();
  } catch {
    res.status(500).json({
      message: "Could not verify administrator access."
    });
  }
}

// SUBMIT APPLICATION
app.post("/api/applications", requireLogin, async (req, res) => {
  try {
    const { jobTitle } = req.body || {};

    if (
      typeof jobTitle !== "string" ||
      !jobTitle.trim() ||
      jobTitle.trim().length > 200
    ) {
      return res.status(400).json({
        message: "Enter a valid job title."
      });
    }

    if (mongoose.connection.readyState !== 1) {
      return res.status(503).json({
        message: "Database is not ready."
      });
    }

    const user = await User.findById(req.userId);

    if (!user) {
      return res.status(401).json({
        message: "Please log in again."
      });
    }

    const application = await Application.create({
      userId: user._id,
      applicantName: user.name,
      email: user.email,
      jobTitle: jobTitle.trim(),
      status: "Submitted"
    });

    res.status(201).json({
      message: "Application submitted successfully!",
      application: {
        id: application._id,
        jobTitle: application.jobTitle,
        status: application.status,
        appliedAt: application.appliedAt
      }
    });
  } catch (error) {
    console.error("Application save error:", error.message);
    res.status(500).json({
      message: "Could not save application. Please try again."
    });
  }
});

// MY APPLICATIONS
app.get("/api/applications/my", requireLogin, async (req, res) => {
  try {
    if (mongoose.connection.readyState !== 1) {
      return res.status(503).json({
        message: "Database is not ready."
      });
    }

    const applications = await Application.find({
      userId: req.userId
    })
      .select("jobTitle status appliedAt statusUpdatedAt")
      .sort({ appliedAt: -1 })
      .lean();

    res.json({
      applications: applications.map(item => ({
        id: item._id,
        jobTitle: item.jobTitle,
        status: item.status,
        appliedAt: item.appliedAt,
        statusUpdatedAt: item.statusUpdatedAt
      }))
    });
  } catch (error) {
    console.error("My applications error:", error.message);
    res.status(500).json({
      message: "Could not load your applications."
    });
  }
});

// ADMIN: UPDATE APPLICATION STATUS
app.patch(
  "/api/applications/:id/status",
  requireLogin,
  requireAdmin,
  async (req, res) => {
    try {
      const { status } = req.body || {};

      if (!APPLICATION_STATUSES.includes(status)) {
        return res.status(400).json({
          message: "Choose a valid application status."
        });
      }

      if (!mongoose.isValidObjectId(req.params.id)) {
        return res.status(400).json({
          message: "Invalid application ID."
        });
      }

      const application = await Application.findByIdAndUpdate(
        req.params.id,
        {
          $set: {
            status,
            statusUpdatedAt: new Date()
          }
        },
        { new: true, runValidators: true }
      ).select("jobTitle status appliedAt statusUpdatedAt");

      if (!application) {
        return res.status(404).json({
          message: "Application not found."
        });
      }

      res.json({
        message: "Application status updated.",
        application
      });
    } catch (error) {
      console.error("Status update error:", error.message);
      res.status(500).json({
        message: "Could not update application status."
      });
    }
  }
);

// START SERVER
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

