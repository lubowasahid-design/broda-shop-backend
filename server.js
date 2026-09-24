const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();

app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  console.error("JWT_SECRET is missing");
  process.exit(1);
}

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL is missing");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

pool.on("error", (error) => {
  console.error("Unexpected PostgreSQL error:", error);
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'member',
      referral_code TEXT UNIQUE NOT NULL,
      referred_by TEXT,
      balance NUMERIC(14,2) NOT NULL DEFAULT 0,
      earnings NUMERIC(14,2) NOT NULL DEFAULT 0,
      referrals INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS contents (
      id TEXT PRIMARY KEY,
      creator_id TEXT NOT NULL,
      title TEXT NOT NULL,
      description TEXT,
      price NUMERIC(14,2) NOT NULL DEFAULT 0,
      type TEXT,
      file_url TEXT DEFAULT '',
      approved BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS purchases (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      content_id TEXT NOT NULL,
      amount NUMERIC(14,2) NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS withdrawals (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      amount NUMERIC(14,2) NOT NULL,
      method TEXT,
      account TEXT,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS activity_events (
      id TEXT PRIMARY KEY,
      user_id TEXT,
      action TEXT NOT NULL,
      details JSONB DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_users_email
      ON users(email);

    CREATE INDEX IF NOT EXISTS idx_users_referral_code
      ON users(referral_code);

    CREATE INDEX IF NOT EXISTS idx_contents_creator
      ON contents(creator_id);

    CREATE INDEX IF NOT EXISTS idx_purchases_user
      ON purchases(user_id);

    CREATE INDEX IF NOT EXISTS idx_withdrawals_user
      ON withdrawals(user_id);

    CREATE INDEX IF NOT EXISTS idx_activity_user
      ON activity_events(user_id);

    CREATE INDEX IF NOT EXISTS idx_activity_created
      ON activity_events(created_at);
  `);

  console.log("BRODA SHOP database initialized");
}

function referralCode() {
  return "BRODA" +
    crypto.randomBytes(4).toString("hex").toUpperCase();
}

function token(user) {
  return jwt.sign(
    {
      id: user.id,
      role: user.role
    },
    JWT_SECRET,
    {
      expiresIn: "7d"
    }
  );
}

function auth(req, res, next) {
  try {
    const header = req.headers.authorization;

    if (!header || !header.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Login required"
      });
    }

    const decoded = jwt.verify(
      header.split(" ")[1],
      JWT_SECRET
    );

    req.user = decoded;
    next();
  } catch {
    res.status(401).json({
      error: "Invalid or expired token"
    });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({
      error: "Admin only"
    });
  }

  next();
}

function publicUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
    referralCode: user.referralCode
  };
}

async function logActivity(userId, action, details = {}) {
  try {
    await pool.query(
      `
      INSERT INTO activity_events
      (id, user_id, action, details)
      VALUES ($1, $2, $3, $4)
      `,
      [
        crypto.randomUUID(),
        userId || null,
        action,
        JSON.stringify(details)
      ]
    );
  } catch (error) {
    console.error("Activity log failed:", error.message);
  }
}

app.get("/", (req, res) => {
  res.json({
    message: "BRODA SHOP backend is running",
    status: "online",
    database: "connected"
  });
});

app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      status: "ok",
      database: "connected"
    });
  } catch {
    res.status(503).json({
      status: "error",
      database: "disconnected"
    });
  }
});

app.post("/api/auth/register", async (req, res) => {
  try {
    const {
      name,
      email,
      password,
      referral
    } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        error: "Name, email and password are required"
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        error: "Password must be at least 6 characters"
      });
    }

    const normalizedEmail = String(email).toLowerCase().trim();

    const existing = await pool.query(
      `
      SELECT id
      FROM users
      WHERE email = $1
      `,
      [normalizedEmail]
    );

    if (existing.rows.length > 0) {
      return res.status(409).json({
        error: "Email already registered"
      });
    }

    let newReferralCode;

    do {
      newReferralCode = referralCode();

      const checkCode = await pool.query(
        `
        SELECT id
        FROM users
        WHERE referral_code = $1
        `,
        [newReferralCode]
      );

      if (checkCode.rows.length === 0) {
        break;
      }
    } while (true);

    let referredBy = null;

    if (referral) {
      const referrer = await pool.query(
        `
        SELECT id, referral_code
        FROM users
        WHERE referral_code = $1
        `,
        [String(referral).trim()]
      );

      if (referrer.rows.length > 0) {
        referredBy = referrer.rows[0].referral_code;
      }
    }

    const id = crypto.randomUUID();

    const hashedPassword = await bcrypt.hash(
      password,
      10
    );

    const result = await pool.query(
      `
      INSERT INTO users
      (
        id,
        name,
        email,
        password,
        role,
        referral_code,
        referred_by
      )
      VALUES ($1, $2, $3, $4, 'member', $5, $6)
      RETURNING
        id,
        name,
        email,
        role,
        referral_code,
        balance,
        earnings,
        referrals
      `,
      [
        id,
        String(name).trim(),
        normalizedEmail,
        hashedPassword,
        newReferralCode,
        referredBy
      ]
    );

    if (referredBy) {
      await pool.query(
        `
        UPDATE users
        SET referrals = referrals + 1
        WHERE referral_code = $1
        `,
        [referredBy]
      );
    }

    const user = {
      id: result.rows[0].id,
      name: result.rows[0].name,
      email: result.rows[0].email,
      role: result.rows[0].role,
      referralCode: result.rows[0].referral_code
    };

    await logActivity(
      id,
      "account_registered",
      {
        referral: referredBy
      }
    );

    res.status(201).json({
      message: "Registration successful",
      user,
      token: token({
        id,
        role: "member"
      })
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Registration failed"
    });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const {
      email,
      password
    } = req.body;

    const normalizedEmail =
      String(email || "").toLowerCase().trim();

    const result = await pool.query(
      `
      SELECT
        id,
        name,
        email,
        password,
        role,
        referral_code
      FROM users
      WHERE email = $1
      `,
      [normalizedEmail]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        error: "Invalid email or password"
      });
    }

    const user = result.rows[0];

    const valid = await bcrypt.compare(
      password || "",
      user.password
    );

    if (!valid) {
      return res.status(401).json({
        error: "Invalid email or password"
      });
    }

    await logActivity(
      user.id,
      "account_login"
    );

    res.json({
      message: "Login successful",
      user: publicUser({
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        referralCode: user.referral_code
      }),
      token: token(user)
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Login failed"
    });
  }
});

app.get("/api/me", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT
        id,
        name,
        email,
        role,
        referral_code
      FROM users
      WHERE id = $1
      `,
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: "User not found"
      });
    }

    const user = result.rows[0];

    res.json(
      publicUser({
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        referralCode: user.referral_code
      })
    );

  } catch {
    res.status(500).json({
      error: "Unable to load user"
    });
  }
});

app.get("/api/dashboard", auth, async (req, res) => {
  try {
    const userResult = await pool.query(
      `
      SELECT
        id,
        earnings,
        referrals,
        balance,
        referral_code
      FROM users
      WHERE id = $1
      `,
      [req.user.id]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({
        error: "User not found"
      });
    }

    const user = userResult.rows[0];

    const purchasesResult = await pool.query(
      `
      SELECT COUNT(*)::integer AS count
      FROM purchases
      WHERE user_id = $1
      `,
      [req.user.id]
    );

    res.json({
      earnings: Number(user.earnings),
      referrals: user.referrals,
      purchases: purchasesResult.rows[0].count,
      balance: Number(user.balance),
      referralLink:
        "https://broda.shop/register?ref=" +
        user.referral_code
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Unable to load dashboard"
    });
  }
});

app.get("/api/content", async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT
        id,
        creator_id AS "creatorId",
        title,
        description,
        price,
        type,
        file_url AS "fileUrl",
        approved,
        created_at AS "createdAt"
      FROM contents
      WHERE approved = TRUE
      ORDER BY created_at DESC
      `
    );

    res.json(
      result.rows.map((content) => ({
        ...content,
        price: Number(content.price)
      }))
    );

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Unable to load content"
    });
  }
});

app.post("/api/content", auth, async (req, res) => {
  try {
    const {
      title,
      description,
      price,
      type,
      fileUrl
    } = req.body;

    if (!title || price === undefined) {
      return res.status(400).json({
        error: "Title and price are required"
      });
    }

    const amount = Number(price);

    if (!Number.isFinite(amount) || amount < 0) {
      return res.status(400).json({
        error: "Invalid price"
      });
    }

    const id = crypto.randomUUID();

    const result = await pool.query(
      `
      INSERT INTO contents
      (
        id,
        creator_id,
        title,
        description,
        price,
        type,
        file_url,
        approved
      )
      VALUES
      ($1, $2, $3, $4, $5, $6, $7, FALSE)
      RETURNING
        id,
        creator_id AS "creatorId",
        title,
        description,
        price,
        type,
        file_url AS "fileUrl",
        approved,
        created_at AS "createdAt"
      `,
      [
        id,
        req.user.id,
        String(title).trim(),
        description || "",
        amount,
        type || "",
        fileUrl || ""
      ]
    );

    await logActivity(
      req.user.id,
      "content_submitted",
      {
        contentId: id,
        title
      }
    );

    const content = result.rows[0];

    res.status(201).json({
      message: "Content submitted for approval",
      content: {
        ...content,
        price: Number(content.price)
      }
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Content submission failed"
    });
  }
});

app.post("/api/purchases", auth, async (req, res) => {
  const client = await pool.connect();

  try {
    const { contentId } = req.body;

    await client.query("BEGIN");

    const contentResult = await client.query(
      `
      SELECT
        id,
        creator_id,
        title,
        price
      FROM contents
      WHERE id = $1
      AND approved = TRUE
      FOR UPDATE
      `,
      [contentId]
    );

    if (contentResult.rows.length === 0) {
      await client.query("ROLLBACK");

      return res.status(404).json({
        error: "Content not found"
      });
    }

    const content = contentResult.rows[0];

    const userResult = await client.query(
      `
      SELECT
        id,
        balance
      FROM users
      WHERE id = $1
      FOR UPDATE
      `,
      [req.user.id]
    );

    if (userResult.rows.length === 0) {
      await client.query("ROLLBACK");

      return res.status(404).json({
        error: "User not found"
      });
    }

    const user = userResult.rows[0];
    const price = Number(content.price);

    if (Number(user.balance) < price) {
      await client.query("ROLLBACK");

      return res.status(400).json({
        error: "Insufficient balance"
      });
    }

    const purchaseId = crypto.randomUUID();

    await client.query(
      `
      UPDATE users
      SET balance = balance - $1
      WHERE id = $2
      `,
      [price, req.user.id]
    );

    await client.query(
      `
      INSERT INTO purchases
      (
        id,
        user_id,
        content_id,
        amount
      )
      VALUES ($1, $2, $3, $4)
      `,
      [
        purchaseId,
        req.user.id,
        content.id,
        price
      ]
    );

    await client.query("COMMIT");

    await logActivity(
      req.user.id,
      "purchase_created",
      {
        purchaseId,
        contentId: content.id,
        amount: price
      }
    );

    res.status(201).json({
      message: "Purchase successful",
      purchase: {
        id: purchaseId,
        userId: req.user.id,
        contentId: content.id,
        amount: price,
        createdAt: new Date().toISOString()
      }
    });

  } catch (error) {
    await client.query("ROLLBACK");

    console.error(error);

    res.status(500).json({
      error: "Purchase failed"
    });
  } finally {
    client.release();
  }
});

app.post("/api/withdrawals", auth, async (req, res) => {
  const client = await pool.connect();

  try {
    const {
      amount,
      method,
      account
    } = req.body;

    const amountNumber = Number(amount);

    if (!Number.isFinite(amountNumber) || amountNumber <= 0) {
      return res.status(400).json({
        error: "Invalid withdrawal amount"
      });
    }

    await client.query("BEGIN");

    const userResult = await client.query(
      `
      SELECT
        id,
        balance
      FROM users
      WHERE id = $1
      FOR UPDATE
      `,
      [req.user.id]
    );

    if (userResult.rows.length === 0) {
      await client.query("ROLLBACK");

      return res.status(404).json({
        error: "User not found"
      });
    }

    const user = userResult.rows[0];

    if (Number(user.balance) < amountNumber) {
      await client.query("ROLLBACK");

      return res.status(400).json({
        error: "Insufficient balance"
      });
    }

    const withdrawalId = crypto.randomUUID();

    await client.query(
      `
      UPDATE users
      SET balance = balance - $1
      WHERE id = $2
      `,
      [
        amountNumber,
        req.user.id
      ]
    );

    await client.query(
      `
      INSERT INTO withdrawals
      (
        id,
        user_id,
        amount,
        method,
        account,
        status
      )
      VALUES
      ($1, $2, $3, $4, $5, 'pending')
      `,
      [
        withdrawalId,
        req.user.id,
        amountNumber,
        method || "",
        account || ""
      ]
    );

    await client.query("COMMIT");

    await logActivity(
      req.user.id,
      "withdrawal_requested",
      {
        withdrawalId,
        amount: amountNumber,
        method: method || ""
      }
    );

    res.status(201).json({
      message: "Withdrawal request submitted",
      withdrawal: {
        id: withdrawalId,
        userId: req.user.id,
        amount: amountNumber,
        method: method || "",
        account: account || "",
        status: "pending",
        createdAt: new Date().toISOString()
      }
    });

  } catch (error) {
    await client.query("ROLLBACK");

    console.error(error);

    res.status(500).json({
      error: "Withdrawal request failed"
    });
  } finally {
    client.release();
  }
});

app.get("/api/admin/stats", auth, adminOnly, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        (SELECT COUNT(*)::integer FROM users) AS users,
        (SELECT COUNT(*)::integer FROM users WHERE role = 'creator') AS creators,
        (SELECT COUNT(*)::integer FROM purchases) AS sales,
        (
          SELECT COUNT(*)::integer
          FROM withdrawals
          WHERE status = 'pending'
        ) AS "pendingWithdrawals"
    `);

    res.json(result.rows[0]);

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Unable to load admin stats"
    });
  }
});

app.patch(
  "/api/admin/content/:id/approve",
  auth,
  adminOnly,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        UPDATE contents
        SET approved = TRUE
        WHERE id = $1
        RETURNING
          id,
          creator_id AS "creatorId",
          title,
          description,
          price,
          type,
          file_url AS "fileUrl",
          approved,
          created_at AS "createdAt"
        `,
        [req.params.id]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          error: "Content not found"
        });
      }

      await logActivity(
        req.user.id,
        "content_approved",
        {
          contentId: req.params.id
        }
      );

      const content = result.rows[0];

      res.json({
        message: "Content approved",
        content: {
          ...content,
          price: Number(content.price)
        }
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Approval failed"
      });
    }
  }
);

app.get(
  "/api/admin/activity",
  auth,
  adminOnly,
  async (req, res) => {
    try {
      const result = await pool.query(`
        SELECT
          id,
          user_id AS "userId",
          action,
          details,
          created_at AS "createdAt"
        FROM activity_events
        ORDER BY created_at DESC
        LIMIT 200
      `);

      res.json(result.rows);

    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Unable to load activity"
      });
    }
  }
);

const PORT = process.env.PORT || 3000;

async function startServer() {
  try {
    await initDb();

    app.listen(PORT, "0.0.0.0", () => {
      console.log(
        `BRODA SHOP backend running on port ${PORT}`
      );
    });
  } catch (error) {
    console.error(
      "Database initialization failed:",
      error
    );

    process.exit(1);
  }
}

startServer();
