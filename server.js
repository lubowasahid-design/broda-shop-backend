const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const app = express();

app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || "broda-shop-secret-change-this";

const users = [];
const contents = [];
const purchases = [];
const withdrawals = [];

function referralCode() {
  return "BRODA" + crypto.randomBytes(4).toString("hex").toUpperCase();
}

function token(user) {
  return jwt.sign(
    { id: user.id, role: user.role },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function auth(req, res, next) {
  try {
    const header = req.headers.authorization;

    if (!header || !header.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Login required" });
    }

    const decoded = jwt.verify(
      header.split(" ")[1],
      JWT_SECRET
    );

    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ error: "Invalid or expired token" });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Admin only" });
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

app.get("/", (req, res) => {
  res.json({
    message: "BRODA SHOP backend is running",
    status: "online"
  });
});

app.get("/api/health", (req, res) => {
  res.json({ status: "ok" });
});

app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password, referral } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        error: "Name, email and password are required"
      });
    }

    const exists = users.find(
      u => u.email.toLowerCase() === email.toLowerCase()
    );

    if (exists) {
      return res.status(409).json({
        error: "Email already registered"
      });
    }

    const user = {
      id: crypto.randomUUID(),
      name,
      email: email.toLowerCase(),
      password: await bcrypt.hash(password, 10),
      role: "member",
      referralCode: referralCode(),
      referredBy: referral || null,
      balance: 0,
      earnings: 0,
      referrals: 0
    };

    users.push(user);

    if (referral) {
      const referrer = users.find(
        u => u.referralCode === referral
      );

      if (referrer) {
        referrer.referrals += 1;
      }
    }

    res.status(201).json({
      message: "Registration successful",
      user: publicUser(user),
      token: token(user)
    });
  } catch (error) {
    res.status(500).json({
      error: "Registration failed"
    });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;

  const user = users.find(
    u => u.email === String(email).toLowerCase()
  );

  if (!user) {
    return res.status(401).json({
      error: "Invalid email or password"
    });
  }

  const valid = await bcrypt.compare(password, user.password);

  if (!valid) {
    return res.status(401).json({
      error: "Invalid email or password"
    });
  }

  res.json({
    message: "Login successful",
    user: publicUser(user),
    token: token(user)
  });
});

app.get("/api/me", auth, (req, res) => {
  const user = users.find(u => u.id === req.user.id);

  if (!user) {
    return res.status(404).json({
      error: "User not found"
    });
  }

  res.json(publicUser(user));
});

app.get("/api/dashboard", auth, (req, res) => {
  const user = users.find(u => u.id === req.user.id);

  res.json({
    earnings: user.earnings,
    referrals: user.referrals,
    purchases: purchases.filter(
      p => p.userId === user.id
    ).length,
    balance: user.balance,
    referralLink:
      "https://broda.shop/register?ref=" +
      user.referralCode
  });
});

app.get("/api/content", (req, res) => {
  res.json(
    contents.filter(content => content.approved)
  );
});

app.post("/api/content", auth, (req, res) => {
  const {
    title,
    description,
    price,
    type,
    fileUrl
  } = req.body;

  const content = {
    id: crypto.randomUUID(),
    creatorId: req.user.id,
    title,
    description,
    price: Number(price),
    type,
    fileUrl: fileUrl || "",
    approved: false,
    createdAt: new Date().toISOString()
  };

  contents.push(content);

  res.status(201).json({
    message: "Content submitted for approval",
    content
  });
});

app.post("/api/purchases", auth, (req, res) => {
  const { contentId } = req.body;

  const content = contents.find(
    c => c.id === contentId && c.approved
  );

  if (!content) {
    return res.status(404).json({
      error: "Content not found"
    });
  }

  const user = users.find(u => u.id === req.user.id);

  if (user.balance < content.price) {
    return res.status(400).json({
      error: "Insufficient balance"
    });
  }

  user.balance -= content.price;

  const purchase = {
    id: crypto.randomUUID(),
    userId: user.id,
    contentId: content.id,
    amount: content.price,
    createdAt: new Date().toISOString()
  };

  purchases.push(purchase);

  res.status(201).json({
    message: "Purchase successful",
    purchase
  });
});

app.post("/api/withdrawals", auth, (req, res) => {
  const { amount, method, account } = req.body;

  const amountNumber = Number(amount);

  if (!amountNumber || amountNumber <= 0) {
    return res.status(400).json({
      error: "Invalid withdrawal amount"
    });
  }

  const user = users.find(u => u.id === req.user.id);

  if (user.balance < amountNumber) {
    return res.status(400).json({
      error: "Insufficient balance"
    });
  }

  user.balance -= amountNumber;

  const withdrawal = {
    id: crypto.randomUUID(),
    userId: user.id,
    amount: amountNumber,
    method,
    account,
    status: "pending",
    createdAt: new Date().toISOString()
  };

  withdrawals.push(withdrawal);

  res.status(201).json({
    message: "Withdrawal request submitted",
    withdrawal
  });
});

app.get("/api/admin/stats", auth, adminOnly, (req, res) => {
  res.json({
    users: users.length,
    creators: users.filter(u => u.role === "creator").length,
    sales: purchases.length,
    pendingWithdrawals:
      withdrawals.filter(w => w.status === "pending").length
  });
});

app.patch(
  "/api/admin/content/:id/approve",
  auth,
  adminOnly,
  (req, res) => {
    const content = contents.find(
      c => c.id === req.params.id
    );

    if (!content) {
      return res.status(404).json({
        error: "Content not found"
      });
    }

    content.approved = true;

    res.json({
      message: "Content approved",
      content
    });
  }
);

const PORT = process.env.PORT || 3000;

app.listen(PORT, "0.0.0.0", () => {
  console.log(`BRODA SHOP backend running on port ${PORT}`);
});
