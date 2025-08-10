require('dotenv').config({ path: __dirname + '/.env' });
console.log("Loading .env from:", __dirname + '/.env');
console.log("User:", process.env.EMAIL_USER);
console.log("Pass loaded:", !!process.env.EMAIL_PASS);

const express = require("express");
const cors = require("cors");
const fs = require("fs").promises;
const path = require("path");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");

const app = express();
app.use(express.json());

// --- Cấu hình từ biến môi trường ---
const PORT = process.env.PORT || 4000;
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:3000";
const JWT_SECRET = process.env.JWT_SECRET || "change_this_secret";
const TOKEN_EXPIRES_MIN = parseInt(process.env.TOKEN_EXPIRES_MIN || "60", 10);

// --- CORS ---
app.use(cors({ origin: FRONTEND_URL }));

// --- Đường dẫn file JSON ---
const DATA_DIR = path.join(__dirname);
const USERS_FILE = path.join(DATA_DIR, "users.json");
const RESETS_FILE = path.join(DATA_DIR, "resets.json");

// --- Mailer (Gmail App Password) ---
const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// --- helper: đọc/ghi JSON ---
async function readJson(file) {
    try {
        const raw = await fs.readFile(file, "utf8");
        return JSON.parse(raw);
    } catch {
        return null;
    }
}
async function writeJson(file, data) {
    await fs.writeFile(file, JSON.stringify(data, null, 2), "utf8");
}

// --- Đăng nhập ---
app.post("/api/login", async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: "Email and password required" });

    const usersData = (await readJson(USERS_FILE)) || { users: [] };
    const user = usersData.users.find(u => u.email === email);
    if (!user) return res.status(401).json({ message: "Invalid credentials" });

    const match = await bcrypt.compare(password, user.passwordHash || "");
    if (!match) return res.status(401).json({ message: "Invalid credentials" });

    return res.json({ message: "OK", id: user.id });
});

// --- Quên mật khẩu ---
app.post("/api/forgot-password", async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: "Email required" });

    const usersData = (await readJson(USERS_FILE)) || { users: [] };
    const user = usersData.users.find(u => u.email === email);
    if (!user) {
        return res.json({ message: "If that email exists, a reset link has been sent." });
    }

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: `${TOKEN_EXPIRES_MIN}m` });

    const resets = (await readJson(RESETS_FILE)) || {};
    resets[user.id] = {
        token,
        createdAt: Date.now(),
        expiresAt: Date.now() + TOKEN_EXPIRES_MIN * 60 * 1000
    };
    await writeJson(RESETS_FILE, resets);

    const resetUrl = `${FRONTEND_URL}/reset-password?token=${encodeURIComponent(token)}`;
    const mailOptions = {
        from: `Your App <${process.env.EMAIL_USER}>`,
        to: user.email,
        subject: "Yêu cầu đặt lại mật khẩu",
        html: `
            <p>Xin chào,</p>
            <p>Bạn hoặc ai đó đã yêu cầu đặt lại mật khẩu. Nhấn link để đặt lại (hết hạn ${TOKEN_EXPIRES_MIN} phút):</p>
            <p><a href="${resetUrl}">Đặt lại mật khẩu</a></p>
            <p>Nếu bạn không yêu cầu, hãy bỏ qua email này.</p>
        `
    };

    try {
        await transporter.sendMail(mailOptions);
        return res.json({ message: "If that email exists, a reset link has been sent." });
    } catch (err) {
        console.error("Mail error:", err);
        return res.status(500).json({ message: "Không thể gửi email" });
    }
});

// --- Đặt lại mật khẩu ---
app.post("/api/reset-password", async (req, res) => {
    const { token, newPassword } = req.body;
    if (!token || !newPassword) return res.status(400).json({ message: "Token and newPassword required" });

    try {
        const payload = jwt.verify(token, JWT_SECRET);
        const { id } = payload;

        const resets = (await readJson(RESETS_FILE)) || {};
        const stored = resets[id];
        if (!stored || stored.token !== token) {
            return res.status(400).json({ message: "Token invalid or used" });
        }

        const hashed = await bcrypt.hash(newPassword, 10);

        const usersData = (await readJson(USERS_FILE)) || { users: [] };
        const idx = usersData.users.findIndex(u => u.id === id);
        if (idx === -1) return res.status(400).json({ message: "User not found" });

        usersData.users[idx].passwordHash = hashed;
        await writeJson(USERS_FILE, usersData);

        delete resets[id];
        await writeJson(RESETS_FILE, resets);

        return res.json({ message: "Password reset successful" });
    } catch (err) {
        console.error("Reset error:", err);
        return res.status(400).json({ message: "Token invalid or expired" });
    }
});

// --- Start server ---
app.listen(PORT, () => {
    console.log(`Backend started on port ${PORT}`);
});
