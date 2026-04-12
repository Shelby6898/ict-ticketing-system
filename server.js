require('dotenv').config();
const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const admin = require('firebase-admin');
const { Resend } = require('resend');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const compression = require('compression');

// ---------------- APP INIT ----------------
const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 5000;
const SECRET = process.env.JWT_SECRET || "CHANGE_ME";
const BASE_URL = process.env.BASE_URL || 'https://ict-ticketing-system-production.up.railway.app';

// ---------------- FIREBASE INIT ----------------
const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  storageBucket: "ict-ticketing-system-39542.appspot.com"
});

const db = admin.firestore();
const bucket = admin.storage().bucket();

// ---------------- RESEND EMAIL INIT ----------------
const resend = new Resend(process.env.RESEND_API_KEY);

async function sendEmail({ to, subject, html }) {
  try {
    await resend.emails.send({
      from: 'ICT HelpDesk <onboarding@resend.dev>',
      to: 'elphazshelby@gmail.com',
      subject: `[To: ${to}] ${subject}`,
      html
    });
  } catch (e) {
    console.error('Email error:', e.message);
  }
}

// ---------------- SECURITY MIDDLEWARE ----------------
app.use(helmet({ contentSecurityPolicy: false }));
app.use(compression());
app.use(morgan('dev'));
app.use(cors({ origin: process.env.CORS_ORIGIN || '*' }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// ---------------- SERVE INDEX WITH RUNTIME API URL FIX ----------------
app.get('/', (req, res) => {
  let html = fs.readFileSync(path.join(__dirname, 'public/index.html'), 'utf8');
  html = html.replace(/const API = ['"].*?['"]/g, "const API = 'https://ict-ticketing-system-production.up.railway.app/api'");
  res.send(html);
});

app.use(express.static('public'));

// ---------------- RATE LIMITING ----------------
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: { error: 'Too many requests, try again later.' }
});
app.use(limiter);

// ---------------- FILE UPLOAD CONFIG ----------------
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }
});

// ---------------- AUTH MIDDLEWARE ----------------
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'Missing token' });

  const token = header.startsWith('Bearer ')
    ? header.split(' ')[1]
    : header;

  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function isAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admins only' });
  }
  next();
}

// ---------------- REGISTER ----------------
app.post('/api/register', async (req, res, next) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'All fields required' });
    }

    // Check if email already exists
    const existing = await db.collection('users').where('email', '==', email).get();
    if (!existing.empty) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    const hash = await bcrypt.hash(password, 10);

    // Save user as unverified
    const userRef = await db.collection('users').add({
      name,
      email,
      password: hash,
      role: 'user',
      verified: false,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

    // Generate verification token (expires in 24 hours)
    const verifyToken = jwt.sign(
      { userId: userRef.id, email },
      SECRET,
      { expiresIn: '24h' }
    );

    const verifyLink = `${BASE_URL}/api/verify-email/${verifyToken}`;

    // Send verification email
    await sendEmail({
      to: email,
      subject: 'Verify Your ICT HelpDesk Account',
      html: `
        <div style="font-family:'Segoe UI',sans-serif;max-width:560px;margin:auto;background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.08);">
          
          <!-- Header -->
          <div style="background:linear-gradient(135deg,#7c5cfc,#00d4ff);padding:40px 32px;text-align:center;">
            <h1 style="color:#ffffff;font-size:26px;margin:0;letter-spacing:-0.5px;">🖥️ ICT HelpDesk</h1>
            <p style="color:rgba(255,255,255,0.85);margin:8px 0 0;font-size:14px;">Your support, our priority</p>
          </div>

          <!-- Body -->
          <div style="padding:40px 32px;">
            <h2 style="font-size:22px;color:#1a1a2e;margin:0 0 8px;">Dear ${name},</h2>
            <p style="color:#555;font-size:15px;line-height:1.7;margin:0 0 20px;">
              Welcome to <strong>ICT HelpDesk</strong>! Your account has been successfully created.
            </p>
            <p style="color:#555;font-size:15px;line-height:1.7;margin:0 0 28px;">
              Your account is <strong>not fully activated</strong> until you verify your email address. 
              Please click the button below to verify your account and get started.
            </p>

            <!-- Verify Button -->
            <div style="text-align:center;margin:32px 0;">
              <a href="${verifyLink}" 
                 style="display:inline-block;background:linear-gradient(135deg,#7c5cfc,#5a3fd6);color:#ffffff;text-decoration:none;padding:16px 40px;border-radius:10px;font-size:16px;font-weight:600;letter-spacing:0.3px;box-shadow:0 4px 16px rgba(124,92,252,0.4);">
                ✅ Verify Account Now
              </a>
            </div>

            <p style="color:#888;font-size:13px;text-align:center;margin:0 0 28px;">
              This link expires in <strong>24 hours</strong>. If you did not create this account, you can safely ignore this email.
            </p>

            <!-- Divider -->
            <hr style="border:none;border-top:1px solid #eee;margin:28px 0;"/>

            <!-- Support -->
            <div style="text-align:center;">
              <p style="color:#555;font-size:14px;margin:0 0 6px;">Have any questions?</p>
              <p style="color:#555;font-size:14px;margin:0 0 12px;">Contact our support team anytime <strong>24/7</strong></p>
              <a href="mailto:${process.env.ADMIN_EMAIL || 'elphazshelby@gmail.com'}" 
                 style="color:#7c5cfc;font-size:14px;text-decoration:none;font-weight:600;">
                📧 Contact Support
              </a>
            </div>
          </div>

          <!-- Footer -->
          <div style="background:#f8f9fc;padding:20px 32px;text-align:center;border-top:1px solid #eee;">
            <p style="color:#aaa;font-size:12px;margin:0;">
              © ${new Date().getFullYear()} ICT HelpDesk. All rights reserved.
            </p>
            <p style="margin:6px 0 0;">
              <a href="${BASE_URL}" style="color:#7c5cfc;font-size:12px;text-decoration:none;">${BASE_URL}</a>
            </p>
          </div>

        </div>
      `
    });

    res.json({ message: 'Registration successful! Please check your email to verify your account.' });
  } catch (err) {
    next(err);
  }
});

// ---------------- VERIFY EMAIL ----------------
app.get('/api/verify-email/:token', async (req, res) => {
  try {
    const decoded = jwt.verify(req.params.token, SECRET);

    await db.collection('users').doc(decoded.userId).update({ verified: true });

    // Redirect to login with success message
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Email Verified — ICT HelpDesk</title>
        <link href="https://fonts.googleapis.com/css2?family=Syne:wght@700;800&family=DM+Sans:wght@400;500&display=swap" rel="stylesheet"/>
        <style>
          * { margin:0; padding:0; box-sizing:border-box; }
          body {
            font-family: 'DM Sans', sans-serif;
            background: #0b0f1a;
            color: #e8edf5;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
          }
          .card {
            background: #131929;
            border: 1px solid #1f2d45;
            border-radius: 20px;
            padding: 48px 44px;
            max-width: 440px;
            width: 100%;
            text-align: center;
            box-shadow: 0 32px 80px rgba(0,0,0,0.5);
          }
          .icon {
            width: 80px; height: 80px;
            background: linear-gradient(135deg, #2ed573, #00b35a);
            border-radius: 50%;
            display: flex; align-items: center; justify-content: center;
            font-size: 36px;
            margin: 0 auto 24px;
            box-shadow: 0 8px 32px rgba(46,213,115,0.3);
          }
          h1 { font-family: 'Syne', sans-serif; font-size: 26px; margin-bottom: 12px; }
          p { color: #6b7d9a; font-size: 15px; line-height: 1.6; margin-bottom: 28px; }
          a {
            display: inline-block;
            background: linear-gradient(135deg, #7c5cfc, #5a3fd6);
            color: #fff;
            text-decoration: none;
            padding: 14px 32px;
            border-radius: 10px;
            font-family: 'Syne', sans-serif;
            font-weight: 600;
            font-size: 15px;
          }
          a:hover { opacity: 0.9; }
        </style>
      </head>
      <body>
        <div class="card">
          <div class="icon">✅</div>
          <h1>Email Verified!</h1>
          <p>Your ICT HelpDesk account has been successfully verified. You can now sign in and submit tickets.</p>
          <a href="${BASE_URL}">Sign In Now</a>
        </div>
      </body>
      </html>
    `);
  } catch (err) {
    res.status(400).send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Invalid Link — ICT HelpDesk</title>
        <style>
          body { font-family: sans-serif; background: #0b0f1a; color: #e8edf5; display:flex; align-items:center; justify-content:center; min-height:100vh; }
          .card { background:#131929; border:1px solid #1f2d45; border-radius:20px; padding:48px 44px; max-width:440px; text-align:center; }
          h1 { color: #ff4757; margin-bottom:12px; }
          p { color:#6b7d9a; margin-bottom:24px; }
          a { color:#7c5cfc; }
        </style>
      </head>
      <body>
        <div class="card">
          <h1>❌ Invalid or Expired Link</h1>
          <p>This verification link has expired or is invalid. Please register again.</p>
          <a href="${BASE_URL}">Back to HelpDesk</a>
        </div>
      </body>
      </html>
    `);
  }
});

// ---------------- LOGIN ----------------
app.post('/api/login', async (req, res, next) => {
  try {
    const { email, password } = req.body;

    const snap = await db.collection('users')
      .where('email', '==', email)
      .get();

    if (snap.empty) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const doc = snap.docs[0];
    const user = doc.data();

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Block unverified users
    if (!user.verified) {
      return res.status(403).json({ error: 'Please verify your email before logging in. Check your inbox.' });
    }

    const token = jwt.sign(
      { id: doc.id, email: user.email, role: user.role },
      SECRET,
      { expiresIn: '1d' }
    );

    res.json({
      token,
      user: {
        id: doc.id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });

  } catch (err) {
    next(err);
  }
});

// ---------------- TICKETS ----------------
app.post('/api/tickets', auth, async (req, res, next) => {
  try {
    const { title, description, priority, category, device } = req.body;

    const doc = await db.collection('tickets').add({
      title,
      description,
      priority,
      category: category || 'other',
      device: device || '',
      status: 'open',
      userEmail: req.user.email,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

    // Email to user
    sendEmail({
      to: req.user.email,
      subject: `✅ Ticket Received — ${title}`,
      html: `
        <div style="font-family:sans-serif;max-width:520px;margin:auto;padding:32px;background:#f9f9f9;border-radius:12px;">
          <h2 style="color:#7c5cfc;">ICT HelpDesk</h2>
          <p>Hi there,</p>
          <p>Your ticket has been received and our ICT team will look into it shortly.</p>
          <div style="background:#fff;border:1px solid #eee;border-radius:8px;padding:20px;margin:20px 0;">
            <p><strong>Ticket ID:</strong> ${doc.id}</p>
            <p><strong>Title:</strong> ${title}</p>
            <p><strong>Category:</strong> ${category || 'other'}</p>
            <p><strong>Priority:</strong> ${priority}</p>
            <p><strong>Description:</strong> ${description}</p>
          </div>
          <p style="color:#888;font-size:13px;">You will be notified when the status changes.</p>
        </div>
      `
    });

    // Email to admin
    sendEmail({
      to: process.env.ADMIN_EMAIL || 'elphazshelby@gmail.com',
      subject: `🎫 New Ticket — ${title} [${(priority||'').toUpperCase()}]`,
      html: `
        <div style="font-family:sans-serif;max-width:520px;margin:auto;padding:32px;background:#f9f9f9;border-radius:12px;">
          <h2 style="color:#ff4757;">New Ticket Submitted</h2>
          <div style="background:#fff;border:1px solid #eee;border-radius:8px;padding:20px;margin:20px 0;">
            <p><strong>Ticket ID:</strong> ${doc.id}</p>
            <p><strong>From:</strong> ${req.user.email}</p>
            <p><strong>Title:</strong> ${title}</p>
            <p><strong>Category:</strong> ${category || 'other'}</p>
            <p><strong>Priority:</strong> ${priority}</p>
            <p><strong>Description:</strong> ${description}</p>
          </div>
          <p style="color:#888;font-size:13px;">Login to the admin dashboard to manage this ticket.</p>
        </div>
      `
    });

    res.json({ id: doc.id });
  } catch (err) {
    next(err);
  }
});

app.get('/api/tickets', auth, async (req, res, next) => {
  try {
    const snap = await db.collection('tickets')
      .orderBy('createdAt', 'desc')
      .get();

    const tickets = snap.docs.map(d => ({
      id: d.id,
      ...d.data()
    }));

    res.json({ tickets });
  } catch (err) {
    next(err);
  }
});

app.put('/api/tickets/:id', auth, isAdmin, async (req, res, next) => {
  try {
    const { status } = req.body;
    const ticketRef = db.collection('tickets').doc(req.params.id);

    const ticketSnap = await ticketRef.get();
    if (!ticketSnap.exists) {
      return res.status(404).json({ error: 'Ticket not found' });
    }

    const ticket = ticketSnap.data();
    await ticketRef.update({ status });

    const statusConfig = {
      'open':        { label: 'Open',        color: '#ffa502', emoji: '🟡' },
      'in-progress': { label: 'In Progress', color: '#00d4ff', emoji: '🔵' },
      'closed':      { label: 'Closed',      color: '#2ed573', emoji: '✅' }
    };

    const cfg = statusConfig[status] || { label: status, color: '#888', emoji: '📋' };

    sendEmail({
      to: ticket.userEmail,
      subject: `${cfg.emoji} Ticket Update — ${ticket.title}`,
      html: `
        <div style="font-family:sans-serif;max-width:520px;margin:auto;padding:32px;background:#f9f9f9;border-radius:12px;">
          <h2 style="color:#7c5cfc;">ICT HelpDesk</h2>
          <p>Hi there,</p>
          <p>Your ticket status has been updated by our ICT team.</p>
          <div style="background:#fff;border:1px solid #eee;border-radius:8px;padding:20px;margin:20px 0;">
            <p><strong>Ticket ID:</strong> ${ticketSnap.id}</p>
            <p><strong>Title:</strong> ${ticket.title}</p>
            <p><strong>New Status:</strong> <span style="color:${cfg.color};font-weight:700;">${cfg.label}</span></p>
            <p><strong>Priority:</strong> ${ticket.priority}</p>
          </div>
          ${status === 'closed'
            ? `<p style="color:#2ed573;font-weight:600;">Your issue has been resolved. Thank you for reaching out!</p>`
            : `<p>Our team is actively working on your issue. We will keep you updated.</p>`
          }
          <p style="color:#888;font-size:13px;">If you have further questions, please submit a new ticket.</p>
        </div>
      `
    });

    res.json({ message: 'Ticket updated' });
  } catch (err) {
    next(err);
  }
});

// ---------------- COMMENTS ----------------
app.post('/api/tickets/:id/comments', auth, async (req, res, next) => {
  try {
    await db.collection('tickets')
      .doc(req.params.id)
      .collection('comments')
      .add({
        message: req.body.message,
        userId: req.user.id,
        createdAt: admin.firestore.FieldValue.serverTimestamp()
      });

    res.json({ message: 'Comment added' });
  } catch (err) {
    next(err);
  }
});

// ---------------- FILE UPLOAD ----------------
app.post('/api/upload/:ticketId', auth, upload.single('file'), async (req, res, next) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const file = req.file;
    const filename = `${uuidv4()}-${file.originalname}`;
    const blob = bucket.file(filename);
    const stream = blob.createWriteStream();
    stream.end(file.buffer);

    await new Promise((resolve, reject) => {
      stream.on('finish', resolve);
      stream.on('error', reject);
    });

    const url = `https://storage.googleapis.com/${bucket.name}/${filename}`;

    await db.collection('tickets')
      .doc(req.params.ticketId)
      .collection('attachments')
      .add({ url });

    res.json({ url });
  } catch (err) {
    next(err);
  }
});

// ---------------- FORGOT PASSWORD ----------------
app.post('/api/forgot-password', async (req, res, next) => {
  try {
    const { email } = req.body;

    const snap = await db.collection('users')
      .where('email', '==', email)
      .get();

    if (snap.empty) {
      return res.status(404).json({ error: 'User not found' });
    }

    const token = jwt.sign({ email }, SECRET, { expiresIn: '10m' });
    const link = `${BASE_URL}/api/reset-password/${token}`;

    await sendEmail({
      to: email,
      subject: 'Password Reset — ICT HelpDesk',
      html: `
        <div style="font-family:sans-serif;max-width:520px;margin:auto;padding:32px;background:#f9f9f9;border-radius:12px;">
          <h2 style="color:#7c5cfc;">ICT HelpDesk</h2>
          <p>Click the link below to reset your password. This link expires in 10 minutes.</p>
          <a href="${link}" style="display:inline-block;margin-top:16px;padding:12px 24px;background:#7c5cfc;color:#fff;border-radius:8px;text-decoration:none;">Reset Password</a>
          <p style="color:#888;font-size:13px;margin-top:20px;">If you didn't request this, ignore this email.</p>
        </div>
      `
    });

    res.json({ message: 'Reset email sent' });
  } catch (err) {
    next(err);
  }
});

// ---------------- RESET PASSWORD ----------------
app.post('/api/reset-password/:token', async (req, res) => {
  try {
    const decoded = jwt.verify(req.params.token, SECRET);
    const hash = await bcrypt.hash(req.body.password, 10);

    const snap = await db.collection('users')
      .where('email', '==', decoded.email)
      .get();

    const id = snap.docs[0].id;

    await db.collection('users')
      .doc(id)
      .update({ password: hash });

    res.json({ message: 'Password updated' });
  } catch (err) {
    res.status(400).json({ error: 'Invalid or expired token' });
  }
});

// ---------------- GLOBAL ERROR HANDLER ----------------
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

// ---------------- START SERVER ----------------
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});/ /   v e r i f y   f e a t u r e  
 