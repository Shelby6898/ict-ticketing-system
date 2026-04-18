
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

// ─────────────────────────────────────────
//  APP INIT
// ─────────────────────────────────────────
const app = express();

app.set('trust proxy', 1);

const PORT        = process.env.PORT        || 5000;
const SECRET      = process.env.JWT_SECRET;
const BASE_URL    = process.env.BASE_URL    || 'https://ict-ticketing-system-production.up.railway.app';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'elphazshelby@gmail.com';

if (!SECRET) {
  console.error('FATAL: JWT_SECRET env variable is not set.');
  process.exit(1);
}

// ─────────────────────────────────────────
//  FIREBASE INIT
// ─────────────────────────────────────────
const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  storageBucket: 'ict-ticketing-system-39542.appspot.com'
});

const db     = admin.firestore();
const bucket = admin.storage().bucket();

// ─────────────────────────────────────────
//  EMAIL
// ─────────────────────────────────────────
const resend = new Resend(process.env.RESEND_API_KEY);

async function sendEmail({ to, subject, html }) {
  try {
    return await resend.emails.send({
      from: 'ICT HelpDesk <noreply@icthelpdesk.site>',
      to,
      subject,
      html
    });
  } catch (err) {
    console.error('Email failed:', err.message);
  }
}

// ─────────────────────────────────────────
//  SECURITY + CORE MIDDLEWARE
// ─────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));
app.use(compression());
app.use(morgan('dev'));
app.use(cors({ origin: process.env.CORS_ORIGIN || '*' }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' }
});
app.use(limiter);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts. Please try again in 15 minutes.' }
});

// ─────────────────────────────────────────
//  BOT & PROBE PROTECTION
// ─────────────────────────────────────────
const BOT_PATHS = [
  '/wp-admin', '/wp-login', '/wordpress', '/.env',
  '/phpMyAdmin', '/phpmyadmin', '/admin.php',
  '/.git', '/config', '/backup', '/shell'
];

app.use((req, res, next) => {
  const isBotPath = BOT_PATHS.some(p =>
    req.path.toLowerCase().startsWith(p.toLowerCase())
  );
  if (isBotPath) {
    console.warn(`[BLOCKED BOT] ${req.method} ${req.path} — IP: ${req.ip}`);
    return res.status(403).end();
  }
  next();
});

// ─────────────────────────────────────────
//  STATIC NOISE SUPPRESSION
// ─────────────────────────────────────────
app.get('/favicon.ico', (_req, res) => res.status(204).end());
app.get('/robots.txt',  (_req, res) =>
  res.type('text/plain').send('User-agent: *\nDisallow: /api/\n')
);

// ─────────────────────────────────────────
//  SERVE FRONTEND
// ─────────────────────────────────────────
app.get('/', (req, res) => {
  let html = fs.readFileSync(path.join(__dirname, 'public/index.html'), 'utf8');
  html = html.replace(
    /const API = ['"].*?['"]/g,
    `const API = '${BASE_URL}/api'`
  );
  res.send(html);
});

app.use(express.static('public'));

// ─────────────────────────────────────────
//  FILE UPLOAD CONFIG
// ─────────────────────────────────────────
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }
});

// ─────────────────────────────────────────
//  AUTH HELPERS
// ─────────────────────────────────────────
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'Missing token' });

  const token = header.startsWith('Bearer ') ? header.split(' ')[1] : header;

  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function isAdmin(req, res, next) {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({ error: 'Admins only' });
  }
  next();
}

// ─────────────────────────────────────────
//  REGISTER
// ─────────────────────────────────────────
app.post('/api/register', authLimiter, async (req, res, next) => {
  try {
    const { name, email, password } = req.body;

    if (!name?.trim() || !email?.trim() || !password) {
      return res.status(400).json({ error: 'All fields are required.' });
    }

    const emailLower = email.toLowerCase().trim();
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(emailLower)) {
      return res.status(400).json({ error: 'Invalid email address.' });
    }

    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    }

    const existing = await db.collection('users').where('email', '==', emailLower).get();
    if (!existing.empty) {
      return res.status(400).json({ error: 'Email already registered.' });
    }

    const hash = await bcrypt.hash(password, 10);

    const userRef = await db.collection('users').add({
      name:      name.trim(),
      email:     emailLower,
      password:  hash,
      role:      'user',
      verified:  false,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

    const verifyToken = jwt.sign(
      { userId: userRef.id, email: emailLower },
      SECRET,
      { expiresIn: '24h' }
    );

    const verifyLink = `${BASE_URL}/api/verify-email/${verifyToken}`;

    await sendEmail({
      to: emailLower,
      subject: 'Verify Your ICT HelpDesk Account',
      html: `
        <div style="font-family:'Segoe UI',sans-serif;max-width:560px;margin:auto;background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.08);">
          <div style="background:linear-gradient(135deg,#7c5cfc,#00d4ff);padding:40px 32px;text-align:center;">
            <h1 style="color:#ffffff;font-size:26px;margin:0;">🖥️ ICT HelpDesk</h1>
            <p style="color:rgba(255,255,255,0.85);margin:8px 0 0;font-size:14px;">Your support, our priority</p>
          </div>
          <div style="padding:40px 32px;">
            <h2 style="font-size:22px;color:#1a1a2e;margin:0 0 8px;">Dear ${name.trim()},</h2>
            <p style="color:#555;font-size:15px;line-height:1.7;margin:0 0 20px;">
              Welcome to <strong>ICT HelpDesk</strong>! Your account has been created.
            </p>
            <p style="color:#555;font-size:15px;line-height:1.7;margin:0 0 28px;">
              Please verify your email to activate your account.
            </p>
            <div style="text-align:center;margin:32px 0;">
              <a href="${verifyLink}"
                 style="display:inline-block;background:linear-gradient(135deg,#7c5cfc,#5a3fd6);color:#ffffff;text-decoration:none;padding:16px 40px;border-radius:10px;font-size:16px;font-weight:600;">
                ✅ Verify Account Now
              </a>
            </div>
            <p style="color:#888;font-size:13px;text-align:center;">
              This link expires in <strong>24 hours</strong>. If you did not create this account, ignore this email.
            </p>
            <hr style="border:none;border-top:1px solid #eee;margin:28px 0;"/>
            <div style="text-align:center;">
              <p style="color:#555;font-size:14px;margin:0 0 6px;">Need help?</p>
              <a href="mailto:${ADMIN_EMAIL}" style="color:#7c5cfc;font-size:14px;text-decoration:none;font-weight:600;">
                📧 Contact Support
              </a>
            </div>
          </div>
          <div style="background:#f8f9fc;padding:20px 32px;text-align:center;border-top:1px solid #eee;">
            <p style="color:#aaa;font-size:12px;margin:0;">© ${new Date().getFullYear()} ICT HelpDesk. All rights reserved.</p>
          </div>
        </div>
      `
    });

    res.json({ message: 'Registration successful! Please check your email to verify your account.' });
  } catch (err) {
    next(err);
  }
});

// ─────────────────────────────────────────
//  VERIFY EMAIL
// ─────────────────────────────────────────
app.get('/api/verify-email/:token', async (req, res) => {
  try {
    const decoded = jwt.verify(req.params.token, SECRET);
    await db.collection('users').doc(decoded.userId).update({ verified: true });

    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8"/>
        <title>Email Verified — ICT HelpDesk</title>
        <link href="https://fonts.googleapis.com/css2?family=Syne:wght@700;800&family=DM+Sans:wght@400;500&display=swap" rel="stylesheet"/>
        <style>
          *{margin:0;padding:0;box-sizing:border-box}
          body{font-family:'DM Sans',sans-serif;background:#0b0f1a;color:#e8edf5;min-height:100vh;display:flex;align-items:center;justify-content:center}
          .card{background:#131929;border:1px solid #1f2d45;border-radius:20px;padding:48px 44px;max-width:440px;width:90%;text-align:center;box-shadow:0 32px 80px rgba(0,0,0,.5)}
          .icon{width:80px;height:80px;background:linear-gradient(135deg,#2ed573,#00b35a);border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:36px;margin:0 auto 24px;box-shadow:0 8px 32px rgba(46,213,115,.3)}
          h1{font-family:'Syne',sans-serif;font-size:26px;margin-bottom:12px}
          p{color:#6b7d9a;font-size:15px;line-height:1.6;margin-bottom:28px}
          a{display:inline-block;background:linear-gradient(135deg,#7c5cfc,#5a3fd6);color:#fff;text-decoration:none;padding:14px 32px;border-radius:10px;font-family:'Syne',sans-serif;font-weight:600;font-size:15px}
          a:hover{opacity:.9}
        </style>
      </head>
      <body>
        <div class="card">
          <div class="icon">✅</div>
          <h1>Email Verified!</h1>
          <p>Your ICT HelpDesk account is now active. You can sign in and submit tickets.</p>
          <a href="${BASE_URL}">Sign In Now</a>
        </div>
      </body>
      </html>
    `);
  } catch {
    res.status(400).send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8"/>
        <title>Invalid Link — ICT HelpDesk</title>
        <style>
          *{margin:0;padding:0;box-sizing:border-box}
          body{font-family:sans-serif;background:#0b0f1a;color:#e8edf5;display:flex;align-items:center;justify-content:center;min-height:100vh}
          .card{background:#131929;border:1px solid #1f2d45;border-radius:20px;padding:48px 44px;max-width:440px;width:90%;text-align:center}
          h1{color:#ff4757;margin-bottom:12px}p{color:#6b7d9a;margin-bottom:24px}a{color:#7c5cfc}
        </style>
      </head>
      <body>
        <div class="card">
          <h1>❌ Invalid or Expired Link</h1>
          <p>This verification link has expired or is invalid. Please register again or request a new verification email.</p>
          <a href="${BASE_URL}">Back to HelpDesk</a>
        </div>
      </body>
      </html>
    `);
  }
});

// ─────────────────────────────────────────
//  LOGIN
// ─────────────────────────────────────────
app.post('/api/login', authLimiter, async (req, res, next) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    const cleanEmail = email.toLowerCase().trim();

    const snap = await db.collection('users')
      .where('email', '==', cleanEmail)
      .limit(1)
      .get();

    if (snap.empty) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    const doc  = snap.docs[0];
    const user = doc.data();

    if (!user.password) {
      console.error('User has no password field:', cleanEmail);
      return res.status(500).json({ error: 'Account misconfigured.' });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    if (user.verified !== true) {
      return res.status(403).json({ error: 'Email not verified. Please check your inbox.' });
    }

    const token = jwt.sign(
      {
        id:    doc.id,
        email: user.email,
        name:  user.name  || '',
        role:  user.role  || 'user'
      },
      SECRET,
      { expiresIn: '1d' }
    );

    return res.json({
      token,
      user: {
        id:    doc.id,
        name:  user.name,
        email: user.email,
        role:  user.role || 'user'
      }
    });
  } catch (err) {
    next(err);
  }
});

// ─────────────────────────────────────────
//  TICKETS
// ─────────────────────────────────────────
app.post('/api/tickets', auth, async (req, res, next) => {
  try {
    let { title, description, priority, category, device } = req.body;

    title       = title?.trim();
    description = description?.trim();
    priority    = priority?.trim() || 'low';
    category    = category?.trim() || 'other';
    device      = device?.trim()   || '';

    if (!title || !description) {
      return res.status(400).json({ error: 'Title and description are required.' });
    }

    const doc = await db.collection('tickets').add({
      title,
      description,
      priority,
      category,
      device,
      status:    'open',
      userId:    req.user.id,
      userEmail: req.user.email,
      userName:  req.user.name || '',
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

    const ticketHtml = (heading, color) => `
      <div style="font-family:sans-serif;max-width:520px;margin:auto;padding:32px;background:#f9f9f9;border-radius:12px;">
        <h2 style="color:${color};">ICT HelpDesk</h2>
        <p>${heading}</p>
        <div style="background:#fff;border:1px solid #eee;border-radius:8px;padding:20px;margin:20px 0;">
          <p><strong>Ticket ID:</strong> ${doc.id}</p>
          <p><strong>Title:</strong> ${title}</p>
          <p><strong>Category:</strong> ${category}</p>
          <p><strong>Priority:</strong> ${priority}</p>
          <p><strong>Description:</strong> ${description}</p>
        </div>
      </div>
    `;

    sendEmail({
      to:      req.user.email,
      subject: `✅ Ticket Received — ${title}`,
      html:    ticketHtml('Your ticket has been received. Our ICT team will respond shortly.', '#7c5cfc')
    });

    sendEmail({
      to:      ADMIN_EMAIL,
      subject: `🎫 New Ticket — ${title} [${priority.toUpperCase()}]`,
      html:    ticketHtml(`New ticket submitted by <strong>${req.user.email}</strong>.`, '#ff4757')
    });

    res.status(201).json({ id: doc.id });
  } catch (err) {
    next(err);
  }
});

app.get('/api/tickets', auth, async (req, res, next) => {
  try {
    let query = db.collection('tickets').orderBy('createdAt', 'desc');

    if (req.user.role !== 'admin') {
      query = query.where('userId', '==', req.user.id);
    }

    const snap    = await query.get();
    const tickets = snap.docs.map(d => ({ id: d.id, ...d.data() }));

    res.json({ tickets });
  } catch (err) {
    next(err);
  }
});

app.put('/api/tickets/:id', auth, isAdmin, async (req, res, next) => {
  try {
    const { status } = req.body;

    const validStatuses = ['open', 'in-progress', 'closed'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ error: `Status must be one of: ${validStatuses.join(', ')}` });
    }

    const ticketRef  = db.collection('tickets').doc(req.params.id);
    const ticketSnap = await ticketRef.get();

    if (!ticketSnap.exists) {
      return res.status(404).json({ error: 'Ticket not found.' });
    }

    const ticket = ticketSnap.data();
    await ticketRef.update({ status, updatedAt: admin.firestore.FieldValue.serverTimestamp() });

    const statusConfig = {
      'open':        { label: 'Open',        color: '#ffa502', emoji: '🟡' },
      'in-progress': { label: 'In Progress', color: '#00d4ff', emoji: '🔵' },
      'closed':      { label: 'Closed',      color: '#2ed573', emoji: '✅' }
    };

    const cfg = statusConfig[status];

    sendEmail({
      to:      ticket.userEmail,
      subject: `${cfg.emoji} Ticket Update — ${ticket.title}`,
      html: `
        <div style="font-family:sans-serif;max-width:520px;margin:auto;padding:32px;background:#f9f9f9;border-radius:12px;">
          <h2 style="color:#7c5cfc;">ICT HelpDesk</h2>
          <p>Your ticket status has been updated.</p>
          <div style="background:#fff;border:1px solid #eee;border-radius:8px;padding:20px;margin:20px 0;">
            <p><strong>Ticket ID:</strong> ${ticketSnap.id}</p>
            <p><strong>Title:</strong> ${ticket.title}</p>
            <p><strong>New Status:</strong> <span style="color:${cfg.color};font-weight:700;">${cfg.label}</span></p>
            <p><strong>Priority:</strong> ${ticket.priority}</p>
          </div>
          ${status === 'closed'
            ? `<p style="color:#2ed573;font-weight:600;">Your issue has been resolved. Thank you!</p>`
            : `<p>Our team is actively working on your issue.</p>`
          }
          <p style="color:#888;font-size:13px;">For further questions, please submit a new ticket.</p>
        </div>
      `
    });

    res.json({ message: 'Ticket updated.' });
  } catch (err) {
    next(err);
  }
});

// ─────────────────────────────────────────
//  COMMENTS
// ─────────────────────────────────────────
app.get('/api/tickets/:id/comments', auth, async (req, res, next) => {
  try {
    const ticketRef  = db.collection('tickets').doc(req.params.id);
    const ticketSnap = await ticketRef.get();

    if (!ticketSnap.exists) {
      return res.status(404).json({ error: 'Ticket not found.' });
    }

    const ticket = ticketSnap.data();
    if (req.user.role !== 'admin' && ticket.userId !== req.user.id) {
      return res.status(403).json({ error: 'Access denied.' });
    }

    const snap     = await ticketRef.collection('comments').orderBy('createdAt', 'asc').get();
    const comments = snap.docs.map(d => ({ id: d.id, ...d.data() }));

    res.json({ comments });
  } catch (err) {
    next(err);
  }
});

app.post('/api/tickets/:id/comments', auth, async (req, res, next) => {
  try {
    const message = req.body.message?.trim();
    if (!message) {
      return res.status(400).json({ error: 'Comment cannot be empty.' });
    }

    const ticketRef  = db.collection('tickets').doc(req.params.id);
    const ticketSnap = await ticketRef.get();

    if (!ticketSnap.exists) {
      return res.status(404).json({ error: 'Ticket not found.' });
    }

    const ticket = ticketSnap.data();
    if (req.user.role !== 'admin' && ticket.userId !== req.user.id) {
      return res.status(403).json({ error: 'Access denied.' });
    }

    await ticketRef.collection('comments').add({
      message,
      userId:    req.user.id,
      userEmail: req.user.email,
      userName:  req.user.name || '',
      role:      req.user.role,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

    res.json({ message: 'Comment added.' });
  } catch (err) {
    next(err);
  }
});

// ─────────────────────────────────────────
//  FILE UPLOAD
// ─────────────────────────────────────────
app.post('/api/upload/:ticketId', auth, upload.single('file'), async (req, res, next) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded.' });
    }

    const ticketRef  = db.collection('tickets').doc(req.params.ticketId);
    const ticketSnap = await ticketRef.get();

    if (!ticketSnap.exists) {
      return res.status(404).json({ error: 'Ticket not found.' });
    }

    const ticket = ticketSnap.data();
    if (req.user.role !== 'admin' && ticket.userId !== req.user.id) {
      return res.status(403).json({ error: 'Access denied.' });
    }

    const filename = `${uuidv4()}-${req.file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_')}`;
    const blob     = bucket.file(filename);
    const stream   = blob.createWriteStream({ metadata: { contentType: req.file.mimetype } });

    stream.end(req.file.buffer);

    await new Promise((resolve, reject) => {
      stream.on('finish', resolve);
      stream.on('error', reject);
    });

    const url = `https://storage.googleapis.com/${bucket.name}/${filename}`;

    await ticketRef.collection('attachments').add({
      url,
      filename:    req.file.originalname,
      uploadedBy:  req.user.email,
      uploadedAt:  admin.firestore.FieldValue.serverTimestamp()
    });

    res.json({ url });
  } catch (err) {
    next(err);
  }
});

// ─────────────────────────────────────────
//  FORGOT PASSWORD
// ─────────────────────────────────────────
app.post('/api/forgot-password', authLimiter, async (req, res, next) => {
  try {
    const email = req.body.email?.toLowerCase().trim();
    const genericResponse = { message: 'If that email is registered, a reset link has been sent.' };

    if (!email) return res.json(genericResponse);

    const snap = await db.collection('users').where('email', '==', email).get();
    if (snap.empty) return res.json(genericResponse);

    const token = jwt.sign({ email }, SECRET, { expiresIn: '10m' });
    const link  = `${BASE_URL}/api/reset-password/${token}`;

    await sendEmail({
      to:      email,
      subject: 'Password Reset — ICT HelpDesk',
      html: `
        <div style="font-family:sans-serif;max-width:520px;margin:auto;padding:32px;background:#f9f9f9;border-radius:12px;">
          <h2 style="color:#7c5cfc;">ICT HelpDesk</h2>
          <p>Click the button below to reset your password. This link expires in <strong>10 minutes</strong>.</p>
          <div style="text-align:center;margin:24px 0;">
            <a href="${link}" style="display:inline-block;padding:12px 28px;background:#7c5cfc;color:#fff;border-radius:8px;text-decoration:none;font-weight:600;">
              Reset Password
            </a>
          </div>
          <p style="color:#888;font-size:13px;">If you didn't request this, you can safely ignore this email.</p>
        </div>
      `
    });

    res.json(genericResponse);
  } catch (err) {
    next(err);
  }
});

// ─────────────────────────────────────────
//  RESET PASSWORD — GET (show form)
// ─────────────────────────────────────────
app.get('/api/reset-password/:token', (req, res) => {
  const token = req.params.token;

  try {
    jwt.verify(token, SECRET);
  } catch {
    return res.status(400).send(`
      <!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"/>
      <title>Expired Link — ICT HelpDesk</title>
      <style>body{font-family:sans-serif;background:#0b0f1a;color:#e8edf5;display:flex;align-items:center;justify-content:center;min-height:100vh}
      .card{background:#131929;border:1px solid #1f2d45;border-radius:20px;padding:48px 44px;max-width:440px;width:90%;text-align:center}
      h1{color:#ff4757;margin-bottom:12px}p{color:#6b7d9a;margin-bottom:24px}a{color:#7c5cfc}</style>
      </head><body>
      <div class="card">
        <h1>❌ Link Expired</h1>
        <p>This password reset link has expired. Please request a new one.</p>
        <a href="${BASE_URL}">Back to HelpDesk</a>
      </div></body></html>
    `);
  }

  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8"/>
      <title>Reset Password — ICT HelpDesk</title>
      <style>
        *{margin:0;padding:0;box-sizing:border-box}
        body{font-family:'Segoe UI',sans-serif;background:#0b0f1a;color:#e8edf5;min-height:100vh;display:flex;align-items:center;justify-content:center}
        .card{background:#131929;border:1px solid #1f2d45;border-radius:20px;padding:48px 44px;max-width:420px;width:90%;box-shadow:0 32px 80px rgba(0,0,0,.5)}
        h1{font-size:22px;margin-bottom:24px;text-align:center}
        label{display:block;font-size:13px;color:#6b7d9a;margin-bottom:6px}
        input{width:100%;padding:12px 16px;background:#0b0f1a;border:1px solid #2a3a52;border-radius:8px;color:#e8edf5;font-size:15px;margin-bottom:16px;outline:none}
        input:focus{border-color:#7c5cfc}
        button{width:100%;padding:14px;background:linear-gradient(135deg,#7c5cfc,#5a3fd6);color:#fff;border:none;border-radius:10px;font-size:16px;font-weight:600;cursor:pointer}
        button:hover{opacity:.9}
        #msg{text-align:center;margin-top:16px;font-size:14px}
        .err{color:#ff4757}.ok{color:#2ed573}
      </style>
    </head>
    <body>
      <div class="card">
        <h1>🔒 Reset Your Password</h1>
        <label for="pw">New Password (min. 8 characters)</label>
        <input id="pw" type="password" placeholder="Enter new password"/>
        <label for="pw2">Confirm Password</label>
        <input id="pw2" type="password" placeholder="Confirm new password"/>
        <button onclick="submit()">Set New Password</button>
        <div id="msg"></div>
      </div>
      <script>
        async function submit() {
          const pw  = document.getElementById('pw').value;
          const pw2 = document.getElementById('pw2').value;
          const msg = document.getElementById('msg');

          if (pw.length < 8) { msg.className='err'; msg.textContent='Password must be at least 8 characters.'; return; }
          if (pw !== pw2)     { msg.className='err'; msg.textContent='Passwords do not match.'; return; }

          try {
            const res  = await fetch('/api/reset-password/${token}', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ password: pw })
            });
            const data = await res.json();

            if (res.ok) {
              msg.className = 'ok';
              msg.textContent = 'Password updated! Redirecting…';
              setTimeout(() => window.location.href = '${BASE_URL}', 2000);
            } else {
              msg.className = 'err';
              msg.textContent = data.error || 'Something went wrong.';
            }
          } catch {
            msg.className = 'err';
            msg.textContent = 'Network error. Please try again.';
          }
        }
      </script>
    </body>
    </html>
  `);
});

// ─────────────────────────────────────────
//  RESET PASSWORD — POST (apply the change)
// ─────────────────────────────────────────
app.post('/api/reset-password/:token', async (req, res, next) => {
  try {
    const decoded = jwt.verify(req.params.token, SECRET);

    if (!req.body.password || req.body.password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    }

    const hash = await bcrypt.hash(req.body.password, 10);

    const snap = await db.collection('users').where('email', '==', decoded.email).get();
    if (snap.empty) return res.status(404).json({ error: 'User not found.' });

    await db.collection('users').doc(snap.docs[0].id).update({ password: hash });

    res.json({ message: 'Password updated successfully.' });
  } catch {
    res.status(400).json({ error: 'Invalid or expired token.' });
  }
});

// ─────────────────────────────────────────
//  GLOBAL ERROR HANDLER
// ─────────────────────────────────────────
app.use((err, req, res, _next) => {
  console.error('[ERROR]', err.message || err);
  res.status(500).json({ error: 'Internal server error.' });
});

// ─────────────────────────────────────────
//  START
// ─────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});