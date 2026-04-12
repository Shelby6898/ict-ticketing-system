require('dotenv').config();
const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const admin = require('firebase-admin');
const nodemailer = require('nodemailer');
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
// Railway fix: trust proxy enabled - v2
app.set('trust proxy', 1);
const PORT = process.env.PORT || 5000;
const SECRET = process.env.JWT_SECRET || "CHANGE_ME";

// ---------------- FIREBASE INIT (FIXED) ----------------
const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  storageBucket: "ict-ticketing-system-39542.appspot.com"
});

const db = admin.firestore();
const bucket = admin.storage().bucket();

// ---------------- SECURITY MIDDLEWARE ----------------
app.use(helmet({
  contentSecurityPolicy: false
}));
app.use(compression());
app.use(morgan('dev'));

app.use(cors({
  origin: process.env.CORS_ORIGIN || '*'
}));

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

// ---------------- EMAIL ----------------
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
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

    const hash = await bcrypt.hash(password, 10);

    await db.collection('users').add({
      name,
      email,
      password: hash,
      role: 'user',
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

    res.json({ message: 'User registered successfully' });
  } catch (err) {
    next(err);
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
    transporter.sendMail({
      from: `"ICT HelpDesk" <${process.env.EMAIL_USER}>`,
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
    }).catch(e => console.error('User email error:', e.message));

    // Email to admin
    transporter.sendMail({
      from: `"ICT HelpDesk" <${process.env.EMAIL_USER}>`,
      to: process.env.EMAIL_USER,
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
    }).catch(e => console.error('Admin email error:', e.message));

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

    transporter.sendMail({
      from: `"ICT HelpDesk" <${process.env.EMAIL_USER}>`,
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
          ${status === 'closed' ? `<p style="color:#2ed573;font-weight:600;">Your issue has been resolved. Thank you for reaching out!</p>` : `<p>Our team is actively working on your issue. We will keep you updated.</p>`}
          <p style="color:#888;font-size:13px;">If you have further questions, please submit a new ticket.</p>
        </div>
      `
    }).catch(e => console.error('Status email error:', e.message));

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

    const link = `${process.env.BASE_URL}/reset-password/${token}`;

    await transporter.sendMail({
      to: email,
      subject: 'Password Reset',
      text: `Reset your password: ${link}`
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
});
