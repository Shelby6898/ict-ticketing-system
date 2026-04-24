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

const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET;
const BASE_URL = process.env.BASE_URL;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@example.com';

if (!SECRET) {
  console.error('❌ JWT_SECRET is missing');
  process.exit(1);
}

if (!BASE_URL) {
  console.error('❌ BASE_URL is missing (set it in Railway env vars)');
  process.exit(1);
}

// ─────────────────────────────────────────
//  FIREBASE INIT
// ─────────────────────────────────────────
const serviceAccount = {
  type: process.env.FIREBASE_TYPE,
  project_id: process.env.FIREBASE_PROJECT_ID,
  private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
  private_key: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
  client_email: process.env.FIREBASE_CLIENT_EMAIL,
  client_id: process.env.FIREBASE_CLIENT_ID,
  auth_uri: process.env.FIREBASE_AUTH_URI,
  token_uri: process.env.FIREBASE_TOKEN_URI,
  auth_provider_x509_cert_url: process.env.FIREBASE_AUTH_PROVIDER_CERT_URL,
  client_x509_cert_url: process.env.FIREBASE_CLIENT_CERT_URL
};

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  storageBucket: process.env.FIREBASE_STORAGE_BUCKET
});

const db = admin.firestore();

// ─────────────────────────────────────────
//  EMAIL (RESEND)
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
    console.error('Email error:', err.message);
  }
}

// ─────────────────────────────────────────
//  SECURITY MIDDLEWARE
// ─────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));
app.use(compression());

app.use(
  morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev')
);

// CORS (production-safe)
app.use(
  cors({
    origin: process.env.CORS_ORIGIN?.split(',') || '*',
    credentials: true
  })
);

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate limiting
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    message: { error: 'Too many requests' } // ← FIXED syntax error
  })
);

// Auth limiter
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Too many login attempts' }
});

// ─────────────────────────────────────────
//  BOT PROTECTION
// ─────────────────────────────────────────
const BOT_PATHS = ['/wp-admin', '/.env', '/phpmyadmin', '/.git'];

app.use((req, res, next) => {
  if (BOT_PATHS.some(p => req.path.includes(p))) {
    console.warn(`Blocked bot: ${req.ip} -> ${req.path}`);
    return res.status(403).end();
  }
  next();
});

// ─────────────────────────────────────────
//  STATIC
// ─────────────────────────────────────────
app.use(express.static('public'));

app.get('/', (req, res) => {
  let html = fs.readFileSync(
    path.join(__dirname, 'public/index.html'),
    'utf8'
  );

  html = html.replace(
    /const API = ['"].*?['"]/g,
    `const API = '${BASE_URL}/api'`
  );

  res.send(html);
});

// ─────────────────────────────────────────
//  FILE UPLOAD
// ─────────────────────────────────────────
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }
});

// ─────────────────────────────────────────
//  AUTH MIDDLEWARE
// ─────────────────────────────────────────
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'No token' });

  const token = header.split(' ')[1];

  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function isAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin only' });
  }
  next();
}

// ─────────────────────────────────────────
//  REGISTER
// ─────────────────────────────────────────
app.post('/api/register', authLimiter, async (req, res, next) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Missing fields' });
    }

    const cleanEmail = email.toLowerCase();

    const existing = await db
      .collection('users')
      .where('email', '==', cleanEmail)
      .get();

    if (!existing.empty) {
      return res.status(400).json({ error: 'User exists' });
    }

    const hash = await bcrypt.hash(password, 10);

    const userRef = await db.collection('users').add({
      name,
      email: cleanEmail,
      password: hash,
      role: 'user',
      verified: false,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

    const token = jwt.sign(
      { userId: userRef.id, email: cleanEmail },
      SECRET,
      { expiresIn: '24h' }
    );

    const link = `${BASE_URL}/api/verify-email/${token}`;

    await sendEmail({
      to: cleanEmail,
      subject: 'Verify Your Account – ICT HelpDesk',
      html: `
        <p>Hi ${name},</p>
        <p>Thanks for registering. Please verify your email address by clicking the button below:</p>
        <a href="${link}" style="display:inline-block;padding:10px 20px;background:#0070f3;color:#fff;border-radius:5px;text-decoration:none;">Verify Email</a>
        <p>This link expires in 24 hours.</p>
        <p>If you did not register, you can safely ignore this email.</p>
      `
    });

    res.json({ message: 'Registered successfully. Please check your email to verify your account.' });
  } catch (err) {
    next(err);
  }
});

// ─────────────────────────────────────────
//  VERIFY EMAIL
// ─────────────────────────────────────────
app.get('/api/verify-email/:token', async (req, res, next) => {
  try {
    const { token } = req.params;

    let payload;
    try {
      payload = jwt.verify(token, SECRET);
    } catch (err) {
      return res.status(400).send(`
        <html><body style="font-family:sans-serif;text-align:center;padding:60px;">
          <h2>❌ Verification link is invalid or has expired.</h2>
          <p>Please register again or request a new verification email.</p>
        </body></html>
      `);
    }

    const { userId } = payload;

    if (!userId) {
      return res.status(400).send(`
        <html><body style="font-family:sans-serif;text-align:center;padding:60px;">
          <h2>❌ Invalid verification token.</h2>
        </body></html>
      `);
    }

    const userRef = db.collection('users').doc(userId);
    const userDoc = await userRef.get();

    if (!userDoc.exists) {
      return res.status(404).send(`
        <html><body style="font-family:sans-serif;text-align:center;padding:60px;">
          <h2>❌ User not found.</h2>
        </body></html>
      `);
    }

    if (userDoc.data().verified) {
      return res.send(`
        <html><body style="font-family:sans-serif;text-align:center;padding:60px;">
          <h2>✅ Email already verified.</h2>
          <p>You can <a href="${BASE_URL}">log in here</a>.</p>
        </body></html>
      `);
    }

    await userRef.update({ verified: true });

    res.send(`
      <html><body style="font-family:sans-serif;text-align:center;padding:60px;">
        <h2>✅ Email verified successfully!</h2>
        <p>Your account is now active. <a href="${BASE_URL}">Click here to log in</a>.</p>
      </body></html>
    `);
  } catch (err) {
    next(err);
  }
});

// ─────────────────────────────────────────
//  LOGIN
// ─────────────────────────────────────────
app.post('/api/login', authLimiter, async (req, res, next) => {
  try {
    const { email, password } = req.body;

    const snap = await db
      .collection('users')
      .where('email', '==', email.toLowerCase())
      .limit(1)
      .get();

    if (snap.empty) {
      return res.status(401).json({ error: 'Invalid login' });
    }

    const doc = snap.docs[0];
    const user = doc.data();

    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.status(401).json({ error: 'Invalid login' });
    }

    if (!user.verified) {
      return res.status(403).json({
        error: 'Please verify your email before logging in. Check your inbox.'
      });
    }

    const token = jwt.sign(
      { id: doc.id, email: user.email, role: user.role, name: user.name },
      SECRET,
      { expiresIn: '1d' }
    );

    res.json({ token, user: { id: doc.id, name: user.name, email: user.email, role: user.role } });
  } catch (err) {
    next(err);
  }
});

// ─────────────────────────────────────────
//  CREATE TICKET  ← FIXED: saves all fields
// ─────────────────────────────────────────
app.post('/api/tickets', auth, async (req, res, next) => {
  try {
    const { title, description, category, priority } = req.body;

    if (!title || !description) {
      return res.status(400).json({ error: 'Title and description are required' });
    }

    // Fetch user's name from Firestore to store as requester
    const userDoc = await db.collection('users').doc(req.user.id).get();
    const requesterName = userDoc.exists ? userDoc.data().name : req.user.email;

    const validCategories = ['hardware', 'software', 'network', 'account', 'other'];
    const validPriorities = ['low', 'medium', 'high', 'urgent'];

    const doc = await db.collection('tickets').add({
      title,
      description,
      category: validCategories.includes(category) ? category : 'other',
      priority: validPriorities.includes(priority) ? priority : 'medium',
      requester: requesterName,
      userEmail: req.user.email,
      status: 'open',
      userId: req.user.id,
      assignedTo: null,
      assignedToName: null,
      assignedToEmail: null,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    res.json({ id: doc.id });
  } catch (err) {
    next(err);
  }
});

// ─────────────────────────────────────────
//  GET TICKETS
// ─────────────────────────────────────────
app.get('/api/tickets', auth, async (req, res, next) => {
  try {
    let query = db.collection('tickets').orderBy('createdAt', 'desc');

    if (req.user.role !== 'admin') {
      query = query.where('userId', '==', req.user.id);
    }

    const snap = await query.get();
    const tickets = snap.docs.map(d => {
      const data = d.data();
      return {
        id: d.id,
        ...data,
        // Ensure these fields always exist even on old tickets
        requester: data.requester || data.userEmail || 'Unknown',
        category: data.category || 'other',
        priority: data.priority || 'medium',
        userEmail: data.userEmail || ''
      };
    });

    res.json({ tickets });
  } catch (err) {
    next(err);
  }
});

// ─────────────────────────────────────────
//  GET AGENTS (admins available to assign)
// ─────────────────────────────────────────
app.get('/api/agents', auth, isAdmin, async (req, res, next) => {
  try {
    const snap = await db
      .collection('users')
      .where('role', '==', 'admin')
      .get();

    const agents = snap.docs.map(d => ({
      id: d.id,
      name: d.data().name,
      email: d.data().email
    }));

    res.json({ agents });
  } catch (err) {
    next(err);
  }
});

// ─────────────────────────────────────────
//  ASSIGN TICKET (admin only)
// ─────────────────────────────────────────
app.patch('/api/tickets/:id/assign', auth, isAdmin, async (req, res, next) => {
  try {
    const { agentId } = req.body;

    if (!agentId) {
      return res.status(400).json({ error: 'agentId is required' });
    }

    const agentDoc = await db.collection('users').doc(agentId).get();

    if (!agentDoc.exists) {
      return res.status(404).json({ error: 'Agent not found' });
    }

    const agent = agentDoc.data();

    if (agent.role !== 'admin') {
      return res.status(400).json({ error: 'User is not an admin' });
    }

    const ticketRef = db.collection('tickets').doc(req.params.id);
    const ticketDoc = await ticketRef.get();

    if (!ticketDoc.exists) {
      return res.status(404).json({ error: 'Ticket not found' });
    }

    const ticket = ticketDoc.data();

    await ticketRef.update({
      assignedTo: agentId,
      assignedToEmail: agent.email,
      assignedToName: agent.name,
      assignedAt: admin.firestore.FieldValue.serverTimestamp(),
      status: 'assigned',
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    await sendEmail({
      to: agent.email,
      subject: `📋 New Ticket Assigned: ${ticket.title}`,
      html: `
        <h2>You have been assigned a new ticket</h2>
        <p><strong>Title:</strong> ${ticket.title}</p>
        <p><strong>Category:</strong> ${ticket.category || 'other'}</p>
        <p><strong>Priority:</strong> ${ticket.priority || 'medium'}</p>
        <p><strong>Submitted by:</strong> ${ticket.requester || ticket.userEmail || 'Unknown'}</p>
        <a href="${BASE_URL}">Open HelpDesk</a>
      `
    });

    res.json({
      message: 'Ticket assigned successfully',
      assignedTo: { id: agentId, name: agent.name, email: agent.email }
    });
  } catch (err) {
    next(err);
  }
});

// ─────────────────────────────────────────
//  UNASSIGN TICKET (admin only)
// ─────────────────────────────────────────
app.patch('/api/tickets/:id/unassign', auth, isAdmin, async (req, res, next) => {
  try {
    const ticketRef = db.collection('tickets').doc(req.params.id);
    const ticketDoc = await ticketRef.get();

    if (!ticketDoc.exists) {
      return res.status(404).json({ error: 'Ticket not found' });
    }

    await ticketRef.update({
      assignedTo: null,
      assignedToEmail: null,
      assignedToName: null,
      assignedAt: null,
      status: 'open',
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    res.json({ message: 'Ticket unassigned' });
  } catch (err) {
    next(err);
  }
});

// ─────────────────────────────────────────
//  UPDATE STATUS (admin only)
// ─────────────────────────────────────────
app.patch('/api/tickets/:id/status', auth, isAdmin, async (req, res, next) => {
  try {
    const { status } = req.body;
    const validStatuses = ['open', 'assigned', 'in_progress', 'in-progress', 'resolved', 'closed'];

    if (!validStatuses.includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }

    const ticketRef = db.collection('tickets').doc(req.params.id);
    const ticketDoc = await ticketRef.get();

    if (!ticketDoc.exists) {
      return res.status(404).json({ error: 'Ticket not found' });
    }

    await ticketRef.update({
      status,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    res.json({ message: 'Status updated', status });
  } catch (err) {
    next(err);
  }
});

// ─────────────────────────────────────────
//  UPDATE TICKET FIELDS (admin only)
// ─────────────────────────────────────────
app.patch('/api/tickets/:id', auth, isAdmin, async (req, res, next) => {
  try {
    const { category, priority } = req.body;
    const validCategories = ['hardware', 'software', 'network', 'account', 'other'];
    const validPriorities = ['low', 'medium', 'high', 'urgent'];

    const updates = { updatedAt: admin.firestore.FieldValue.serverTimestamp() };

    if (category) {
      if (!validCategories.includes(category)) {
        return res.status(400).json({ error: 'Invalid category' });
      }
      updates.category = category;
    }

    if (priority) {
      if (!validPriorities.includes(priority)) {
        return res.status(400).json({ error: 'Invalid priority' });
      }
      updates.priority = priority;
    }

    const ticketRef = db.collection('tickets').doc(req.params.id);
    const ticketDoc = await ticketRef.get();

    if (!ticketDoc.exists) {
      return res.status(404).json({ error: 'Ticket not found' });
    }

    await ticketRef.update(updates);

    res.json({ message: 'Ticket updated', ...updates });
  } catch (err) {
    next(err);
  }
});

// ─────────────────────────────────────────
//  ERROR HANDLER
// ─────────────────────────────────────────
app.use((err, req, res, _next) => {
  console.error('[ERROR]', err.message);
  res.status(500).json({ error: 'Server error' });
});

// ─────────────────────────────────────────
//  START SERVER
// ─────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});