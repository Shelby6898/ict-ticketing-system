const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { db } = require('../services/firebase');
const auth = require('../middleware/auth');
const isAdmin = require('../middleware/admin');

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many login attempts. Try again in 15 minutes.' }
});

// LOGIN
router.post('/login', loginLimiter, async (req, res, next) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    const snap = await db
      .collection('users')
      .where('email', '==', email.toLowerCase().trim())
      .limit(1)
      .get();

    if (snap.empty) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    const doc = snap.docs[0];
    const user = doc.data();

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    const token = jwt.sign(
      { id: doc.id, email: user.email, role: user.role, name: user.name },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );

    res.json({
      token,
      user: { id: doc.id, name: user.name, email: user.email, role: user.role }
    });
  } catch (err) {
    next(err);
  }
});

// CREATE USER (admin only)
router.post('/users', auth, isAdmin, async (req, res, next) => {
  try {
    const { name, email, password, role = 'user' } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: 'name, email and password are required.' });
    }

    const validRoles = ['user', 'admin'];
    if (!validRoles.includes(role)) {
      return res.status(400).json({ error: 'role must be "user" or "admin".' });
    }

    const cleanEmail = email.toLowerCase().trim();

    const existing = await db
      .collection('users')
      .where('email', '==', cleanEmail)
      .get();

    if (!existing.empty) {
      return res.status(409).json({ error: 'A user with that email already exists.' });
    }

    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    }

    const hash = await bcrypt.hash(password, 10);
    const { admin: adminSdk } = require('../services/firebase');

    const userRef = await db.collection('users').add({
      name,
      email: cleanEmail,
      password: hash,
      role,
      createdAt: adminSdk.firestore.FieldValue.serverTimestamp(),
      createdBy: req.user.id
    });

    res.status(201).json({
      message: 'User created successfully.',
      user: { id: userRef.id, name, email: cleanEmail, role }
    });
  } catch (err) {
    next(err);
  }
});

// LIST USERS (admin only)
router.get('/users', auth, isAdmin, async (req, res, next) => {
  try {
    const snap = await db.collection('users').orderBy('createdAt', 'desc').get();

    const users = snap.docs.map(d => {
      const data = d.data();
      return { id: d.id, name: data.name, email: data.email, role: data.role, createdAt: data.createdAt };
    });

    res.json({ users });
  } catch (err) {
    next(err);
  }
});

// DELETE USER (admin only)
router.delete('/users/:id', auth, isAdmin, async (req, res, next) => {
  try {
    if (req.params.id === req.user.id) {
      return res.status(400).json({ error: 'You cannot delete your own account.' });
    }

    const userRef = db.collection('users').doc(req.params.id);
    const userDoc = await userRef.get();

    if (!userDoc.exists) {
      return res.status(404).json({ error: 'User not found.' });
    }

    await userRef.delete();
    res.json({ message: 'User deleted.' });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
