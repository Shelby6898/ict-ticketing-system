const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { db } = require('../services/firebase');
const { sendEmail } = require('../services/email');
const auth = require('../middleware/auth');
const isAdmin = require('../middleware/admin');
const isSuperAdmin = require('../middleware/superadmin');
const { isValidDepartment } = require('../config/departments');

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
      { id: doc.id, email: user.email, role: user.role, name: user.name, department: user.department || null },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );
    res.json({
      token,
      user: { id: doc.id, name: user.name, email: user.email, role: user.role, department: user.department || null }
    });
  } catch (err) {
    next(err);
  }
});

// CREATE USER (admin only)
router.post('/users', auth, isSuperAdmin, async (req, res, next) => {
  try {
    const { name, email, password, role = 'user', department, homeDepartment } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'name, email and password are required.' });
    }
    const validRoles = ['user', 'admin', 'superadmin'];
    if (!validRoles.includes(role)) {
      return res.status(400).json({ error: 'role must be "user", "admin", or "superadmin".' });
    }
    if (role === 'admin' && !isValidDepartment(department)) {
      return res.status(400).json({ error: 'A valid department is required for admin users.' });
    }
    // Only a superadmin can create another superadmin
    if (role === 'superadmin' && req.user.role !== 'superadmin') {
      return res.status(403).json({ error: 'Only a superadmin can create another superadmin.' });
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
    const userDept = role === 'admin' ? department : null;
    const homeDept = role === 'user' ? (homeDepartment && homeDepartment.trim() ? homeDepartment.trim() : null) : null;
    const userRef = await db.collection('users').add({
      name,
      email: cleanEmail,
      password: hash,
      role,
      department: userDept,
      homeDepartment: homeDept,
      createdAt: adminSdk.firestore.FieldValue.serverTimestamp(),
      createdBy: req.user.id
    });
    res.status(201).json({
      message: 'User created successfully.',
      user: { id: userRef.id, name, email: cleanEmail, role, department: userDept, homeDepartment: homeDept }
    });
  } catch (err) {
    next(err);
  }
});

// LIST USERS (admin only)
router.get('/users', auth, isSuperAdmin, async (req, res, next) => {
  try {
    const snap = await db.collection('users').orderBy('createdAt', 'desc').get();
    const users = snap.docs.map(d => {
      const data = d.data();
      return { id: d.id, name: data.name, email: data.email, role: data.role, department: data.department || null, homeDepartment: data.homeDepartment || null, createdAt: data.createdAt };
    });
    res.json({ users });
  } catch (err) {
    next(err);
  }
});

// RESET PASSWORD (admin only)
router.patch('/users/:id/reset-password', auth, isSuperAdmin, async (req, res, next) => {
  try {
    const { newPassword } = req.body;

    if (!newPassword) {
      return res.status(400).json({ error: 'newPassword is required.' });
    }
    if (newPassword.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    }

    const userRef = db.collection('users').doc(req.params.id);
    const userDoc = await userRef.get();

    if (!userDoc.exists) {
      return res.status(404).json({ error: 'User not found.' });
    }

    const user = userDoc.data();
    const hash = await bcrypt.hash(newPassword, 10);

    await userRef.update({ password: hash });

    await sendEmail({
      to: user.email,
      subject: '🔑 Your Password Has Been Reset — Ticketing HelpDesk',
      html: `
        <div style="font-family:sans-serif;max-width:600px;margin:0 auto;padding:24px;">
          <h2 style="color:#6366f1;">Ticketing HelpDesk</h2>
          <p>Hi ${user.name},</p>
          <p>Your password has been reset by an administrator.</p>
          <div style="background:#f1f5f9;border-radius:8px;padding:16px;margin:20px 0;">
            <p style="margin:0 0 8px;"><strong>Email:</strong> ${user.email}</p>
            <p style="margin:0;"><strong>New Password:</strong> ${newPassword}</p>
          </div>
          <p style="color:#64748b;font-size:13px;">Please log in and change your password as soon as possible.</p>
          <a href="${process.env.BASE_URL}" style="display:inline-block;padding:10px 20px;background:#6366f1;color:#fff;border-radius:6px;text-decoration:none;font-weight:600;">Log In →</a>
          <hr style="border:none;border-top:1px solid #e2e8f0;margin:20px 0;"/>
          <p style="color:#94a3b8;font-size:12px;">Ticketing HelpDesk — ${process.env.BASE_URL}</p>
        </div>
      `
    });
    res.json({ message: 'Password reset successfully. User has been notified by email.' });
  } catch (err) {
    next(err);
  }
});

// DELETE USER (admin only)
router.delete('/users/:id', auth, isSuperAdmin, async (req, res, next) => {
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


// CHANGE DEPARTMENT (superadmin only)
router.patch('/users/:id/department', auth, isSuperAdmin, async (req, res, next) => {
  try {
    if (req.user.role !== 'superadmin') {
      return res.status(403).json({ error: 'Only a superadmin can change a department.' });
    }
    const { department } = req.body;
    const { isValidDepartment } = require('../config/departments');
    if (!isValidDepartment(department)) {
      return res.status(400).json({ error: 'A valid department is required.' });
    }
    const userRef = db.collection('users').doc(req.params.id);
    const userDoc = await userRef.get();
    if (!userDoc.exists) return res.status(404).json({ error: 'User not found.' });
    const user = userDoc.data();
    if (user.role !== 'admin') {
      return res.status(400).json({ error: 'Only department admins have a department to change.' });
    }
    await userRef.update({ department });
    res.json({ message: 'Department updated.', department });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
