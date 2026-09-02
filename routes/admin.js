const express = require('express');
const router = express.Router();
const { db } = require('../services/firebase');
const auth = require('../middleware/auth');
const isAdmin = require('../middleware/admin');
const { DEPARTMENTS } = require('../config/departments');

// GET AGENTS (for assign-ticket dropdown)
// Admins see only agents in their own department. Superadmins see everyone,
// optionally filtered with ?department=xxx.
router.get('/agents', auth, isAdmin, async (req, res, next) => {
  try {
    let query = db.collection('users').where('role', 'in', ['admin', 'superadmin']);

    const snap = await query.get();
    let agents = snap.docs.map(d => ({
      id: d.id,
      name: d.data().name,
      email: d.data().email,
      role: d.data().role,
      department: d.data().department || null
    }));

    if (req.user.role === 'admin') {
      agents = agents.filter(a => a.role === 'superadmin' || a.department === req.user.department);
    } else if (req.user.role === 'superadmin' && req.query.department) {
      agents = agents.filter(a => a.role === 'superadmin' || a.department === req.query.department);
    }

    res.json({ agents });
  } catch (err) {
    next(err);
  }
});

// GET DEPARTMENTS (for frontend dropdowns)
router.get('/departments', auth, async (req, res) => {
  const list = Object.entries(DEPARTMENTS).map(([key, val]) => ({
    key, label: val.label, icon: val.icon,
    categories: Object.entries(val.categories).map(([ck, cv]) => ({ key: ck, label: cv }))
  }));
  res.json({ departments: list });
});

module.exports = router;
