const express = require('express');
const router = express.Router();
const { db } = require('../services/firebase');
const auth = require('../middleware/auth');
const isAdmin = require('../middleware/admin');

router.get('/agents', auth, isAdmin, async (req, res, next) => {
  try {
    const snap = await db
      .collection('users')
      .where('role', '==', 'admin')
      .get();

    const agents = snap.docs.map(d => ({
      id:    d.id,
      name:  d.data().name,
      email: d.data().email
    }));

    res.json({ agents });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
