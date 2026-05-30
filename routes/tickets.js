const express = require('express');
const router = express.Router();
const { db, admin } = require('../services/firebase');
const { sendEmail } = require('../services/email');
const auth = require('../middleware/auth');
const isAdmin = require('../middleware/admin');

const VALID_CATEGORIES = ['hardware', 'software', 'network', 'account', 'other'];
const VALID_PRIORITIES = ['low', 'medium', 'high', 'urgent'];
const VALID_STATUSES   = ['open', 'assigned', 'in-progress', 'resolved', 'closed'];

// GET TICKETS
router.get('/', auth, async (req, res, next) => {
  try {
    let query = db.collection('tickets').orderBy('createdAt', 'desc');
    if (req.user.role !== 'admin') {
      query = query.where('userId', '==', req.user.id);
    }
    const snap = await query.get();
    const tickets = snap.docs.map(d => {
      const data = d.data();
      return {
        id: d.id, ...data,
        requester: data.requester || data.userEmail || 'Unknown',
        category:  data.category  || 'other',
        priority:  data.priority  || 'medium',
        userEmail: data.userEmail || '',
        userName:  data.userName  || data.requester || ''
      };
    });
    res.json({ tickets });
  } catch (err) { next(err); }
});

// CREATE TICKET
router.post('/', auth, async (req, res, next) => {
  try {
    const { title, description, category, priority, device } = req.body;
    if (!title || !description) {
      return res.status(400).json({ error: 'title and description are required.' });
    }
    const userDoc = await db.collection('users').doc(req.user.id).get();
    const requesterName = userDoc.exists ? userDoc.data().name : req.user.email;

    const docRef = await db.collection('tickets').add({
      title, description, device: device || '',
      category:  VALID_CATEGORIES.includes(category) ? category : 'other',
      priority:  VALID_PRIORITIES.includes(priority) ? priority : 'medium',
      requester: requesterName, userName: requesterName,
      userEmail: req.user.email, userId: req.user.id,
      status: 'open',
      assignedTo: null, assignedToName: null, assignedToEmail: null,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });
    res.status(201).json({ id: docRef.id, message: 'Ticket created.' });
  } catch (err) { next(err); }
});

// UPDATE STATUS
router.patch('/:id/status', auth, isAdmin, async (req, res, next) => {
  try {
    const { status } = req.body;
    if (!VALID_STATUSES.includes(status)) {
      return res.status(400).json({ error: `Invalid status. Use: ${VALID_STATUSES.join(', ')}` });
    }
    const ref = db.collection('tickets').doc(req.params.id);
    const doc = await ref.get();
    if (!doc.exists) return res.status(404).json({ error: 'Ticket not found.' });
    await ref.update({ status, updatedAt: admin.firestore.FieldValue.serverTimestamp() });
    res.json({ message: 'Status updated.', status });
  } catch (err) { next(err); }
});

// ASSIGN TICKET
router.patch('/:id/assign', auth, isAdmin, async (req, res, next) => {
  try {
    const { agentId } = req.body;
    if (!agentId) return res.status(400).json({ error: 'agentId is required.' });
    const agentDoc = await db.collection('users').doc(agentId).get();
    if (!agentDoc.exists) return res.status(404).json({ error: 'Agent not found.' });
    const agent = agentDoc.data();
    if (agent.role !== 'admin') {
      return res.status(400).json({ error: 'Assignee must be an admin.' });
    }
    const ticketRef = db.collection('tickets').doc(req.params.id);
    const ticketDoc = await ticketRef.get();
    if (!ticketDoc.exists) return res.status(404).json({ error: 'Ticket not found.' });
    const ticket = ticketDoc.data();
    await ticketRef.update({
      assignedTo: agentId, assignedToEmail: agent.email, assignedToName: agent.name,
      assignedAt: admin.firestore.FieldValue.serverTimestamp(),
      status: 'assigned', updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });
    await sendEmail({
      to: agent.email,
      subject: `Ticket Assigned: ${ticket.title}`,
      html: `<h2>You have been assigned a ticket</h2>
             <p><strong>Title:</strong> ${ticket.title}</p>
             <p><strong>Priority:</strong> ${ticket.priority || 'medium'}</p>
             <p><strong>Submitted by:</strong> ${ticket.requester || ticket.userEmail}</p>
             <a href="${process.env.BASE_URL}">Open HelpDesk</a>`
    });
    res.json({ message: 'Ticket assigned.', assignedTo: { id: agentId, name: agent.name, email: agent.email } });
  } catch (err) { next(err); }
});

// UNASSIGN TICKET
router.patch('/:id/unassign', auth, isAdmin, async (req, res, next) => {
  try {
    const ref = db.collection('tickets').doc(req.params.id);
    const doc = await ref.get();
    if (!doc.exists) return res.status(404).json({ error: 'Ticket not found.' });
    await ref.update({
      assignedTo: null, assignedToEmail: null, assignedToName: null,
      assignedAt: null, status: 'open',
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });
    res.json({ message: 'Ticket unassigned.' });
  } catch (err) { next(err); }
});

// UPDATE TICKET FIELDS
router.patch('/:id', auth, isAdmin, async (req, res, next) => {
  try {
    const { category, priority } = req.body;
    const updates = { updatedAt: admin.firestore.FieldValue.serverTimestamp() };
    if (category) {
      if (!VALID_CATEGORIES.includes(category)) return res.status(400).json({ error: 'Invalid category.' });
      updates.category = category;
    }
    if (priority) {
      if (!VALID_PRIORITIES.includes(priority)) return res.status(400).json({ error: 'Invalid priority.' });
      updates.priority = priority;
    }
    const ref = db.collection('tickets').doc(req.params.id);
    const doc = await ref.get();
    if (!doc.exists) return res.status(404).json({ error: 'Ticket not found.' });
    await ref.update(updates);
    res.json({ message: 'Ticket updated.', ...updates });
  } catch (err) { next(err); }
});

// DELETE TICKET
router.delete('/:id', auth, isAdmin, async (req, res, next) => {
  try {
    const ref = db.collection('tickets').doc(req.params.id);
    const doc = await ref.get();
    if (!doc.exists) return res.status(404).json({ error: 'Ticket not found.' });
    await ref.delete();
    res.json({ message: 'Ticket deleted.' });
  } catch (err) { next(err); }
});

module.exports = router;
