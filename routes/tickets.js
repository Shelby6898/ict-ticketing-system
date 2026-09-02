const express = require('express');
const router = express.Router();
const { db, admin } = require('../services/firebase');
const { sendEmail } = require('../services/email');
const auth = require('../middleware/auth');
const isAdmin = require('../middleware/admin');
const { isValidDepartment, isValidCategory } = require('../config/departments');

const VALID_PRIORITIES = ['low', 'medium', 'high', 'urgent'];
const VALID_STATUSES   = ['open', 'assigned', 'in-progress', 'resolved', 'closed'];

// GET TICKETS
router.get('/', auth, async (req, res, next) => {
  try {
    let query = db.collection('tickets').orderBy('createdAt', 'desc');
    if (req.user.role === 'user') {
      query = query.where('userId', '==', req.user.id);
    } else if (req.user.role === 'admin') {
      query = query.where('department', '==', req.user.department);
    } else if (req.user.role === 'superadmin' && req.query.department) {
      query = query.where('department', '==', req.query.department);
    }
    const snap = await query.get();
    const tickets = snap.docs.map(d => {
      const data = d.data();
      return {
        id: d.id, ...data,
        requester: data.requester || data.userEmail || 'Unknown',
        department: data.department || 'ict',
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
    const { title, description, department, category, priority, device } = req.body;
    if (!title || !description) {
      return res.status(400).json({ error: 'title and description are required.' });
    }
    if (!isValidDepartment(department)) {
      return res.status(400).json({ error: 'A valid department is required.' });
    }
    if (!isValidCategory(department, category)) {
      return res.status(400).json({ error: 'Invalid category for the selected department.' });
    }

    const userDoc = await db.collection('users').doc(req.user.id).get();
    const requesterName = userDoc.exists ? userDoc.data().name : req.user.email;

    const finalPriority = VALID_PRIORITIES.includes(priority) ? priority : 'medium';

    const docRef = await db.collection('tickets').add({
      title, description, device: device || '',
      department,
      category,
      priority:  finalPriority,
      requester: requesterName,
      userName:  requesterName,
      userEmail: req.user.email,
      userId:    req.user.id,
      status:    'open',
      assignedTo: null, assignedToName: null, assignedToEmail: null,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    // ── 1. Confirmation email to the user ──
    await sendEmail({
      to: req.user.email,
      subject: `✅ Ticket Received: ${title}`,
      html: `
        <div style="font-family:sans-serif;max-width:600px;margin:0 auto;padding:24px;">
          <h2 style="color:#6366f1;">University HelpDesk</h2>
          <p>Hi ${requesterName},</p>
          <p>Your ticket has been received and the ${department.toUpperCase()} team will get back to you shortly.</p>
          <div style="background:#f1f5f9;border-radius:8px;padding:16px;margin:20px 0;">
            <p style="margin:0 0 8px;"><strong>Ticket ID:</strong> ${docRef.id}</p>
            <p style="margin:0 0 8px;"><strong>Title:</strong> ${title}</p>
            <p style="margin:0 0 8px;"><strong>Department:</strong> ${department}</p>
            <p style="margin:0 0 8px;"><strong>Category:</strong> ${category}</p>
            <p style="margin:0 0 8px;"><strong>Priority:</strong> ${finalPriority}</p>
            <p style="margin:0;"><strong>Device/Reference:</strong> ${device || '—'}</p>
          </div>
          <p style="color:#64748b;font-size:13px;">You will be notified when your ticket is updated.</p>
          <hr style="border:none;border-top:1px solid #e2e8f0;margin:20px 0;"/>
          <p style="color:#94a3b8;font-size:12px;">University HelpDesk — ${process.env.BASE_URL}</p>
        </div>
      `
    });

    // ── 2. Notification email to admins in that department (+ superadmins) ──
    const [deptAdminsSnap, superAdminsSnap] = await Promise.all([
      db.collection('users').where('role', '==', 'admin').where('department', '==', department).get(),
      db.collection('users').where('role', '==', 'superadmin').get()
    ]);
    const adminEmails = [...deptAdminsSnap.docs, ...superAdminsSnap.docs].map(d => d.data().email);

    if (adminEmails.length) {
      await sendEmail({
        to: adminEmails,
        subject: `🎫 New ${department.toUpperCase()} Ticket: ${title}`,
        html: `
          <div style="font-family:sans-serif;max-width:600px;margin:0 auto;padding:24px;">
            <h2 style="color:#ef4444;">University HelpDesk — New Ticket</h2>
            <p>A new support ticket has been submitted to ${department.toUpperCase()}.</p>
            <div style="background:#f1f5f9;border-radius:8px;padding:16px;margin:20px 0;">
              <p style="margin:0 0 8px;"><strong>Ticket ID:</strong> ${docRef.id}</p>
              <p style="margin:0 0 8px;"><strong>Title:</strong> ${title}</p>
              <p style="margin:0 0 8px;"><strong>Submitted by:</strong> ${requesterName} (${req.user.email})</p>
              <p style="margin:0 0 8px;"><strong>Department:</strong> ${department}</p>
              <p style="margin:0 0 8px;"><strong>Category:</strong> ${category}</p>
              <p style="margin:0 0 8px;"><strong>Priority:</strong> ${finalPriority}</p>
              <p style="margin:0;"><strong>Description:</strong> ${description}</p>
            </div>
            <a href="${process.env.BASE_URL}" style="display:inline-block;padding:10px 20px;background:#6366f1;color:#fff;border-radius:6px;text-decoration:none;font-weight:600;">Open HelpDesk →</a>
            <hr style="border:none;border-top:1px solid #e2e8f0;margin:20px 0;"/>
            <p style="color:#94a3b8;font-size:12px;">University HelpDesk — ${process.env.BASE_URL}</p>
          </div>
        `
      });
    }

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

    const ticket = doc.data();
    if (req.user.role === 'admin' && ticket.department !== req.user.department) {
      return res.status(403).json({ error: 'You can only manage tickets in your own department.' });
    }

    await ref.update({ status, updatedAt: admin.firestore.FieldValue.serverTimestamp() });

    if (ticket.userEmail) {
      await sendEmail({
        to: ticket.userEmail,
        subject: `🔄 Ticket Update: ${ticket.title}`,
        html: `
          <div style="font-family:sans-serif;max-width:600px;margin:0 auto;padding:24px;">
            <h2 style="color:#6366f1;">University HelpDesk</h2>
            <p>Hi ${ticket.userName || ticket.requester || 'there'},</p>
            <p>Your ticket status has been updated.</p>
            <div style="background:#f1f5f9;border-radius:8px;padding:16px;margin:20px 0;">
              <p style="margin:0 0 8px;"><strong>Ticket:</strong> ${ticket.title}</p>
              <p style="margin:0;"><strong>New Status:</strong> <span style="color:#6366f1;font-weight:600;">${status}</span></p>
            </div>
            <a href="${process.env.BASE_URL}" style="display:inline-block;padding:10px 20px;background:#6366f1;color:#fff;border-radius:6px;text-decoration:none;font-weight:600;">View Ticket →</a>
            <hr style="border:none;border-top:1px solid #e2e8f0;margin:20px 0;"/>
            <p style="color:#94a3b8;font-size:12px;">University HelpDesk — ${process.env.BASE_URL}</p>
          </div>
        `
      });
    }

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
    if (!['admin', 'superadmin'].includes(agent.role)) {
      return res.status(400).json({ error: 'Assignee must be an admin.' });
    }

    const ticketRef = db.collection('tickets').doc(req.params.id);
    const ticketDoc = await ticketRef.get();
    if (!ticketDoc.exists) return res.status(404).json({ error: 'Ticket not found.' });
    const ticket = ticketDoc.data();

    if (req.user.role === 'admin' && ticket.department !== req.user.department) {
      return res.status(403).json({ error: 'You can only manage tickets in your own department.' });
    }
    if (agent.role === 'admin' && agent.department !== ticket.department) {
      return res.status(400).json({ error: 'Agent must belong to the ticket\'s department.' });
    }

    await ticketRef.update({
      assignedTo: agentId, assignedToEmail: agent.email, assignedToName: agent.name,
      assignedAt: admin.firestore.FieldValue.serverTimestamp(),
      status: 'assigned', updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    await sendEmail({
      to: agent.email,
      subject: `📋 Ticket Assigned to You: ${ticket.title}`,
      html: `
        <div style="font-family:sans-serif;max-width:600px;margin:0 auto;padding:24px;">
          <h2 style="color:#6366f1;">University HelpDesk</h2>
          <p>Hi ${agent.name},</p>
          <p>A ticket has been assigned to you.</p>
          <div style="background:#f1f5f9;border-radius:8px;padding:16px;margin:20px 0;">
            <p style="margin:0 0 8px;"><strong>Ticket ID:</strong> ${req.params.id}</p>
            <p style="margin:0 0 8px;"><strong>Title:</strong> ${ticket.title}</p>
            <p style="margin:0 0 8px;"><strong>Submitted by:</strong> ${ticket.requester || ticket.userEmail}</p>
            <p style="margin:0 0 8px;"><strong>Department:</strong> ${ticket.department || 'ict'}</p>
            <p style="margin:0 0 8px;"><strong>Category:</strong> ${ticket.category || 'other'}</p>
            <p style="margin:0;"><strong>Priority:</strong> ${ticket.priority || 'medium'}</p>
          </div>
          <a href="${process.env.BASE_URL}" style="display:inline-block;padding:10px 20px;background:#6366f1;color:#fff;border-radius:6px;text-decoration:none;font-weight:600;">Open HelpDesk →</a>
          <hr style="border:none;border-top:1px solid #e2e8f0;margin:20px 0;"/>
          <p style="color:#94a3b8;font-size:12px;">University HelpDesk — ${process.env.BASE_URL}</p>
        </div>
      `
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
    const ticket = doc.data();
    if (req.user.role === 'admin' && ticket.department !== req.user.department) {
      return res.status(403).json({ error: 'You can only manage tickets in your own department.' });
    }
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
    const ref = db.collection('tickets').doc(req.params.id);
    const doc = await ref.get();
    if (!doc.exists) return res.status(404).json({ error: 'Ticket not found.' });
    const ticket = doc.data();
    if (req.user.role === 'admin' && ticket.department !== req.user.department) {
      return res.status(403).json({ error: 'You can only manage tickets in your own department.' });
    }

    const updates = { updatedAt: admin.firestore.FieldValue.serverTimestamp() };
    if (category) {
      if (!isValidCategory(ticket.department, category)) return res.status(400).json({ error: 'Invalid category for this ticket\'s department.' });
      updates.category = category;
    }
    if (priority) {
      if (!VALID_PRIORITIES.includes(priority)) return res.status(400).json({ error: 'Invalid priority.' });
      updates.priority = priority;
    }
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
    const ticket = doc.data();
    if (req.user.role === 'admin' && ticket.department !== req.user.department) {
      return res.status(403).json({ error: 'You can only manage tickets in your own department.' });
    }
    await ref.delete();
    res.json({ message: 'Ticket deleted.' });
  } catch (err) { next(err); }
});

module.exports = router;
