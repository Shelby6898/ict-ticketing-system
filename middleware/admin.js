function isAdmin(req, res, next) {
  if (!['admin', 'superadmin'].includes(req.user?.role)) {
    return res.status(403).json({ error: 'Admin access only' });
  }
  next();
}

module.exports = isAdmin;
