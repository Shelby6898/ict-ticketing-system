function isSuperAdmin(req, res, next) {
  if (req.user?.role !== 'superadmin') {
    return res.status(403).json({ error: 'Super admin access only' });
  }
  next();
}

module.exports = isSuperAdmin;
