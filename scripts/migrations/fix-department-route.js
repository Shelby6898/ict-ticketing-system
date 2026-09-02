const fs = require('fs');
let content = fs.readFileSync('routes/auth.js', 'utf8');
const startMarker = '// CHANGE DEPARTMENT';
const idx = content.indexOf(startMarker);
content = content.slice(0, idx);
content += `// CHANGE DEPARTMENT (superadmin only)
router.patch('/users/:id/department', auth, isAdmin, async (req, res, next) => {
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
`;
fs.writeFileSync('routes/auth.js', content);
console.log('Route rewritten cleanly.');
