const fs = require('fs');
const path = 'routes/auth.js';
let content = fs.readFileSync(path, 'utf8');
let applied = 0;

function replaceOnce(label, oldStr, newStr) {
  if (!content.includes(oldStr)) { console.log(`⚠️  SKIPPED: ${label}`); return; }
  content = content.replace(oldStr, newStr);
  console.log(`✅ Applied: ${label}`);
  applied++;
}

replaceOnce('import isSuperAdmin',
`const isAdmin = require('../middleware/admin');`,
`const isAdmin = require('../middleware/admin');
const isSuperAdmin = require('../middleware/superadmin');`);

replaceOnce('CREATE USER -> superadmin only',
`router.post('/users', auth, isAdmin, async (req, res, next) => {`,
`router.post('/users', auth, isSuperAdmin, async (req, res, next) => {`);

replaceOnce('LIST USERS -> superadmin only',
`router.get('/users', auth, isAdmin, async (req, res, next) => {`,
`router.get('/users', auth, isSuperAdmin, async (req, res, next) => {`);

replaceOnce('RESET PASSWORD -> superadmin only',
`router.patch('/users/:id/reset-password', auth, isAdmin, async (req, res, next) => {`,
`router.patch('/users/:id/reset-password', auth, isSuperAdmin, async (req, res, next) => {`);

replaceOnce('DELETE USER -> superadmin only',
`router.delete('/users/:id', auth, isAdmin, async (req, res, next) => {`,
`router.delete('/users/:id', auth, isSuperAdmin, async (req, res, next) => {`);

replaceOnce('CHANGE DEPARTMENT -> superadmin only (route-level)',
`router.patch('/users/:id/department', auth, isAdmin, async (req, res, next) => {`,
`router.patch('/users/:id/department', auth, isSuperAdmin, async (req, res, next) => {`);

fs.writeFileSync(path, content);
console.log(`\n=== DONE: ${applied} applied ===`);
