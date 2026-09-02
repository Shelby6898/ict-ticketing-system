const fs = require('fs');
const path = 'public/index.html';
let html = fs.readFileSync(path, 'utf8');
let applied = 0, skipped = 0;

function replaceOnce(label, oldStr, newStr) {
  if (!html.includes(oldStr)) { console.log(`⚠️  SKIPPED: ${label}`); skipped++; return; }
  html = html.replace(oldStr, newStr);
  console.log(`✅ Applied: ${label}`);
  applied++;
}

// Hide the department filter dropdown for department admins (only superadmin needs it)
replaceOnce('hide department filter for non-superadmins',
`function updateAdminBranding(){
  const label=document.getElementById('adminBrandLabel');
  const icon=document.getElementById('adminBrandIcon');
  const topNavUsersBtn=document.getElementById('topNavUsersBtn');
  const navUsers=document.getElementById('navUsers');
  const isSuperAdmin=currentUser&&currentUser.role==='superadmin';
  if(topNavUsersBtn)topNavUsersBtn.style.display=isSuperAdmin?'':'none';
  if(navUsers)navUsers.style.display=isSuperAdmin?'':'none';
  if(!label||!currentUser)return;`,
`function updateAdminBranding(){
  const label=document.getElementById('adminBrandLabel');
  const icon=document.getElementById('adminBrandIcon');
  const topNavUsersBtn=document.getElementById('topNavUsersBtn');
  const navUsers=document.getElementById('navUsers');
  const filterDeptSel=document.getElementById('filterDepartment');
  const isSuperAdmin=currentUser&&currentUser.role==='superadmin';
  if(topNavUsersBtn)topNavUsersBtn.style.display=isSuperAdmin?'':'none';
  if(navUsers)navUsers.style.display=isSuperAdmin?'':'none';
  if(filterDeptSel)filterDeptSel.style.display=isSuperAdmin?'':'none';
  if(!label||!currentUser)return;`);

fs.writeFileSync(path, html);
console.log(`\n=== DONE: ${applied} applied, ${skipped} skipped ===`);
