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

// 1. Top mobile-nav Users button + sidebar Users nav item — add ids to hide
replaceOnce('top mobile nav Users button id',
`<button class="btn btn-ghost btn-sm" onclick="showAdminPanel('users')">👥 Users</button>`,
`<button class="btn btn-ghost btn-sm" id="topNavUsersBtn" onclick="showAdminPanel('users')">👥 Users</button>`);

replaceOnce('sidebar Users nav item id',
`<div class="nav-item" id="navUsers" onclick="showAdminPanel('users')"><span class="nav-icon">👥</span> Users</div>`,
`<div class="nav-item" id="navUsers" onclick="showAdminPanel('users')" style="display:none;"><span class="nav-icon">👥</span> Users</div>`);

// 2. Hide/show based on role inside initSession or updateAdminBranding
replaceOnce('hide Users tab for department admins',
`function updateAdminBranding(){
  const label=document.getElementById('adminBrandLabel');
  const icon=document.getElementById('adminBrandIcon');
  if(!label||!currentUser)return;`,
`function updateAdminBranding(){
  const label=document.getElementById('adminBrandLabel');
  const icon=document.getElementById('adminBrandIcon');
  const topNavUsersBtn=document.getElementById('topNavUsersBtn');
  const navUsers=document.getElementById('navUsers');
  const isSuperAdmin=currentUser&&currentUser.role==='superadmin';
  if(topNavUsersBtn)topNavUsersBtn.style.display=isSuperAdmin?'':'none';
  if(navUsers)navUsers.style.display=isSuperAdmin?'':'none';
  if(!label||!currentUser)return;`);

fs.writeFileSync(path, html);
console.log(`\n=== DONE: ${applied} applied, ${skipped} skipped ===`);
