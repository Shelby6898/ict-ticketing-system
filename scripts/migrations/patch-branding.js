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

// 1. Admin topbar — add IDs
replaceOnce('admin topbar dynamic branding markup',
`    <div class="topbar-brand">
      <div class="logo-mark" style="width:32px;height:32px;font-size:14px;border-radius:8px;background:linear-gradient(135deg,#ef4444,#f97316);">🖥️</div>
      ICT <span class="brand-dot">·</span> Admin
    </div>`,
`    <div class="topbar-brand">
      <div class="logo-mark" id="adminBrandIcon" style="width:32px;height:32px;font-size:14px;border-radius:8px;background:linear-gradient(135deg,#ef4444,#f97316);">🖥️</div>
      <span id="adminBrandLabel">University</span> <span class="brand-dot">·</span> Admin
    </div>`);

// 2. User topbar — generic branding
replaceOnce('user topbar generic branding',
`    <div class="topbar-brand">
      <div class="logo-mark" style="width:32px;height:32px;font-size:14px;border-radius:8px;">🖥️</div>
      ICT <span class="brand-dot">·</span> HelpDesk
    </div>`,
`    <div class="topbar-brand">
      <div class="logo-mark" style="width:32px;height:32px;font-size:14px;border-radius:8px;">🎓</div>
      University <span class="brand-dot">·</span> HelpDesk
    </div>`);

// 3. Login screen branding
replaceOnce('login screen generic branding',
`      <div class="logo-mark">🖥️</div>
      <div class="logo-text">ICT <span>HelpDesk</span></div>`,
`      <div class="logo-mark">🎓</div>
      <div class="logo-text">University <span>HelpDesk</span></div>`);

// 4. Add updateAdminBranding() function, hook into loadDepartments()
replaceOnce('updateAdminBranding() function + hook into loadDepartments',
`async function loadDepartments(){
  try{
    const r=await fetch(\`\${API}/departments\`,{headers:{Authorization:'Bearer '+token}});
    const data=await r.json();
    if(r.ok&&data.departments){
      DEPARTMENTS=data.departments;
      const deptSel=document.getElementById('ticketDepartment');
      if(deptSel)deptSel.innerHTML='<option value="">Select a department</option>'+DEPARTMENTS.map(d=>\`<option value="\${d.key}">\${d.icon} \${d.label}</option>\`).join('');
      const filterDeptSel=document.getElementById('filterDepartment');
      if(filterDeptSel)filterDeptSel.innerHTML='<option value="">All Departments</option>'+DEPARTMENTS.map(d=>\`<option value="\${d.key}">\${d.icon} \${d.label}</option>\`).join('');
      const cuDeptSel=document.getElementById('cuDepartment');
      if(cuDeptSel)cuDeptSel.innerHTML=DEPARTMENTS.map(d=>\`<option value="\${d.key}">\${d.icon} \${d.label}</option>\`).join('');
    }
  }catch(e){}
}`,
`async function loadDepartments(){
  try{
    const r=await fetch(\`\${API}/departments\`,{headers:{Authorization:'Bearer '+token}});
    const data=await r.json();
    if(r.ok&&data.departments){
      DEPARTMENTS=data.departments;
      const deptSel=document.getElementById('ticketDepartment');
      if(deptSel)deptSel.innerHTML='<option value="">Select a department</option>'+DEPARTMENTS.map(d=>\`<option value="\${d.key}">\${d.icon} \${d.label}</option>\`).join('');
      const filterDeptSel=document.getElementById('filterDepartment');
      if(filterDeptSel)filterDeptSel.innerHTML='<option value="">All Departments</option>'+DEPARTMENTS.map(d=>\`<option value="\${d.key}">\${d.icon} \${d.label}</option>\`).join('');
      const cuDeptSel=document.getElementById('cuDepartment');
      if(cuDeptSel)cuDeptSel.innerHTML=DEPARTMENTS.map(d=>\`<option value="\${d.key}">\${d.icon} \${d.label}</option>\`).join('');
      updateAdminBranding();
    }
  }catch(e){}
}
function updateAdminBranding(){
  const label=document.getElementById('adminBrandLabel');
  const icon=document.getElementById('adminBrandIcon');
  if(!label||!currentUser)return;
  if(currentUser.role==='superadmin'||!currentUser.department){
    label.textContent='University';
    if(icon)icon.textContent='🎓';
  }else{
    const dept=DEPARTMENTS.find(d=>d.key===currentUser.department);
    if(dept){
      label.textContent=dept.label;
      if(icon)icon.textContent=dept.icon;
    }
  }
}`);

fs.writeFileSync(path, html);
console.log(`\n=== DONE: ${applied} applied, ${skipped} skipped ===`);
