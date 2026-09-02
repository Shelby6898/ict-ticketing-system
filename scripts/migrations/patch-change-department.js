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

// 1. Add "Change Department Modal" HTML after resetPasswordModal
replaceOnce('add changeDepartmentModal HTML',
`<div class="modal-overlay" id="resetPasswordModal">`,
`<div class="modal-overlay" id="changeDepartmentModal">
  <div class="modal" style="max-width:420px;">
    <div class="modal-header">
      <span class="modal-title">🏢 Change Department</span>
      <button class="modal-close" onclick="closeModal('changeDepartmentModal')">✕</button>
    </div>
    <div class="err-msg" id="changeDeptErr"></div>
    <p style="color:var(--text2);font-size:13px;margin-bottom:20px;">Reassigning <strong id="changeDeptUserName"></strong> to a new department</p>
    <div class="field"><label>Department</label><select id="changeDeptSelect"></select></div>
    <button class="btn btn-primary" onclick="submitChangeDepartment()" id="changeDeptBtn">Update Department</button>
  </div>
</div>

<div class="modal-overlay" id="resetPasswordModal">`);

// 2. Add openChangeDeptModal + submitChangeDepartment JS after resetPassword()
replaceOnce('add openChangeDeptModal + submitChangeDepartment functions',
`async function loadUsers(){`,
`let changeDeptTargetId = null;
function openChangeDeptModal(id, name){
  changeDeptTargetId = id;
  document.getElementById('changeDeptUserName').textContent = name;
  const sel = document.getElementById('changeDeptSelect');
  sel.innerHTML = DEPARTMENTS.map(d => \`<option value="\${d.key}">\${d.icon} \${d.label}</option>\`).join('');
  openModal('changeDepartmentModal');
}
async function submitChangeDepartment(){
  const department = document.getElementById('changeDeptSelect').value;
  if(!department) return showErr('changeDeptErr','Please select a department.');
  setLoading('changeDeptBtn', true);
  try{
    const r = await fetch(\`\${API}/auth/users/\${changeDeptTargetId}/department\`,{
      method:'PATCH',
      headers:{'Content-Type':'application/json',Authorization:'Bearer '+token},
      body: JSON.stringify({ department })
    });
    const data = await r.json();
    if(!r.ok) throw new Error(data.error || 'Failed to update department.');
    closeModal('changeDepartmentModal');
    toast('Department updated.');
    loadUsers();
    loadAgents();
  }catch(e){
    showErr('changeDeptErr', e.message);
  }finally{
    setLoading('changeDeptBtn', false);
  }
}

async function loadUsers(){`);

// 3. Add "Change Dept" button next to Reset/Delete, only for admin-role users, only when current user is superadmin
replaceOnce('add Change Dept button in user actions',
`<td><div class="actions">\${u.id!==currentUser.id?\`<button class="btn btn-ghost btn-sm" onclick="openResetModal('\${u.id}','\${u.name}')">🔑 Reset</button><button class="btn btn-danger btn-sm" onclick="deleteUser('\${u.id}','\${u.name}')">🗑 Delete</button>\`:'<span style="font-size:11px;color:var(--text3)">You</span>'}</div></td>`,
`<td><div class="actions">\${u.id!==currentUser.id?\`\${(u.role==='admin'&&currentUser.role==='superadmin')?\`<button class="btn btn-ghost btn-sm" onclick="openChangeDeptModal('\${u.id}','\${u.name}')">🏢 Dept</button>\`:''}<button class="btn btn-ghost btn-sm" onclick="openResetModal('\${u.id}','\${u.name}')">🔑 Reset</button><button class="btn btn-danger btn-sm" onclick="deleteUser('\${u.id}','\${u.name}')">🗑 Delete</button>\`:'<span style="font-size:11px;color:var(--text3)">You</span>'}</div></td>`);

fs.writeFileSync(path, html);
console.log(`\n=== DONE: ${applied} applied, ${skipped} skipped ===`);
