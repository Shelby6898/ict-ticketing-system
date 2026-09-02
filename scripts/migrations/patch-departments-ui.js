const fs = require('fs');
const path = 'public/index.html';
let html = fs.readFileSync(path, 'utf8');
let applied = 0, skipped = 0;

function replaceOnce(label, oldStr, newStr) {
  if (!html.includes(oldStr)) {
    console.log(`⚠️  SKIPPED (not found): ${label}`);
    skipped++;
    return;
  }
  html = html.replace(oldStr, newStr);
  console.log(`✅ Applied: ${label}`);
  applied++;
}

function replaceAll(label, oldStr, newStr) {
  if (!html.includes(oldStr)) {
    console.log(`⚠️  SKIPPED (not found): ${label}`);
    skipped++;
    return;
  }
  const count = html.split(oldStr).length - 1;
  html = html.split(oldStr).join(newStr);
  console.log(`✅ Applied (${count}x): ${label}`);
  applied++;
}

// 1. Ticket form: Department + Title row, then Category alone
replaceOnce('ticket form department field',
`      <div class="form-row">
        <div class="field"><label>Issue title</label><input type="text" id="ticketTitle" placeholder="Brief summary of the issue"/></div>
        <div class="field">
          <label>Category</label>
          <select id="ticketCategory">
            <option value="">Select a category</option>
            <option value="hardware">🖥️ Hardware</option>
            <option value="software">💾 Software</option>
            <option value="network">🌐 Network</option>
            <option value="other">📋 Other</option>
          </select>
        </div>
      </div>`,
`      <div class="form-row">
        <div class="field">
          <label>Department</label>
          <select id="ticketDepartment" onchange="onDepartmentChange()">
            <option value="">Select a department</option>
          </select>
        </div>
        <div class="field"><label>Issue title</label><input type="text" id="ticketTitle" placeholder="Brief summary of the issue"/></div>
      </div>
      <div class="form-row">
        <div class="field">
          <label>Category</label>
          <select id="ticketCategory">
            <option value="">Select a department first</option>
          </select>
        </div>
      </div>`);

// 2. submitTicket()
replaceOnce('submitTicket() department handling',
`async function submitTicket(){
  const title=document.getElementById('ticketTitle').value.trim();
  const category=document.getElementById('ticketCategory').value;
  const priority=document.getElementById('ticketPriority').value;
  const device=document.getElementById('ticketDevice').value.trim();
  const desc=document.getElementById('ticketDesc').value.trim();
  if(!title||!category||!desc)return toast('Please fill in Title, Category, and Description.','error');
  setLoading('submitBtn',true);
  try{
    const r=await fetch(\`\${API}/tickets\`,{method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+token},body:JSON.stringify({title,description:desc,priority,category,device})});`,
`async function submitTicket(){
  const department=document.getElementById('ticketDepartment').value;
  const title=document.getElementById('ticketTitle').value.trim();
  const category=document.getElementById('ticketCategory').value;
  const priority=document.getElementById('ticketPriority').value;
  const device=document.getElementById('ticketDevice').value.trim();
  const desc=document.getElementById('ticketDesc').value.trim();
  if(!department||!title||!category||!desc)return toast('Please fill in Department, Title, Category, and Description.','error');
  setLoading('submitBtn',true);
  try{
    const r=await fetch(\`\${API}/tickets\`,{method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+token},body:JSON.stringify({title,description:desc,priority,department,category,device})});`);

// 3. clearForm()
replaceOnce('clearForm() department reset',
`function clearForm(){
  ['ticketTitle','ticketDevice','ticketDesc'].forEach(id=>document.getElementById(id).value='');
  document.getElementById('ticketCategory').value='';
  document.getElementById('ticketPriority').value='medium';
}`,
`function clearForm(){
  ['ticketTitle','ticketDevice','ticketDesc'].forEach(id=>document.getElementById(id).value='');
  document.getElementById('ticketDepartment').value='';
  document.getElementById('ticketCategory').innerHTML='<option value="">Select a department first</option>';
  document.getElementById('ticketPriority').value='medium';
}`);

// 4. Add departmentBadge + loadDepartments + onDepartmentChange after categoryBadge()
replaceOnce('departmentBadge + loadDepartments + onDepartmentChange functions',
`function categoryBadge(c){
  const map={hardware:'badge-hardware',software:'badge-software',network:'badge-network',other:'badge-other'};
  return\`<span class="badge \${map[c]||'badge-other'}">\${c||'—'}</span>\`;
}`,
`function categoryBadge(c){
  const map={hardware:'badge-hardware',software:'badge-software',network:'badge-network',other:'badge-other'};
  return\`<span class="badge \${map[c]||'badge-other'}">\${c||'—'}</span>\`;
}
let DEPARTMENTS=[];
function departmentBadge(d){
  const dept=DEPARTMENTS.find(x=>x.key===d);
  const label=dept?\`\${dept.icon} \${dept.label}\`:(d||'—');
  return\`<span class="badge badge-other">\${label}</span>\`;
}
async function loadDepartments(){
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
}
function onDepartmentChange(){
  const deptKey=document.getElementById('ticketDepartment').value;
  const catSel=document.getElementById('ticketCategory');
  const dept=DEPARTMENTS.find(d=>d.key===deptKey);
  if(!dept){catSel.innerHTML='<option value="">Select a department first</option>';return;}
  catSel.innerHTML='<option value="">Select a category</option>'+dept.categories.map(c=>\`<option value="\${c.key}">\${c.label}</option>\`).join('');
}`);

// 5. initSession() — support superadmin, load departments
replaceOnce('initSession() superadmin support + loadDepartments call',
`function initSession(){
  if(!currentUser)return show('loginScreen');
  if(currentUser.role==='admin'){
    document.getElementById('adminName').textContent=currentUser.name||currentUser.email;
    show('adminScreen');
    loadAgents().then(()=>loadAdminTickets());
  }else{
    document.getElementById('userName').textContent=currentUser.name||currentUser.email;
    document.getElementById('userAvatar').textContent=(currentUser.name||'U')[0].toUpperCase();
    show('userScreen');
    loadMyTickets();
  }
}`,
`function initSession(){
  if(!currentUser)return show('loginScreen');
  loadDepartments();
  if(currentUser.role==='admin'||currentUser.role==='superadmin'){
    document.getElementById('adminName').textContent=currentUser.name||currentUser.email;
    show('adminScreen');
    loadAgents().then(()=>loadAdminTickets());
  }else{
    document.getElementById('userName').textContent=currentUser.name||currentUser.email;
    document.getElementById('userAvatar').textContent=(currentUser.name||'U')[0].toUpperCase();
    show('userScreen');
    loadMyTickets();
  }
}`);

// 6. Toolbar: add department filter dropdown
replaceOnce('admin toolbar department filter dropdown',
`          <select class="filter-sel" id="filterCategory" onchange="renderAdminTable()">
            <option value="">All Categories</option>
            <option value="hardware">Hardware</option>
            <option value="software">Software</option>
            <option value="network">Network</option>
            <option value="other">Other</option>
          </select>
        </div>`,
`          <select class="filter-sel" id="filterCategory" onchange="renderAdminTable()">
            <option value="">All Categories</option>
            <option value="hardware">Hardware</option>
            <option value="software">Software</option>
            <option value="network">Network</option>
            <option value="other">Other</option>
          </select>
          <select class="filter-sel" id="filterDepartment" onchange="renderAdminTable()">
            <option value="">All Departments</option>
          </select>
        </div>`);

// 7. renderAdminTable() filter logic
replaceOnce('renderAdminTable() department filter logic',
`function renderAdminTable(){
  const search=document.getElementById('adminSearch').value.toLowerCase();
  const status=document.getElementById('filterStatus').value;
  const prio=document.getElementById('filterPriority').value;
  const cat=document.getElementById('filterCategory').value;
  const list=allTickets.filter(t=>{
    const m=!search||(t.title||'').toLowerCase().includes(search)||(t.userEmail||'').toLowerCase().includes(search)||(t.userName||'').toLowerCase().includes(search)||(t.id||'').toLowerCase().includes(search);
    return m&&(!status||t.status===status)&&(!prio||t.priority===prio)&&(!cat||t.category===cat);
  });`,
`function renderAdminTable(){
  const search=document.getElementById('adminSearch').value.toLowerCase();
  const status=document.getElementById('filterStatus').value;
  const prio=document.getElementById('filterPriority').value;
  const cat=document.getElementById('filterCategory').value;
  const deptSel=document.getElementById('filterDepartment');
  const dept=deptSel?deptSel.value:'';
  const list=allTickets.filter(t=>{
    const m=!search||(t.title||'').toLowerCase().includes(search)||(t.userEmail||'').toLowerCase().includes(search)||(t.userName||'').toLowerCase().includes(search)||(t.id||'').toLowerCase().includes(search);
    return m&&(!status||t.status===status)&&(!prio||t.priority===prio)&&(!cat||t.category===cat)&&(!dept||t.department===dept);
  });`);

// 8. Admin table header
replaceOnce('admin table header department column',
`<thead><tr><th>ID</th><th>Requester</th><th>Issue</th><th>Category</th><th>Priority</th><th>Status</th><th>Assign To</th><th>Date</th><th>Actions</th></tr></thead>`,
`<thead><tr><th>ID</th><th>Requester</th><th>Issue</th><th>Department</th><th>Category</th><th>Priority</th><th>Status</th><th>Assign To</th><th>Date</th><th>Actions</th></tr></thead>`);

// 9. Admin table row
replaceOnce('admin table row department cell',
`  tbody.innerHTML=list.map(t=>\`
    <tr>
      <td><span class="ticket-id">\${t.id}</span></td>
      <td style="font-size:12px;"><span style="font-weight:500;">\${t.userName||t.requester||'—'}</span><br><span style="color:var(--text3);font-size:11px;">\${t.userEmail||''}</span></td>
      <td><div class="ticket-title-cell">\${t.title}<small>\${t.device||(t.description||'').substring(0,36)||''}</small></div></td>
      <td>\${categoryBadge(t.category)}</td>
      <td>\${priorityBadge(t.priority)}</td>`,
`  tbody.innerHTML=list.map(t=>\`
    <tr>
      <td><span class="ticket-id">\${t.id}</span></td>
      <td style="font-size:12px;"><span style="font-weight:500;">\${t.userName||t.requester||'—'}</span><br><span style="color:var(--text3);font-size:11px;">\${t.userEmail||''}</span></td>
      <td><div class="ticket-title-cell">\${t.title}<small>\${t.device||(t.description||'').substring(0,36)||''}</small></div></td>
      <td>\${departmentBadge(t.department)}</td>
      <td>\${categoryBadge(t.category)}</td>
      <td>\${priorityBadge(t.priority)}</td>`);

// 10. My Tickets table header
replaceOnce('my tickets table header department column',
`<thead><tr><th>Ticket ID</th><th>Issue</th><th>Category</th><th>Priority</th><th>Status</th><th>Assigned To</th><th>Submitted</th></tr></thead>`,
`<thead><tr><th>Ticket ID</th><th>Issue</th><th>Department</th><th>Category</th><th>Priority</th><th>Status</th><th>Assigned To</th><th>Submitted</th></tr></thead>`);

// 11. My Tickets row
replaceOnce('my tickets row department cell',
`  tbody.innerHTML=tickets.map(t=>\`
    <tr onclick="openUserTicketDetail('\${t.id}')" style="cursor:pointer;">
      <td><span class="ticket-id">\${t.id}</span></td>
      <td><div class="ticket-title-cell">\${t.title}<small>\${t.device||''}</small></div></td>
      <td>\${categoryBadge(t.category)}</td>
      <td>\${priorityBadge(t.priority)}</td>`,
`  tbody.innerHTML=tickets.map(t=>\`
    <tr onclick="openUserTicketDetail('\${t.id}')" style="cursor:pointer;">
      <td><span class="ticket-id">\${t.id}</span></td>
      <td><div class="ticket-title-cell">\${t.title}<small>\${t.device||''}</small></div></td>
      <td>\${departmentBadge(t.department)}</td>
      <td>\${categoryBadge(t.category)}</td>
      <td>\${priorityBadge(t.priority)}</td>`);

// 12. Ticket detail modals (both admin + user) — add department badge
replaceAll('ticket detail badges (department added)',
`        \${statusBadge(ticket.status)}
        \${priorityBadge(ticket.priority)}
        \${categoryBadge(ticket.category)}`,
`        \${statusBadge(ticket.status)}
        \${departmentBadge(ticket.department)}
        \${priorityBadge(ticket.priority)}
        \${categoryBadge(ticket.category)}`);

// 13. Create User modal HTML
replaceOnce('create user modal — department field + superadmin role',
`    <div class="field">
      <label>Role</label>
      <select id="cuRole">
        <option value="user">User</option>
        <option value="admin">Admin</option>
      </select>
    </div>
    <button class="btn btn-primary" onclick="createUser()" id="createUserBtn">Create User</button>`,
`    <div class="field">
      <label>Role</label>
      <select id="cuRole" onchange="onCuRoleChange()">
        <option value="user">User</option>
        <option value="admin">Department Admin</option>
        <option value="superadmin">Super Admin</option>
      </select>
    </div>
    <div class="field" id="cuDepartmentField" style="display:none;">
      <label>Department</label>
      <select id="cuDepartment"></select>
    </div>
    <button class="btn btn-primary" onclick="createUser()" id="createUserBtn">Create User</button>`);

// 14. createUser() JS
replaceOnce('createUser() department handling + onCuRoleChange()',
`async function createUser(){
  const name=document.getElementById('cuName').value.trim();
  const email=document.getElementById('cuEmail').value.trim();
  const pass=document.getElementById('cuPass').value;
  const role=document.getElementById('cuRole').value;
  if(!name||!email||!pass)return showErr('createUserErr','All fields are required.');
  if(pass.length<8)return showErr('createUserErr','Password must be at least 8 characters.');
  setLoading('createUserBtn',true);
  try{
    const r=await fetch(\`\${API}/auth/users\`,{method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+token},body:JSON.stringify({name,email,password:pass,role})});
    const data=await r.json();
    if(!r.ok)throw new Error(data.error||'Failed to create user.');
    closeModal('createUserModal');
    ['cuName','cuEmail','cuPass'].forEach(id=>document.getElementById(id).value='');
    document.getElementById('cuRole').value='user';
    toast(\`User "\${name}" created.\`);
    loadUsers();
    if(role==='admin')loadAgents();
  }catch(e){showErr('createUserErr',e.message);}
  finally{setLoading('createUserBtn',false);}
}`,
`function onCuRoleChange(){
  const role=document.getElementById('cuRole').value;
  document.getElementById('cuDepartmentField').style.display=(role==='admin')?'block':'none';
}
async function createUser(){
  const name=document.getElementById('cuName').value.trim();
  const email=document.getElementById('cuEmail').value.trim();
  const pass=document.getElementById('cuPass').value;
  const role=document.getElementById('cuRole').value;
  const department=role==='admin'?document.getElementById('cuDepartment').value:undefined;
  if(!name||!email||!pass)return showErr('createUserErr','All fields are required.');
  if(pass.length<8)return showErr('createUserErr','Password must be at least 8 characters.');
  if(role==='admin'&&!department)return showErr('createUserErr','Please select a department for this admin.');
  setLoading('createUserBtn',true);
  try{
    const r=await fetch(\`\${API}/auth/users\`,{method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+token},body:JSON.stringify({name,email,password:pass,role,department})});
    const data=await r.json();
    if(!r.ok)throw new Error(data.error||'Failed to create user.');
    closeModal('createUserModal');
    ['cuName','cuEmail','cuPass'].forEach(id=>document.getElementById(id).value='');
    document.getElementById('cuRole').value='user';
    document.getElementById('cuDepartmentField').style.display='none';
    toast(\`User "\${name}" created.\`);
    loadUsers();
    if(role==='admin')loadAgents();
  }catch(e){showErr('createUserErr',e.message);}
  finally{setLoading('createUserBtn',false);}
}`);

// 15. Users table header
replaceOnce('users table header department column',
`<thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Actions</th></tr></thead>`,
`<thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Department</th><th>Actions</th></tr></thead>`);

// 16. loadUsers()
replaceOnce('loadUsers() department column + superadmin badge',
`async function loadUsers(){
  const tbody=document.getElementById('usersTbody');
  tbody.innerHTML=\`<tr><td colspan="4" style="text-align:center;padding:24px;color:var(--text3);">Loading…</td></tr>\`;
  try{
    const r=await fetch(\`\${API}/auth/users\`,{headers:{Authorization:'Bearer '+token}});
    const data=await r.json();
    if(!r.ok)throw new Error(data.error);
    if(!data.users.length){tbody.innerHTML=\`<tr><td colspan="4"><div class="empty-state"><span class="empty-icon">👥</span><p>No users found.</p></div></td></tr>\`;return;}
    tbody.innerHTML=data.users.map(u=>\`
      <tr>
        <td style="font-weight:500;">\${u.name}</td>
        <td style="font-size:12px;color:var(--text2);">\${u.email}</td>
        <td>\${u.role==='admin'?'<span class="badge badge-assigned">Admin</span>':'<span class="badge badge-other">User</span>'}</td>
        <td><div class="actions">\${u.id!==currentUser.id?\`<button class="btn btn-ghost btn-sm" onclick="openResetModal('\${u.id}','\${u.name}')">🔑 Reset</button><button class="btn btn-danger btn-sm" onclick="deleteUser('\${u.id}','\${u.name}')">🗑 Delete</button>\`:'<span style="font-size:11px;color:var(--text3)">You</span>'}</div></td>
      </tr>
    \`).join('');
  }catch(e){tbody.innerHTML=\`<tr><td colspan="4" style="text-align:center;padding:24px;color:var(--danger);">Failed to load users.</td></tr>\`;}
}`,
`async function loadUsers(){
  const tbody=document.getElementById('usersTbody');
  tbody.innerHTML=\`<tr><td colspan="5" style="text-align:center;padding:24px;color:var(--text3);">Loading…</td></tr>\`;
  try{
    const r=await fetch(\`\${API}/auth/users\`,{headers:{Authorization:'Bearer '+token}});
    const data=await r.json();
    if(!r.ok)throw new Error(data.error);
    if(!data.users.length){tbody.innerHTML=\`<tr><td colspan="5"><div class="empty-state"><span class="empty-icon">👥</span><p>No users found.</p></div></td></tr>\`;return;}
    const roleBadge=u=>u.role==='superadmin'?'<span class="badge badge-high">Super Admin</span>':u.role==='admin'?'<span class="badge badge-assigned">Admin</span>':'<span class="badge badge-other">User</span>';
    tbody.innerHTML=data.users.map(u=>\`
      <tr>
        <td style="font-weight:500;">\${u.name}</td>
        <td style="font-size:12px;color:var(--text2);">\${u.email}</td>
        <td>\${roleBadge(u)}</td>
        <td>\${u.department?departmentBadge(u.department):'<span style="color:var(--text3);font-size:11px;">—</span>'}</td>
        <td><div class="actions">\${u.id!==currentUser.id?\`<button class="btn btn-ghost btn-sm" onclick="openResetModal('\${u.id}','\${u.name}')">🔑 Reset</button><button class="btn btn-danger btn-sm" onclick="deleteUser('\${u.id}','\${u.name}')">🗑 Delete</button>\`:'<span style="font-size:11px;color:var(--text3)">You</span>'}</div></td>
      </tr>
    \`).join('');
  }catch(e){tbody.innerHTML=\`<tr><td colspan="5" style="text-align:center;padding:24px;color:var(--danger);">Failed to load users.</td></tr>\`;}
}`);

fs.writeFileSync(path, html);
console.log(`\n=== DONE: ${applied} applied, ${skipped} skipped ===`);
if (skipped > 0) console.log('⚠️  Some patches were skipped — review before deploying.');
