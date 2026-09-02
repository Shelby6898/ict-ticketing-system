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

// 1. Replace static priorityBadge cell with an editable select in the admin table row
replaceOnce('admin table row: editable priority select',
`      <td>\${departmentBadge(t.department)}</td>
      <td>\${categoryBadge(t.category)}</td>
      <td>\${priorityBadge(t.priority)}</td>
      <td>
        <select class="status-select" onchange="changeStatus('\${t.id}',this.value)">`,
`      <td>\${departmentBadge(t.department)}</td>
      <td>\${categoryBadge(t.category)}</td>
      <td>
        <select class="status-select" onchange="changePriority('\${t.id}',this.value)">
          <option value="low" \${t.priority==='low'?'selected':''}>🟢 Low</option>
          <option value="medium" \${t.priority==='medium'?'selected':''}>🟡 Medium</option>
          <option value="high" \${t.priority==='high'?'selected':''}>🔴 High</option>
          <option value="urgent" \${t.priority==='urgent'?'selected':''}>🚨 Urgent</option>
        </select>
      </td>
      <td>
        <select class="status-select" onchange="changeStatus('\${t.id}',this.value)">`);

// 2. Add changePriority() function right after changeStatus()
replaceOnce('add changePriority() function',
`async function changeStatus(id,status){
  const idx=allTickets.findIndex(t=>t.id===id);
  if(idx>-1)allTickets[idx].status=status;
  updateStats();
  try{
    const r=await fetch(\`\${API}/tickets/\${id}/status\`,{method:'PATCH',headers:{'Content-Type':'application/json',Authorization:'Bearer '+token},body:JSON.stringify({status})});
    if(!r.ok)throw new Error();
    toast(\`Status updated to "\${status}"\`);
  }catch(e){toast(\`Status updated to "\${status}"\`);}
}`,
`async function changeStatus(id,status){
  const idx=allTickets.findIndex(t=>t.id===id);
  if(idx>-1)allTickets[idx].status=status;
  updateStats();
  try{
    const r=await fetch(\`\${API}/tickets/\${id}/status\`,{method:'PATCH',headers:{'Content-Type':'application/json',Authorization:'Bearer '+token},body:JSON.stringify({status})});
    if(!r.ok)throw new Error();
    toast(\`Status updated to "\${status}"\`);
  }catch(e){toast(\`Status updated to "\${status}"\`);}
}

async function changePriority(id,priority){
  const idx=allTickets.findIndex(t=>t.id===id);
  const prev=idx>-1?allTickets[idx].priority:null;
  if(idx>-1)allTickets[idx].priority=priority;
  try{
    const r=await fetch(\`\${API}/tickets/\${id}\`,{method:'PATCH',headers:{'Content-Type':'application/json',Authorization:'Bearer '+token},body:JSON.stringify({priority})});
    const data=await r.json();
    if(!r.ok)throw new Error(data.error||'Failed to update priority.');
    toast(\`Priority updated to "\${priority}"\`);
  }catch(e){
    if(idx>-1)allTickets[idx].priority=prev;
    renderAdminTable();
    toast('❌ '+e.message,'error');
  }
}`);

fs.writeFileSync(path, html);
console.log(`\n=== DONE: ${applied} applied, ${skipped} skipped ===`);
