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

// 1. Page subtitle — make dynamic, add id
replaceOnce('page subtitle id',
`      <p class="page-sub">Describe your issue and our ICT team will respond promptly</p>`,
`      <p class="page-sub" id="ticketPageSub">Describe your issue and the relevant department will respond promptly</p>`);

// 2. Device field — add ids to label + input for dynamic updates
replaceOnce('device field label/placeholder ids',
`<div class="field"><label>Affected device / system</label><input type="text" id="ticketDevice" placeholder="e.g. Dell Laptop, HP Printer"/></div>`,
`<div class="field"><label id="ticketDeviceLabel">Reference / Affected Item</label><input type="text" id="ticketDevice" placeholder="Optional reference"/></div>`);

// 3. Description field — remove hardcoded ICT-flavored placeholder, id already exists (ticketDesc)
replaceOnce('description field generic default placeholder',
`<div class="field"><label>Description</label><textarea id="ticketDesc" placeholder="Describe the issue — what happened, when it started, any error messages…"></textarea></div>`,
`<div class="field"><label>Description</label><textarea id="ticketDesc" placeholder="Describe your issue in detail…"></textarea></div>`);

// 4. Extend onDepartmentChange() to update hints
replaceOnce('onDepartmentChange() field-hint logic',
`function onDepartmentChange(){
  const deptKey=document.getElementById('ticketDepartment').value;
  const catSel=document.getElementById('ticketCategory');
  const dept=DEPARTMENTS.find(d=>d.key===deptKey);
  if(!dept){catSel.innerHTML='<option value="">Select a department first</option>';return;}
  catSel.innerHTML='<option value="">Select a category</option>'+dept.categories.map(c=>\`<option value="\${c.key}">\${c.label}</option>\`).join('');
}`,
`const FIELD_HINTS={
  ict:{deviceLabel:'Affected Device / System',devicePlaceholder:'e.g. Dell Laptop, HP Printer',descPlaceholder:'Describe the issue — what happened, when it started, any error messages…'},
  finance:{deviceLabel:'Reference (Invoice/Receipt No.)',devicePlaceholder:'e.g. Receipt #2024-1123',descPlaceholder:'Describe your finance issue — fee balance, refund request, payroll discrepancy…'},
  academics:{deviceLabel:'Reference (Course/Unit Code)',devicePlaceholder:'e.g. BSC101',descPlaceholder:'Describe your academic issue — registration, transcript, exam, or grade concern…'},
  hostel:{deviceLabel:'Room Number',devicePlaceholder:'e.g. Block C, Room 12',descPlaceholder:'Describe your accommodation issue — allocation, maintenance, complaint…'},
  library:{deviceLabel:'Book / Resource Reference',devicePlaceholder:'e.g. ISBN or Book Title',descPlaceholder:'Describe your library issue — access, fines, book request, returns…'}
};
function onDepartmentChange(){
  const deptKey=document.getElementById('ticketDepartment').value;
  const catSel=document.getElementById('ticketCategory');
  const dept=DEPARTMENTS.find(d=>d.key===deptKey);
  if(!dept){
    catSel.innerHTML='<option value="">Select a department first</option>';
    document.getElementById('ticketDeviceLabel').textContent='Reference / Affected Item';
    document.getElementById('ticketDevice').placeholder='Optional reference';
    document.getElementById('ticketDesc').placeholder='Describe your issue in detail…';
    document.getElementById('ticketPageSub').textContent='Describe your issue and the relevant department will respond promptly';
    return;
  }
  catSel.innerHTML='<option value="">Select a category</option>'+dept.categories.map(c=>\`<option value="\${c.key}">\${c.label}</option>\`).join('');
  const hint=FIELD_HINTS[deptKey];
  if(hint){
    document.getElementById('ticketDeviceLabel').textContent=hint.deviceLabel;
    document.getElementById('ticketDevice').placeholder=hint.devicePlaceholder;
    document.getElementById('ticketDesc').placeholder=hint.descPlaceholder;
  }
  document.getElementById('ticketPageSub').textContent=\`Describe your issue and the \${dept.label} team will respond promptly\`;
}`);

fs.writeFileSync(path, html);
console.log(`\n=== DONE: ${applied} applied, ${skipped} skipped ===`);
