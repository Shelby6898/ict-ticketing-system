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

// 1. Add id to the submit hint paragraph
replaceOnce('submit hint id',
`<p class="submit-hint">Our ICT team will review your ticket and respond promptly.</p>`,
`<p class="submit-hint" id="ticketSubmitHint">Our support team will review your ticket and respond promptly.</p>`);

// 2. Update it inside onDepartmentChange()
replaceOnce('update submit hint per department',
`document.getElementById('ticketPageSub').textContent=\`Describe your issue and the \${dept.label} team will respond promptly\`;
}`,
`document.getElementById('ticketPageSub').textContent=\`Describe your issue and the \${dept.label} team will respond promptly\`;
  const submitHint=document.getElementById('ticketSubmitHint');
  if(submitHint)submitHint.textContent=\`Our \${dept.label} team will review your ticket and respond promptly.\`;
}`);

fs.writeFileSync(path, html);
console.log(`\n=== DONE: ${applied} applied, ${skipped} skipped ===`);
