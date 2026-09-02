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

// 1. Page title
replaceOnce('page title',
`<title>ICT HelpDesk</title>`,
`<title>University HelpDesk</title>`);

// 2. Success modal text — add id, generic default
replaceOnce('success modal id + generic default',
`<h3>Ticket Submitted!</h3>
      <p>Your ticket has been received. Our ICT team will review it shortly.</p>`,
`<h3>Ticket Submitted!</h3>
      <p id="successModalText">Your ticket has been received. Our support team will review it shortly.</p>`);

// 3. Update success modal text on submit, right after openModal('successModal')
replaceOnce('update success modal text with department on submit',
`await loadMyTickets();clearForm();openModal('successModal');`,
`const submittedDept=DEPARTMENTS.find(d=>d.key===department);
    const successText=document.getElementById('successModalText');
    if(successText)successText.textContent=\`Your ticket has been received. Our \${submittedDept?submittedDept.label:''} team will review it shortly.\`;
    await loadMyTickets();clearForm();openModal('successModal');`);

fs.writeFileSync(path, html);
console.log(`\n=== DONE: ${applied} applied, ${skipped} skipped ===`);
