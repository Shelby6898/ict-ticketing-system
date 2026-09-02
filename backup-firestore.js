require('dotenv').config();
// backup-firestore.js
// Dumps tickets (with their comments subcollections) and users to local JSON files.
// Run from your project root: node backup-firestore.js

const fs = require('fs');
const path = require('path');
const { db } = require('./services/firebase');

async function backupCollection(collectionName, withSubcollection) {
  const snap = await db.collection(collectionName).get();
  const docs = [];

  for (const doc of snap.docs) {
    const data = { id: doc.id, ...doc.data() };

    if (withSubcollection) {
      const subSnap = await doc.ref.collection(withSubcollection).get();
      data[withSubcollection] = subSnap.docs.map(sub => ({ id: sub.id, ...sub.data() }));
    }

    docs.push(data);
  }

  return docs;
}

async function main() {
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const outDir = path.join(__dirname, `backup-${stamp}`);
  fs.mkdirSync(outDir, { recursive: true });

  console.log('Backing up tickets (with comments)...');
  const tickets = await backupCollection('tickets', 'comments');
  fs.writeFileSync(path.join(outDir, 'tickets.json'), JSON.stringify(tickets, null, 2));
  console.log(`  -> ${tickets.length} tickets saved.`);

  console.log('Backing up users...');
  const users = await backupCollection('users', null);
  fs.writeFileSync(path.join(outDir, 'users.json'), JSON.stringify(users, null, 2));
  console.log(`  -> ${users.length} users saved.`);

  console.log(`\nBackup complete: ${outDir}`);
  process.exit(0);
}

main().catch(err => {
  console.error('Backup failed:', err);
  process.exit(1);
});
