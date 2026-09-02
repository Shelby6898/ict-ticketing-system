require('dotenv').config();
// wipe-tickets.js
// Deletes every document in the 'tickets' collection, including each ticket's
// 'comments' subcollection first (Firestore does not cascade-delete subcollections).
// Does NOT touch the 'users' collection.
//
// Run from your project root: node wipe-tickets.js
// ALWAYS run backup-firestore.js first and confirm the backup file has real data.

const { db } = require('./services/firebase');

async function deleteSubcollection(docRef, subName) {
  const subSnap = await docRef.collection(subName).get();
  const batchDeletes = subSnap.docs.map(d => d.ref.delete());
  await Promise.all(batchDeletes);
  return subSnap.size;
}

async function main() {
  console.log('Fetching tickets...');
  const snap = await db.collection('tickets').get();
  console.log(`Found ${snap.size} tickets. Deleting comments subcollections first...`);

  let totalComments = 0;
  for (const doc of snap.docs) {
    const count = await deleteSubcollection(doc.ref, 'comments');
    totalComments += count;
  }
  console.log(`Deleted ${totalComments} total comments across all tickets.`);

  console.log('Deleting ticket documents...');
  const deletes = snap.docs.map(d => d.ref.delete());
  await Promise.all(deletes);

  console.log(`\nDone. Deleted ${snap.size} tickets and ${totalComments} comments.`);
  console.log('The "users" collection was NOT touched.');
  process.exit(0);
}

main().catch(err => {
  console.error('Wipe failed:', err);
  process.exit(1);
});
