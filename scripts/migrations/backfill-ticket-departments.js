require('dotenv').config();
const { db, admin } = require('./services/firebase');

(async () => {
  const snap = await db.collection('tickets').get();
  let updated = 0;
  for (const doc of snap.docs) {
    const data = doc.data();
    if (!data.department) {
      await doc.ref.update({ department: 'ict', updatedAt: admin.firestore.FieldValue.serverTimestamp() });
      console.log(`Updated ${doc.id} ("${data.title}") -> department: ict`);
      updated++;
    }
  }
  console.log(`\n=== DONE: ${updated} ticket(s) backfilled ===`);
  process.exit(0);
})();
