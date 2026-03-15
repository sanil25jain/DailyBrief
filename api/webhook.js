import crypto from 'crypto';
import admin from 'firebase-admin';

// 1. Initialize Firebase Admin (but only do it once to avoid errors)
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      // The replace function fixes formatting issues with private keys in environment variables
      privateKey: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
    }),
  });
}

const db = admin.firestore();

export default async function handler(req, res) {
  // Only allow POST requests (which is what Razorpay sends)
  if (req.method !== 'POST') {
    return res.status(405).send('Method Not Allowed');
  }

  const secret = process.env.RAZORPAY_WEBHOOK_SECRET;
  const signature = req.headers['x-razorpay-signature'];

  // 2. Verify that this request actually came from Razorpay (Security check!)
  const expectedSignature = crypto
    .createHmac('sha256', secret)
    .update(JSON.stringify(req.body))
    .digest('hex');

  if (expectedSignature !== signature) {
    return res.status(400).json({ status: 'error', message: 'Invalid signature' });
  }

  try {
    const eventType = req.body.event;
    const usersRef = db.collection('users');

    // ---------------------------------------------------------
    // SCENARIO 1: SUCCESSFUL PAYMENT OR RENEWAL
    // ---------------------------------------------------------
    if (eventType === 'subscription.charged' || eventType === 'payment.captured') {
      const email = req.body.payload.payment.entity.email;

      if (!email) {
        return res.status(400).json({ status: 'error', message: 'No email found in payload' });
      }

      const snapshot = await usersRef.where('email', '==', email).get();

      if (!snapshot.empty) {
        const userDoc = snapshot.docs[0];
        await userDoc.ref.update({ isSubscribed: true });
        console.log(`✅ Access GRANTED for: ${email}`);
      } else {
        console.log(`Payment received for ${email}, but user not found in database.`);
      }
    }

    // ---------------------------------------------------------
    // SCENARIO 2: CANCELLATION OR PAYMENT FAILURE
    // ---------------------------------------------------------
    else if (eventType === 'subscription.cancelled' || eventType === 'subscription.halted') {
      // Use optional chaining (?.) to prevent crashes if the payload structure varies slightly
      const email = req.body.payload.subscription?.entity?.notes?.email;

      if (!email) {
        console.log('No email found in subscription notes payload.');
        return res.status(400).json({ status: 'error', message: 'No email found in payload' });
      }

      const snapshot = await usersRef.where('email', '==', email).get();

      if (!snapshot.empty) {
        const userDoc = snapshot.docs[0];
        await userDoc.ref.update({ isSubscribed: false });
        console.log(`❌ Access REVOKED for: ${email}`);
      } else {
        console.log(`Cancellation received for ${email}, but user not found in database.`);
      }
    }

    // 3. Always tell Razorpay we received the message successfully
    return res.status(200).json({ status: 'ok' });
    
  } catch (error) {
    console.error('Error updating Firestore:', error);
    return res.status(500).json({ status: 'error', message: 'Internal Server Error' });
  }
}