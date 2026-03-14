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
    // 3. Extract the email of the person who just paid
    const email = req.body.payload.payment.entity.email;

    if (!email) {
      return res.status(400).json({ status: 'error', message: 'No email found in payload' });
    }

    // 4. Find that user in your Firestore database
    const usersRef = db.collection('users');
    const snapshot = await usersRef.where('email', '==', email).get();

    if (snapshot.empty) {
      console.log(`Payment received for ${email}, but user not found in database.`);
      return res.status(404).json({ status: 'error', message: 'User not found' });
    }

    // 5. Update their document to unlock the app
    const userDoc = snapshot.docs[0];
    await userDoc.ref.update({ isSubscribed: true });

    console.log(`Successfully unlocked app for: ${email}`);
    
    // 6. Tell Razorpay we received the message successfully
    return res.status(200).json({ status: 'ok' });
    
  } catch (error) {
    console.error('Error updating Firestore:', error);
    return res.status(500).json({ status: 'error', message: 'Internal Server Error' });
  }
}