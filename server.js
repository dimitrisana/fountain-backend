const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Stripe = require('stripe');

const app = express();

// Environment Variables
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || 'sk_test_dummy_key';
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || '';
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_fountain_key_123';
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/fountain';
const PORT = process.env.PORT || 5000;
const CLIENT_URL = process.env.FRONTEND_URL || process.env.CLIENT_URL || 'https://fountain-frontend.vercel.app';

// Initialize Stripe
const stripe = Stripe(STRIPE_SECRET_KEY);

// --- SCHEMAS & MODELS ---

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

const wishSchema = new mongoose.Schema({
    text: { type: String, required: true },
    isPublic: { type: Boolean, default: true },
    author: { type: String, default: 'Anonymous' },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    createdAt: { type: Date, default: Date.now }
});
const Wish = mongoose.model('Wish', wishSchema);

// --- STRIPE WEBHOOK ENDPOINT ---
// Πρέπει να μπει ΠΡΙΝ το app.use(express.json()) επειδή η Stripe απαιτεί raw body για την επαλήθευση υπογραφής.
app.post('/api/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
    const sig = req.headers['stripe-signature'];
    let event;

    try {
        if (STRIPE_WEBHOOK_SECRET) {
            event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
        } else {
            event = JSON.parse(req.body.toString());
        }
    } catch (err) {
        console.error(`Webhook Error: ${err.message}`);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    // Διαχείριση επιτυχούς πληρωμής
    if (event.type === 'checkout.session.completed') {
        const session = event.data.object;
        const metadata = session.metadata || {};

        try {
            const newWish = new Wish({
                text: metadata.wishText || 'Wish Fountain Coin',
                isPublic: metadata.isPublic === 'true',
                author: metadata.author || 'Anonymous',
                userId: metadata.userId ? metadata.userId : null
            });
            await newWish.save();
            console.log('Wish saved successfully after payment:', newWish);
        } catch (dbErr) {
            console.error('Error saving wish to DB via webhook:', dbErr);
        }
    }

    res.json({ received: true });
});

// Middleware για τα υπόλοιπα JSON endpoints
app.use(express.json());
app.use(cors());

// --- AUTHENTICATION ENDPOINTS ---

app.post('/api/auth/signup', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(400).json({ message: 'Username and password are required.' });
        }

        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ message: 'Username already exists.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, password: hashedPassword });
        await newUser.save();

        const token = jwt.sign({ id: newUser._id, username: newUser.username }, JWT_SECRET, { expiresIn: '7d' });

        res.status(201).json({
            message: 'User created successfully',
            token,
            user: { id: newUser._id, username: newUser.username }
        });
    } catch (err) {
        res.status(500).json({ message: 'Error creating user', error: err.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials.' });
        }

        const token = jwt.sign({ id: user._id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });

        res.json({
            message: 'Login successful',
            token,
            user: { id: user._id, username: user.username }
        });
    } catch (err) {
        res.status(500).json({ message: 'Error logging in', error: err.message });
    }
});

// --- WISHES ENDPOINTS ---

app.get('/api/wishes', async (req, res) => {
    try {
        const wishes = await Wish.find({ isPublic: true }).sort({ createdAt: -1 });
        res.json(wishes);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.post('/api/wishes', async (req, res) => {
    try {
        const { text, isPublic, author, userId } = req.body;
        const newWish = new Wish({ 
            text, 
            isPublic: isPublic !== undefined ? isPublic : true, 
            author: author || 'Anonymous', 
            userId: userId || null 
        });
        await newWish.save();
        res.status(201).json(newWish);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// --- STRIPE CHECKOUT SESSION ENDPOINT ---

app.post('/api/create-checkout-session', async (req, res) => {
    try {
        const { wishText, isPublic, author, userId } = req.body;

        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items: [{
                price_data: {
                    currency: 'eur',
                    product_data: {
                        name: 'Make a Wish ✨',
                        description: wishText ? `Wish: "${wishText}"` : 'Wish Fountain Coin',
                    },
                    unit_amount: 100, // 1.00 EUR
                },
                quantity: 1,
            }],
            mode: 'payment',
            metadata: {
                wishText: wishText || '',
                isPublic: String(isPublic),
                author: author || 'Anonymous',
                userId: userId || ''
            },
            success_url: `${CLIENT_URL}/?success=true`,
            cancel_url: `${CLIENT_URL}/?canceled=true`,
        });

        res.json({ id: session.id });
    } catch (err) {
        res.status(500).json({ message: 'Stripe Checkout Error', error: err.message });
    }
});

// --- DATABASE & SERVER START ---

mongoose.connect(MONGO_URI)
    .then(() => {
        console.log('MongoDB Connected!');
        app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
    })
    .catch(err => console.error('DB Connection Error:', err));
