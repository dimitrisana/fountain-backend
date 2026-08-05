const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jwt-simple'); // ή jsonwebtoken
const jwtLib = require('jsonwebtoken');
const Stripe = require('stripe');

const app = express();
app.use(express.json());
app.use(cors());

// Initialize Stripe (Χρησιμοποιεί το Secret Key από το .env / Render)
const stripe = Stripe(process.env.STRIPE_SECRET_KEY || 'sk_test_dummy_key');

const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_fountain_key_123';

// --- SCHEMAS & MODELS ---

// User Schema
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

// Wish Schema
const wishSchema = new mongoose.Schema({
    text: { type: String, required: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    createdAt: { type: Date, default: Date.now }
});
const Wish = mongoose.model('Wish', wishSchema);

// --- AUTHENTICATION ENDPOINTS ---

// Signup Route
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

        const token = jwtLib.sign({ id: newUser._id, username: newUser.username }, JWT_SECRET, { expiresIn: '7d' });

        res.status(201).json({
            message: 'User created successfully',
            token,
            user: { id: newUser._id, username: newUser.username }
        });
    } catch (err) {
        res.status(500).json({ message: 'Error creating user', error: err.message });
    }
});

// Login Route
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

        const token = jwtLib.sign({ id: user._id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });

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
        const wishes = await Wish.find().sort({ createdAt: -1 });
        res.json(wishes);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.post('/api/wishes', async (req, res) => {
    try {
        const { text, userId } = req.body;
        const newWish = new Wish({ text, userId: userId || null });
        await newWish.save();
        res.status(201).json(newWish);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

// --- STRIPE PAYMENT ENDPOINT ---

app.post('/api/create-payment-intent', async (req, res) => {
    try {
        const { amount } = req.body; // Ποσό σε cents (π.χ. 100 = 1.00€)
        
        const paymentIntent = await stripe.paymentIntents.create({
            amount: amount || 100, // Default 1€
            currency: 'eur',
            automatic_payment_methods: { enabled: true },
        });

        res.json({ clientSecret: paymentIntent.client_secret });
    } catch (err) {
        res.status(500).json({ message: 'Payment Intent Error', error: err.message });
    }
});

// Database Connection & Server Listen
const MONGO_URI = process.env.MONGO_URI;
const PORT = process.env.PORT || 5000;

mongoose.connect(MONGO_URI)
    .then(() => {
        console.log('MongoDB Connected!');
        app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
    })
    .catch(err => console.error('DB Connection Error:', err));