const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const path = require('path');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const axios = require('axios');
const MongoStore = require('connect-mongo');
const helmet = require('helmet');
const mongoose = require('mongoose');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

app.set('trust proxy', 1); // Trust the first proxy for secure cookies

app.use(bodyParser.json());
app.use(cookieParser());

const mongoUrl = 'mongodb+srv://hystoriyaallusiataylor:mtW4aUnsTIr5VVcV@mikumiku.jf47gbz.mongodb.net/myfirstdatabase?retryWrites=true&w=majority&appName=mikumiku';

// Connect to MongoDB
mongoose.connect(mongoUrl, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log('Connected to MongoDB');
}).catch((err) => {
    console.error('Error connecting to MongoDB:', err);
});

const sessionStore = MongoStore.create({
    mongoUrl: mongoUrl,
    collectionName: 'sessions', // Ensure this matches the collection name in MongoDB
    ttl: 14 * 24 * 60 * 60, // 14 days
    autoRemove: 'native'
});

sessionStore.on('connected', () => {
    console.log('Session store connected to MongoDB');
});

sessionStore.on('error', (error) => {
    console.error('Session store error:', error);
});

app.use(session({
    secret: process.env.SESSION_SECRET || 'your-session-secret-key',
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
    cookie: {
        secure: true, // Ensure secure flag is true for HTTPS
        sameSite: 'None', // Adjusting SameSite attribute
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

app.use((req, res, next) => {
    console.log(`Session ID: ${req.session.id}`);
    console.log(`Session Data before modification: ${JSON.stringify(req.session)}`);
    console.log(`Cookies: ${JSON.stringify(req.cookies)}`);
    next();
});

// Set CSP headers using helmet
app.use(helmet());
app.use(helmet.contentSecurityPolicy({
    directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        imgSrc: ["'self'", "data:", "https://*"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        connectSrc: ["'self'", "https://*"],
        frameSrc: ["'self'", "https://discord.com"],
        frameAncestors: ["'self'", "https://discord.com"]
    }
}));

app.use(express.static(path.join(__dirname, 'public')));

// MongoDB Schema and Model
const userSchema = new mongoose.Schema({
    bungie_name: { type: String, required: true },
    membership_id: { type: String, unique: true, required: true },
    platform_type: { type: Number, required: true }
});

const User = mongoose.model('User', userSchema);

const sessionSchema = new mongoose.Schema({
    state: { type: String, required: true, unique: true },
    user_id: { type: String, required: true }
});

const Session = mongoose.model('Session', sessionSchema, 'sessions'); // Explicitly specify the collection name

const users = [
    {
        username: process.env.ADMIN_USERNAME,
        password: bcrypt.hashSync(process.env.ADMIN_PASSWORD, 8)
    }
];

// OAuth Configuration
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REDIRECT_URI = 'https://mikumiku.dev/callback';  // Ensure this matches the URL in your Bungie app settings

// OAuth Login Route
app.get('/login', (req, res) => {
    const state = req.session.state;
    console.log(`Using session state: ${state}`); // Logging state from session
    const authorizeUrl = `https://www.bungie.net/en/OAuth/Authorize?client_id=${CLIENT_ID}&response_type=code&state=${state}&redirect_uri=${REDIRECT_URI}`;
    res.redirect(authorizeUrl);
});

// OAuth Callback Route
app.get('/callback', async (req, res) => {
    const state = req.query.state;
    const code = req.query.code;

    console.log(`Received state: ${state}`); // Logging received state

    try {
        // Additional debug logs for MongoDB query
        console.log(`Querying MongoDB for state: ${state}`);
        const sessionData = await Session.findOne({ state: state }).exec();
        console.log(`Session data from DB: ${JSON.stringify(sessionData)}`);

        if (!sessionData) {
            console.log("State mismatch. Potential CSRF attack.");
            return res.status(400).send('State mismatch. Potential CSRF attack.');
        }

        const tokenData = await getBungieToken(code);
        if (!tokenData.access_token) {
            throw new Error('Failed to obtain access token');
        }
        const accessToken = tokenData.access_token;
        const userInfo = await getBungieUserInfo(accessToken);

        if (!userInfo.Response || !userInfo.Response.membershipId) {
            console.error('Incomplete user info response:', userInfo);
            throw new Error('Failed to obtain user information');
        }

        const bungieName = userInfo.Response.uniqueName;
        const membershipId = userInfo.Response.membershipId;
        const platformType = userInfo.Response.primaryMembershipType || 1; // Defaulting to 1 if not provided

        // Store the user information in MongoDB
        const user = await User.findOneAndUpdate(
            { membership_id: membershipId },
            { bungie_name: bungieName, platform_type: platformType },
            { new: true, upsert: true }
        );

        await Session.deleteOne({ state: state });

        res.json({
            bungie_name: user.bungie_name,
            membership_id: user.membership_id,
            platform_type: user.platform_type
        });
    } catch (error) {
        console.error('Error during callback:', error);

        // Detailed logging
        if (error.response) {
            console.log('Response data:', error.response.data);
            console.log('Response status:', error.response.status);
            console.log('Response headers:', error.response.headers);
        } else if (error.request) {
            console.log('Request made but no response received:', error.request);
        } else {
            console.log('Error setting up request:', error.message);
        }

        res.status(500).send('Internal Server Error');
    }
});

async function getBungieToken(code) {
    const url = 'https://www.bungie.net/Platform/App/OAuth/Token/';
    const payload = new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        redirect_uri: REDIRECT_URI
    });
    const headers = { 
