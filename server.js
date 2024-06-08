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

const mongoUrl = process.env.MONGO_URL || 'mongodb+srv://hystoriyaallusiataylor:mtW4aUnsTIr5VVcV@mikumiku.jf47gbz.mongodb.net/?retryWrites=true&w=majority&appName=mikumiku';

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
    collectionName: 'sessions',
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
    const state = generateRandomString(16);
    req.session.state = state;
    req.session.save(err => {
        if (err) {
            console.error('Error saving session:', err);
            return res.status(500).send('Internal Server Error');
        } else {
            console.log(`Generated state: ${state}`); // Logging state
            console.log(`Session after saving state: ${JSON.stringify(req.session)}`); // Logging session
            const authorizeUrl = `https://www.bungie.net/en/OAuth/Authorize?client_id=${CLIENT_ID}&response_type=code&state=${state}&redirect_uri=${REDIRECT_URI}`;
            res.redirect(authorizeUrl);
        }
    });
});

// OAuth Callback Route
app.get('/callback', async (req, res) => {
    const state = req.query.state;
    const code = req.query.code;

    console.log(`Received state: ${state}`); // Logging received state
    console.log(`Session state: ${req.session.state}`); // Logging session state
    console.log(`Complete session: ${JSON.stringify(req.session)}`);
    console.log(`Cookies: ${JSON.stringify(req.cookies)}`); // Log cookies

    if (state !== req.session.state) {
        return res.status(400).send('State mismatch. Potential CSRF attack.');
    }

    try {
        const tokenData = await getBungieToken(code);
        if (!tokenData.access_token) {
            throw new Error('Failed to obtain access token');
        }
        const accessToken = tokenData.access_token;
        const userInfo = await getBungieUserInfo(accessToken);

        if (!userInfo.Response || !userInfo.Response.bungieNetUser) {
            console.error('User info response:', userInfo);
            throw new Error('Failed to obtain user information');
        }

        const bungieName = userInfo.Response.bungieNetUser.displayName;
        const membershipId = userInfo.Response.bungieNetUser.membershipId;
        const platformType = userInfo.Response.primaryMembershipType;

        // Store the user information in MongoDB
        const user = await User.findOneAndUpdate(
            { membership_id: membershipId },
            { bungie_name: bungieName, platform_type: platformType },
            { new: true, upsert: true }
        );

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

function generateRandomString(length) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

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
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-API-Key': process.env.X_API_KEY  // Adding X-API-Key header
    };

    try {
        const response = await axios.post(url, payload.toString(), { headers });
        console.log('Token Response:', response.data); // Debugging
        return response.data;
    } catch (error) {
        console.error('Error fetching Bungie token:', error);
        if (error.response) {
            console.log('Response data:', error.response.data);
            console.log('Response status:', error.response.status);
            console.log('Response headers:', error.response.headers);
        } else if (error.request) {
            console.log('Request made but no response received:', error.request);
        } else {
            console.log('Error setting up request:', error.message);
        }
        throw new Error('Failed to fetch Bungie token');
    }
}

async function getBungieUserInfo(accessToken) {
    const url = 'https://www.bungie.net/Platform/User/GetCurrentBungieNetUser/';
    const headers = {
        'Authorization': `Bearer ${accessToken}`,
        'X-API-Key': process.env.X_API_KEY,  // Adding X-API-Key header
        'User-Agent': 'axios/0.21.4'
    };

    try {
        const response = await axios.get(url, { headers });
        console.log('User Info Response:', response.data); // Debugging
        return response.data;
    } catch (error) {
        console.error('Error fetching Bungie user info:', error);

        if (error.response) {
            console.log('Response data:', error.response.data);
            console.log('Response status:', error.response.status);
            console.log('Response headers:', error.response.headers);
        } else if (error.request) {
            console.log('Request made but no response received:', error.request);
        } else {
            console.log('Error setting up request:', error.message);
        }

        throw new Error('Failed to fetch Bungie user info');
    }
}

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);
    if (!user) {
        return res.status(400).send({ auth: false, message: 'Invalid username or password' });
    }

    const passwordIsValid = bcrypt.compareSync(password, user.password);
    if (!passwordIsValid) {
        return res.status(400).send({ auth: false, message: 'Invalid username or password' });
    }

    const token = jwt.sign({ id: user.username }, process.env.JWT_SECRET || 'your-jwt-secret-key', {
        expiresIn: 86400 // 24 hours
    });

    res.cookie('token', token, {
        httpOnly: true,
        secure: true, // Set to true if using HTTPS
        maxAge: 86400 * 1000 // 24 hours
    });

    res.status(200).send({ auth: true, token });
});

function verifyToken(req, res, next) {
    const token = req.cookies.token;
    if (!token) {
        return res.status(401).send({ redirect: '/admin-login.html' });
    }

    jwt.verify(token, process.env.JWT_SECRET || 'your-jwt-secret-key', (err, decoded) => {
        if (err) {
            return res.status(401).send({ redirect: '/admin-login.html' });
        }
        req.userId = decoded.id;
        next();
    });
}

// Public route for fetching videos
app.get('/api/videos/public', async (req, res) => {
    try {
        // Add your logic here for fetching video metadata from MongoDB
        res.json([]); // Placeholder response
    } catch (err) {
        console.error('Error retrieving video metadata:', err);
        res.status(500).send({ error: 'Error retrieving video metadata' });
    }
});

// Protected route for adding videos
app.post('/api/videos', verifyToken, async (req, res) => {
    const videoMetadata = {
        url: req.body.url.replace('youtu.be', 'youtube.com/embed'),
        title: req.body.title,
        description: req.body.description,
        category: req.body.category,
        uploadedAt: new Date()
    };

    try {
        // Add your logic here for saving video metadata to MongoDB
        res.status(201).send({ message: 'Video added', video: videoMetadata }); // Placeholder response
    } catch (err) {
        console.error('Error saving video metadata:', err);
        res.status(500).send({ error: 'Error saving video metadata' });
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
