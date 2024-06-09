const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const axios = require('axios');
const MongoStore = require('connect-mongo');
const mongoose = require('mongoose');

const app = express();
const PORT = process.env.PORT || 3000;

app.set('trust proxy', 1); // Trust the first proxy for secure cookies

app.use(bodyParser.json());
app.use(cookieParser());

const mongoUrl = process.env.MONGO_URL || 'mongodb://localhost:27017/myfirstdatabase';

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
    ttl: 14 * 24 * 60 * 60,
    autoRemove: 'native'
});

app.use(session({
    secret: process.env.SESSION_SECRET || 'your-session-secret-key',
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
    cookie: {
        secure: true,
        sameSite: 'None',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000
    }
}));

app.use((req, res, next) => {
    console.log(`Session ID: ${req.session.id}`);
    console.log(`Session Data before modification: ${JSON.stringify(req.session)}`);
    console.log(`Cookies: ${JSON.stringify(req.cookies)}`);
    next();
});

app.get('/login', (req, res) => {
    const state = generateRandomString(16);
    req.session.state = state;
    req.session.save(err => {
        if (err) {
            console.error('Error saving session:', err);
            return res.status(500).send('Internal Server Error');
        } else {
            console.log(`Generated state: ${state}`);
            console.log(`Session after saving state: ${JSON.stringify(req.session)}`);
            const authorizeUrl = `https://www.bungie.net/en/OAuth/Authorize?client_id=${CLIENT_ID}&response_type=code&state=${state}&redirect_uri=${REDIRECT_URI}`;
            res.redirect(authorizeUrl);
        }
    });
});

app.get('/callback', async (req, res) => {
    const state = req.query.state;
    const code = req.query.code;

    console.log(`Received state: ${state}`);
    console.log(`Session state: ${req.session.state}`);
    console.log(`Complete session: ${JSON.stringify(req.session)}`);
    console.log(`Cookies: ${JSON.stringify(req.cookies)}`);

    if (state !== req.session.state) {
        return res.status(400).send('State mismatch. Potential CSRF attack.');
    }

    if (!req.session) {
        return res.status(401).send('Session expired');
    }

    try {
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
        const platformType = userInfo.Response.primaryMembershipType || 1;

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
        'X-API-Key': process.env.X_API_KEY
    };

    try {
        const response = await axios.post(url, payload.toString(), { headers });
        console.log('Token Response:', response.data);
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
        'X-API-Key': process.env.X_API_KEY,
        'User-Agent': 'axios/0.21.4'
    };

    try {
        const response = await axios.get(url, { headers });
        console.log('User Info Response:', response.data);
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

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
