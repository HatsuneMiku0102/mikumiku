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
const crypto = require('crypto');
const fs = require('fs');
const winston = require('winston');
const { format, parseISO } = require('date-fns');

// Configure logging
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: 'app.log' })
    ]
});

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
    useUnifiedTopology: true,
    useFindAndModify: false  // Address deprecation warning
}).then(() => {
    logger.info('Connected to MongoDB');
}).catch((err) => {
    logger.error('Error connecting to MongoDB:', err);
});

const sessionStore = MongoStore.create({
    mongoUrl: mongoUrl,
    collectionName: 'sessions',
    ttl: 14 * 24 * 60 * 60, // 14 days
    autoRemove: 'native'
});

sessionStore.on('connected', () => {
    logger.info('Session store connected to MongoDB');
});

sessionStore.on('error', (error) => {
    logger.error('Session store error:', error);
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
    logger.info(`Session ID: ${req.session.id}`);
    logger.info(`Session Data before modification: ${JSON.stringify(req.session)}`);
    logger.info(`Cookies: ${JSON.stringify(req.cookies)}`);
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
    discord_id: { type: String, required: true },
    bungie_name: { type: String, required: true },
    memberships: { type: Array, required: true },
    token: { type: String, unique: true }, // Added token field
    registration_date: { type: Date, default: Date.now }, // Added registration_date field
    clan_name: { type: String }, // Added clan_name field
    profile_picture_path: { type: String }, // Added profile_picture_path field
    first_access: { type: Date }, // Added first_access field
    last_update: { type: Date } // Added last_update field
});

const User = mongoose.model('User', userSchema);

const sessionSchema = new mongoose.Schema({
    state: { type: String, required: true, unique: true },
    user_id: { type: String, required: true },
    session_id: { type: String, required: true },
    created_at: { type: Date, default: Date.now, expires: 86400 }, // 24 hours
    ip_address: { type: String },
    user_agent: { type: String }
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

const membershipFilePath = path.join(__dirname, 'membership_mapping.json');

function updateMembershipMapping(discordId, userInfo) {
    let membershipMapping = {};

    // Read the existing file if it exists
    if (fs.existsSync(membershipFilePath)) {
        const data = fs.readFileSync(membershipFilePath, 'utf8');
        logger.info('Read existing membership mapping file:', data);
        try {
            membershipMapping = JSON.parse(data);
        } catch (err) {
            logger.error('Error parsing membership mapping file:', err);
            membershipMapping = {};
        }
    } else {
        logger.info('Membership mapping file does not exist. A new one will be created.');
    }

    // Update the membership mapping with new user info
    membershipMapping[discordId] = {
        "memberships": userInfo.memberships,
        "bungie_name": userInfo.bungieName,
        "registration_date": new Date(), // Add the registration date here
        "clan_id": "4900827",
        "clan_name": userInfo.clanName, // Add the clan name here
        "profile_picture_path": userInfo.profilePicturePath,
        "first_access": userInfo.firstAccess,
        "last_update": userInfo.lastUpdate
    };

    // Write the updated membership mapping back to the file
    try {
        fs.writeFileSync(membershipFilePath, JSON.stringify(membershipMapping, null, 2), 'utf8');
        logger.info('Updated membership mapping file:', JSON.stringify(membershipMapping, null, 2));
    } catch (err) {
        logger.error('Error writing to membership mapping file:', err);
    }

    // Read and log the file contents to confirm update
    try {
        const updatedData = fs.readFileSync(membershipFilePath, 'utf8');
        logger.info('Verified membership mapping file content:', updatedData);
    } catch (err) {
        logger.error('Error reading membership mapping file after update:', err);
    }
}

async function sendUserInfoToDiscordBot(discordId, userInfo) {
    // You can implement additional actions here if needed
    logger.info('User info ready to be sent to Discord bot:', userInfo);
}

// OAuth Login Route
app.get('/login', async (req, res) => {
    const state = generateRandomString(16);
    const user_id = req.query.user_id; // Assume user_id is passed in the query for simplicity
    const ip_address = req.ip;
    const user_agent = req.get('User-Agent');

    const sessionData = new Session({
        state,
        user_id,
        session_id: req.session.id,
        ip_address,
        user_agent
    });

    try {
        await sessionData.save();
        logger.info(`Generated state: ${state}`);
        logger.info(`Inserted session: ${JSON.stringify(sessionData)}`);
        const authorizeUrl = `https://www.bungie.net/en/OAuth/Authorize?client_id=${CLIENT_ID}&response_type=code&state=${state}&redirect_uri=${REDIRECT_URI}`;
        res.redirect(authorizeUrl);
    } catch (err) {
        logger.error('Error saving session to DB:', err);
        res.status(500).send('Internal Server Error');
    }
});

// OAuth Callback Route
app.get('/callback', async (req, res) => {
    const state = req.query.state;
    const code = req.query.code;

    logger.info(`Received state: ${state}`);
    logger.info(`Received code: ${code}`);

    try {
        const sessionData = await Session.findOne({ state });
        logger.info(`Session data from DB: ${JSON.stringify(sessionData)}`);

        if (!sessionData) {
            logger.warn("State mismatch. Potential CSRF attack.");
            return res.status(400).send('State mismatch. Potential CSRF attack.');
        }

        const tokenData = await getBungieToken(code);
        logger.info(`Token data: ${JSON.stringify(tokenData)}`);

        if (!tokenData.access_token) {
            throw new Error('Failed to obtain access token');
        }

        const accessToken = tokenData.access_token;
        const userInfo = await getBungieUserInfo(accessToken);
        logger.info('User Info Response:', userInfo);

        if (!userInfo.Response || !userInfo.Response.destinyMemberships) {
            logger.error('Incomplete user info response:', userInfo);
            throw new Error('Failed to obtain user information');
        }

        const bungieGlobalDisplayName = String(userInfo.Response.bungieNetUser.cachedBungieGlobalDisplayName);
        const bungieGlobalDisplayNameCode = String(userInfo.Response.bungieNetUser.cachedBungieGlobalDisplayNameCode);
        const bungieName = `${bungieGlobalDisplayName}#${bungieGlobalDisplayNameCode}`;
        const profilePicturePath = userInfo.Response.bungieNetUser.profilePicturePath;
        const firstAccess = parseISO(userInfo.Response.bungieNetUser.firstAccess);
        const lastUpdate = parseISO(userInfo.Response.bungieNetUser.lastUpdate);

        const primaryMembership = userInfo.Response.destinyMemberships.find(
            m => m.membershipId === userInfo.Response.primaryMembershipId
        );

        if (!primaryMembership) {
            throw new Error('Primary membership not found');
        }

        const memberships = userInfo.Response.destinyMemberships.map(m => ({
            membership_id: m.membershipId,
            platform_type: m.membershipType,
            display_name: m.displayName,
            is_primary: m.membershipId === userInfo.Response.primaryMembershipId
        }));

        const membershipId = primaryMembership.membershipId;
        const platformType = primaryMembership.membershipType;

        if (!membershipId) {
            throw new Error('Membership ID is null');
        }

        // Fetch clan name
        const clanInfo = await getClanInfo(membershipId, platformType, accessToken);
        const clanName = clanInfo && clanInfo.Response.results.length > 0 ? clanInfo.Response.results[0].group.name : 'No Clan';

        logger.info(`Extracted bungieName: ${bungieName}, memberships: ${JSON.stringify(memberships)}, clanName: ${clanName}, profilePicturePath: ${profilePicturePath}, firstAccess: ${firstAccess}, lastUpdate: ${lastUpdate}`);

        const discordId = sessionData.user_id;

        const user = await User.findOneAndUpdate(
            { discord_id: discordId },
            {
                bungie_name: bungieName,
                memberships: memberships,
                profile_picture_path: profilePicturePath,
                registration_date: new Date(), // Set the registration date here
                clan_name: clanName, // Save the clan name
                first_access: firstAccess,
                last_update: lastUpdate,
                membership_id: membershipId // Ensure membership_id is set
            },
            { upsert: true, new: true }
        );

        // Send the stored data to the Discord bot
        await sendUserInfoToDiscordBot(discordId, { bungieName, memberships, clanName, profilePicturePath, firstAccess, lastUpdate });

        // Save the user info to the membership mapping JSON file
        updateMembershipMapping(discordId, { bungieName, memberships, clanName, profilePicturePath, firstAccess, lastUpdate });

        await Session.deleteOne({ state });

        res.redirect(`/confirmation.html?token=${user.token}`);
    } catch (error) {
        logger.error('Error during callback:', error);
        if (error.response) {
            logger.error('Response data:', error.response.data);
            logger.error('Response status:', error.response.status);
            logger.error('Response headers:', error.response.headers);
        } else if (error.request) {
            logger.error('Request made but no response received:', error.request);
        } else {
            logger.error('Error setting up request:', error.message);
        }
        res.status(500).send('Internal Server Error');
    }
});

function generateRandomString(length) {
    return crypto.randomBytes(length).toString('hex');
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
        logger.info('Token Response:', response.data);
        return response.data;
    } catch (error) {
        logger.error('Error fetching Bungie token:', error);
        if (error.response) {
            logger.error('Response data:', error.response.data);
            logger.error('Response status:', error.response.status);
            logger.error('Response headers:', error.response.headers);
        } else if (error.request) {
            logger.error('Request made but no response received:', error.request);
        } else {
            logger.error('Error setting up request:', error.message);
        }
        throw new Error('Failed to fetch Bungie token');
    }
}

async function getBungieUserInfo(accessToken) {
    const url = 'https://www.bungie.net/Platform/User/GetMembershipsForCurrentUser/';
    const headers = {
        'Authorization': `Bearer ${accessToken}`,
        'X-API-Key': process.env.X_API_KEY,
        'User-Agent': 'axios/0.21.4'
    };

    try {
        const response = await axios.get(url, { headers });
        logger.info('User Info Response:', response.data);
        return response.data;
    } catch (error) {
        logger.error('Error fetching Bungie user info:', error);
        if (error.response) {
            logger.error('Response data:', error.response.data);
            logger.error('Response status:', error.response.status);
            logger.error('Response headers:', error.response.headers);
        } else if (error.request) {
            logger.error('Request made but no response received:', error.request);
        } else {
            logger.error('Error setting up request:', error.message);
        }
        throw new Error('Failed to fetch Bungie user info');
    }
}

async function getClanInfo(membershipId, platformType, accessToken) {
    const url = `https://www.bungie.net/Platform/GroupV2/User/${platformType}/${membershipId}/0/1/`;
    const headers = {
        'Authorization': `Bearer ${accessToken}`,
        'X-API-Key': process.env.X_API_KEY,
        'User-Agent': 'axios/0.21.4'
    };

    try {
        const response = await axios.get(url, { headers });
        logger.info('Clan Info Response:', response.data);
        return response.data;
    } catch (error) {
        logger.error('Error fetching clan info:', error);
        if (error.response) {
            logger.error('Response data:', error.response.data);
            logger.error('Response status:', error.response.status);
            logger.error('Response headers:', error.response.headers);
        } else if (error.request) {
            logger.error('Request made but no response received:', error.request);
        } else {
            logger.error('Error setting up request:', error.message);
        }
        throw new Error('Failed to fetch clan info');
    }
}

const platformTypes = {
    1: 'Xbox',
    2: 'PlayStation',
    3: 'Steam',
    4: 'Blizzard',
    5: 'Stadia',
    10: 'Demon',
    254: 'Bungie Next'
};

// API endpoint to fetch Bungie account info
app.get('/api/bungie-info', async (req, res) => {
    const token = req.query.token;

    try {
        const user = await User.findOne({ token });
        if (!user) {
            return res.status(400).send({ error: 'Invalid token' });
        }

        const bungieInfo = {
            bungie_name: user.bungie_name,
            memberships: user.memberships.map(m => ({
                ...m,
                platform_name: platformTypes[m.platform_type] || 'Unknown'
            })),
            registration_date: user.registration_date,
            clan_name: user.clan_name,
            profile_picture_path: user.profile_picture_path,
            first_access: format(user.first_access, 'MMMM dd, yyyy'),
            last_update: format(user.last_update, 'MMMM dd, yyyy')
        };

        res.send(bungieInfo);
    } catch (err) {
        logger.error('Error fetching Bungie info:', err);
        res.status(500).send({ error: 'Internal Server Error' });
    }
});

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
        logger.error('Error retrieving video metadata:', err);
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
        logger.error('Error saving video metadata:', err);
        res.status(500).send({ error: 'Error saving video metadata' });
    }
});

app.listen(PORT, () => {
    logger.info(`Server is running on port ${PORT}`);
});
