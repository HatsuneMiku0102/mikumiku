const express = require('express');
const http = require('http'); // Required for setting up Socket.IO with Express
const socketIo = require('socket.io'); // Import Socket.IO
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
const { DateTime } = require('luxon'); // Import luxon for datetime handling
const ipinfo = require('ipinfo');

dotenv.config();

const app = express();
const server = http.createServer(app); // Create an HTTP server for Socket.IO
const io = socketIo(server, {
    cors: {
        origin: "chrome-extension://<ealgoodedcojbceodddhbpcklnpneocp>",
        methods: ["GET", "POST"],
        allowedHeaders: ["my-custom-header"],
        credentials: true
    }
});

const PORT = process.env.PORT || 3000;

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

app.set('trust proxy', 1);

// Middleware
app.use(bodyParser.json());
app.use(cookieParser());

// MongoDB Connection
const mongoUrl = process.env.MONGO_URL || 'mongodb://localhost:27017/myfirstdatabase'; // Use environment variable for MongoDB URL

mongoose.connect(mongoUrl, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    useFindAndModify: false  // Address deprecation warning
}).then(() => {
    logger.info('Connected to MongoDB');
}).catch((err) => {
    logger.error('Error connecting to MongoDB:', err);
});

// Session Store
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

// Session Middleware
app.use(session({
    secret: process.env.SESSION_SECRET || 'your-default-session-secret',  // Use a strong secret in production
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
    cookie: {
        secure: process.env.NODE_ENV === 'production',  // Only use cookies over HTTPS in production
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 24-hour expiration for sessions
    }
}));

// Set CSP headers using helmet
app.use(helmet.contentSecurityPolicy({
    directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com", "https://www.youtube.com", "https://www.youtube.com/iframe_api"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        imgSrc: ["'self'", "data:", "https://i.ytimg.com", "https://img.youtube.com"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        connectSrc: ["'self'", "https://www.googleapis.com", "https://*.youtube.com"],
        frameSrc: ["'self'", "https://discord.com", "https://www.youtube.com"],
        mediaSrc: ["'self'", "https://www.youtube.com"],
        frameAncestors: ["'self'", "https://discord.com"]
    }
}));

// Serve static files excluding the protected directory
app.use(express.static(path.join(__dirname, 'public'), {
    etag: false,
    maxAge: 0,
    lastModified: false
}));

// MongoDB Schemas and Models
const userSchema = new mongoose.Schema({
    discord_id: { type: String, required: true },
    bungie_name: { type: String, required: true },
    membership_id: { type: String, unique: true, required: true },
    platform_type: { type: Number, required: true },
    token: { type: String, unique: true },
    registration_date: { type: Date, default: Date.now },
    access_token: { type: String, required: true },
    refresh_token: { type: String, required: true },
    token_expiry: { type: Date, required: true }
});

const User = mongoose.model('User', userSchema);

const pendingMemberSchema = new mongoose.Schema({
    membershipId: { type: String, required: true },
    displayName: { type: String, required: true },
    joinDate: { type: Date, required: true }
});

const PendingMember = mongoose.model('PendingMember', pendingMemberSchema);

const sessionSchema = new mongoose.Schema({
    state: { type: String, required: true, unique: true },
    user_id: { type: String, required: true },
    session_id: { type: String, required: true },
    created_at: { type: Date, default: Date.now, expires: 86400 }, // 24 hours
    ip_address: { type: String },
    user_agent: { type: String }
});

const Session = mongoose.model('Session', sessionSchema, 'sessions'); // Explicitly specify the collection name

// Comment Schema and Model
const commentSchema = new mongoose.Schema({
    username: { type: String, required: true },
    comment: { type: String, required: true },
    timestamp: { type: Date, default: Date.now },
    approved: { type: Boolean, default: true } // For moderation
});

const Comment = mongoose.model('Comment', commentSchema);

// Users (for admin authentication)
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
        "membership_id": userInfo.membershipId,
        "platform_type": userInfo.platformType,
        "bungie_name": userInfo.bungieName,
        "registration_date": new Date(),
        "clan_id": "4900827"
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
    // Implement additional actions here if needed
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
        const authorizeUrl = `https://www.bungie.net/en/OAuth/Authorize?client_id=${CLIENT_ID}&response_type=code&state=${state}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}`;
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
        const refreshToken = tokenData.refresh_token;  // Get the refresh token
        const expiresIn = tokenData.expires_in; // In seconds
        const tokenExpiry = DateTime.now().plus({ seconds: expiresIn }).toJSDate(); // Calculate expiry date

        const userInfo = await getBungieUserInfo(accessToken);
        logger.info('User Info Response:', userInfo);

        if (!userInfo.Response || !userInfo.Response.destinyMemberships) {
            logger.error('Incomplete user info response:', userInfo);
            throw new Error('Failed to obtain user information');
        }

        const bungieGlobalDisplayName = userInfo.Response.bungieNetUser.cachedBungieGlobalDisplayName;
        const bungieGlobalDisplayNameCode = userInfo.Response.bungieNetUser.cachedBungieGlobalDisplayNameCode.toString().padStart(4, '0'); // Ensure the code is treated as a string and padded with zeros if necessary
        const bungieName = `${bungieGlobalDisplayName}#${bungieGlobalDisplayNameCode}`;

        let primaryMembership = userInfo.Response.destinyMemberships.find(
            membership => membership.membershipId === userInfo.Response.primaryMembershipId
        );

        if (!primaryMembership) {
            // If no primary membership is found, fallback to the first membership
            primaryMembership = userInfo.Response.destinyMemberships[0];
        }

        if (!primaryMembership) {
            throw new Error('Failed to obtain platform-specific membership ID');
        }

        const membershipId = primaryMembership.membershipId;
        const platformType = primaryMembership.membershipType;

        logger.info(`Extracted bungieName: ${bungieName}, membershipId: ${membershipId}, platformType: ${platformType}`);

        const discordId = sessionData.user_id;

        const user = await User.findOneAndUpdate(
            { membership_id: membershipId },
            {
                discord_id: discordId,
                bungie_name: bungieName,
                platform_type: platformType,
                token: generateRandomString(16), // Generate a token for the user
                registration_date: new Date(), // Set the registration date here
                access_token: accessToken, // Store the access token
                refresh_token: refreshToken, // Store the refresh token
                token_expiry: tokenExpiry // Store the token expiry
            },
            { upsert: true, new: true }
        );

        // Send the stored data to the Discord bot
        await sendUserInfoToDiscordBot(discordId, { bungieName, platformType, membershipId });

        // Save the user info to the membership mapping JSON file
        updateMembershipMapping(discordId, { bungieName, platformType, membershipId });

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

// Serve the confirmation page
app.get('/confirmation.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'confirmation.html'));
});

// API endpoint to fetch Bungie name
app.get('/api/bungie-name', async (req, res) => {
    const token = req.query.token;

    try {
        const user = await User.findOne({ token });
        if (!user) {
            return res.status(400).send({ error: 'Invalid token' });
        }

        res.send({ bungie_name: user.bungie_name });
    } catch (err) {
        logger.error('Error fetching Bungie name:', err);
        res.status(500).send({ error: 'Internal Server Error' });
    }
});

// Comment Routes

// Add a comment
app.post('/api/comments', async (req, res) => {
    try {
        const { username, comment } = req.body;
        const newComment = new Comment({ username, comment });
        await newComment.save();
        res.status(201).send(newComment);
    } catch (error) {
        logger.error('Error saving comment:', error);
        res.status(500).send({ error: 'Error saving comment' });
    }
});

// Fetch approved comments
app.get('/api/comments', async (req, res) => {
    try {
        const comments = await Comment.find({ approved: true });
        res.json(comments);
    } catch (error) {
        logger.error('Error fetching comments:', error);
        res.status(500).send({ error: 'Error fetching comments' });
    }
});

// Delete a comment (requires authentication)
app.delete('/api/comments/:id', verifyToken, async (req, res) => {
    try {
        const { id } = req.params;
        await Comment.findByIdAndDelete(id);
        res.status(200).send({ message: 'Comment deleted' });
    } catch (error) {
        logger.error('Error deleting comment:', error);
        res.status(500).send({ error: 'Error deleting comment' });
    }
});

// Utility Functions
function generateRandomString(size = 16) {  // Default size of 16 bytes
    return crypto.randomBytes(size).toString('hex');
}

// Function to get Bungie token
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

// Function to refresh Bungie token
async function refreshBungieToken(refreshToken) {
    const url = 'https://www.bungie.net/Platform/App/OAuth/Token/';
    const payload = new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET
    });
    const headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-API-Key': process.env.X_API_KEY
    };

    try {
        const response = await axios.post(url, payload.toString(), { headers });
        logger.info('Refresh Token Response:', response.data);
        return response.data;
    } catch (error) {
        logger.error('Error refreshing Bungie token:', error);
        if (error.response) {
            logger.error('Response data:', error.response.data);
            logger.error('Response status:', error.response.status);
            logger.error('Response headers:', error.response.headers);
        } else if (error.request) {
            logger.error('Request made but no response received:', error.request);
        } else {
            logger.error('Error setting up request:', error.message);
        }
        throw new Error('Failed to refresh Bungie token');
    }
}

// Function to get Bungie user info
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

// Function to get access token for user
async function getAccessTokenForUser(user) {
    const now = DateTime.now();
    const tokenExpiry = DateTime.fromJSDate(user.token_expiry);

    if (now >= tokenExpiry) {
        // Token expired, refresh it
        const newTokenData = await refreshBungieToken(user.refresh_token);
        user.access_token = newTokenData.access_token;
        user.refresh_token = newTokenData.refresh_token;
        user.token_expiry = DateTime.now().plus({ seconds: newTokenData.expires_in }).toJSDate();
        await user.save();
        logger.info(`Refreshed access token for user ${user.discord_id}`);
    }

    return user.access_token;
}

// Function to get pending clan members
async function getPendingClanMembers(accessToken, groupId) {
    const url = `https://www.bungie.net/Platform/GroupV2/${groupId}/Members/Pending/`;
    const headers = {
        'Authorization': `Bearer ${accessToken}`,
        'X-API-Key': process.env.X_API_KEY
    };

    try {
        const response = await axios.get(url, { headers });
        logger.info('Pending Clan Members Response:', response.data);
        return response.data.Response.results;
    } catch (error) {
        logger.error('Error fetching pending clan members:', error);
        if (error.response) {
            logger.error('Response data:', error.response.data);
            logger.error('Response status:', error.response.status);
            logger.error('Response headers:', error.response.headers);
        } else if (error.request) {
            logger.error('Request made but no response received:', error.request);
        } else {
            logger.error('Error setting up request:', error.message);
        }
        throw new Error('Failed to fetch pending clan members');
    }
}

// Admin Dashboard Protected Route
app.get('/admin-dashboard.html', verifyToken, (req, res) => {
    res.sendFile(path.join(__dirname, 'protected', 'admin-dashboard.html'));
});

// Dynamic Admin Dashboard Route (if needed)
app.get('/admin-dashboard-:random.html', verifyToken, (req, res) => {
    res.sendFile(path.join(__dirname, 'protected', 'admin-dashboard.html'));
});

// Route to get pending clan members and save to the database
app.get('/api/clan/pending', verifyToken, async (req, res) => {
    const userId = req.userId;

    try {
        const user = await User.findOne({ discord_id: userId });
        if (!user) {
            return res.status(400).send({ error: 'User not found' });
        }

        const accessToken = await getAccessTokenForUser(user);
        const pendingMembers = await getPendingClanMembers(accessToken, '5236471'); // Replace '5236471' with the actual group ID

        // Save pending members to the database
        await PendingMember.deleteMany(); // Clear existing entries
        const pendingMemberDocs = pendingMembers.map(member => ({
            membershipId: member.destinyUserInfo.membershipId,
            displayName: member.destinyUserInfo.displayName,
            joinDate: new Date(member.joinDate)
        }));
        await PendingMember.insertMany(pendingMemberDocs);

        res.send({ pending_members: pendingMembers });
    } catch (err) {
        logger.error('Error fetching pending clan members:', err);
        res.status(500).send({ error: 'Internal Server Error' });
    }
});

// Route to retrieve pending clan members from the database
app.get('/api/clan/pending/fromdb', verifyToken, async (req, res) => {
    try {
        const pendingMembers = await PendingMember.find();
        res.send({ pending_members: pendingMembers });
    } catch (err) {
        logger.error('Error retrieving pending clan members from DB:', err);
        res.status(500).send({ error: 'Internal Server Error' });
    }
});

// Serve the protected admin dashboard
app.get('/:dashboardURL', verifyToken, (req, res) => {
    const requestedDashboardURL = `/${req.params.dashboardURL}`;
    console.log('Requested Dashboard URL:', requestedDashboardURL);
    console.log('Session Dashboard URL:', req.session.dashboardURL);

    if (requestedDashboardURL === req.session.dashboardURL) {
        res.sendFile(path.join(__dirname, 'protected', 'admin-dashboard.html'));
    } else {
        console.log('Dashboard URL mismatch. Redirecting to login.');
        res.status(401).redirect('/admin-login.html');
    }
});

// JWT Verification Middleware
function verifyToken(req, res, next) {
    const token = req.cookies.token;
    console.log('Token from cookie:', token);

    if (!token) {
        console.log('Token not found. Redirecting to login.');
        return res.redirect('/admin-login.html');  // Redirect if no token
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            console.log('Token verification failed:', err.message);
            return res.redirect('/admin-login.html');  // Redirect if token is invalid
        }
        console.log('Token successfully verified. User ID:', decoded.id);
        req.userId = decoded.id;
        next();
    });
}

// Password Hashing Utility
function hashPassword(password, salt) {
    const hash = crypto.createHmac('sha256', salt)
                       .update(password)
                       .digest('hex');
    return hash;
}

// Define the password and salt
const plainPassword = 'Aria';  // Your actual password
const salt = 'random_salt';  // You can change this to any fixed salt, just ensure it's consistent

// Hash the password
const hashedPassword = hashPassword(plainPassword, salt);
console.log('Hashed Password:', hashedPassword);

// POST route for login
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    const adminUsername = process.env.ADMIN_USERNAME;
    const adminPasswordHash = process.env.ADMIN_PASSWORD; // Ensure this is already hashed
    const salt = 'random_salt';

    if (username !== adminUsername) {
        return res.status(401).json({ auth: false, message: 'Invalid username or password' });
    }

    // Hash the submitted password with the same salt
    const hashedInputPassword = hashPassword(password, salt);

    // Compare the hashed input password with the stored hash
    if (hashedInputPassword !== adminPasswordHash) {
        return res.status(401).json({ auth: false, message: 'Invalid username or password' });
    }

    // If the password is correct, generate a token
    const token = jwt.sign({ id: adminUsername }, process.env.JWT_SECRET || 'your-jwt-secret-key', {
        expiresIn: 86400  // 24 hours
    });

    // Generate dynamic dashboard URL
    const dashboardURL = `/admin-dashboard-${generateRandomString()}.html`;

    // Store the dashboard URL in the session
    req.session.dashboardURL = dashboardURL;
    console.log('Stored dashboardURL in session:', req.session.dashboardURL);

    // Set the token as a secure cookie
    res.cookie('token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',  // Use true in production, false for local development
        maxAge: 86400 * 1000  // 24 hours
    });

    // Define the protected dashboard route
    app.get(dashboardURL, verifyToken, (req, res) => {
        res.sendFile(path.join(__dirname, 'protected', 'admin-dashboard.html'));
    });

    // Send back the auth and redirect URL to the frontend
    req.session.save((err) => {
        if (err) {
            console.error('Error saving session:', err);
            return res.status(500).json({ auth: false, message: 'Error saving session' });
        }
        res.status(200).json({ auth: true, redirect: dashboardURL });
    });
});

// Serve the dynamic dashboard URL after successful login
// Note: This route is now handled within the login POST route

// POST route for logout
app.post('/logout', verifyToken, (req, res) => {
    res.clearCookie('token'); // Clear the JWT token cookie
    req.session.destroy(); // Destroy the session

    res.redirect('/admin-login.html'); // Redirect to login page
});

// Socket.IO Connection Handling
let activeUsers = [];

async function fetchLocationData(ip) {
    try {
        // Ensure only a single IP address is passed by splitting if necessary
        const singleIp = ip.split(',')[0].trim(); // Take the first IP if multiple are present
        const response = await axios.get(`https://ipinfo.io/${singleIp}?token=14eb346301d8b9`);
        const { ip: userIP, city, region, country } = response.data;
        return { ip: userIP, city, region, country };
    } catch (error) {
        console.error('Error fetching location data:', error);
        return { ip, city: 'Unknown', region: 'Unknown', country: 'Unknown' };
    }
}

function normalizeIp(ip) {
    if (ip.startsWith('::ffff:')) {
        return ip.replace('::ffff:', '');  // Normalize IPv6-mapped IPv4 to IPv4
    }
    return ip;
}

io.on('connection', async (socket) => {  
    let ip = socket.handshake.headers['x-forwarded-for'] || socket.handshake.address;

    // Handle cases where x-forwarded-for contains multiple IPs
    if (ip.includes(',')) {
        ip = ip.split(',')[0].trim();  // Take the first IP in the list
    }

    ip = normalizeIp(ip);  // Normalize IP (handle IPv6-mapped IPv4 addresses)

    // Ensure the IP isn't already in the active users list
    if (!activeUsers.some(user => user.ip === ip)) {
        const locationData = await fetchLocationData(ip);
        activeUsers.push(locationData);  // Store user info
    }

    // Emit updated active users list to all clients
    io.emit('activeUsersUpdate', { users: activeUsers });

    socket.on('disconnect', () => {
        activeUsers = activeUsers.filter(user => user.ip !== ip);
        io.emit('activeUsersUpdate', { users: activeUsers });
    });
});

// Serve your admin dashboard where you'll display the location data
// Already handled by the protected route above

// Additional API Endpoints

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

// Function to generate random URLs (if needed)
function generateRandomUrl() {
    return '/admin-dashboard/' + crypto.randomBytes(16).toString('hex');
}

// API Check YouTube
app.get('/api/check-youtube', async (req, res) => {
    try {
        // Add your logic here for checking YouTube API status
        const youtubeApiStatus = true;  // Example: Assume the API is available

        res.json({
            available: youtubeApiStatus,
            status: youtubeApiStatus ? 'YouTube API is working' : 'YouTube API is unavailable'
        });
    } catch (error) {
        console.error('Error checking YouTube API:', error);
        res.status(500).json({
            available: false,
            status: 'Error checking YouTube API'
        });
    }
});

// Bungie API Status Check
app.get('/api/check-bungie', async (req, res) => {
    const bungieApiKey = process.env.X_API_KEY;
    const url = 'https://www.bungie.net/Platform/Destiny2/Manifest/';

    try {
        const response = await axios.get(url, {
            headers: { 'X-API-Key': bungieApiKey }
        });
        if (response.status === 200) {
            return res.json({ status: 'Bungie API is working', available: true });
        }
    } catch (error) {
        console.error('Error checking Bungie API:', error);
        return res.json({ status: 'Bungie API is unavailable', available: false });
    }
});

// Start the server
server.listen(PORT, () => {
    logger.info(`Server is running on port ${PORT}`);
});
