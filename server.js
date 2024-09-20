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

// Set CSP headers using helmet
app.use(helmet.contentSecurityPolicy({
    directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com", "https://www.youtube.com", "https://www.youtube.com/iframe_api"], // Add YouTube script sources
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        imgSrc: ["'self'", "data:", "https://i.ytimg.com", "https://img.youtube.com"], // Allow YouTube images and thumbnails
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        connectSrc: ["'self'", "https://www.googleapis.com", "https://*.youtube.com"], // Allow YouTube API calls
        frameSrc: ["'self'", "https://discord.com", "https://www.youtube.com"], // Allow embedding YouTube videos in iframes
        mediaSrc: ["'self'", "https://www.youtube.com"], // Allow media from YouTube
        frameAncestors: ["'self'", "https://discord.com"]
    }
}));


app.use(express.static(path.join(__dirname, 'public')));

// MongoDB Schemas and Models
const userSchema = new mongoose.Schema({
    discord_id: { type: String, required: true },
    bungie_name: { type: String, required: true },
    membership_id: { type: String, unique: true, required: true },
    platform_type: { type: Number, required: true },
    token: { type: String, unique: true }, // Added token field
    registration_date: { type: Date, default: Date.now }, // Added registration_date field
    access_token: { type: String, required: true }, // Added access_token field
    refresh_token: { type: String, required: true }, // Added refresh_token field
    token_expiry: { type: Date, required: true } // Added token_expiry field
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
    approved: { type: Boolean, default: true } // You can use this for moderation
});

const Comment = mongoose.model('Comment', commentSchema);

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
        "registration_date": new Date(), // Add the registration date here
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
        logger.info(Generated state: ${state});
        logger.info(Inserted session: ${JSON.stringify(sessionData)});
        const authorizeUrl = https://www.bungie.net/en/OAuth/Authorize?client_id=${CLIENT_ID}&response_type=code&state=${state}&redirect_uri=${REDIRECT_URI};
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

    logger.info(Received state: ${state});
    logger.info(Received code: ${code});

    try {
        const sessionData = await Session.findOne({ state });
        logger.info(Session data from DB: ${JSON.stringify(sessionData)});

        if (!sessionData) {
            logger.warn("State mismatch. Potential CSRF attack.");
            return res.status(400).send('State mismatch. Potential CSRF attack.');
        }

        const tokenData = await getBungieToken(code);
        logger.info(Token data: ${JSON.stringify(tokenData)});

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
        const bungieName = ${bungieGlobalDisplayName}#${bungieGlobalDisplayNameCode};

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

        logger.info(Extracted bungieName: ${bungieName}, membershipId: ${membershipId}, platformType: ${platformType});

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

        res.redirect(/confirmation.html?token=${user.token});
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

// Function to generate a random string
function generateRandomString(length) {
    return crypto.randomBytes(length).toString('hex');
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
        'Authorization': Bearer ${accessToken},
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
        logger.info(Refreshed access token for user ${user.discord_id});
    }

    return user.access_token;
}

// Function to get pending clan members
async function getPendingClanMembers(accessToken, groupId) {
    const url = https://www.bungie.net/Platform/GroupV2/${groupId}/Members/Pending/;
    const headers = {
        'Authorization': Bearer ${accessToken},
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

let currentVideoTitle = 'Loading...';
let currentVideoUrl = ''; // New variable for the video URL

io.on('connection', (socket) => {
    console.log('New client connected');

    // Global variables for video title, URL, and start time
    let currentVideoTitle = 'Your Video Title'; // Replace with default title if needed
    let currentVideoUrl = 'https://www.youtube.com/watch?v=YourVideoID'; // Replace with default URL if needed
    let videoStartTimestamp = Date.now(); // The timestamp for when the video started

    // Emit the current video title, URL, and start timestamp to the new client
    socket.emit('nowPlayingUpdate', { title: currentVideoTitle, videoUrl: currentVideoUrl, startTimestamp: videoStartTimestamp });

    // Listen for 'updateVideoTitle' from the client
    socket.on('updateVideoTitle', ({ title, videoUrl }) => {
        console.log('Received video title:', title);
        console.log('Received video URL:', videoUrl);  // Log the received video URL

        // Update global variables
        currentVideoTitle = title;
        currentVideoUrl = videoUrl;
        videoStartTimestamp = Date.now(); // Update timestamp when the video changes

        // Broadcast the updated video title, URL, and start time to all clients
        io.emit('nowPlayingUpdate', { title, videoUrl, startTimestamp: videoStartTimestamp });
    });

    socket.on('disconnect', () => {
        console.log('Client disconnected');
    });
});




// Endpoint to send real-time data to clients
app.post('/api/update', (req, res) => {
    const data = req.body;
    // Emit an event to all connected clients
    io.emit('updateData', data);
    res.status(200).send({ message: 'Data sent to clients' });
});

server.listen(PORT, () => {
    logger.info(Server is running on port ${PORT});
});
