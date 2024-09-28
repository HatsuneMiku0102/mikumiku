// server.js

'use strict';

const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
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
const { DateTime } = require('luxon');
const fetch = require('node-fetch');
const retry = require('async-retry');
const { body, validationResult } = require('express-validator');
const dialogflow = require('@google-cloud/dialogflow');
const uuid = require('uuid');
const cors = require('cors');

dotenv.config();


const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: "*", // Temporarily allow all origins
        methods: ["GET", "POST"],
        allowedHeaders: ["my-custom-header"],
        credentials: true
    }
});

const PORT = process.env.PORT || 3000;

// Configure logging using winston
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.printf(({ timestamp, level, message }) => {
            return `${timestamp} [${level.toUpperCase()}]: ${message}`;
        })
    ),
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: 'server.log' })
    ]
});

app.get('/api/keys', (req, res) => {
  res.json({
    YOUTUBE_API_KEY: process.env.YOUTUBE_API_KEY,
    OPENWEATHER_API_KEY: process.env.OPENWEATHER_API_KEY,
  });
});

app.set('trust proxy', 1);

// Middleware
app.use(bodyParser.json());
app.use(cookieParser());
app.use(cors());


app.post('/updateVideoData', async (req, res) => {
    const { videoId } = req.body;

    if (!videoId) {
        logger.error('Invalid video ID received');
        return res.status(400).send('Invalid video ID');
    }

    try {
        const apiUrl = `https://www.googleapis.com/youtube/v3/videos?id=${videoId}&key=${process.env.YOUTUBE_API_KEY}&part=snippet,statistics,contentDetails`;
        const response = await axios.get(apiUrl);

        if (response.data.items && response.data.items.length > 0) {
            const videoData = response.data.items[0].snippet;
            const statistics = response.data.items[0].statistics;
            const contentDetails = response.data.items[0].contentDetails;

            const category = categoryMap[videoData.categoryId] || "Unknown Category";

            currentVideoData = {
                videoId: videoId,
                title: videoData.title,
                description: videoData.description,
                channelTitle: videoData.channelTitle,
                viewCount: statistics.viewCount,
                likeCount: statistics.likeCount,
                duration: contentDetails.duration,
                publishedAt: videoData.publishedAt,
                category: category,
                thumbnail: `https://img.youtube.com/vi/${videoId}/hqdefault.jpg`,
            };

            io.emit('nowPlayingUpdate', currentVideoData);
            logger.info(`Video data updated and emitted to all clients: ${JSON.stringify(currentVideoData)}`);
            res.status(200).send('Video data received successfully');
        } else {
            logger.error('No video data found for the given video ID');
            res.status(404).send('No video data found');
        }
    } catch (error) {
        logger.error(`Error fetching video data: ${error.message}`);
        res.status(500).send('Error fetching video data');
    }
});

// Socket.IO connection handling
io.on('connection', (socket) => {
    logger.info(`[Socket.IO] Youtube Client Connected on socket ID: ${socket.id}`);
    socket.emit('nowPlayingUpdate', currentVideoData);

    socket.on('disconnect', () => {
        logger.info(`[Socket.IO] Youtube Client disconnected: ${socket.id}`);
    });
});





// MongoDB Connection
const mongoUrl = process.env.MONGO_URL;

mongoose.connect(mongoUrl, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    useFindAndModify: false
}).then(() => {
    logger.info('Connected to MongoDB');
}).catch((err) => {
    logger.error(`Error connecting to MongoDB: ${err}`);
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
    logger.error(`Session store error: ${error}`);
});

// Session Middleware
app.use(session({
    secret: process.env.SESSION_SECRET || 'your-session-secret',
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
    cookie: {
        secure: process.env.NODE_ENV === 'production', // Set to true in production
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 1 day
    }
}));

// Set Content Security Policy using helmet
app.use(
    helmet.contentSecurityPolicy({
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: [
                "'self'",
                "'unsafe-inline'", // Consider replacing with nonces or hashes for better security
                "https://fonts.googleapis.com",
                "https://cdnjs.cloudflare.com",
                "https://www.youtube.com"
            ],
            styleSrc: [
                "'self'",
                "'unsafe-inline'", // Consider replacing with nonces or hashes for better security
                "https://fonts.googleapis.com"
            ],
            imgSrc: [
                "'self'",
                "data:",
                "https://i.ytimg.com",
                "https://img.youtube.com",
                "https://openweathermap.org"
            ],
            fontSrc: [
                "'self'",
                "https://fonts.gstatic.com"
            ],
            connectSrc: [
                "'self'",
                "https://www.googleapis.com",
                "https://*.youtube.com",
                "https://api.openweathermap.org"
            ],
            frameSrc: [
                "'self'",
                "https://discord.com",
                "https://www.youtube.com"
            ],
            mediaSrc: [
                "'self'",
                "https://www.youtube.com"
            ],
            frameAncestors: [
                "'self'",
                "https://discord.com"
            ],
            upgradeInsecureRequests: []
        }
    })
);

// Serve static files from 'public'
app.use(express.static(path.join(__dirname, 'public'), {
    etag: false,
    maxAge: 0,
    lastModified: false
}));




console.log("Loading credentials from environment variable...");
let credentials;

try {
    credentials = JSON.parse(process.env.GOOGLE_APPLICATION_CREDENTIALS_JSON);
    console.log("Credentials loaded successfully.");
} catch (error) {
    console.error("Error parsing credentials JSON from environment variable:", error);
    process.exit(1);
}

// Create a new Dialogflow session client with credentials
let sessionClient;

try {
    sessionClient = new dialogflow.SessionsClient({
        credentials: {
            client_email: credentials.client_email,
            private_key: credentials.private_key,
        },
    });
    console.log("Dialogflow session client initialized successfully.");
} catch (error) {
    console.error("Error initializing Dialogflow session client:", error);
    process.exit(1);
}

// Set the project ID explicitly to ensure we're using the correct Dialogflow agent
const projectId = 'haru-ai-sxjr'; // Set the project ID explicitly here
console.log(`Using project ID: ${projectId}`);



async function performWebSearch(query) {
    const GOOGLE_API_KEY = process.env.GOOGLE_API_KEY;
    const GOOGLE_CSE_ID = process.env.GOOGLE_CSE_ID;
    const SEARCH_ENDPOINT = `https://www.googleapis.com/customsearch/v1?q=${encodeURIComponent(query)}&key=${GOOGLE_API_KEY}&cx=${GOOGLE_CSE_ID}`;

    try {
        console.log(`Performing Google Custom Search for query: "${query}"`);
        const response = await fetch(SEARCH_ENDPOINT);
        const data = await response.json();

        if (data.items && data.items.length > 0) {
            // Format the top search results
            const formattedResults = data.items.slice(0, 3).map((item, index) => {
                return `**${index + 1}. [${item.title}](${item.link})**\n${item.snippet}`;
            }).join("\n\n");
            
            return `Here are the top results I found for "${query}":\n\n${formattedResults}`;
        } else {
            return `Sorry, I couldn’t find anything relevant for "${query}".`;
        }
    } catch (error) {
        console.error('Error fetching web search results:', error);
        return 'Sorry, something went wrong while searching the web.';
    }
}


// Define the web search function
async function getWebSearchResults(query) {
    const GOOGLE_API_KEY = process.env.GOOGLE_API_KEY;
    const GOOGLE_CSE_ID = process.env.GOOGLE_CSE_ID;

    if (!GOOGLE_API_KEY || !GOOGLE_CSE_ID) {
        console.error("Missing Google API Key or CSE ID.");
        return 'Configuration error: Missing Google API Key or CSE ID.';
    }

    const SEARCH_ENDPOINT = `https://www.googleapis.com/customsearch/v1?q=${encodeURIComponent(query)}&key=${GOOGLE_API_KEY}&cx=${GOOGLE_CSE_ID}`;

    try {
        console.log(`Fetching web search results for query: "${query}"`);
        const response = await fetch(SEARCH_ENDPOINT);

        if (!response.ok) {
            console.error(`Error fetching web search results: ${response.status} - ${response.statusText}`);
            return handleFetchError(response.status);
        }

        const data = await response.json();
        console.log("Received web search data:", data);

        if (data.items && data.items.length > 0) {
            const lowerCaseQuery = query.toLowerCase();
            const keyWords = ["who", "what", "when", "where", "why", "how"];
            const questionType = keyWords.find(word => lowerCaseQuery.startsWith(word));

            const topResults = data.items.slice(0, 3).map((item, index) => {
                let responseSnippet = item.snippet;
                let focusText = '';

                // Advanced context extraction based on question type
                if (questionType === "who" || questionType === "what") {
                    // Provide a direct answer by focusing on the first sentence
                    responseSnippet = item.snippet.split('. ')[0];
                } else if (questionType === "when") {
                    // Look for dates or time-related keywords
                    const datePattern = /\b(?:\d{1,2}(?:st|nd|rd|th)?\s\w+|\w+\s\d{1,2},\s\d{4}|\d{4})\b/;
                    const dateMatch = item.snippet.match(datePattern);
                    if (dateMatch) {
                        focusText = `<br><i>Related Time/Date:</i> ${dateMatch[0]}`;
                    }
                } else if (questionType === "where") {
                    // Look for location keywords in the snippet
                    const locationKeywords = ["city", "country", "location", "place"];
                    const location = locationKeywords.find(keyword => item.snippet.toLowerCase().includes(keyword));
                    if (location) {
                        focusText = `<br><i>Location Reference:</i> ${location}`;
                    }
                }

                // Format the response for better readability
                return `<b>${index + 1}. <a href="${item.link}" target="_blank">${item.title}</a></b><br>${responseSnippet}${focusText}`;
            }).join("<br><br>");

            return `Here are the top results I found for "<b>${query}</b>":<br><br>${topResults}`;
        } else {
            return `Sorry, I couldn’t find anything relevant for "<b>${query}</b>".`;
        }
    } catch (error) {
        console.error('Error fetching web search results:', error);
        return 'Sorry, something went wrong while searching the web.';
    }
}

// Handle fetch errors and provide specific messages for different error codes
function handleFetchError(status) {
    switch (status) {
        case 400:
            return 'Bad Request: Please check your query and try again.';
        case 403:
            return 'Access Forbidden: This might be due to an API key issue or quota limits being exceeded.';
        case 404:
            return 'No results found. Please check your query and try again.';
        default:
            return 'An unexpected error occurred. Please try again later.';
    }
}



// Handle incoming Dialogflow requests
app.post('/api/dialogflow', async (req, res) => {
    const userMessage = req.body.message;
    console.log(`Received user message: ${userMessage}`);

    if (!userMessage) {
        console.error("No user message provided in request.");
        res.status(400).json({ response: 'No message provided.' });
        return;
    }

    const sessionId = uuid.v4();
    const sessionPath = sessionClient.projectAgentSessionPath(projectId, sessionId);
    console.log(`Generated session path: ${sessionPath}`);

    const request = {
        session: sessionPath,
        queryInput: {
            text: {
                text: userMessage,
                languageCode: 'en-US',
            },
        },
    };

    console.log("Sending request to Dialogflow...");
    try {
        const responses = await sessionClient.detectIntent(request);
        console.log("Received response from Dialogflow.");

        const result = responses[0].queryResult;
        console.log("Query Result:", JSON.stringify(result, null, 2));

        if (result && result.fulfillmentText) {
            console.log("Sending fulfillment text back to client:", result.fulfillmentText);
            // Send the interim response back while search is being performed
            res.json({ response: result.fulfillmentText });

            // If the action is web.search, initiate the search
            if (result.action === 'web.search') {
                console.log("Handling web search action...");
                const parameters = result.parameters.fields;

                if (parameters && parameters.q && parameters.q.stringValue) {
                    const searchQuery = parameters.q.stringValue;
                    console.log(`Performing web search for query: "${searchQuery}"`);

                    // Perform web search using Google Custom Search API
                    const webSearchResponse = await getWebSearchResults(searchQuery);
                    console.log("Received web search data:", webSearchResponse);

                    // After obtaining the search result, notify the client via a WebSocket or another POST request to update the response.
                    // Assuming you're using WebSockets to maintain real-time updates:
                    io.emit('webSearchResult', { userMessage, response: webSearchResponse });
                } else {
                    console.error("Missing search query parameter.");
                }
            }
        } else {
            console.warn("Dialogflow response did not contain fulfillment text or actionable intent.");
            res.json({ response: 'Sorry, I couldn’t understand that.' });
        }
    } catch (error) {
        console.error('Dialogflow API error:', error);
        res.status(500).json({ response: 'Sorry, something went wrong.' });
    }
});


// Web search function
async function getWebSearchResults(query) {
    const GOOGLE_API_KEY = process.env.GOOGLE_API_KEY;
    const GOOGLE_CSE_ID = process.env.GOOGLE_CSE_ID;

    if (!GOOGLE_API_KEY || !GOOGLE_CSE_ID) {
        console.error("Missing Google API Key or CSE ID.");
        return 'Configuration error: Missing Google API Key or CSE ID.';
    }

    const SEARCH_ENDPOINT = `https://www.googleapis.com/customsearch/v1?q=${encodeURIComponent(query)}&key=${GOOGLE_API_KEY}&cx=${GOOGLE_CSE_ID}`;

    try {
        console.log(`Fetching web search results for query: "${query}"`);
        const response = await fetch(SEARCH_ENDPOINT);

        if (!response.ok) {
            console.error(`Error fetching web search results: ${response.status} - ${response.statusText}`);
            return `Error: Received status code ${response.status}. Please check the request or try again later.`;
        }

        const data = await response.json();
        console.log("Received web search data:", data);

        if (data.items && data.items.length > 0) {
            const topResults = data.items.slice(0, 3).map((item, index) => {
                return `<b>${index + 1}. <a href="${item.link}" target="_blank">${item.title}</a></b><br>${item.snippet}`;
            }).join("<br><br>");

            return `Here are the top results I found for "${query}":<br><br>${topResults}`;
        } else {
            return 'Sorry, I couldn’t find anything relevant.';
        }
    } catch (error) {
        console.error('Error fetching web search results:', error);
        return 'Sorry, something went wrong while searching the web.';
    }
}








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
    created_at: { type: Date, default: Date.now, expires: 86400 }, // Expires after 1 day
    ip_address: { type: String },
    user_agent: { type: String }
});

const Session = mongoose.model('Session', sessionSchema, 'sessions');

const commentSchema = new mongoose.Schema({
    username: { type: String, required: true },
    comment: { type: String, required: true },
    timestamp: { type: Date, default: Date.now },
    approved: { type: Boolean, default: true }
});

const Comment = mongoose.model('Comment', commentSchema);

// Helper Functions
function generateRandomString(size = 16) {
    return crypto.randomBytes(size).toString('hex');
}

function hashPassword(password, salt) {
    return crypto.createHmac('sha256', salt)
        .update(password)
        .digest('hex');
}

// Example: Hashing a plain password (for demonstration purposes)
const plainPassword = 'Aria';
const salt = 'random_salt';
const hashedPassword = hashPassword(plainPassword, salt);
logger.info(`Hashed Password: ${hashedPassword}`);

// JWT Verification Middleware
function verifyToken(req, res, next) {
    const token = req.cookies.token;
    logger.info(`Token from cookie: ${token}`);

    if (!token) {
        logger.info('Token not found. Redirecting to login.');
        return res.redirect('/admin-login.html');
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            logger.info(`Token verification failed: ${err.message}`);
            return res.redirect('/admin-login.html');
        }
        logger.info(`Token successfully verified. User ID: ${decoded.id}`);
        req.userId = decoded.id;
        next();
    });
}





app.get('/api/youtube', async (req, res) => {
    const videoId = req.query.videoId;

    if (!videoId) {
        return res.status(400).json({ error: 'videoId parameter is required.' });
    }

    const apiKey = process.env.YOUTUBE_API_KEY;
    if (!apiKey) {
        console.error('YOUTUBE_API_KEY is not set in environment variables.');
        return res.status(500).json({ error: 'Internal Server Error' });
    }

    const apiUrl = `https://www.googleapis.com/youtube/v3/videos?id=${encodeURIComponent(videoId)}&part=snippet,statistics,contentDetails&key=${apiKey}`;

    try {
        const data = await retry(
            async (bail, attempt) => {
                try {
                    const response = await axios.get(apiUrl);
                    
                    // Handle the response
                    if (response.status === 200) {
                        const responseData = response.data;

                        // Validate the response structure
                        if (
                            !responseData.items ||
                            responseData.items.length === 0 ||
                            !responseData.items[0].snippet
                        ) {
                            throw new Error('Unexpected response structure from YouTube API.');
                        }

                        return responseData;
                    } else if (response.status === 403) {
                        // If the error is related to a forbidden request or quota limit, bail and do not retry
                        bail(new Error('YouTube API quota exceeded or access forbidden.'));
                    } else {
                        throw new Error(`Failed to fetch data from YouTube API. Status: ${response.status}`);
                    }
                } catch (err) {
                    if (err.response) {
                        // Handle HTTP response errors
                        if (err.response.status === 404) {
                            bail(new Error('Video not found.'));
                        } else if (err.response.status >= 500) {
                            // Retry if YouTube's servers are having issues
                            console.warn(`Attempt ${attempt}: YouTube API returned a server error. Retrying...`);
                            throw err; // Retry this error
                        } else {
                            // For other client-side errors, do not retry
                            bail(err);
                        }
                    } else {
                        // Handle network errors or other unknown errors
                        console.warn(`Attempt ${attempt}: Network error or unknown issue occurred. Retrying...`);
                        throw err; // Retry on network errors
                    }
                }
            },
            {
                retries: 3, // Retry up to 3 times before failing
                factor: 2, // Exponential backoff factor
                minTimeout: 1000, // Minimum time between retries (1 second)
                maxTimeout: 5000, // Maximum time between retries (5 seconds)
            }
        );

        // Successfully fetched data
        res.status(200).json(data);
    } catch (error) {
        console.error(`Error fetching YouTube video data for videoId ${videoId}: ${error.message}`);

        // Differentiate error types for better client handling
        if (error.message.includes('quota')) {
            return res.status(403).json({ error: 'YouTube API quota exceeded. Please try again later.' });
        } else if (error.message.includes('not found')) {
            return res.status(404).json({ error: 'The requested video was not found.' });
        } else if (error.message.includes('forbidden')) {
            return res.status(403).json({ error: 'YouTube API access forbidden. Please check your API key.' });
        } else {
            return res.status(500).json({ error: 'Internal Server Error' });
        }
    }
});


// OAuth Configuration
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REDIRECT_URI = 'https://mikumiku.dev/callback';

const membershipFilePath = path.join(__dirname, 'membership_mapping.json');

function updateMembershipMapping(discordId, userInfo) {
    let membershipMapping = {};

    if (fs.existsSync(membershipFilePath)) {
        const data = fs.readFileSync(membershipFilePath, 'utf8');
        logger.info(`Read existing membership mapping file: ${data}`);
        try {
            membershipMapping = JSON.parse(data);
        } catch (err) {
            logger.error(`Error parsing membership mapping file: ${err}`);
            membershipMapping = {};
        }
    } else {
        logger.info('Membership mapping file does not exist. A new one will be created.');
    }

    membershipMapping[discordId] = {
        "membership_id": userInfo.membershipId,
        "platform_type": userInfo.platformType,
        "bungie_name": userInfo.bungieName,
        "registration_date": new Date(),
        "clan_id": "4900827"
    };

    try {
        fs.writeFileSync(membershipFilePath, JSON.stringify(membershipMapping, null, 2), 'utf8');
        logger.info(`Updated membership mapping file: ${JSON.stringify(membershipMapping, null, 2)}`);
    } catch (err) {
        logger.error(`Error writing to membership mapping file: ${err}`);
    }

    try {
        const updatedData = fs.readFileSync(membershipFilePath, 'utf8');
        logger.info(`Verified membership mapping file content: ${updatedData}`);
    } catch (err) {
        logger.error(`Error reading membership mapping file after update: ${err}`);
    }
}

async function sendUserInfoToDiscordBot(discordId, userInfo) {
    logger.info(`User info ready to be sent to Discord bot: ${JSON.stringify(userInfo)}`);
    // Implement the logic to send user info to your Discord bot here
}

// OAuth Routes
app.get('/login', async (req, res) => {
    const state = generateRandomString(16);
    const user_id = req.query.user_id;
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
        logger.error(`Error saving session to DB: ${err}`);
        res.status(500).send('Internal Server Error');
    }
});

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
        const refreshToken = tokenData.refresh_token;
        const expiresIn = tokenData.expires_in;
        const tokenExpiry = DateTime.now().plus({ seconds: expiresIn }).toJSDate();

        const userInfo = await getBungieUserInfo(accessToken);
        logger.info('User Info Response:', JSON.stringify(userInfo));

        if (!userInfo.Response || !userInfo.Response.destinyMemberships) {
            logger.error('Incomplete user info response:', JSON.stringify(userInfo));
            throw new Error('Failed to obtain user information');
        }

        const bungieGlobalDisplayName = userInfo.Response.bungieNetUser.cachedBungieGlobalDisplayName;
        const bungieGlobalDisplayNameCode = userInfo.Response.bungieNetUser.cachedBungieGlobalDisplayNameCode.toString().padStart(4, '0');
        const bungieName = `${bungieGlobalDisplayName}#${bungieGlobalDisplayNameCode}`;

        let primaryMembership = userInfo.Response.destinyMemberships.find(
            membership => membership.membershipId === userInfo.Response.primaryMembershipId
        );

        if (!primaryMembership) {
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
                token: generateRandomString(16),
                registration_date: new Date(),
                access_token: accessToken,
                refresh_token: refreshToken,
                token_expiry: tokenExpiry
            },
            { upsert: true, new: true }
        );

        await sendUserInfoToDiscordBot(discordId, { bungieName, platformType, membershipId });

        updateMembershipMapping(discordId, { bungieName, platformType, membershipId });

        await Session.deleteOne({ state });

        res.redirect(`/confirmation.html?token=${user.token}`);
    } catch (error) {
        logger.error(`Error during callback: ${error}`);
        if (error.response) {
            logger.error(`Response data: ${JSON.stringify(error.response.data)}`);
            logger.error(`Response status: ${error.response.status}`);
            logger.error(`Response headers: ${JSON.stringify(error.response.headers)}`);
        } else if (error.request) {
            logger.error(`Request made but no response received: ${error.request}`);
        } else {
            logger.error(`Error setting up request: ${error.message}`);
        }
        res.status(500).send('Internal Server Error');
    }
});

app.get('/confirmation.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'confirmation.html'));
});

app.get('/api/bungie-name', async (req, res) => {
    const token = req.query.token;

    try {
        const user = await User.findOne({ token });
        if (!user) {
            return res.status(400).send({ error: 'Invalid token' });
        }

        res.send({ bungie_name: user.bungie_name });
    } catch (err) {
        logger.error(`Error fetching Bungie name: ${err}`);
        res.status(500).send({ error: 'Internal Server Error' });
    }
});

// Comment Routes
app.post('/api/comments', async (req, res) => {
    try {
        const { username, comment } = req.body;
        const newComment = new Comment({ username, comment });
        await newComment.save();
        res.status(201).send(newComment);
    } catch (error) {
        logger.error(`Error saving comment: ${error}`);
        res.status(500).send({ error: 'Error saving comment' });
    }
});

app.get('/api/comments', async (req, res) => {
    try {
        const comments = await Comment.find({ approved: true });
        res.json(comments);
    } catch (error) {
        logger.error(`Error fetching comments: ${error}`);
        res.status(500).send({ error: 'Error fetching comments' });
    }
});

app.delete('/api/comments/:id', verifyToken, async (req, res) => {
    try {
        const { id } = req.params;
        await Comment.findByIdAndDelete(id);
        res.status(200).send({ message: 'Comment deleted' });
    } catch (error) {
        logger.error(`Error deleting comment: ${error}`);
        res.status(500).send({ error: 'Error deleting comment' });
    }
});

// Utility Functions
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
        logger.info(`Token Response: ${JSON.stringify(response.data)}`);
        return response.data;
    } catch (error) {
        logger.error(`Error fetching Bungie token: ${error}`);
        if (error.response) {
            logger.error(`Response data: ${JSON.stringify(error.response.data)}`);
            logger.error(`Response status: ${error.response.status}`);
            logger.error(`Response headers: ${JSON.stringify(error.response.headers)}`);
        } else if (error.request) {
            logger.error(`Request made but no response received: ${error.request}`);
        } else {
            logger.error(`Error setting up request: ${error.message}`);
        }
        throw new Error('Failed to fetch Bungie token');
    }
}

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
        logger.info(`Refresh Token Response: ${JSON.stringify(response.data)}`);
        return response.data;
    } catch (error) {
        logger.error(`Error refreshing Bungie token: ${error}`);
        if (error.response) {
            logger.error(`Response data: ${JSON.stringify(error.response.data)}`);
            logger.error(`Response status: ${error.response.status}`);
            logger.error(`Response headers: ${JSON.stringify(error.response.headers)}`);
        } else if (error.request) {
            logger.error(`Request made but no response received: ${error.request}`);
        } else {
            logger.error(`Error setting up request: ${error.message}`);
        }
        throw new Error('Failed to refresh Bungie token');
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
        logger.info(`User Info Response: ${JSON.stringify(response.data)}`);
        return response.data;
    } catch (error) {
        logger.error(`Error fetching Bungie user info: ${error}`);
        if (error.response) {
            logger.error(`Response data: ${JSON.stringify(error.response.data)}`);
            logger.error(`Response status: ${error.response.status}`);
            logger.error(`Response headers: ${JSON.stringify(error.response.headers)}`);
        } else if (error.request) {
            logger.error(`Request made but no response received: ${error.request}`);
        } else {
            logger.error(`Error setting up request: ${error.message}`);
        }
        throw new Error('Failed to fetch Bungie user info');
    }
}

async function getAccessTokenForUser(user) {
    const now = DateTime.now();
    const tokenExpiry = DateTime.fromJSDate(user.token_expiry);

    if (now >= tokenExpiry) {
        const newTokenData = await refreshBungieToken(user.refresh_token);
        user.access_token = newTokenData.access_token;
        user.refresh_token = newTokenData.refresh_token;
        user.token_expiry = DateTime.now().plus({ seconds: newTokenData.expires_in }).toJSDate();
        await user.save();
        logger.info(`Refreshed access token for user ${user.discord_id}`);
    }

    return user.access_token;
}

async function getPendingClanMembers(accessToken, groupId) {
    const url = `https://www.bungie.net/Platform/GroupV2/${groupId}/Members/Pending/`;
    const headers = {
        'Authorization': `Bearer ${accessToken}`,
        'X-API-Key': process.env.X_API_KEY
    };

    try {
        const response = await axios.get(url, { headers });
        logger.info(`Pending Clan Members Response: ${JSON.stringify(response.data)}`);
        return response.data.Response.results;
    } catch (error) {
        logger.error(`Error fetching pending clan members: ${error}`);
        if (error.response) {
            logger.error(`Response data: ${JSON.stringify(error.response.data)}`);
            logger.error(`Response status: ${error.response.status}`);
            logger.error(`Response headers: ${JSON.stringify(error.response.headers)}`);
        } else if (error.request) {
            logger.error(`Request made but no response received: ${error.request}`);
        } else {
            logger.error(`Error setting up request: ${error.message}`);
        }
        throw new Error('Failed to fetch pending clan members');
    }
}

app.get('/api/clan/pending', verifyToken, async (req, res) => {
    const userId = req.userId;

    try {
        const user = await User.findOne({ discord_id: userId });
        if (!user) {
            return res.status(400).send({ error: 'User not found' });
        }

        const accessToken = await getAccessTokenForUser(user);
        const pendingMembers = await getPendingClanMembers(accessToken, '5236471');

        await PendingMember.deleteMany();
        const pendingMemberDocs = pendingMembers.map(member => ({
            membershipId: member.destinyUserInfo.membershipId,
            displayName: member.destinyUserInfo.displayName,
            joinDate: new Date(member.joinDate)
        }));
        await PendingMember.insertMany(pendingMemberDocs);

        res.send({ pending_members: pendingMembers });
    } catch (err) {
        logger.error(`Error fetching pending clan members: ${err}`);
        res.status(500).send({ error: 'Internal Server Error' });
    }
});

app.get('/api/clan/pending/fromdb', verifyToken, async (req, res) => {
    try {
        const pendingMembers = await PendingMember.find();
        res.send({ pending_members: pendingMembers });
    } catch (err) {
        logger.error(`Error retrieving pending clan members from DB: ${err}`);
        res.status(500).send({ error: 'Internal Server Error' });
    }
});

// Additional Security Configurations
app.use((req, res, next) => {
    if (process.env.NODE_ENV === 'production') {
        if (req.headers['x-forwarded-proto'] !== 'https') {
            return res.redirect(`https://${req.headers.host}${req.url}`);
        }
    }
    next();
});

// Protected Admin Dashboard Route
app.get('/admin-dashboard-:random.html', verifyToken, (req, res) => {
    res.sendFile(path.join(__dirname, 'admin-dashboard.html'));
});

// Login Route
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    const adminUsername = process.env.ADMIN_USERNAME;
    const adminPasswordHash = process.env.ADMIN_PASSWORD; // Should be hashed
    const salt = 'random_salt';

    if (username !== adminUsername) {
        logger.warn(`Failed login attempt for username: ${username} from IP: ${req.ip}`);
        return res.status(401).json({ auth: false, message: 'Invalid username or password' });
    }

    const hashedInputPassword = hashPassword(password, salt);

    if (hashedInputPassword !== adminPasswordHash) {
        logger.warn(`Failed login attempt for username: ${username} from IP: ${req.ip}`);
        return res.status(401).json({ auth: false, message: 'Invalid username or password' });
    }

    const token = jwt.sign({ id: adminUsername }, process.env.JWT_SECRET || 'your-jwt-secret-key', {
        expiresIn: 86400 // 24 hours
    });

    const dashboardURL = `/admin-dashboard-${generateRandomString()}.html`;

    req.session.dashboardURL = dashboardURL;
    logger.info(`Stored dashboardURL in session: ${req.session.dashboardURL}`);

    res.cookie('token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: 86400 * 1000 // 24 hours
    });

    app.get(dashboardURL, verifyToken, (req, res) => {
        res.sendFile(path.join(__dirname, 'admin-dashboard.html'));
    });

    req.session.save((err) => {
        if (err) {
            logger.error(`Error saving session: ${err}`);
            return res.status(500).json({ auth: false, message: 'Error saving session' });
        }
        res.status(200).json({ auth: true, redirect: dashboardURL });
    });
});

// Logout Route
app.post('/logout', (req, res) => {
    res.clearCookie('token');
    req.session.destroy();
    res.redirect('/admin-login.html');
});

// Video Status Variables (Server-Side State)
let currentVideoData = {};

// Socket.IO Connection Handling
io.on('connection', (socket) => {
    logger.info(`[Socket.IO] New client connected: ${socket.id}`);

    // Emit the current video status to the newly connected client
    socket.emit('nowPlayingUpdate', currentVideoData);

    // Handle video status updates from clients
    socket.on('updateVideoTitle', (data) => {
        logger.info(`[Socket.IO] Received "updateVideoTitle" event from client ${socket.id}: ${JSON.stringify(data)}`);

        // Destructure the incoming data
        const { videoId, title, description, thumbnail, category, currentTime = 0, isPaused = false, isOffline = false } = data;

        // Log each piece of data for better debugging
        logger.info(`[Socket.IO] Video ID: ${videoId}, Title: ${title}, Description: ${description}, Thumbnail: ${thumbnail}, Category: ${category}, Current Time: ${currentTime}, Is Paused: ${isPaused}, Is Offline: ${isOffline}`);

        // Update the server state with the new video data
        currentVideoData = {
            videoId,
            title,
            description,
            thumbnail,
            category,
            currentTime,
            isPaused,
            isOffline,
            videoUrl: `https://www.youtube.com/watch?v=${videoId}`,
            startTimestamp: Date.now() - (currentTime * 1000)
        };

        // Emit the updated video data to all connected clients
        io.emit('nowPlayingUpdate', currentVideoData);

        logger.info(`[Socket.IO] Emitted "nowPlayingUpdate" to all clients: Title="${title}", Video ID="${videoId}", isPaused=${isPaused}, isOffline=${isOffline}`);
    });

    // Handle client disconnection
    socket.on('disconnect', () => {
        logger.info(`[Socket.IO] Client disconnected: ${socket.id}`);
    });
});





// Real-time Data Endpoint
app.post('/api/update', (req, res) => {
    const data = req.body;
    io.emit('updateData', data);
    res.status(200).send({ message: 'Data sent to clients' });
});

// Video Routes (You can expand these based on your requirements)
app.get('/api/videos/public', async (req, res) => {
    try {
        // Implement logic to retrieve public videos
        res.json([]);
    } catch (err) {
        logger.error(`Error retrieving video metadata: ${err}`);
        res.status(500).send({ error: 'Error retrieving video metadata' });
    }
});

app.post('/api/videos',
    verifyToken,
    [
        body('url').isURL().withMessage('Invalid URL format'),
        body('title').isString().notEmpty().withMessage('Title is required'),
        body('description').isString().optional(),
        body('category').isString().notEmpty().withMessage('Category is required')
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const sanitizedUrl = req.body.url.replace('youtu.be', 'youtube.com/embed');
        const sanitizedTitle = req.body.title;
        const sanitizedDescription = req.body.description ? req.body.description : '';
        const sanitizedCategory = req.body.category;

        const videoMetadata = {
            url: sanitizedUrl,
            title: sanitizedTitle,
            description: sanitizedDescription,
            category: sanitizedCategory,
            uploadedAt: new Date()
        };

        try {
            // Logic to save video metadata to the database
            res.status(201).json({ message: 'Video added successfully', video: videoMetadata });
        } catch (err) {
            logger.error(`Error saving video metadata: ${err.message}`);
            res.status(500).json({ error: 'Error saving video metadata' });
        }
    }
);

// Active Users Tracking Helper Functions
const IPINFO_API_KEY = process.env.IPINFO_API_KEY; // Using your environment variable

// Function to fetch location data from IPInfo API
async function fetchLocationData(ip) {
    try {
        // Split IPs in case multiple are forwarded
        const ipList = ip.split(',');
        const validIp = ipList[0].trim(); // Take the first valid IP address

        const response = await axios.get(`https://ipinfo.io/${validIp}?token=${IPINFO_API_KEY}`);
        const { ip: userIP, city, region, country } = response.data;

        return {
            ip: userIP,
            city: city || 'Unknown',
            region: region || 'Unknown',
            country: country || 'Unknown'
        };
    } catch (error) {
        console.error(`Error fetching location data for IP ${ip}:`, error);
        return {
            ip,
            city: 'Unknown',
            region: 'Unknown',
            country: 'Unknown'
        };
    }
}



async function attachLocationData(req, res, next) {
    const clientIp = getClientIp(req);

    if (clientIp) {
        console.log(`Client IP detected: ${clientIp}`);

        const locationData = await fetchLocationData(clientIp);
        req.location = locationData; // Attach location data to the request object
    } else {
        console.log('No valid public IP detected.');
    }

    next();
}

module.exports = { attachLocationData };

// Function to normalize IP address (remove "::ffff:" prefix if present)
function normalizeIp(ip) {
    if (ip.startsWith('::ffff:')) {
        return ip.replace('::ffff:', '');
    }
    return ip;
}


// Additional Routes
app.get('/admin-dashboard', verifyToken, (req, res) => {
    res.sendFile(path.join(__dirname, 'admin-dashboard.html'));
});

app.get('/api/check-youtube', async (req, res) => {
    try {
        const youtubeApiStatus = true;
        res.json({
            available: youtubeApiStatus,
            status: youtubeApiStatus ? 'YouTube API is working' : 'YouTube API is unavailable'
        });
    } catch (error) {
        logger.error(`Error checking YouTube API: ${error}`);
        res.status(500).json({
            available: false,
            status: 'Error checking YouTube API'
        });
    }
});

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
        logger.error(`Error checking Bungie API: ${error}`);
        return res.json({ status: 'Bungie API is unavailable', available: false });
    }
});

app.get('/api/weather', async (req, res) => {
    const city = req.query.city || 'Leeds';
    const units = 'metric'; // or 'imperial' for Fahrenheit
    const apiKey = process.env.OPENWEATHER_API_KEY;

    if (!apiKey) {
        console.error('OPENWEATHER_API_KEY is not set in environment variables.');
        return res.status(500).json({ error: 'Internal Server Error' });
    }

    const apiUrl = `https://api.openweathermap.org/data/2.5/weather?q=${encodeURIComponent(city)}&units=${units}&appid=${apiKey}`;

    try {
        const response = await fetch(apiUrl);
        if (!response.ok) {
            // Attempt to parse error message from response
            let errorMsg = 'Failed to fetch weather data';
            try {
                const errorData = await response.json();
                errorMsg = errorData.message || errorMsg;
            } catch (e) {
                console.error('Error parsing error response:', e);
            }
            return res.status(response.status).json({ error: errorMsg });
        }
        const data = await response.json();
        res.json(data);
    } catch (error) {
        console.error(`Error fetching weather data for city ${city}:`, error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


const processedIPs = new Set(); // Set to store unique IPs

function getValidIpAddress(req) {
    let ipAddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress;

    if (ipAddress.includes(',')) {
        // Extract first valid IP from the list (ignoring local/internal IPs if present)
        ipAddress = ipAddress.split(',').map(ip => ip.trim())[0];
    }

    // If IP starts with "::ffff:", it is an IPv6 representation of IPv4, clean it up
    if (ipAddress.startsWith('::ffff:')) {
        ipAddress = ipAddress.replace('::ffff:', '');
    }

    // Check if the IP has already been processed to avoid duplicates
    if (processedIPs.has(ipAddress)) {
        console.log(`Duplicate IP detected: ${ipAddress}, skipping processing.`);
        return null; // Return null to indicate a duplicate IP
    }

    // Add the new IP to the set of processed IPs
    processedIPs.add(ipAddress);
    return ipAddress;
}

module.exports = { fetchLocationData, getValidIpAddress };


app.get('/api/location', async (req, res) => {
    const clientIp = getValidIpAddress(req);

    if (!clientIp) {
        return res.status(400).send('Duplicate IP detected, location not processed.');
    }

    try {
        const locationData = await fetchLocationData(clientIp); // Fetch the location using the public IP
        res.json(locationData);
    } catch (error) {
        console.error(`Error fetching location for IP ${clientIp}:`, error);
        res.status(500).send('Error fetching location data');
    }
});


function getClientIp(req) {
    const forwarded = req.headers['x-forwarded-for'];
    let ip = forwarded ? forwarded.split(',')[0] : req.connection.remoteAddress;
    
    // Strip the ::ffff: IPv6 prefix if present
    if (ip.includes("::ffff:")) {
        ip = ip.split("::ffff:")[1];
    }
    
    return ip;
}


async function fetchUserLocation(ip) {
    try {
        const response = await axios.get(`https://ipinfo.io/${ip}/geo?token=${process.env.IPINFO_API_KEY}`);
        const { city, region, country } = response.data;
        return { ip, city, region, country };
    } catch (error) {
        console.error(`Error fetching location data for IP ${ip}:`, error);
        return { ip, city: 'Unknown', region: 'Unknown', country: 'Unknown' };
    }
}

// Function to get all active users with their locations
async function getActiveUsersWithLocations() {
    // Fetch all active users' location data asynchronously
    const userPromises = activeUsers.map(user => fetchUserLocation(user.ip));
    return await Promise.all(userPromises);
}





let activeUsers = []; // Initialize an empty array to track active users

// Socket.IO Connection Handling
io.on('connection', async (socket) => {
    logger.info(`[Socket.IO] New client connected: ${socket.id}`);

    // Fetch client IP and location data
    const ip = socket.request.headers['x-forwarded-for'] || socket.request.connection.remoteAddress;
    const locationData = await fetchLocationData(ip);
    logger.info(`[Socket.IO] Location data fetched: ${JSON.stringify(locationData)}`);

    // Add the user with location data to active users list
    const user = {
        id: socket.id,
        ip: locationData.ip,
        city: locationData.city,
        region: locationData.region,
        country: locationData.country
    };

    // Ensure `activeUsers` is accessible here
    activeUsers.push(user);
    io.emit('activeUsersUpdate', { users: activeUsers });

    // Handle user disconnection
    socket.on('disconnect', () => {
        logger.info(`[Socket.IO] Client disconnected: ${socket.id}`);
        // Remove user from active list
        activeUsers = activeUsers.filter(u => u.id !== socket.id);
        io.emit('activeUsersUpdate', { users: activeUsers });
    });
});

// Start the server
server.listen(PORT, () => {
    logger.info(`Server is running on port ${PORT}`);
});

