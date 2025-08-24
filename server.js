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
const { body, validationResult } = require('express-validator');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const OpenAI = require('openai');
const { MongoClient } = require('mongodb');
const nacl = require('tweetnacl');
const os = require('os');
const { createProxyMiddleware } = require('http-proxy-middleware');

dotenv.config();

const DISCORD_PUBLIC_KEY = process.env.DISCORD_PUBLIC_KEY;
const OPENWEATHER_API_KEY = process.env.OPENWEATHER_API_KEY;
const BOT_TOKEN = process.env.BOT_TOKEN || '';

const app = express();
const server = http.createServer(app);
const io = socketIo(server, { cors: { origin: '*', methods: ['GET', 'POST'], allowedHeaders: ['*'], credentials: true } });
const PORT = process.env.PORT || 3000;

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.printf(({ timestamp, level, message }) => `${timestamp} [${level.toUpperCase()}]: ${message}`)),
  transports: [new winston.transports.Console(), new winston.transports.File({ filename: 'server.log' })]
});

app.use(bodyParser.json({ verify: (req, res, buf) => { if (req.path === '/interactions') req.rawBody = buf.toString(); } }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors());

app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com", "https://www.youtube.com", "https://unpkg.com", "https://cdn.jsdelivr.net", "https://cdn.skypack.dev", "https://cdn.socket.io", "https://api.mapbox.com"],
    styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com", "https://api.mapbox.com"],
    imgSrc: ["'self'", "blob:", "data:", "https://i.ytimg.com", "https://img.youtube.com", "https://openweathermap.org", "https://i.postimg.cc", "https://threejs.org", "https://www.youtube.com", "https://raw.githubusercontent.com", "https://api.tiles.mapbox.com", "https://*.tiles.mapbox.com"],
    fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
    connectSrc: ["'self'", "blob:", "https://www.googleapis.com", "https://*.youtube.com", "https://api.openweathermap.org", "https://cdn.socket.io", "https://mikumiku.dev", "https://api.mapbox.com", "https://events.mapbox.com"],
    frameSrc: ["'self'", "https://discord.com", "https://www.youtube.com"],
    mediaSrc: ["'self'", "https://www.youtube.com"],
    frameAncestors: ["'self'", "https://discord.com"],
    workerSrc: ["'self'", "blob:"],
    upgradeInsecureRequests: []
  }
}));

app.set('trust proxy', true);

app.post('/interactions', async (req, res) => {
  try {
    const signature = req.get('X-Signature-Ed25519') || '';
    const timestamp = req.get('X-Signature-Timestamp') || '';
    const raw = req.rawBody || '';
    const valid = nacl.sign.detached.verify(Buffer.from(timestamp + raw), Buffer.from(signature, 'hex'), Buffer.from(DISCORD_PUBLIC_KEY, 'hex'));
    if (!valid) return res.sendStatus(401);
    let payload;
    try { payload = JSON.parse(raw); } catch { return res.sendStatus(400); }
    if (payload.type === 1) return res.json({ type: 1 });
    if (payload.type === 2 && payload.data.name === 'status') {
      const now = Date.now();
      const sentMs = Number(timestamp) * 1000;
      const latency = now - sentMs;
      let webStatus = '❌ Error', webLatency = 'N/A';
      try { const start = Date.now(); const resp = await axios.get('https://mikumiku.dev/'); webStatus = `✅ ${resp.status} ${resp.statusText}`; webLatency = `⏱️ ${Date.now() - start} ms`; } catch {}
      const upSec = process.uptime();
      const hrs = Math.floor(upSec / 3600);
      const mins = Math.floor((upSec % 3600) / 60);
      const secs = Math.floor(upSec % 60);
      const uptime = `⏰ ${hrs}h ${mins}m ${secs}s`;
      const memMb = (process.memoryUsage().heapUsed / 1024 / 1024).toFixed(2);
      const loadAvg = os.loadavg()[0].toFixed(2);
      const dbState = mongoose.connection.readyState === 1 ? '🟢 Connected' : '🔴 Disconnected';
      const sockets = io.engine.clientsCount;
      const env = process.env.NODE_ENV === 'production' ? '🟢 Production' : '🟡 Dev';
      const version = process.env.COMMIT_SHA?.slice(0, 7) || process.version;
      const statusEmbed = { author: { name: '🎤 Mikumiku Status', icon_url: 'https://mikumiku.dev/logo.webp' }, thumbnail: { url: 'https://mikumiku.dev/logo.webp' }, title: '📊 System Overview', color: 0x39C5BB, description: `> **Latency:** \`${latency} ms\`\n> **Web:** \`${webStatus}\` (${webLatency})\n> **Load Avg:** \`${loadAvg}\`\n`, fields: [{ name: '⏰ Uptime', value: uptime, inline: true }, { name: '💾 Memory', value: `${memMb} MB`, inline: true }, { name: '🗄 DB Status', value: dbState, inline: true }, { name: '🔌 Sockets', value: `${sockets}`, inline: true }, { name: '🔧 Environment', value: env, inline: true }, { name: '📦 Version', value: version, inline: true }], footer: { text: 'Powered by mikumiku.dev', icon_url: 'https://mikumiku.dev/logo.webp' } };
      return res.json({ type: 4, data: { embeds: [statusEmbed] } });
    }
    if (payload.type === 2 && payload.data.name === 'weather') {
      const city = payload.data.options.find(o => o.name === 'city').value;
      if (!OPENWEATHER_API_KEY) return res.json({ type: 4, data: { content: '❌ Weather service not configured.' } });
      try {
        const resp = await axios.get(`https://api.openweathermap.org/data/2.5/weather?q=${encodeURIComponent(city)}&units=metric&appid=${OPENWEATHER_API_KEY}`);
        const { weather, main, wind, sys, name, coord } = resp.data;
        const weatherEmbed = { author: { name: `🌤️ Weather in ${name}, ${sys.country}`, icon_url: `http://openweathermap.org/img/wn/${weather[0].icon}@2x.png` }, color: 0x39C5BB, fields: [{ name: '🌡️ Temp', value: `${main.temp}°C`, inline: true }, { name: '📈 Feels Like', value: `${main.feels_like}°C`, inline: true }, { name: '💧 Humidity', value: `${main.humidity}%`, inline: true }, { name: '🌬️ Wind', value: `${wind.speed} m/s`, inline: true }, { name: '⛅ Condition', value: weather[0].description, inline: true }, { name: '📍 Coordinates', value: `[${coord.lat}, ${coord.lon}]`, inline: true }], thumbnail: { url: 'https://mikumiku.dev/logo.webp' }, footer: { text: 'Powered by OpenWeatherMap', icon_url: 'https://openweathermap.org/themes/openweathermap/assets/vendor/owm/img/widgets/logo_60x60.png' } };
        return res.json({ type: 4, data: { embeds: [weatherEmbed] } });
      } catch {
        return res.json({ type: 4, data: { content: `❌ Could not fetch weather for \`${city}\`.` } });
      }
    }
    if (payload.type === 2 && payload.data.name === 'cat') {
      const gifUrl = `https://cataas.com/cat/gif?${Date.now()}`;
      const userOption = payload.data.options?.find(o => o.name === 'user');
      const mention = userOption ? `<@${userOption.value}>` : '';
      const embed = { title: '😺 Here’s a random cat for you!', color: 0x39C5BB, image: { url: gifUrl }, footer: { text: 'Enjoy! 🐾', icon_url: 'https://mikumiku.dev/logo.webp' } };
      return res.json({ type: 4, data: { content: mention, embeds: [embed] } });
    }
    if (payload.type === 2 && payload.data.name === 'remind') {
      const timeStr = payload.data.options.find(o => o.name === 'time').value;
      const msg = payload.data.options.find(o => o.name === 'message').value;
      const userId = payload.member.user.id;
      const m = timeStr.match(/in (\d+) minutes?/i);
      if (!m) return res.json({ type: 4, data: { content: "❌ Invalid time format. Use something like `/remind time:\"in 10 minutes\" message:\"Do the thing\"`." } });
      const delayMs = parseInt(m[1], 10) * 60000;
      res.json({ type: 4, data: { content: `✅ Okay, I'll remind you in ${m[1]} minutes.` } });
      setTimeout(async () => {
        try {
          if (!BOT_TOKEN) return;
          const dm = await axios.post('https://discord.com/api/v10/users/@me/channels', { recipient_id: userId }, { headers: { Authorization: `Bot ${BOT_TOKEN}`, 'Content-Type': 'application/json' } });
          await axios.post(`https://discord.com/api/v10/channels/${dm.data.id}/messages`, { content: `<@${userId}> ⏰ Reminder: ${msg}` }, { headers: { Authorization: `Bot ${BOT_TOKEN}`, 'Content-Type': 'application/json' } });
        } catch {}
      }, delayMs);
      return;
    }
    if (payload.type === 2 && payload.data.name === 'time') {
      const loc = payload.data.options.find(o => o.name === 'location')?.value || 'UTC';
      let dt;
      try { dt = DateTime.now().setZone(loc); } catch { dt = null; }
      if (!dt || !dt.isValid) return res.json({ type: 4, data: { content: '❌ Invalid timezone. Please provide an IANA zone like `Europe/London`.' } });
      const formatted = dt.toFormat('DDD, t');
      return res.json({ type: 4, data: { content: `⏰ Current time in **${loc}**: \`${formatted}\`` } });
    }
    return res.sendStatus(400);
  } catch {
    return res.sendStatus(500);
  }
});

const mongoUrl = process.env.MONGO_URL;
mongoose.connect(mongoUrl, { useNewUrlParser: true, useUnifiedTopology: true }).then(() => { logger.info('Connected to MongoDB'); }).catch((err) => { logger.error(`Error connecting to MongoDB: ${err}`); process.exit(1); });

const GeoDataSchema = new mongoose.Schema({ ip: { type: String, required: true, unique: true }, city: { type: String, default: 'Unknown' }, region: { type: String, default: 'Unknown' }, country: { type: String, default: 'Unknown' }, timestamp: { type: Date, default: Date.now } });
const GeoData = mongoose.model('GeoData', GeoDataSchema, 'geodatas');

const userSchema = new mongoose.Schema({ discord_id: { type: String, required: true }, bungie_name: { type: String, required: true }, membership_id: { type: String, unique: true, required: true }, platform_type: { type: Number, required: true }, token: { type: String, unique: true }, registration_date: { type: Date, default: Date.now }, access_token: { type: String, required: true }, refresh_token: { type: String, required: true }, token_expiry: { type: Date, required: true } });
const User = mongoose.model('User', userSchema);

const pendingMemberSchema = new mongoose.Schema({ membershipId: { type: String, required: true }, displayName: { type: String, required: true }, joinDate: { type: Date, required: true } });
const PendingMember = mongoose.model('PendingMember', pendingMemberSchema);

const sessionSchema = new mongoose.Schema({ state: { type: String, required: true, unique: true }, user_id: { type: String, required: true }, session_id: { type: String, required: true }, created_at: { type: Date, default: Date.now, expires: 86400 }, ip_address: { type: String }, user_agent: { type: String } });
const Session = mongoose.model('Session', sessionSchema, 'sessions');

const commentSchema = new mongoose.Schema({ username: { type: String, required: true }, comment: { type: String, required: true }, timestamp: { type: Date, default: Date.now }, approved: { type: Boolean, default: true } });
const Comment = mongoose.model('Comment', commentSchema);

const sessionStore = MongoStore.create({ mongoUrl: mongoUrl, collectionName: 'sessions', ttl: 14 * 24 * 60 * 60, autoRemove: 'native' });
sessionStore.on('connected', () => { logger.info('Session store connected to MongoDB'); });
sessionStore.on('error', (error) => { logger.error(`Session store error: ${error}`); });

const adminSessionStore = MongoStore.create({ mongoUrl: process.env.MONGO_URL, collectionName: 'admin_sessions', ttl: 14 * 24 * 60 * 60 });

app.use(session({
  name: 'admin_session_cookie',
  secret: process.env.SESSION_SECRET || 'your-session-secret',
  resave: false,
  saveUninitialized: false,
  store: adminSessionStore,
  cookie: { secure: process.env.NODE_ENV === 'production', httpOnly: true, sameSite: 'strict', maxAge: 60 * 60 * 1000 }
}));

function generateRandomString(size = 16) { return crypto.randomBytes(size).toString('hex'); }
function convertISO8601ToSeconds(isoDuration) { const m = isoDuration.match(/PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?/); const h = parseInt(m[1] || 0, 10); const mi = parseInt(m[2] || 0, 10); const s = parseInt(m[3] || 0, 10); return h * 3600 + mi * 60 + s; }
function verifyToken(req, res, next) { const token = req.cookies.token; if (!token) return res.redirect('/auth'); jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => { if (err) return res.redirect('/auth'); req.userId = decoded.id; next(); }); }

async function getBungieToken(code) {
  const url = 'https://www.bungie.net/Platform/App/OAuth/Token/';
  const payload = new URLSearchParams({ grant_type: 'authorization_code', code, client_id: process.env.CLIENT_ID, client_secret: process.env.CLIENT_SECRET, redirect_uri: process.env.REDIRECT_URI || 'https://mikumiku.dev/callback' });
  const headers = { 'Content-Type': 'application/x-www-form-urlencoded', 'X-API-Key': process.env.X_API_KEY };
  const response = await axios.post(url, payload.toString(), { headers });
  return response.data;
}
async function refreshBungieToken(refreshToken) {
  const url = 'https://www.bungie.net/Platform/App/OAuth/Token/';
  const payload = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: refreshToken, client_id: process.env.CLIENT_ID, client_secret: process.env.CLIENT_SECRET });
  const headers = { 'Content-Type': 'application/x-www-form-urlencoded', 'X-API-Key': process.env.X_API_KEY };
  const response = await axios.post(url, payload.toString(), { headers });
  return response.data;
}
async function getBungieUserInfo(accessToken) {
  const url = 'https://www.bungie.net/Platform/User/GetMembershipsForCurrentUser/';
  const headers = { Authorization: `Bearer ${accessToken}`, 'X-API-Key': process.env.X_API_KEY, 'User-Agent': 'axios/0.21.4' };
  const response = await axios.get(url, { headers });
  return response.data;
}

const membershipFilePath = path.join(__dirname, 'membership_mapping.json');
function updateMembershipMapping(discordId, userInfo) {
  let mapping = {};
  if (fs.existsSync(membershipFilePath)) { try { mapping = JSON.parse(fs.readFileSync(membershipFilePath, 'utf8')); } catch { mapping = {}; } }
  mapping[discordId] = { membership_id: userInfo.membershipId, platform_type: userInfo.platformType, bungie_name: userInfo.bungieName, registration_date: new Date(), clan_id: '4900827' };
  fs.writeFileSync(membershipFilePath, JSON.stringify(mapping, null, 2), 'utf8');
}
async function sendUserInfoToDiscordBot(discordId, userInfo) {}

const IPINFO_API_KEY = process.env.IPINFO_API_KEY;
if (!IPINFO_API_KEY) { logger.error('IPINFO_API_KEY environment variable is not set.'); process.exit(1); }

const getClientIp = (req) => { const forwardedFor = req.headers['x-forwarded-for']; if (forwardedFor) return forwardedFor.split(',')[0].trim(); return req.connection.remoteAddress; };

async function getGeoLocation(ip) { try { return await getAccurateGeoLocation(ip); } catch { return { city: 'Unknown', region: 'Unknown', country: 'Unknown', ip }; } }
async function getAccurateGeoLocation(ip) {
  try {
    const ipInfoResponse = await axios.get(`https://ipinfo.io/${ip}/json?token=${IPINFO_API_KEY}`);
    const ipInfoData = ipInfoResponse.data;
    const maxMindApiKey = process.env.MAXMIND_API_KEY;
    let maxMindData = {};
    if (maxMindApiKey) { try { const resp = await axios.get(`https://geoip.maxmind.com/geoip/v2.1/city/${ip}`, { headers: { Authorization: `Bearer ${maxMindApiKey}` } }); maxMindData = resp.data; } catch {} }
    const location = { city: ipInfoData.city || (maxMindData.city && maxMindData.city.names.en) || 'Unknown', region: ipInfoData.region || (maxMindData.subdivisions && maxMindData.subdivisions[0].names.en) || 'Unknown', country: ipInfoData.country || (maxMindData.country && maxMindData.country.names.en) || 'Unknown', ip, loc: ipInfoData.loc || null };
    return location;
  } catch { return { city: 'Unknown', region: 'Unknown', country: 'Unknown', ip }; }
}

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5, message: 'Too many login attempts from this IP, please try again after 15 minutes' });

app.get('/login', async (req, res) => {
  const state = generateRandomString(16);
  const user_id = req.query.user_id;
  const ip_address = getClientIp(req);
  const user_agent = req.get('User-Agent');
  const sessionData = new Session({ state, user_id, session_id: req.session.id, ip_address, user_agent });
  try {
    await sessionData.save();
    const authorizeUrl = `https://www.bungie.net/en/OAuth/Authorize?client_id=${process.env.CLIENT_ID}&response_type=code&state=${state}&redirect_uri=${encodeURIComponent(process.env.REDIRECT_URI || 'https://mikumiku.dev/callback')}`;
    res.redirect(authorizeUrl);
  } catch {
    res.status(500).send('Internal Server Error');
  }
});

app.get('/callback', async (req, res) => {
  const state = req.query.state;
  const code = req.query.code;
  try {
    const sessionData = await Session.findOne({ state });
    if (!sessionData) return res.status(400).send('State mismatch. Potential CSRF attack.');
    const tokenData = await getBungieToken(code);
    if (!tokenData.access_token) throw new Error('Failed to obtain access token');
    const accessToken = tokenData.access_token;
    const refreshToken = tokenData.refresh_token;
    const expiresIn = tokenData.expires_in;
    const tokenExpiry = DateTime.now().plus({ seconds: expiresIn }).toJSDate();
    const userInfo = await getBungieUserInfo(accessToken);
    if (!userInfo.Response || !userInfo.Response.destinyMemberships) throw new Error('Failed to obtain user information');
    const bungieGlobalDisplayName = userInfo.Response.bungieNetUser.cachedBungieGlobalDisplayName;
    const bungieGlobalDisplayNameCode = userInfo.Response.bungieNetUser.cachedBungieGlobalDisplayNameCode.toString().padStart(4, '0');
    const bungieName = `${bungieGlobalDisplayName}#${bungieGlobalDisplayNameCode}`;
    let primaryMembership = userInfo.Response.destinyMemberships.find(m => m.membershipId === userInfo.Response.primaryMembershipId);
    if (!primaryMembership) primaryMembership = userInfo.Response.destinyMemberships[0];
    if (!primaryMembership) throw new Error('Failed to obtain platform-specific membership ID');
    const membershipId = primaryMembership.membershipId;
    const platformType = primaryMembership.membershipType;
    const discordId = sessionData.user_id;
    const user = await User.findOneAndUpdate({ membership_id: membershipId }, { discord_id: discordId, bungie_name: bungieName, platform_type: platformType, token: generateRandomString(16), registration_date: new Date(), access_token: accessToken, refresh_token: refreshToken, token_expiry: tokenExpiry }, { upsert: true, new: true });
    await sendUserInfoToDiscordBot(discordId, { bungieName, platformType, membershipId });
    updateMembershipMapping(discordId, { bungieName, platformType, membershipId });
    await Session.deleteOne({ state });
    res.redirect(`/confirmation.html?token=${user.token}`);
  } catch {
    res.status(500).send('Internal Server Error');
  }
});

app.get('/confirmation.html', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'confirmation.html')); });

app.get('/api/bungie-name', async (req, res) => {
  const token = req.query.token;
  try { const user = await User.findOne({ token }); if (!user) return res.status(400).send({ error: 'Invalid token' }); res.send({ bungie_name: user.bungie_name }); }
  catch { res.status(500).send({ error: 'Internal Server Error' }); }
});

app.post('/login', loginLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    const adminUsername = process.env.ADMIN_USERNAME;
    const adminPasswordHash = process.env.ADMIN_PASSWORD_HASH;
    if (username !== adminUsername) return res.status(401).json({ auth: false, message: 'Invalid username or password' });
    const isPasswordValid = await bcrypt.compare(password, adminPasswordHash);
    if (!isPasswordValid) return res.status(401).json({ auth: false, message: 'Invalid username or password' });
    const token = jwt.sign({ id: adminUsername }, process.env.JWT_SECRET || 'your-jwt-secret-key', { expiresIn: 86400 });
    res.cookie('token', token, { httpOnly: false, secure: process.env.NODE_ENV === 'production', sameSite: 'Lax', path: '/', maxAge: 86400 * 1000 });
    req.session.save((err) => { if (err) return res.status(500).json({ auth: false, message: 'Error saving session' }); res.status(200).json({ auth: true, redirect: '/admin' }); });
  } catch {
    res.status(500).json({ auth: false, message: 'Internal Server Error' });
  }
});

app.get('/auth', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'admin-login.html')); });

app.post('/logout', (req, res) => {
  req.session.destroy((err) => { if (err) return res.status(500).json({ message: 'Error logging out' });
    res.clearCookie('admin_session_cookie', { path: '/', httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict' });
    res.redirect('/auth');
  });
});

app.post('/api/comments', async (req, res) => {
  try { const { username, comment } = req.body; const newComment = new Comment({ username, comment }); await newComment.save(); res.status(201).send(newComment); }
  catch { res.status(500).send({ error: 'Error saving comment' }); }
});
app.get('/api/comments', async (req, res) => {
  try { const comments = await Comment.find({ approved: true }); res.json(comments); }
  catch { res.status(500).send({ error: 'Error fetching comments' }); }
});
app.delete('/api/comments/:id', verifyToken, async (req, res) => {
  try { const { id } = req.params; await Comment.findByIdAndDelete(id); res.status(200).send({ message: 'Comment deleted' }); }
  catch { res.status(500).send({ error: 'Error deleting comment' }); }
});

app.get('/admin', verifyToken, (req, res) => { res.sendFile(path.join(__dirname, 'public', 'admin-dashboard.html')); });
app.get('/admin-dashboard.html', (req, res) => { res.redirect('/admin'); });

app.use(express.static(path.join(__dirname, 'public'), { etag: false, maxAge: 0, lastModified: false, redirect: false }));

app.get('/fetch-location', async (req, res) => {
  const ip = getClientIp(req);
  try { const locationData = await getGeoLocation(ip); res.json(locationData); }
  catch { res.status(500).json({ error: 'Failed to fetch location data' }); }
});
app.get('/api/location/:ip', async (req, res) => {
  try { const ip = req.params.ip; const locationData = await getGeoLocation(ip); res.json({ ip, city: locationData.city, region: locationData.region, country: locationData.country }); }
  catch { res.status(500).json({ error: 'Failed to fetch geolocation data' }); }
});

app.post('/track-visitor', async (req, res) => {
  const ip = getClientIp(req);
  try {
    const loc = await getGeoLocation(ip);
    const city = loc.city || 'Unknown';
    const region = loc.region || 'Unknown';
    const country = loc.country || 'Unknown';
    await GeoData.updateOne({ ip }, { $set: { city, region, country }, $setOnInsert: { timestamp: new Date() } }, { upsert: true });
    const byCountry = await GeoData.aggregate([{ $group: { _id: "$country", count: { $sum: 1 } } }, { $sort: { count: -1 } }]);
    io.emit("geoDataUpdate", byCountry);
    if (loc && loc.loc) {
      const [latitude, longitude] = loc.loc.split(',');
      io.emit("visitorLocation", { id: ip, latitude: parseFloat(latitude), longitude: parseFloat(longitude), info: `${city}, ${country}` });
    }
    res.status(200).json({ success: true });
  } catch (err) {
    logger.error(`track-visitor failed for ${ip}: ${err.message}`);
    res.status(500).json({ success: false });
  }
});

const ipBanSchema = new mongoose.Schema({ ip: { type: String, required: true, unique: true }, blockedAt: { type: Date, default: Date.now } });
const IPbans = mongoose.model('IPbans', ipBanSchema);

const HEARTBEAT_TIMEOUT = 60000;
const blockedIps = new Set();
let currentVideo = null;
let currentBrowsing = null;
const videoHeartbeat = {};
const activeUsers = new Map();

function emitCurrentPresence(socket) { if (currentVideo) socket.emit('presenceUpdate', { presenceType: 'video', ...currentVideo }); else if (currentBrowsing) socket.emit('presenceUpdate', { presenceType: 'browsing', ...currentBrowsing }); else socket.emit('presenceUpdate', { presenceType: 'offline' }); }
function handleBrowsingPresence(data) { currentVideo = null; currentBrowsing = { title: data.title || 'YouTube', description: data.description || 'Browsing videos', thumbnail: data.thumbnail || 'https://www.youtube.com/img/desktop/yt_1200.png', timeElapsed: data.timeElapsed || 0 }; }
function handleVideoPresence(data) { const presence = { videoId: data.videoId, title: data.title, description: data.description, channelTitle: data.channelTitle, viewCount: data.viewCount, likeCount: data.likeCount, publishedAt: data.publishedAt, category: data.category, thumbnail: data.thumbnail, currentTime: data.currentTime, duration: data.duration, isPaused: data.isPaused, isLive: data.isLive }; if (currentVideo?.videoId === data.videoId) Object.assign(currentVideo, presence); else { currentVideo = presence; currentBrowsing = null; } }
function handleOfflinePresence() { currentVideo = null; currentBrowsing = null; }

setInterval(() => {
  const now = Date.now();
  for (const [videoId, ts] of Object.entries(videoHeartbeat)) {
    if (now - ts > HEARTBEAT_TIMEOUT) { delete videoHeartbeat[videoId]; currentVideo = null; currentBrowsing = null; io.emit('presenceUpdate', { presenceType: 'offline' }); break; }
  }
}, HEARTBEAT_TIMEOUT / 2);

let lastHeartbeat = 0;
let latestBotInfo = { status: 'offline', uptime: 'N/A', latency: 'N/A', memoryUsage: 'N/A', botName: 'N/A' };
let lastBotStatusUpdate = Date.now();
let smsSent = false;
let highLatencyAlertSent = false;
const OFFLINE_TIMEOUT = 90000;
const HIGH_LATENCY_THRESHOLD = 100;

const dbName = process.env.MONGO_DB_NAME || 'myfirstdatabase';
const client = new MongoClient(process.env.MONGO_URL, { useUnifiedTopology: true });
let timelineCollection;
let configCollection;

async function connectToMongo() {
  try {
    await client.connect();
    const db = client.db(dbName);
    configCollection = db.collection('config');
    timelineCollection = db.collection('timeline');
    let toggleDoc = await configCollection.findOne({ _id: 'toggle' });
    if (!toggleDoc) { toggleDoc = { _id: 'toggle', commands_enabled: true }; await configCollection.insertOne(toggleDoc); }
  } catch (err) { console.error('Error connecting to MongoDB:', err); }
}
connectToMongo();

app.get('/api/timeline', async (req, res) => { try { const entries = await timelineCollection.find().sort({ rawTimestamp: 1 }).toArray(); res.json(entries); } catch (err) { res.status(500).json({ error: err.message }); } });
app.post('/api/timeline', async (req, res) => { try { const update = req.body; const lastEntryArray = await timelineCollection.find().sort({ rawTimestamp: -1 }).limit(1).toArray(); if (lastEntryArray.length > 0) { const lastEntry = lastEntryArray[0]; const lastMinute = Math.floor(lastEntry.rawTimestamp / 60000); const newMinute = Math.floor(update.rawTimestamp / 60000); if (lastMinute === newMinute) return res.json({ status: 'duplicate' }); } await timelineCollection.insertOne(update); const count = await timelineCollection.countDocuments(); const MAX_MINUTES = 60; if (count > MAX_MINUTES) { const excess = count - MAX_MINUTES; const oldest = await timelineCollection.find().sort({ rawTimestamp: 1 }).limit(excess).toArray(); const ids = oldest.map(e => e._id); await timelineCollection.deleteMany({ _id: { $in: ids } }); } res.json({ status: 'ok' }); } catch (err) { res.status(500).json({ error: err.message }); } });
app.get('/api/toggle', async (req, res) => { try { const toggleDoc = await configCollection.findOne({ _id: 'toggle' }); res.json(toggleDoc); } catch (err) { res.status(500).json({ error: err.message }); } });
app.post('/api/toggle', async (req, res) => { try { const data = req.body; if (typeof data.commands_enabled === 'undefined') return res.status(400).json({ status: 'error', message: "Missing 'commands_enabled' property." }); await configCollection.updateOne({ _id: 'toggle' }, { $set: { commands_enabled: data.commands_enabled } }); const toggleDoc = await configCollection.findOne({ _id: 'toggle' }); res.json({ status: 'success', commands_enabled: toggleDoc.commands_enabled }); } catch (err) { res.status(500).json({ status: 'error', message: 'Could not update configuration.' }); } });

function sendSMSAlert(message) {
  const smsData = { messages: [{ source: 'nodejs', from: process.env.SMS_SENDER, to: process.env.TO_PHONE_NUMBER, body: message }] };
  const auth = { username: process.env.CLICKSEND_USERNAME, password: process.env.CLICKSEND_API_KEY };
  axios.post('https://rest.clicksend.com/v3/sms/send', smsData, { auth }).then(() => {}).catch(() => {});
}

setInterval(() => {
  const elapsed = Date.now() - lastBotStatusUpdate;
  if (elapsed > OFFLINE_TIMEOUT) { if (!smsSent) { sendSMSAlert('Alert: The bot is offline!'); smsSent = true; } }
}, 5000);

app.get('/api/geo-data', async (req, res) => { try { const countryData = await GeoData.aggregate([{ $group: { _id: "$country", count: { $sum: 1 } } }, { $sort: { count: -1 } }]); res.json(countryData); } catch { res.status(500).json({ error: 'Error fetching geo data' }); } });
app.get('/api/geo-data/refresh', async (req, res) => { try { const agg = await GeoData.aggregate([{ $group: { _id: "$country", count: { $sum: 1 } } }, { $sort: { count: -1 } }]); io.emit('geoDataUpdate', agg); res.json({ ok: true }); } catch { res.status(500).json({ ok: false }); } });

app.get('/api/videos/public', async (req, res) => { try { res.json([]); } catch { res.status(500).send({ error: 'Error retrieving video metadata' }); } });
app.post('/api/videos', verifyToken, [body('url').isURL().withMessage('Invalid URL format'), body('title').isString().notEmpty().withMessage('Title is required'), body('description').isString().optional(), body('category').isString().notEmpty().withMessage('Category is required')], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  const sanitizedUrl = req.body.url.replace('youtu.be', 'youtube.com/embed');
  const videoMetadata = { url: sanitizedUrl, title: req.body.title, description: req.body.description ? req.body.description : '', category: req.body.category, uploadedAt: new Date() };
  try { logger.info(`New video added: ${JSON.stringify(videoMetadata)}`); res.status(201).json({ message: 'Video added successfully', video: videoMetadata }); }
  catch { res.status(500).json({ error: 'Error saving video metadata' }); }
});

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const sessions = {};
const openAICallLimiter = rateLimit({ windowMs: 60 * 1000, max: 60, message: { error: 'Too many requests, please try again later.' }, standardHeaders: true, legacyHeaders: false });

async function makeOpenAIRequest(messages, retries = 3, backoff = 1000) {
  try { const response = await openai.createChatCompletion({ model: 'gpt-3.5-turbo', messages, temperature: 0.7, max_tokens: 150 }); return response.data.choices[0].message.content.trim(); }
  catch (error) { if (error.response && error.response.status === 429 && retries > 0) { await new Promise(r => setTimeout(r, backoff)); return makeOpenAIRequest(messages, retries - 1, backoff * 2); } else { throw error; } }
}

app.post('/api/openai-chat', openAICallLimiter, async (req, res) => {
  const { message, sessionId } = req.body;
  if (!message || !sessionId) return res.status(400).json({ error: 'Message and sessionId are required.' });
  if (!sessions[sessionId]) sessions[sessionId] = [{ role: 'system', content: 'You are Haru AI, a helpful assistant.' }];
  sessions[sessionId].push({ role: 'user', content: message });
  try { const botResponse = await makeOpenAIRequest(sessions[sessionId]); sessions[sessionId].push({ role: 'assistant', content: botResponse }); res.json({ response: botResponse }); }
  catch (error) { if (error.response && error.response.status === 429) res.status(429).json({ error: 'Too many requests. Please try again later.' }); else res.status(500).json({ error: 'An error occurred while processing your request.' }); }
});

app.get('/aria-status', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'aria-status.html')); });

app.get('/status-proxy', async (req, res) => {
  try { const response = await fetch('https://us-nyc-02.wisp.uno:8282/status'); const data = await response.json(); res.json(data); }
  catch { res.status(500).json({ status: 'offline' }); }
});

app.use(async (req, res, next) => {
  try {
    if (!req.cookies.vtracked) {
      const ip = getClientIp(req);
      const loc = await getGeoLocation(ip);
      await GeoData.updateOne({ ip }, { $set: { city: loc.city || 'Unknown', region: loc.region || 'Unknown', country: loc.country || 'Unknown', timestamp: new Date() } }, { upsert: true });
      res.cookie('vtracked', '1', { maxAge: 12 * 60 * 60 * 1000, sameSite: 'Lax' });
      const agg = await GeoData.aggregate([{ $group: { _id: "$country", count: { $sum: 1 } } }, { $sort: { count: -1 } }]);
      io.emit('geoDataUpdate', agg);
    }
  } catch {}
  next();
});

const ORIGIN = "http://us-nyc-02.wisp.uno:8282";

app.use("/oauth", createProxyMiddleware({
  target: ORIGIN,
  changeOrigin: true,
  xfwd: true,
  secure: false,
  ws: true,
  proxyTimeout: 45000,
  timeout: 45000,
  onProxyReq(proxyReq, req, res) {
    if (!req.body || !Object.keys(req.body).length) return;
    const ct = proxyReq.getHeader('Content-Type') || '';
    let bodyData;
    if (ct.includes('application/json')) {
      bodyData = JSON.stringify(req.body);
    } else if (ct.includes('application/x-www-form-urlencoded')) {
      bodyData = new URLSearchParams(req.body).toString();
    }
    if (bodyData) {
      proxyReq.setHeader('Content-Length', Buffer.byteLength(bodyData));
      proxyReq.write(bodyData);
    }
  }
}));

app.use("/notify-ready", createProxyMiddleware({
  target: ORIGIN,
  changeOrigin: true,
  xfwd: true,
  secure: false,
  proxyTimeout: 45000,
  timeout: 45000,
  onProxyReq(proxyReq, req, res) {
    if (!req.body || !Object.keys(req.body).length) return;
    const ct = proxyReq.getHeader('Content-Type') || '';
    let bodyData;
    if (ct.includes('application/json')) {
      bodyData = JSON.stringify(req.body);
    } else if (ct.includes('application/x-www-form-urlencoded')) {
      bodyData = new URLSearchParams(req.body).toString();
    }
    if (bodyData) {
      proxyReq.setHeader('Content-Length', Buffer.byteLength(bodyData));
      proxyReq.write(bodyData);
    }
  }
}));

app.use("/notify-status", createProxyMiddleware({
  target: ORIGIN,
  changeOrigin: true,
  xfwd: true,
  secure: false,
  proxyTimeout: 45000,
  timeout: 45000
}));

app.get("/health", (_req, res) => res.json({ ok: true }));

io.on('connection', socket => {
  const ip = socket.handshake.headers['x-forwarded-for']?.split(',')[0].trim() || socket.handshake.address;
  const type = socket.handshake.query.connectionType || 'website';
  if (blockedIps.has(ip)) return socket.disconnect(true);
  if (!activeUsers.has(ip)) activeUsers.set(ip, { connectionTypes: new Set() });
  activeUsers.get(ip).connectionTypes.add(type);
  socket.broadcast.emit('activeUsersUpdate', { users: Array.from(activeUsers.entries()).map(([k, v]) => ({ ip: k, connectionTypes: Array.from(v.connectionTypes) })) });
  emitCurrentPresence(socket);
  socket.emit('botStatusUpdate', latestBotInfo);
  socket.on('presenceUpdate', data => { switch (data.presenceType) { case 'video': handleVideoPresence(data); break; case 'browsing': handleBrowsingPresence(data); break; case 'offline': handleOfflinePresence(); break; } socket.broadcast.emit('presenceUpdate', data); });
  socket.on('updateBrowsingPresence', data => { handleBrowsingPresence(data); socket.broadcast.emit('presenceUpdate', { presenceType: 'browsing', ...currentBrowsing }); });
  socket.on('updateVideoProgress', data => { handleVideoPresence(data); socket.broadcast.emit('presenceUpdate', { presenceType: 'video', ...currentVideo }); });
  socket.on('heartbeat', (data, ack) => { const { videoId } = data; if (currentVideo?.videoId === videoId) { videoHeartbeat[videoId] = Date.now(); if (ack) ack({ status: 'ok' }); } else if (ack) ack({ status: 'error', message: 'Unknown video ID' }); });
  socket.on('getToggleState', async () => { if (!configCollection) return socket.emit('toggleState', { commands_enabled: true }); try { const toggleDoc = await configCollection.findOne({ _id: 'toggle' }); socket.emit('toggleState', toggleDoc); } catch { socket.emit('toggleState', { commands_enabled: true }); } });
  socket.on('toggleCommands', async (data) => { if (typeof data.commands_enabled === 'undefined') return socket.emit('toggleResponse', { status: 'error', message: "Missing 'commands_enabled' property." }); if (!configCollection) return socket.emit('toggleResponse', { status: 'error', message: 'Database not connected.' }); try { await configCollection.updateOne({ _id: 'toggle' }, { $set: { commands_enabled: data.commands_enabled } }); const toggleDoc = await configCollection.findOne({ _id: 'toggle' }); socket.emit('toggleResponse', { status: 'success', commands_enabled: toggleDoc.commands_enabled }); socket.broadcast.emit('toggleUpdated', { commands_enabled: toggleDoc.commands_enabled }); } catch { socket.emit('toggleResponse', { status: 'error', message: 'Could not update configuration.' }); } });
  socket.on('botHeartbeat', (data) => { const status = (data.status || '').toLowerCase().trim(); lastHeartbeat = Date.now(); latestBotInfo = { status: 'online', uptime: data.uptime, latency: data.latency, memoryUsage: data.memoryUsage, botName: data.botName }; io.emit('botStatusUpdate', latestBotInfo); lastBotStatusUpdate = Date.now(); if (status === 'online') { smsSent = false; const latency = parseInt(data.latency); if (latency > HIGH_LATENCY_THRESHOLD && !highLatencyAlertSent) { sendSMSAlert('Alert: The bot is experiencing high latency!'); highLatencyAlertSent = true; } else if (latency <= HIGH_LATENCY_THRESHOLD) { highLatencyAlertSent = false; } } });
  socket.on('blockUser', async (payload, ack) => { try { const r = await fetch('http://localhost:' + PORT + '/api/block-user', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ip: payload.ip }) }); const j = await r.json(); if (ack) ack(j); } catch { if (ack) ack({ status: 'error', message: 'Request failed' }); } });
  socket.on('unblockUser', async (payload, ack) => { try { const r = await fetch('http://localhost:' + PORT + '/api/unblock-user', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ip: payload.ip }) }); const j = await r.json(); if (ack) ack(j); } catch { if (ack) ack({ status: 'error', message: 'Request failed' }); } });
  socket.on('disconnect', () => { const user = activeUsers.get(ip); if (user) { user.connectionTypes.delete(type); if (user.connectionTypes.size === 0) activeUsers.delete(ip); } socket.broadcast.emit('activeUsersUpdate', { users: Array.from(activeUsers.entries()).map(([k, v]) => ({ ip: k, connectionTypes: Array.from(v.connectionTypes) })) }); });
});

server.listen(PORT, () => { logger.info(`Server is running on port ${PORT}`); });
