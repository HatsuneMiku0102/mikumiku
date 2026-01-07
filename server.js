'use strict';

const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
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

const DISCORD_PUBLIC_KEY = process.env.DISCORD_PUBLIC_KEY || '';
const OPENWEATHER_API_KEY = process.env.OPENWEATHER_API_KEY || '';
const BOT_TOKEN = process.env.BOT_TOKEN || '';
const PORT = process.env.PORT || 3000;

const IMAGE_API_TARGET = (process.env.IMAGE_API_TARGET || 'https://image-host-bde701503cb6.herokuapp.com').trim();
const IMAGE_API_KEY = (process.env.IMAGE_API_KEY || '').trim();

const IMAGE_HOST_ADMIN_TARGET = (process.env.IMAGE_HOST_ADMIN_TARGET || '').trim();
const IMAGE_HOST_ADMIN_SECRET = (process.env.IMAGE_HOST_ADMIN_SECRET || '').trim();

const ORIGIN = process.env.PROXY_ORIGIN || 'http://us-nyc-02.wisp.uno:8282';

const JWT_SECRET = (process.env.JWT_SECRET || '').trim();
if (!JWT_SECRET) {
  console.error('JWT_SECRET is not set.');
  process.exit(1);
}

const mongoUrl = process.env.MONGO_URL;
if (!mongoUrl) {
  console.error('MONGO_URL is not set.');
  process.exit(1);
}

const app = express();
app.set('trust proxy', true);

const server = http.createServer(app);
const io = socketIo(server, { cors: { origin: true, methods: ['GET', 'POST'], allowedHeaders: ['*'], credentials: true } });

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(({ timestamp, level, message }) => `${timestamp} [${level.toUpperCase()}]: ${message}`)
  ),
  transports: [new winston.transports.Console(), new winston.transports.File({ filename: 'server.log' })]
});

app.use(cors({
  origin: true,
  methods: ['GET', 'POST', 'OPTIONS', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'x-admin-secret', 'X-Admin-Secret'],
  credentials: true
}));

app.use(express.json({
  verify: (req, _res, buf) => {
    if (req.path === '/interactions') req.rawBody = buf.toString();
  }
}));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: [
      "'self'",
      "'unsafe-inline'",
      'https://fonts.googleapis.com',
      'https://cdnjs.cloudflare.com',
      'https://www.youtube.com',
      'https://www.youtube-nocookie.com',
      'https://unpkg.com',
      'https://cdn.jsdelivr.net',
      'https://cdn.skypack.dev',
      'https://cdn.socket.io',
      'https://api.mapbox.com'
    ],
    styleSrc: [
      "'self'",
      "'unsafe-inline'",
      'https://fonts.googleapis.com',
      'https://cdnjs.cloudflare.com',
      'https://api.mapbox.com'
    ],
    imgSrc: [
      "'self'",
      'blob:',
      'data:',
      'https://i.ytimg.com',
      'https://img.youtube.com',
      'https://ytimg.com',
      'https://openweathermap.org',
      'https://i.postimg.cc',
      'https://threejs.org',
      'https://www.youtube.com',
      'https://www.youtube-nocookie.com',
      'https://raw.githubusercontent.com',
      'https://api.tiles.mapbox.com',
      'https://*.tiles.mapbox.com',
      'https://raider.io',
      'https://render.worldofwarcraft.com',
      'https://images.mikumiku.dev'
    ],
    fontSrc: [
      "'self'",
      'https://fonts.gstatic.com',
      'https://cdnjs.cloudflare.com'
    ],
    connectSrc: [
      "'self'",
      'blob:',
      'https://www.googleapis.com',
      'https://*.youtube.com',
      'https://www.youtube-nocookie.com',
      'https://*.ytimg.com',
      'https://api.openweathermap.org',
      'https://cdn.socket.io',
      'https://cdnjs.cloudflare.com',
      'https://cdn.jsdelivr.net',
      'https://mikumiku.dev',
      'https://api.mapbox.com',
      'https://events.mapbox.com',
      'https://mikumikudev-c530e6b3e669.herokuapp.com',
      'https://raider.io',
      'https://oauth.battle.net',
      'https://*.api.blizzard.com',
      'https://images.mikumiku.dev'
    ],
    frameSrc: [
      "'self'",
      'https://discord.com',
      'https://www.youtube.com',
      'https://www.youtube-nocookie.com'
    ],
    mediaSrc: [
      "'self'",
      'https://www.youtube.com',
      'https://www.youtube-nocookie.com'
    ],
    frameAncestors: [
      "'self'",
      'https://discord.com'
    ],
    workerSrc: [
      "'self'",
      'blob:'
    ],
    upgradeInsecureRequests: []
  }
}));

mongoose.connect(mongoUrl)
  .then(() => { logger.info('Connected to MongoDB'); })
  .catch((err) => { logger.error(`Error connecting to MongoDB: ${err}`); process.exit(1); });

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, minlength: 3, maxlength: 32 },
  passwordHash: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }

  const userApiKeySchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
  keyId: { type: String, required: true },
  apiKey: { type: String, required: true },
  name: { type: String, default: 'user' },
  scopes: { type: String, default: 'upload,fetch' },
  ratePerMinute: { type: Number, default: 30 },
  createdAt: { type: Date, default: Date.now }
})
userApiKeySchema.index({ userId: 1, keyId: 1 }, { unique: true })
const UserApiKey = mongoose.model('UserApiKey', userApiKeySchema, 'user_api_keys')

const userSettingsSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, required: true, unique: true },
  activeKeyId: { type: String, default: '' },
  updatedAt: { type: Date, default: Date.now }
})
const UserSettings = mongoose.model('UserSettings', userSettingsSchema, 'user_settings')

});
const User = mongoose.model('User', userSchema, 'users');

const GeoDataSchema = new mongoose.Schema({
  ip: { type: String, required: true, unique: true },
  city: { type: String, default: 'Unknown' },
  region: { type: String, default: 'Unknown' },
  country: { type: String, default: 'Unknown' },
  timestamp: { type: Date, default: Date.now }
});
const GeoData = mongoose.model('GeoData', GeoDataSchema, 'geodatas');

const sessionSchema = new mongoose.Schema({
  state: { type: String, required: true, unique: true },
  user_id: { type: String, required: true },
  session_id: { type: String, required: true },
  created_at: { type: Date, default: Date.now, expires: 86400 },
  ip_address: { type: String },
  user_agent: { type: String }
});
mongoose.model('Session', sessionSchema, 'sessions');

const sessionStore = MongoStore.create({
  mongoUrl,
  collectionName: 'sessions',
  ttl: 14 * 24 * 60 * 60,
  autoRemove: 'native'
});

sessionStore.on('connected', () => { logger.info('Session store connected to MongoDB'); });
sessionStore.on('error', (error) => { logger.error(`Session store error: ${error}`); });

const adminSessionStore = MongoStore.create({
  mongoUrl,
  collectionName: 'admin_sessions',
  ttl: 14 * 24 * 60 * 60
});

app.use(session({
  name: 'admin_session_cookie',
  secret: process.env.SESSION_SECRET || 'your-session-secret',
  resave: false,
  saveUninitialized: false,
  store: adminSessionStore,
  cookie: { secure: process.env.NODE_ENV === 'production', httpOnly: true, sameSite: 'strict', maxAge: 60 * 60 * 1000 }
}));

function signAuthToken(payload) {
  const secret = String(process.env.JWT_SECRET || '').trim()
  if (!secret) throw new Error('JWT_SECRET is not set')
  return jwt.sign(payload, secret, { expiresIn: '7d' })
}

function readJwt(req) {
  const token = req.cookies.token;
  if (!token) return null;
  try { return jwt.verify(token, JWT_SECRET); } catch { return null; }
}

function verifyTokenApi(req, res, next) {
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  const decoded = readJwt(req);
  if (!decoded) return res.status(401).json({ error: 'Unauthorized' });
  req.auth = decoded;
  next();
}

function verifyTokenPage(redirectTo) {
  return (req, res, next) => {
    const decoded = readJwt(req);
    if (!decoded) return res.redirect(redirectTo);
    req.auth = decoded;
    next();
  };
}

function requireAdminApi(req, res, next) {
  if (!req.auth || req.auth.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  next();
}

function requireAdminPage(req, res, next) {
  if (!req.auth || req.auth.role !== 'admin') return res.redirect('/auth');
  next();
}

function requireUserApi(req, res, next) {
  if (!req.auth || (req.auth.role !== 'user' && req.auth.role !== 'admin')) return res.status(403).json({ error: 'Forbidden' });
  next();
}

function requireUserPage(req, res, next) {
  const token = req.cookies.token
  if (!token) return res.redirect('/auth')
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err || !decoded || (decoded.role !== 'user' && decoded.role !== 'admin')) return res.redirect('/auth')
    req.auth = decoded
    next()
  })
}

async function getActiveUserKey(userId) {
  const settings = await UserSettings.findOne({ userId })
  if (!settings?.activeKeyId) return null
  return UserApiKey.findOne({ userId, keyId: settings.activeKeyId })
}


app.get('/user/signup', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'user-signup.html')));
app.get('/user/auth', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'user-login.html')));

app.post('/user/register', async (req, res) => {
  try {
    const username = String(req.body?.username || '').trim()
    const password = String(req.body?.password || '')

    if (username.length < 3 || username.length > 32) return res.status(400).json({ error: 'Invalid username' })
    if (password.length < 8) return res.status(400).json({ error: 'Password too short' })

    const exists = await User.findOne({ username })
    if (exists) return res.status(409).json({ error: 'Username already taken' })

    const passwordHash = await bcrypt.hash(password, 12)
    const u = await User.create({ username, passwordHash })

    const token = signAuthToken({ role: 'user', userId: String(u._id), username: u.username })
    res.cookie('token', token, { httpOnly: false, secure: process.env.NODE_ENV === 'production', sameSite: 'Lax', path: '/', maxAge: 7 * 86400 * 1000 })
    res.json({ ok: true, redirect: '/image-host/' })
  } catch (err) {
    logger.error(`user/register failed: ${err?.message || err}`)
    res.status(500).json({ error: 'Internal Server Error' })
  }
})

app.post('/user/login', async (req, res) => {
  try {
    const username = String(req.body?.username || '').trim()
    const password = String(req.body?.password || '')

    const u = await User.findOne({ username })
    if (!u) return res.status(401).json({ error: 'Invalid credentials' })

    const ok = await bcrypt.compare(password, u.passwordHash)
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' })

    const token = signAuthToken({ role: 'user', userId: String(u._id), username: u.username })
    res.cookie('token', token, { httpOnly: false, secure: process.env.NODE_ENV === 'production', sameSite: 'Lax', path: '/', maxAge: 7 * 86400 * 1000 })
    res.json({ ok: true, redirect: '/image-host/' })
  } catch (err) {
    logger.error(`user/login failed: ${err?.message || err}`)
    res.status(500).json({ error: 'Internal Server Error' })
  }
})

app.post('/user/logout', (_req, res) => {
  res.cookie('token', '', { httpOnly: false, secure: process.env.NODE_ENV === 'production', sameSite: 'Lax', path: '/', expires: new Date(0) });
  res.json({ ok: true });
});

const IPINFO_API_KEY = process.env.IPINFO_API_KEY;
if (!IPINFO_API_KEY) {
  logger.error('IPINFO_API_KEY environment variable is not set.');
  process.exit(1);
}

const getClientIp = (req) => {
  const forwardedFor = req.headers['x-forwarded-for'];
  if (forwardedFor) return String(forwardedFor).split(',')[0].trim();
  return req.connection.remoteAddress;
};

async function getGeoLocation(ip) {
  try {
    const ipInfoResponse = await axios.get(`https://ipinfo.io/${ip}/json?token=${IPINFO_API_KEY}`);
    const ipInfoData = ipInfoResponse.data;
    return {
      city: ipInfoData.city || 'Unknown',
      region: ipInfoData.region || 'Unknown',
      country: ipInfoData.country || 'Unknown',
      ip,
      loc: ipInfoData.loc || null
    };
  } catch {
    return { city: 'Unknown', region: 'Unknown', country: 'Unknown', ip, loc: null };
  }
}

app.options('/image-api/*', (_req, res) => res.sendStatus(204));

const imageApiProxy = createProxyMiddleware({
  target: IMAGE_API_TARGET,
  changeOrigin: true,
  secure: true,
  xfwd: true,
  proxyTimeout: 60000,
  timeout: 60000,
  pathRewrite: { '^/image-api': '' },
  onProxyReq: (proxyReq) => {
    if (!IMAGE_API_KEY) throw new Error('IMAGE_API_KEY is not set on Node server');
    proxyReq.setHeader('Authorization', `Bearer ${String(IMAGE_API_KEY).trim()}`);
  },
  onError: (_err, _req, res) => {
    res.status(502).json({ detail: 'Image API proxy error' });
  }
});

app.use('/image-api', verifyTokenApi, requireUserApi, imageApiProxy);

app.get('/api/user/me', verifyTokenApi, requireUser, (req, res) => {
  res.json({ userId: req.auth.userId, username: req.auth.username, role: req.auth.role })
})

app.get('/api/user/keys', verifyTokenApi, requireUser, async (req, res) => {
  try {
    const userId = new mongoose.Types.ObjectId(String(req.auth.userId))
    const keys = await UserApiKey.find({ userId }).sort({ createdAt: -1 }).limit(25).lean()
    const settings = await UserSettings.findOne({ userId }).lean()
    res.json({
      activeKeyId: settings?.activeKeyId || '',
      keys: keys.map(k => ({ keyId: k.keyId, name: k.name, scopes: k.scopes, ratePerMinute: k.ratePerMinute, createdAt: k.createdAt, apiKey: k.apiKey }))
    })
  } catch (err) {
    res.status(500).json({ error: String(err?.message || err) })
  }
})

app.post('/api/user/keys/create', verifyTokenApi, requireUser, async (req, res) => {
  try {
    if (!IMAGE_HOST_ADMIN_TARGET) return res.status(500).json({ error: 'IMAGE_HOST_ADMIN_TARGET not set' })
    if (!IMAGE_HOST_ADMIN_SECRET) return res.status(500).json({ error: 'IMAGE_HOST_ADMIN_SECRET not set' })

    const target = IMAGE_HOST_ADMIN_TARGET.replace(/\/$/, '')
    const name = String(req.body?.name || req.auth.username || 'user').slice(0, 64)
    const scopes = String(req.body?.scopes || 'upload,fetch')
    const rpm = Number.isFinite(Number(req.body?.rate_per_minute)) ? parseInt(req.body.rate_per_minute, 10) : 30

    const body = new URLSearchParams()
    body.set('name', name)
    body.set('scopes', scopes)
    body.set('rate_per_minute', String(rpm))
    body.set('never_expires', '1')
    body.set('user_id', String(req.auth.userId))

    const resp = await axios.post(
      `${target}/admin/keys/create`,
      body.toString(),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'x-admin-secret': String(IMAGE_HOST_ADMIN_SECRET).trim() } }
    )

    const keyId = String(resp.data?.key_id || '')
    const apiKey = String(resp.data?.api_key || '')
    if (!keyId || !apiKey) return res.status(500).json({ error: 'Upstream did not return key_id/api_key' })

    const userId = new mongoose.Types.ObjectId(String(req.auth.userId))

    await UserApiKey.updateOne(
      { userId, keyId },
      { $set: { apiKey, name, scopes, ratePerMinute: rpm } },
      { upsert: true }
    )

    await UserSettings.updateOne(
      { userId },
      { $setOnInsert: { userId }, $set: { activeKeyId: keyId, updatedAt: new Date() } },
      { upsert: true }
    )

    res.json({ keyId, apiKey, active: true, imageHost: target })
  } catch (err) {
    res.status(err?.response?.status || 500).json({ error: err?.response?.data || String(err?.message || err) })
  }
})

app.post('/api/user/keys/activate', verifyTokenApi, requireUser, async (req, res) => {
  try {
    const keyId = String(req.body?.keyId || '').trim()
    if (!keyId) return res.status(400).json({ error: 'Missing keyId' })

    const userId = new mongoose.Types.ObjectId(String(req.auth.userId))
    const exists = await UserApiKey.findOne({ userId, keyId })
    if (!exists) return res.status(404).json({ error: 'Key not found' })

    await UserSettings.updateOne(
      { userId },
      { $setOnInsert: { userId }, $set: { activeKeyId: keyId, updatedAt: new Date() } },
      { upsert: true }
    )

    res.json({ ok: true, activeKeyId: keyId })
  } catch (err) {
    res.status(500).json({ error: String(err?.message || err) })
  }
})

const userImageApiProxy = createProxyMiddleware({
  target: IMAGE_API_TARGET,
  changeOrigin: true,
  secure: true,
  xfwd: true,
  proxyTimeout: 60000,
  timeout: 60000,
  pathRewrite: { '^/user-image-api': '' },
  onProxyReq: async (proxyReq, req) => {
    const token = req.cookies.token
    if (!token) throw new Error('No auth token')

    const decoded = jwt.verify(token, process.env.JWT_SECRET)
    if (!decoded || (decoded.role !== 'user' && decoded.role !== 'admin')) throw new Error('Forbidden')

    const userId = new mongoose.Types.ObjectId(String(decoded.userId))
    const activeKey = await getActiveUserKey(userId)
    if (!activeKey?.apiKey) throw new Error('No active API key')

    proxyReq.setHeader('Authorization', `Bearer ${String(activeKey.apiKey).trim()}`)
  },
  onError: (_err, _req, res) => {
    res.status(502).json({ error: 'User image proxy error' })
  }
})

app.use('/user-image-api', userImageApiProxy)


app.post('/api/image-host/keys/create', verifyTokenApi, requireAdminApi, async (req, res) => {
  try {
    if (!IMAGE_HOST_ADMIN_TARGET) return res.status(500).json({ error: 'IMAGE_HOST_ADMIN_TARGET not set' });
    if (!IMAGE_HOST_ADMIN_SECRET) return res.status(500).json({ error: 'IMAGE_HOST_ADMIN_SECRET not set' });

    const target = IMAGE_HOST_ADMIN_TARGET.replace(/\/$/, '');
    const name = String(req.body?.name || 'user').slice(0, 64);
    const scopes = String(req.body?.scopes || 'upload,fetch');
    const rpm = Number.isFinite(Number(req.body?.rate_per_minute)) ? String(parseInt(req.body.rate_per_minute, 10)) : '30';
    const never = req.body?.never_expires ? '1' : '1';

    const bodyParams = new URLSearchParams();
    bodyParams.set('name', name);
    bodyParams.set('scopes', scopes);
    bodyParams.set('rate_per_minute', rpm);
    bodyParams.set('never_expires', never);

    const resp = await axios.post(
      `${target}/admin/keys/create`,
      bodyParams.toString(),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'x-admin-secret': String(IMAGE_HOST_ADMIN_SECRET).trim() } }
    );

    res.json({ ...resp.data, image_host: target });
  } catch (err) {
    res.status(err?.response?.status || 500).json({ error: err?.response?.data || err?.message || 'Failed' });
  }
});

app.get('/image-host/', requireUserPage, (req, res) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate')
  res.setHeader('Pragma', 'no-cache')
  res.setHeader('Expires', '0')
  res.sendFile(path.join(__dirname, 'public', 'image-host', 'index.html'))
})


app.get('/api/image-host/debug-headers', verifyTokenApi, requireAdminApi, async (_req, res) => {
  try {
    if (!IMAGE_HOST_ADMIN_TARGET) return res.status(500).json({ error: 'IMAGE_HOST_ADMIN_TARGET not set' });
    if (!IMAGE_HOST_ADMIN_SECRET) return res.status(500).json({ error: 'IMAGE_HOST_ADMIN_SECRET not set' });

    const target = IMAGE_HOST_ADMIN_TARGET.replace(/\/$/, '');
    const resp = await axios.get(`${target}/debug/headers`, {
      headers: { 'x-admin-secret': String(IMAGE_HOST_ADMIN_SECRET).trim() }
    });

    res.json({ target, upstream: resp.data });
  } catch (err) {
    res.status(err?.response?.status || 500).json({ error: err?.response?.data || err?.message || 'Failed' });
  }
});

app.post('/interactions', async (req, res) => {
  try {
    const signature = req.get('X-Signature-Ed25519') || '';
    const timestamp = req.get('X-Signature-Timestamp') || '';
    const raw = req.rawBody || '';
    const valid = nacl.sign.detached.verify(
      Buffer.from(timestamp + raw),
      Buffer.from(signature, 'hex'),
      Buffer.from(DISCORD_PUBLIC_KEY, 'hex')
    );
    if (!valid) return res.sendStatus(401);

    let payload;
    try { payload = JSON.parse(raw); } catch { return res.sendStatus(400); }

    if (payload.type === 1) return res.json({ type: 1 });

    if (payload.type === 2 && payload.data.name === 'status') {
      const now = Date.now();
      const sentMs = Number(timestamp) * 1000;
      const latency = now - sentMs;

      let webStatus = '❌ Error';
      let webLatency = 'N/A';
      try {
        const start = Date.now();
        const resp = await axios.get('https://mikumiku.dev/');
        webStatus = `✅ ${resp.status} ${resp.statusText}`;
        webLatency = `⏱️ ${Date.now() - start} ms`;
      } catch {}

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

      const statusEmbed = {
        author: { name: '🎤 Mikumiku Status', icon_url: 'https://mikumiku.dev/logo.webp' },
        thumbnail: { url: 'https://mikumiku.dev/logo.webp' },
        title: '📊 System Overview',
        color: 0x39C5BB,
        description: `> **Latency:** \`${latency} ms\`\n> **Web:** \`${webStatus}\` (${webLatency})\n> **Load Avg:** \`${loadAvg}\`\n`,
        fields: [
          { name: '⏰ Uptime', value: uptime, inline: true },
          { name: '💾 Memory', value: `${memMb} MB`, inline: true },
          { name: '🗄 DB Status', value: dbState, inline: true },
          { name: '🔌 Sockets', value: `${sockets}`, inline: true },
          { name: '🔧 Environment', value: env, inline: true },
          { name: '📦 Version', value: version, inline: true }
        ],
        footer: { text: 'Powered by mikumiku.dev', icon_url: 'https://mikumiku.dev/logo.webp' }
      };

      return res.json({ type: 4, data: { embeds: [statusEmbed] } });
    }

    if (payload.type === 2 && payload.data.name === 'weather') {
      const cityOption = payload.data.options.find(o => o.name === 'city');
      if (!cityOption || !cityOption.value) return res.json({ type: 4, data: { content: '❌ Please provide a city name.' } });
      const city = cityOption.value.trim();
      if (!OPENWEATHER_API_KEY) return res.json({ type: 4, data: { content: '❌ Weather service not configured.' } });

      try {
        const resp = await axios.get(`https://api.openweathermap.org/data/2.5/weather?q=${encodeURIComponent(city)}&units=metric&appid=${OPENWEATHER_API_KEY}`);
        const { weather, main, wind, sys, name, coord } = resp.data;
        const weatherEmbed = {
          author: { name: `🌤️ Weather in ${name}, ${sys.country}`, icon_url: `http://openweathermap.org/img/wn/${weather[0].icon}@2x.png` },
          color: 0x39C5BB,
          fields: [
            { name: '🌡️ Temp', value: `${main.temp}°C`, inline: true },
            { name: '📈 Feels Like', value: `${main.feels_like}°C`, inline: true },
            { name: '💧 Humidity', value: `${main.humidity}%`, inline: true },
            { name: '🌬️ Wind', value: `${wind.speed} m/s`, inline: true },
            { name: '⛅ Condition', value: weather[0].description, inline: true },
            { name: '📍 Coordinates', value: `[${coord.lat}, ${coord.lon}]`, inline: true }
          ],
          thumbnail: { url: 'https://mikumiku.dev/logo.webp' },
          footer: { text: 'Powered by OpenWeatherMap', icon_url: 'https://openweathermap.org/themes/openweathermap/assets/vendor/owm/img/widgets/logo_60x60.png' }
        };
        return res.json({ type: 4, data: { embeds: [weatherEmbed] } });
      } catch {
        return res.json({ type: 4, data: { content: `❌ Could not fetch weather for \`${city}\`.` } });
      }
    }

    if (payload.type === 2 && payload.data.name === 'cat') {
      const gifUrl = `https://cataas.com/cat/gif?${Date.now()}`;
      const userOption = payload.data.options?.find(o => o.name === 'user');
      const mention = userOption ? `<@${userOption.value}>` : '';
      const embed = {
        title: '😺 Here’s a random cat for you!',
        color: 0x39C5BB,
        image: { url: gifUrl },
        footer: { text: 'Enjoy! 🐾', icon_url: 'https://mikumiku.dev/logo.webp' }
      };
      return res.json({ type: 4, data: { content: mention, embeds: [embed] } });
    }

    if (payload.type === 2 && payload.data.name === 'remind') {
      const timeStr = payload.data.options.find(o => o.name === 'time').value;
      const msg = payload.data.options.find(o => o.name === 'message').value;
      const userId = payload.member.user.id;
      const m = timeStr.match(/in (\d+) minutes?/i);
      if (!m) return res.json({ type: 4, data: { content: '❌ Invalid time format.' } });
      const delayMs = parseInt(m[1], 10) * 60000;

      res.json({ type: 4, data: { content: `✅ Okay, I'll remind you in ${m[1]} minutes.` } });

      setTimeout(async () => {
        try {
          if (!BOT_TOKEN) return;
          const dm = await axios.post(
            'https://discord.com/api/v10/users/@me/channels',
            { recipient_id: userId },
            { headers: { Authorization: `Bot ${BOT_TOKEN}`, 'Content-Type': 'application/json' } }
          );
          await axios.post(
            `https://discord.com/api/v10/channels/${dm.data.id}/messages`,
            { content: `<@${userId}> ⏰ Reminder: ${msg}` },
            { headers: { Authorization: `Bot ${BOT_TOKEN}`, 'Content-Type': 'application/json' } }
          );
        } catch {}
      }, delayMs);
      return;
    }

    if (payload.type === 2 && payload.data.name === 'time') {
      const loc = payload.data.options.find(o => o.name === 'location')?.value || 'UTC';
      let dt;
      try { dt = DateTime.now().setZone(loc); } catch { dt = null; }
      if (!dt || !dt.isValid) return res.json({ type: 4, data: { content: '❌ Invalid timezone.' } });
      const formatted = dt.toFormat('DDD, t');
      return res.json({ type: 4, data: { content: `⏰ Current time in **${loc}**: \`${formatted}\`` } });
    }

    return res.sendStatus(400);
  } catch {
    return res.sendStatus(500);
  }
});

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5, message: 'Too many login attempts from this IP, please try again after 15 minutes' });

app.get('/auth', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'admin-login.html')));

app.post('/login', loginLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    const adminUsername = process.env.ADMIN_USERNAME || '';
    const adminPasswordHash = process.env.ADMIN_PASSWORD_HASH || '';
    if (!adminUsername || !adminPasswordHash) return res.status(500).json({ auth: false, message: 'Admin not configured' });

    if (String(username || '') !== adminUsername) return res.status(401).json({ auth: false, message: 'Invalid username or password' });
    const isPasswordValid = await bcrypt.compare(String(password || ''), adminPasswordHash);
    if (!isPasswordValid) return res.status(401).json({ auth: false, message: 'Invalid username or password' });

    const token = signAuthToken({ role: 'admin', adminId: adminUsername, username: adminUsername });
    res.cookie('token', token, { httpOnly: false, secure: process.env.NODE_ENV === 'production', sameSite: 'Lax', path: '/', maxAge: 7 * 86400 * 1000 });

    req.session.save((err) => {
      if (err) return res.status(500).json({ auth: false, message: 'Error saving session' });
      res.status(200).json({ auth: true, redirect: '/admin' });
    });
  } catch {
    res.status(500).json({ auth: false, message: 'Internal Server Error' });
  }
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('admin_session_cookie', { path: '/', httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict' });
    res.cookie('token', '', { httpOnly: false, secure: process.env.NODE_ENV === 'production', sameSite: 'Lax', path: '/', expires: new Date(0) });
    res.redirect('/auth');
  });
});

app.get('/admin', verifyTokenPage('/auth'), requireAdminPage, (_req, res) => res.sendFile(path.join(__dirname, 'public', 'admin-dashboard.html')));
app.get('/admin-dashboard.html', (_req, res) => res.redirect('/admin'));

app.get(/^\/image-host$/, (_req, res) => res.redirect(301, '/image-host/'));
app.use('/image-host', verifyTokenPage('/user/auth'), requireUserPage);
app.get('/image-host/', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'image-host', 'index.html')));

app.use(express.static(path.join(__dirname, 'public'), { etag: false, maxAge: 0, lastModified: false, redirect: false }));

app.get('/api/geo-data', verifyTokenApi, requireAdminApi, async (_req, res) => {
  try {
    const byCountry = await GeoData.aggregate([
      { $group: { _id: '$country', count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);
    res.json(byCountry);
  } catch {
    res.status(500).json({ error: 'Failed to fetch geo data' });
  }
});

const blockedIps = new Set();

app.post('/api/block-user', verifyTokenApi, requireAdminApi, (req, res) => {
  const ip = String(req.body?.ip || '').trim();
  if (!ip) return res.status(400).json({ status: 'error', message: 'Missing ip' });
  blockedIps.add(ip);
  for (const [, s] of io.of('/').sockets) {
    const sip = s.handshake.headers['x-forwarded-for']?.split(',')[0].trim() || s.handshake.address;
    if (sip === ip) s.disconnect(true);
  }
  res.json({ status: 'success' });
});

app.post('/api/unblock-user', verifyTokenApi, requireAdminApi, (req, res) => {
  const ip = String(req.body?.ip || '').trim();
  if (!ip) return res.status(400).json({ status: 'error', message: 'Missing ip' });
  blockedIps.delete(ip);
  res.json({ status: 'success' });
});

app.get('/fetch-location', async (req, res) => {
  const ip = getClientIp(req);
  try {
    const locationData = await getGeoLocation(ip);
    res.json(locationData);
  } catch {
    res.status(500).json({ error: 'Failed to fetch location data' });
  }
});

app.get('/api/location/:ip', async (req, res) => {
  try {
    const ip = req.params.ip;
    const locationData = await getGeoLocation(ip);
    res.json({ ip, city: locationData.city, region: locationData.region, country: locationData.country });
  } catch {
    res.status(500).json({ error: 'Failed to fetch geolocation data' });
  }
});

app.post('/track-visitor', async (req, res) => {
  const ip = getClientIp(req);
  try {
    const loc = await getGeoLocation(ip);
    const city = loc.city || 'Unknown';
    const region = loc.region || 'Unknown';
    const country = loc.country || 'Unknown';
    await GeoData.updateOne(
      { ip },
      { $set: { city, region, country }, $setOnInsert: { timestamp: new Date() } },
      { upsert: true }
    );

    const byCountry = await GeoData.aggregate([
      { $group: { _id: '$country', count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);

    io.emit('geoDataUpdate', byCountry);

    if (loc && loc.loc) {
      const [latitude, longitude] = loc.loc.split(',');
      io.emit('visitorLocation', { id: ip, latitude: parseFloat(latitude), longitude: parseFloat(longitude), info: `${city}, ${country}` });
    }

    res.status(200).json({ success: true });
  } catch (err) {
    logger.error(`track-visitor failed for ${ip}: ${err?.message || 'error'}`);
    res.status(500).json({ success: false });
  }
});

const dbName = process.env.MONGO_DB_NAME || 'myfirstdatabase';
const client = new MongoClient(process.env.MONGO_URL, {});
let timelineCollection;
let configCollection;

async function connectToMongo() {
  try {
    await client.connect();
    const db2 = client.db(dbName);
    configCollection = db2.collection('config');
    timelineCollection = db2.collection('timeline');
    let toggleDoc = await configCollection.findOne({ _id: 'toggle' });
    if (!toggleDoc) await configCollection.insertOne({ _id: 'toggle', commands_enabled: true });
  } catch {}
}
connectToMongo();

app.get('/api/timeline', verifyTokenApi, requireAdminApi, async (_req, res) => {
  try {
    const entries = await timelineCollection.find().sort({ rawTimestamp: 1 }).toArray();
    res.json(entries);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/timeline', verifyTokenApi, requireAdminApi, async (req, res) => {
  try {
    const update = req.body || {};
    const lastEntryArray = await timelineCollection.find().sort({ rawTimestamp: -1 }).limit(1).toArray();
    if (lastEntryArray.length > 0) {
      const lastEntry = lastEntryArray[0];
      const lastMinute = Math.floor(Number(lastEntry.rawTimestamp || 0) / 60000);
      const newMinute = Math.floor(Number(update.rawTimestamp || 0) / 60000);
      if (lastMinute === newMinute) return res.json({ status: 'duplicate' });
    }
    await timelineCollection.insertOne(update);
    const count = await timelineCollection.countDocuments();
    const MAX_MINUTES = 60;
    if (count > MAX_MINUTES) {
      const excess = count - MAX_MINUTES;
      const oldest = await timelineCollection.find().sort({ rawTimestamp: 1 }).limit(excess).toArray();
      const ids = oldest.map(e => e._id);
      await timelineCollection.deleteMany({ _id: { $in: ids } });
    }
    res.json({ status: 'ok' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/toggle', verifyTokenApi, requireAdminApi, async (_req, res) => {
  try {
    const toggleDoc = await configCollection.findOne({ _id: 'toggle' });
    res.json(toggleDoc);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/toggle', verifyTokenApi, requireAdminApi, async (req, res) => {
  try {
    const data = req.body || {};
    if (typeof data.commands_enabled === 'undefined') return res.status(400).json({ status: 'error', message: "Missing 'commands_enabled' property." });
    await configCollection.updateOne({ _id: 'toggle' }, { $set: { commands_enabled: !!data.commands_enabled } }, { upsert: true });
    const toggleDoc = await configCollection.findOne({ _id: 'toggle' });
    res.json({ status: 'success', commands_enabled: !!toggleDoc?.commands_enabled });
  } catch {
    res.status(500).json({ status: 'error', message: 'Could not update configuration.' });
  }
});

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const sessions = {};
const openAICallLimiter = rateLimit({ windowMs: 60 * 1000, max: 60, message: { error: 'Too many requests, please try again later.' }, standardHeaders: true, legacyHeaders: false });

async function makeOpenAIRequest(messages, retries = 3, backoff = 1000) {
  try {
    const response = await openai.createChatCompletion({ model: 'gpt-3.5-turbo', messages, temperature: 0.7, max_tokens: 150 });
    return response.data.choices[0].message.content.trim();
  } catch (error) {
    if (error.response && error.response.status === 429 && retries > 0) {
      await new Promise(r => setTimeout(r, backoff));
      return makeOpenAIRequest(messages, retries - 1, backoff * 2);
    }
    throw error;
  }
}

app.post('/api/openai-chat', openAICallLimiter, async (req, res) => {
  const { message, sessionId } = req.body || {};
  if (!message || !sessionId) return res.status(400).json({ error: 'Message and sessionId are required.' });
  if (!sessions[sessionId]) sessions[sessionId] = [{ role: 'system', content: 'You are Haru AI, a helpful assistant.' }];
  sessions[sessionId].push({ role: 'user', content: String(message) });
  try {
    const botResponse = await makeOpenAIRequest(sessions[sessionId]);
    sessions[sessionId].push({ role: 'assistant', content: botResponse });
    res.json({ response: botResponse });
  } catch (error) {
    if (error.response && error.response.status === 429) res.status(429).json({ error: 'Too many requests. Please try again later.' });
    else res.status(500).json({ error: 'An error occurred while processing your request.' });
  }
});

app.get('/aria-status', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'aria-status.html')));

app.get('/status-proxy', async (_req, res) => {
  try {
    const response = await fetch(`${ORIGIN}/status`);
    const data = await response.json();
    res.json(data);
  } catch {
    res.status(500).json({ status: 'offline' });
  }
});

function forwardBody(proxyReq, req) {
  if (!req.body || !Object.keys(req.body).length) return;
  const ct = String(proxyReq.getHeader('Content-Type') || '');
  let bodyData;
  if (ct.includes('application/json')) bodyData = JSON.stringify(req.body);
  else if (ct.includes('application/x-www-form-urlencoded')) bodyData = new URLSearchParams(req.body).toString();
  if (bodyData) {
    proxyReq.setHeader('Content-Length', Buffer.byteLength(bodyData));
    proxyReq.write(bodyData);
  }
}

app.options(['/oauth/intake', '/oauth/submit', '/notify-ready', '/notify-status'], (_req, res) => res.sendStatus(204));

const proxy = createProxyMiddleware({
  target: ORIGIN,
  changeOrigin: true,
  xfwd: true,
  secure: false,
  ws: true,
  proxyTimeout: 45000,
  timeout: 45000,
  onProxyReq: forwardBody
});

app.post('/oauth/intake', proxy);
app.post('/oauth/submit', proxy);
app.post('/notify-ready', proxy);
app.get('/notify-status', proxy);

app.get('/health', (_req, res) => res.json({ ok: true }));

const HEARTBEAT_TIMEOUT = 60000;
let currentVideo = null;
let currentBrowsing = null;
const videoHeartbeat = {};
const activeUsers = new Map();

function emitCurrentPresence(socket) {
  if (currentVideo) socket.emit('presenceUpdate', { presenceType: 'video', ...currentVideo });
  else if (currentBrowsing) socket.emit('presenceUpdate', { presenceType: 'browsing', ...currentBrowsing });
  else socket.emit('presenceUpdate', { presenceType: 'offline' });
}

function handleBrowsingPresence(data) {
  currentVideo = null;
  currentBrowsing = {
    title: data.title || 'YouTube',
    description: data.description || 'Browsing videos',
    thumbnail: data.thumbnail || 'https://www.youtube.com/img/desktop/yt_1200.png',
    timeElapsed: data.timeElapsed || 0
  };
}

function handleVideoPresence(data) {
  const presence = {
    videoId: data.videoId,
    title: data.title,
    description: data.description,
    channelTitle: data.channelTitle,
    viewCount: data.viewCount,
    likeCount: data.likeCount,
    publishedAt: data.publishedAt,
    category: data.category,
    thumbnail: data.thumbnail,
    currentTime: data.currentTime,
    duration: data.duration,
    isPaused: data.isPaused,
    isLive: data.isLive
  };
  if (currentVideo?.videoId === data.videoId) Object.assign(currentVideo, presence);
  else {
    currentVideo = presence;
    currentBrowsing = null;
  }
}

function handleOfflinePresence() {
  currentVideo = null;
  currentBrowsing = null;
}

setInterval(() => {
  const now = Date.now();
  for (const [videoId, ts] of Object.entries(videoHeartbeat)) {
    if (now - ts > HEARTBEAT_TIMEOUT) {
      delete videoHeartbeat[videoId];
      currentVideo = null;
      currentBrowsing = null;
      io.emit('presenceUpdate', { presenceType: 'offline' });
      break;
    }
  }
}, HEARTBEAT_TIMEOUT / 2);

let lastBotStatusUpdate = Date.now();
let smsSent = false;
let highLatencyAlertSent = false;
const OFFLINE_TIMEOUT = 90000;
const HIGH_LATENCY_THRESHOLD = 100;

function sendSMSAlert(message) {
  const smsData = { messages: [{ source: 'nodejs', from: process.env.SMS_SENDER, to: process.env.TO_PHONE_NUMBER, body: message }] };
  const auth = { username: process.env.CLICKSEND_USERNAME, password: process.env.CLICKSEND_API_KEY };
  axios.post('https://rest.clicksend.com/v3/sms/send', smsData, { auth }).then(() => {}).catch(() => {});
}

setInterval(() => {
  const elapsed = Date.now() - lastBotStatusUpdate;
  if (elapsed > OFFLINE_TIMEOUT) {
    if (!smsSent) {
      sendSMSAlert('Alert: The bot is offline!');
      smsSent = true;
    }
  }
}, 5000);

io.on('connection', socket => {
  const ip = socket.handshake.headers['x-forwarded-for']?.split(',')[0].trim() || socket.handshake.address;
  const type = socket.handshake.query.connectionType || 'website';
  if (blockedIps.has(ip)) return socket.disconnect(true);

  if (!activeUsers.has(ip)) activeUsers.set(ip, { connectionTypes: new Set() });
  activeUsers.get(ip).connectionTypes.add(type);

  socket.broadcast.emit('activeUsersUpdate', {
    users: Array.from(activeUsers.entries()).map(([k, v]) => ({ ip: k, connectionTypes: Array.from(v.connectionTypes) }))
  });

  emitCurrentPresence(socket);

  socket.on('getToggleState', async () => {
    try {
      const doc = await configCollection.findOne({ _id: 'toggle' });
      socket.emit('toggleState', doc || { commands_enabled: true });
    } catch {
      socket.emit('toggleState', { commands_enabled: true });
    }
  });

  socket.on('toggleCommands', async (data) => {
    try {
      const nextVal = !!data?.commands_enabled;
      await configCollection.updateOne({ _id: 'toggle' }, { $set: { commands_enabled: nextVal } }, { upsert: true });
      io.emit('toggleUpdated', { commands_enabled: nextVal });
    } catch {}
  });

  socket.on('presenceUpdate', data => {
    switch (data.presenceType) {
      case 'video': handleVideoPresence(data); break;
      case 'browsing': handleBrowsingPresence(data); break;
      case 'offline': handleOfflinePresence(); break;
    }
    socket.broadcast.emit('presenceUpdate', data);
  });

  socket.on('updateBrowsingPresence', data => {
    handleBrowsingPresence(data);
    socket.broadcast.emit('presenceUpdate', { presenceType: 'browsing', ...currentBrowsing });
  });

  socket.on('updateVideoProgress', data => {
    handleVideoPresence(data);
    socket.broadcast.emit('presenceUpdate', { presenceType: 'video', ...currentVideo });
  });

  socket.on('heartbeat', (data, ack) => {
    const { videoId } = data || {};
    if (currentVideo?.videoId === videoId) {
      videoHeartbeat[videoId] = Date.now();
      if (ack) ack({ status: 'ok' });
    } else {
      if (ack) ack({ status: 'error', message: 'Unknown video ID' });
    }
  });

  socket.on('botHeartbeat', (data) => {
    const status = (data?.status || '').toLowerCase().trim();
    lastBotStatusUpdate = Date.now();

    io.emit('botStatusUpdate', data || {});

    if (status === 'online') {
      smsSent = false;
      const latency = parseInt(data?.latency);
      if (Number.isFinite(latency) && latency > HIGH_LATENCY_THRESHOLD && !highLatencyAlertSent) {
        sendSMSAlert('Alert: The bot is experiencing high latency!');
        highLatencyAlertSent = true;
      } else if (Number.isFinite(latency) && latency <= HIGH_LATENCY_THRESHOLD) {
        highLatencyAlertSent = false;
      }
    }
  });

  socket.on('disconnect', () => {
    const user = activeUsers.get(ip);
    if (user) {
      user.connectionTypes.delete(type);
      if (user.connectionTypes.size === 0) activeUsers.delete(ip);
    }
    socket.broadcast.emit('activeUsersUpdate', {
      users: Array.from(activeUsers.entries()).map(([k, v]) => ({ ip: k, connectionTypes: Array.from(v.connectionTypes) }))
    });
  });
});

app.get('/api/weather', async (req, res) => {
  const city = req.query.city;
  if (!city) return res.status(400).json({ error: 'City is required' });
  if (!OPENWEATHER_API_KEY) return res.status(500).json({ error: 'Weather service not configured.' });

  try {
    const resp = await axios.get(`https://api.openweathermap.org/data/2.5/weather?q=${encodeURIComponent(city)}&units=metric&appid=${OPENWEATHER_API_KEY}`);
    const { weather, main, wind, sys, name, coord } = resp.data;
    res.json({
      city: name,
      country: sys.country,
      temperature: main.temp,
      feels_like: main.feels_like,
      humidity: main.humidity,
      wind_speed: wind.speed,
      condition: weather[0].description,
      coordinates: coord
    });
  } catch {
    res.status(500).json({ error: `Could not fetch weather for "${city}".` });
  }
});

app.get('/api/videos/public', async (_req, res) => {
  try {
    res.json([]);
  } catch {
    res.status(500).send({ error: 'Error retrieving video metadata' });
  }
});

app.post('/api/videos', verifyTokenApi, requireAdminApi, [
  body('url').isURL().withMessage('Invalid URL format'),
  body('title').isString().notEmpty().withMessage('Title is required'),
  body('description').isString().optional(),
  body('category').isString().notEmpty().withMessage('Category is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const sanitizedUrl = String(req.body.url || '').replace('youtu.be', 'youtube.com/embed');
  const videoMetadata = {
    url: sanitizedUrl,
    title: req.body.title,
    description: req.body.description ? req.body.description : '',
    category: req.body.category,
    uploadedAt: new Date()
  };

  try {
    logger.info(`New video added: ${JSON.stringify(videoMetadata)}`);
    res.status(201).json({ message: 'Video added successfully', video: videoMetadata });
  } catch {
    res.status(500).json({ error: 'Error saving video metadata' });
  }
});

server.listen(PORT, () => { logger.info(`Server is running on port ${PORT}`); });
