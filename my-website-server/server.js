const express = require('express');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bodyParser = require('body-parser');
const app = express();
const fs = require('fs');
const path = require('path');

// Middleware for body parsing
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// Set up session middleware
app.use(session({ secret: 'your_secret_key', resave: false, saveUninitialized: false }));

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Configure the local strategy for Passport
passport.use(new LocalStrategy((username, password, done) => {
    if (username === 'admin' && password === 'password') {
        return done(null, { username: 'admin' });
    }
    return done(null, false, { message: 'Incorrect username or password.' });
}));

// Serialize user information into the session
passport.serializeUser((user, done) => {
    done(null, user.username);
});

// Deserialize user information from the session
passport.deserializeUser((username, done) => {
    done(null, { username: username });
});

// Serve static files from the public directory
app.use(express.static(path.join(__dirname, 'public')));

// Set the view engine to EJS
app.set('view engine', 'ejs');

// Load video data from a JSON file
const videoDataPath = path.join(__dirname, 'videos.json');
let videoData = [];
if (fs.existsSync(videoDataPath)) {
    const rawData = fs.readFileSync(videoDataPath);
    videoData = JSON.parse(rawData);
}

// Save video data to the JSON file
const saveVideoData = () => {
    fs.writeFileSync(videoDataPath, JSON.stringify(videoData, null, 2));
};

// Helper function to convert YouTube URL to embed URL
const convertToEmbedUrl = (url) => {
    const videoIdMatch = url.match(/(?:youtube\.com\/(?:[^\/]+\/.+\/|(?:v|e(?:mbed)?)\/|.*[?&]v=)|youtu\.be\/)([^"&?\/\s]{11})/i);
    return videoIdMatch ? `https://www.youtube.com/embed/${videoIdMatch[1]}` : url;
};

// Render the home page
app.get('/', (req, res) => {
    res.render('index', { videos: videoData });
});

// Render the login page
app.get('/login', (req, res) => {
    res.render('login');
});

// Handle login requests
app.post('/login', passport.authenticate('local', {
    successRedirect: '/admin',
    failureRedirect: '/login'
}));

// Handle logout requests
app.get('/logout', (req, res) => {
    req.logout((err) => {
        if (err) {
            return next(err);
        }
        res.redirect('/');
    });
});

// Render the admin page
app.get('/admin', (req, res) => {
    if (req.isAuthenticated()) {
        res.render('admin', { videos: videoData });
    } else {
        res.redirect('/login');
    }
});

// Handle video addition
app.post('/add-video', (req, res) => {
    const { title, url, description } = req.body;
    if (title && url && description) {
        videoData.push({ title, url: convertToEmbedUrl(url), description });
        saveVideoData();
    }
    res.redirect('/admin');
});

// Handle video deletion
app.post('/delete-video', (req, res) => {
    const { index } = req.body;
    if (index >= 0 && index < videoData.length) {
        videoData.splice(index, 1);
        saveVideoData();
    }
    res.redirect('/admin');
});

// Start the server
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`Server is running and updating on http://localhost:${PORT}`);
});
