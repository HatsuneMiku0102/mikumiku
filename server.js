const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const fs = require('fs');
const path = require('path');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(bodyParser.json());

app.use(session({
    secret: process.env.SESSION_SECRET || 'your-secret-key',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: true, sameSite: 'strict' } 
}));

// Serve static files from the "public" directory
app.use(express.static(path.join(__dirname, 'public')));

const users = [
    {
        username: process.env.ADMIN_USERNAME,
        password: bcrypt.hashSync(process.env.ADMIN_PASSWORD, 8)
    }
];

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

    req.session.user = {
        username: user.username
    };
    console.log('Session created:', req.session); // Logging session creation
    res.status(200).send({ auth: true });
});

function isAuthenticated(req, res, next) {
    console.log('Checking authentication:', req.session); // Logging session check
    if (req.session.user) {
        next();
    } else {
        res.redirect('/admin-login.html');
    }
}

// Protecting the admin dashboard route
app.get('/admin-dashboard.html', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin-dashboard.html'));
});

app.post('/api/videos', isAuthenticated, (req, res) => {
    const newVideo = req.body;
    const videosFilePath = path.join(__dirname, 'public', 'videos.json');

    if (!fs.existsSync(videosFilePath)) {
        fs.writeFileSync(videosFilePath, JSON.stringify([], null, 2));
    }

    fs.readFile(videosFilePath, 'utf8', (err, data) => {
        if (err) {
            return res.status(500).send({ message: 'Error reading video data', error: err });
        }

        let videos;
        try {
            videos = JSON.parse(data);
        } catch (parseErr) {
            return res.status(500).send({ message: 'Error parsing video data', error: parseErr });
        }

        videos.push(newVideo);

        fs.writeFile(videosFilePath, JSON.stringify(videos, null, 2), (err) => {
            if (err) {
                return res.status(500).send({ message: 'Error saving video data', error: err });
            }

            res.status(201).send({ message: 'Video added' });
        });
    });
});

app.get('/api/videos', (req, res) => {
    const videosFilePath = path.join(__dirname, 'public', 'videos.json');

    fs.readFile(videosFilePath, 'utf8', (err, data) => {
        if (err) {
            return res.status(500).send({ message: 'Error reading video data', error: err });
        }

        res.json(JSON.parse(data));
    });
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).send({ message: 'Failed to log out' });
        }
        console.log('Session destroyed'); // Logging session destruction
        res.redirect('/admin-login.html');
    });
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
