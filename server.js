const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'transform-ai-super-secret-key-123456';
const USERS_FILE = path.join(__dirname, 'users.json');

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Initialize users.json if it doesn't exist
if (!fs.existsSync(USERS_FILE)) {
    const defaultUsers = [
        {
            id: 1,
            email: 'demo@company.com',
            passwordHash: bcrypt.hashSync('password123', 10),
            name: 'Demo User'
        }
    ];
    fs.writeFileSync(USERS_FILE, JSON.stringify(defaultUsers, null, 2));
}

function getUsers() {
    try {
        const data = fs.readFileSync(USERS_FILE, 'utf8');
        return JSON.parse(data);
    } catch (err) {
        return [];
    }
}

function saveUsers(users) {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

// Authentication Middleware for API requests
function authenticateToken(req, res, next) {
    const token = req.cookies.token;
    if (!token) {
        return res.status(401).json({ error: 'Unauthorized: No token provided' });
    }
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Forbidden: Invalid token' });
        }
        req.user = user;
        next();
    });
}

// Authentication Middleware for Page requests (HTML files)
function requireAuth(req, res, next) {
    const token = req.cookies.token;
    if (!token) {
        return res.redirect('/');
    }
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            res.clearCookie('token');
            return res.redirect('/');
        }
        req.user = user;
        next();
    });
}

// API Routes
app.post('/api/auth/register', (req, res) => {
    const { email, password, name } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }

    const users = getUsers();
    if (users.find(u => u.email.toLowerCase() === email.toLowerCase())) {
        return res.status(400).json({ error: 'User already exists' });
    }

    const newUser = {
        id: Date.now(),
        email: email.toLowerCase(),
        passwordHash: bcrypt.hashSync(password, 10),
        name: name || email.split('@')[0]
    };

    users.push(newUser);
    saveUsers(users);

    const token = jwt.sign({ id: newUser.id, email: newUser.email }, JWT_SECRET, { expiresIn: '24h' });
    res.cookie('token', token, { httpOnly: true, secure: false }); // secure: true in production

    res.status(201).json({ message: 'User registered successfully', user: { id: newUser.id, email: newUser.email, name: newUser.name } });
});

app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }

    const users = getUsers();
    const user = users.find(u => u.email.toLowerCase() === email.toLowerCase());

    if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
        return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });
    res.cookie('token', token, { httpOnly: true, secure: false });

    res.status(200).json({ message: 'Login successful', user: { id: user.id, email: user.email, name: user.name } });
});

app.post('/api/auth/logout', (req, res) => {
    res.clearCookie('token');
    res.status(200).json({ message: 'Logout successful' });
});

app.get('/api/auth/me', authenticateToken, (req, res) => {
    const users = getUsers();
    const user = users.find(u => u.id === req.user.id);
    if (!user) {
        return res.status(404).json({ error: 'User not found' });
    }
    res.status(200).json({ user: { id: user.id, email: user.email, name: user.name } });
});

// Protect static HTML pages
const protectedPages = [
    '/dashboard.html',
    '/new-transformation.html',
    '/settings.html',
    '/transformation-processing.html',
    '/artifact-workspace.html'
];

protectedPages.forEach(page => {
    app.get(page, requireAuth, (req, res) => {
        res.sendFile(path.join(__dirname, page));
    });
});

// Redirect authenticated users trying to access root/login page
app.get('/', (req, res, next) => {
    const token = req.cookies.token;
    if (token) {
        jwt.verify(token, JWT_SECRET, (err, user) => {
            if (!err) {
                return res.redirect('/dashboard.html');
            }
            res.clearCookie('token');
            next();
        });
    } else {
        next();
    }
});

// Serve public static assets/files
app.use(express.static(__dirname));

// Start server
app.listen(PORT, () => {
    console.log(`TransformAI backend server is running on http://localhost:${PORT}`);
});
