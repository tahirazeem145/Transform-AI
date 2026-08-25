require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const { createClient } = require('@supabase/supabase-js');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Initialize Supabase Client
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_ANON_KEY;

if (!supabaseUrl || !supabaseKey || supabaseUrl.includes('your-project-id')) {
    console.warn('WARNING: Supabase URL or Anon Key is missing or using placeholder values in .env. Please configure them to get Supabase integration working.');
}

const supabase = createClient(supabaseUrl || 'https://placeholder.supabase.co', supabaseKey || 'placeholder-key');

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Authentication Middleware for API requests
async function authenticateToken(req, res, next) {
    const token = req.cookies.token;
    if (!token) {
        return res.status(401).json({ error: 'Unauthorized: No token provided' });
    }
    try {
        const { data: { user }, error } = await supabase.auth.getUser(token);
        if (error || !user) {
            return res.status(403).json({ error: 'Forbidden: Invalid session' });
        }
        req.user = user;
        next();
    } catch (err) {
        return res.status(500).json({ error: 'Internal server error during auth verification' });
    }
}

// Authentication Middleware for Page requests (HTML files)
async function requireAuth(req, res, next) {
    const token = req.cookies.token;
    if (!token) {
        return res.redirect('/');
    }
    try {
        const { data: { user }, error } = await supabase.auth.getUser(token);
        if (error || !user) {
            res.clearCookie('token');
            return res.redirect('/');
        }
        req.user = user;
        next();
    } catch (err) {
        res.clearCookie('token');
        return res.redirect('/');
    }
}

// API Routes
app.post('/api/auth/register', async (req, res) => {
    const { email, password, name } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }

    try {
        const { data, error } = await supabase.auth.signUp({
            email,
            password,
            options: {
                data: {
                    name: name || email.split('@')[0]
                }
            }
        });

        if (error) {
            return res.status(400).json({ error: error.message });
        }

        if (data.session) {
            res.cookie('token', data.session.access_token, { httpOnly: true, secure: false });
        }

        res.status(201).json({ 
            message: data.session ? 'Registration successful' : 'Registration successful! Please check your email for confirmation.', 
            user: data.user 
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }

    try {
        const { data, error } = await supabase.auth.signInWithPassword({
            email,
            password
        });

        if (error) {
            return res.status(401).json({ error: error.message });
        }

        res.cookie('token', data.session.access_token, { httpOnly: true, secure: false });
        res.status(200).json({ message: 'Login successful', user: data.user });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/auth/logout', async (req, res) => {
    const token = req.cookies.token;
    if (token) {
        // Sign out from Supabase auth session
        await supabase.auth.admin.signOut(token).catch(() => {});
    }
    res.clearCookie('token');
    res.status(200).json({ message: 'Logout successful' });
});

app.get('/api/auth/me', authenticateToken, (req, res) => {
    res.status(200).json({ 
        user: { 
            id: req.user.id, 
            email: req.user.email, 
            name: req.user.user_metadata?.name || req.user.email.split('@')[0] 
        } 
    });
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
app.get('/', async (req, res, next) => {
    const token = req.cookies.token;
    if (token) {
        try {
            const { data: { user }, error } = await supabase.auth.getUser(token);
            if (!error && user) {
                return res.redirect('/dashboard.html');
            }
            res.clearCookie('token');
            next();
        } catch (err) {
            res.clearCookie('token');
            next();
        }
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
