const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'your_jwt_secret_key'; // Replace with a secure key

// Middleware
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('uploads'));

// PostgreSQL connection
const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'hrms_db',
    password: 'root',
    port: 5432,
});

// Ensure uploads directory exists
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir);
}

// Multer setup for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        if (!file.originalname) {
            return cb(new Error('No file name provided'));
        }
        cb(null, Date.now() + path.extname(file.originalname));
    }
});
const upload = multer({
    storage: storage,
    fileFilter: (req, file, cb) => {
        if (file.mimetype === 'image/jpeg') {
            cb(null, true);
        } else {
            cb(new Error('Only JPG images are allowed'), false);
        }
    }
});

// Token blacklist (in-memory, use a database for production)
const blacklistedTokens = new Set();

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer <token>

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    if (blacklistedTokens.has(token)) {
        return res.status(403).json({ error: 'Token is blacklisted' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user; // Attach user data to request
        next();
    });
};

// Register user
app.post('/api/register', upload.single('profileImage'), async (req, res) => {
    try {
        console.log('Register request received:', req.body, req.file);
        const { username, email, password } = req.body;
        const profileImage = req.file ? `/uploads/${req.file.filename}` : null;

        // Validate input
        if (!username || !email || !password || !profileImage) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        const usernameRegex = /^[A-Za-z]{5,}$/;
        if (!usernameRegex.test(username)) {
            return res.status(400).json({ error: 'Username must be at least 5 letters' });
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }

        // Check if user exists
        const userCheck = await pool.query(
            'SELECT * FROM users WHERE email = $1 OR username = $2',
            [email, username]
        );
        if (userCheck.rows.length > 0) {
            return res.status(400).json({ error: 'Username or email already exists' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert user
        await pool.query(
            'INSERT INTO users (username, email, password, profile_image) VALUES ($1, $2, $3, $4)',
            [username, email, hashedPassword, profileImage]
        );

        res.status(201).json({ message: 'Registration successful' });
    } catch (error) {
        console.error('Error in /api/register:', error.message, error.stack);
        res.status(500).json({ error: 'Server error' });
    }
});

// Login user
app.post('/api/login', async (req, res) => {
    try {
        console.log('Login request received:', req.body);
        const { username, password } = req.body;

        // Validate input
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }

        // Check user
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        const user = result.rows[0];

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        // Generate JWT
        const token = jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET, {
            expiresIn: '1h'
        });

        res.json({
            token,
            user: {
                username: user.username,
                email: user.email,
                profileImage: user.profile_image
            }
        });
    } catch (error) {
        console.error('Error in /api/login:', error.message, error.stack);
        res.status(500).json({ error: 'Server error' });
    }
});

// Forgot password
app.post('/api/forgot-password', async (req, res) => {
    try {
        console.log('Forgot-password request received:', req.body);
        const { email, password } = req.body;

        // Validate input
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }

        // Password validation
        const passwordRequirements = [
            { regex: /.{8,}/, message: 'Password must be at least 8 characters long' },
            { regex: /[A-Z]/, message: 'Password must contain an uppercase letter' },
            { regex: /[a-z]/, message: 'Password must contain a lowercase letter' },
            { regex: /[0-9]/, message: 'Password must contain a number' },
            { regex: /[!@#$%^&*]/, message: 'Password must contain a special character (!@#$%^&*)' }
        ];

        for (const requirement of passwordRequirements) {
            if (!requirement.regex.test(password)) {
                return res.status(400).json({ error: requirement.message });
            }
        }

        // Check if user exists
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        const user = result.rows[0];

        if (!user) {
            return res.status(404).json({ error: 'Email not found' });
        }

        // Hash new password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Update password
        await pool.query('UPDATE users SET password = $1 WHERE email = $2', [
            hashedPassword,
            email
        ]);

        res.json({ message: 'Password reset successful' });
    } catch (error) {
        console.error('Error in /api/forgot-password:', error.message, error.stack);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get user profile
app.get('/api/user', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        const result = await pool.query('SELECT username, email, profile_image FROM users WHERE id = $1', [userId]);
        const user = result.rows[0];

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({
            username: user.username,
            email: user.email,
            profileImage: user.profile_image
        });
    } catch (error) {
        console.error('Error in /api/user:', error.message, error.stack);
        res.status(500).json({ error: 'Server error' });
    }
});

// Logout user
app.post('/api/logout', authenticateToken, (req, res) => {
    try {
        const token = req.headers['authorization'].split(' ')[1];
        blacklistedTokens.add(token); // Blacklist the token
        res.json({ message: 'Logged out successfully' });
    } catch (error) {
        console.error('Error in /api/logout:', error.message, error.stack);
        res.status(500).json({ error: 'Server error' });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err.message, err.stack);
    res.status(500).json({ error: 'Server error' });
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});