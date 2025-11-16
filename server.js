// server.js - Node.js + Express Backend for Webhook Management
const express = require('express');
const cors = require('cors');
const fs = require('fs').promises;
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcrypt');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));
app.use(express.json());
app.use(express.static('public'));
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key-change-this',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// File paths
const WEBHOOKS_FILE = path.join(__dirname, 'data', 'webhooks.json');
const USERS_FILE = path.join(__dirname, 'data', 'users.json');

// Ensure data directory exists
async function ensureDataDir() {
  try {
    await fs.mkdir(path.join(__dirname, 'data'), { recursive: true });
  } catch (err) {
    console.error('Error creating data directory:', err);
  }
}

// Initialize files if they don't exist
async function initializeFiles() {
  await ensureDataDir();
  
  try {
    await fs.access(WEBHOOKS_FILE);
  } catch {
    await fs.writeFile(WEBHOOKS_FILE, JSON.stringify({
      purchase: '',
      visit: '',
      secondary: ''
    }, null, 2));
  }

  try {
    await fs.access(USERS_FILE);
  } catch {
    // Create default admin user (password: admin123)
    const hashedPassword = await bcrypt.hash('admin123', 10);
    await fs.writeFile(USERS_FILE, JSON.stringify({
      users: [{
        email: 'admin@reotnik.com',
        password: hashedPassword,
        role: 'admin'
      }]
    }, null, 2));
    console.log('⚠️  Default admin account created: admin@reotnik.com / admin123');
    console.log('⚠️  Please change this password immediately!');
  }
}

// Authentication middleware
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) {
    next();
  } else {
    res.status(401).json({ error: 'Unauthorized. Please login.' });
  }
}

// API key middleware (for Roblox requests)
function validateApiKey(req, res, next) {
  const apiKey = req.headers['x-api-key'] || req.query.apiKey;
  const validKey = process.env.API_KEY || 'your-api-key-change-this';
  
  if (apiKey === validKey) {
    next();
  } else {
    res.status(403).json({ error: 'Invalid API key' });
  }
}

// ============ AUTH ROUTES ============

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    const usersData = await fs.readFile(USERS_FILE, 'utf8');
    const { users } = JSON.parse(usersData);
    
    const user = users.find(u => u.email === email);
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Set session
    req.session.userId = user.email;
    req.session.role = user.role;
    
    res.json({ 
      success: true, 
      message: 'Login successful',
      user: { email: user.email, role: user.role }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Logout
app.post('/api/auth/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Logout failed' });
    }
    res.json({ success: true, message: 'Logged out successfully' });
  });
});

// Check auth status
app.get('/api/auth/status', (req, res) => {
  if (req.session && req.session.userId) {
    res.json({ 
      authenticated: true, 
      user: { 
        email: req.session.userId, 
        role: req.session.role 
      }
    });
  } else {
    res.json({ authenticated: false });
  }
});

// ============ WEBHOOK ROUTES ============

// Get webhooks (protected - requires authentication)
app.get('/api/webhooks', requireAuth, async (req, res) => {
  try {
    const data = await fs.readFile(WEBHOOKS_FILE, 'utf8');
    const webhooks = JSON.parse(data);
    res.json(webhooks);
  } catch (err) {
    console.error('Error reading webhooks:', err);
    res.status(500).json({ error: 'Failed to read webhooks' });
  }
});

// Get webhooks (for Roblox - requires API key)
app.get('/api/webhooks/public', validateApiKey, async (req, res) => {
  try {
    const data = await fs.readFile(WEBHOOKS_FILE, 'utf8');
    const webhooks = JSON.parse(data);
    res.json(webhooks);
  } catch (err) {
    console.error('Error reading webhooks:', err);
    res.status(500).json({ error: 'Failed to read webhooks' });
  }
});

// Update webhooks (protected)
app.post('/api/webhooks', requireAuth, async (req, res) => {
  try {
    const { purchase, visit, secondary } = req.body;

    if (!purchase || !visit) {
      return res.status(400).json({ error: 'Purchase and visit webhooks are required' });
    }

    // Validate webhook URLs
    const urlPattern = /^https:\/\/discord\.com\/api\/webhooks\/\d+\/[\w-]+$/;
    
    if (!urlPattern.test(purchase) || !urlPattern.test(visit)) {
      return res.status(400).json({ error: 'Invalid Discord webhook URL format' });
    }

    if (secondary && secondary.trim() !== '' && !urlPattern.test(secondary)) {
      return res.status(400).json({ error: 'Invalid secondary webhook URL format' });
    }

    const webhooks = {
      purchase: purchase.trim(),
      visit: visit.trim(),
      secondary: secondary ? secondary.trim() : ''
    };

    await fs.writeFile(WEBHOOKS_FILE, JSON.stringify(webhooks, null, 2));
    
    res.json({ 
      success: true, 
      message: 'Webhooks updated successfully',
      webhooks 
    });
  } catch (err) {
    console.error('Error updating webhooks:', err);
    res.status(500).json({ error: 'Failed to update webhooks' });
  }
});

// ============ USER MANAGEMENT (Optional) ============

// Change password
app.post('/api/user/change-password', requireAuth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Current and new password required' });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'New password must be at least 6 characters' });
    }

    const usersData = await fs.readFile(USERS_FILE, 'utf8');
    const data = JSON.parse(usersData);
    
    const userIndex = data.users.findIndex(u => u.email === req.session.userId);
    
    if (userIndex === -1) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = data.users[userIndex];
    const validPassword = await bcrypt.compare(currentPassword, user.password);
    
    if (!validPassword) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    // Update password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    data.users[userIndex].password = hashedPassword;
    
    await fs.writeFile(USERS_FILE, JSON.stringify(data, null, 2));
    
    res.json({ success: true, message: 'Password changed successfully' });
  } catch (err) {
    console.error('Error changing password:', err);
    res.status(500).json({ error: 'Failed to change password' });
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Start server
async function startServer() {
  await initializeFiles();
  
  app.listen(PORT, () => {
    console.log(`✅ Server running on port ${PORT}`);
    console.log(`📍 API Base URL: http://localhost:${PORT}`);
    console.log(`🔑 Dashboard: http://localhost:${PORT}/dashboard.html`);
    console.log(`🔗 Roblox Webhook Endpoint: http://localhost:${PORT}/api/webhooks/public`);
    console.log(`⚠️  API Key: ${process.env.API_KEY || 'your-api-key-change-this'}`);
  });
}

startServer();