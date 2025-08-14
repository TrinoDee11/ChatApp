
/**
 * Simple chat app with Node.js, Express, EJS, JWT (cookie-based auth), and file JSON storage.
 * Not production-ready (no CSRF, rate-limiting, etc.) but good for learning.
 */
const express = require('express');
const path = require('path');
const fs = require('fs').promises;
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;

// ==== Config ====
const DATA_DIR = path.join(__dirname, 'data');
const USERS_PATH = path.join(DATA_DIR, 'users.json');
const MESSAGES_PATH = path.join(DATA_DIR, 'messages.json');
const JWT_SECRET = process.env.JWT_SECRET || 'dev-super-secret-change-me';

// ==== Middleware ====
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Attach user to res.locals for templates if logged in
app.use(async (req, res, next) => {
  const token = req.cookies?.token;
  if (!token) return next();
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    res.locals.currentUser = payload;
  } catch (err) {
    // Invalid token; clear it
    res.clearCookie('token', { httpOnly: true, sameSite: 'lax' });
  }
  next();
});

// ==== Helpers ====
async function loadJSON(filePath, fallback) {
  try {
    const raw = await fs.readFile(filePath, 'utf-8');
    return JSON.parse(raw);
  } catch (e) {
    return fallback;
  }
}

async function saveJSON(filePath, data) {
  await fs.writeFile(filePath, JSON.stringify(data, null, 2), 'utf-8');
}

async function getUsers() {
  return await loadJSON(USERS_PATH, []);
}

async function saveUsers(users) {
  await saveJSON(USERS_PATH, users);
}

async function getMessages() {
  return await loadJSON(MESSAGES_PATH, []);
}

async function saveMessages(messages) {
  await saveJSON(MESSAGES_PATH, messages);
}

function requireAuth(req, res, next) {
  if (!req.user) return res.redirect('/login');
  next();
}

// ==== Routes ====
app.get('/', (req, res) => {
  if (req.user) return res.redirect('/chat');
  res.redirect('/login');
});

// Registration
app.get('/register', (req, res) => {
  if (req.user) return res.redirect('/chat');
  res.render('pages/register', { error: null, form: {} });
});

app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;
  const form = { name, email };
  try {
    if (!name || !email || !password) {
      return res.status(400).render('pages/register', { error: 'All fields are required.', form });
    }
    const users = await getUsers();
    if (users.find(u => u.email.toLowerCase() === email.toLowerCase())) {
      return res.status(400).render('pages/register', { error: 'Email already exists.', form });
    }
    if (users.find(u => u.name.toLowerCase() === name.toLowerCase())) {
      return res.status(400).render('pages/register', { error: 'Username already exists.', form });
    }
    const hash = await bcrypt.hash(password, 10);
    const user = { id: uuidv4(), name, email, passwordHash: hash, createdAt: new Date().toISOString() };
    users.push(user);
    await saveUsers(users);

    const token = jwt.sign({ id: user.id, name: user.name, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.cookie('token', token, { httpOnly: true, sameSite: 'lax' });
    res.redirect('/chat');
  } catch (e) {
    console.error(e);
    res.status(500).render('pages/register', { error: 'Something went wrong.', form });
  }
});

// Login
app.get('/login', (req, res) => {
  if (req.user) return res.redirect('/chat');
  res.render('pages/login', { error: null, form: {} });
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const form = { email };
  try {
    if (!email || !password) {
      return res.status(400).render('pages/login', { error: 'Email and password are required.', form });
    }
    const users = await getUsers();
    const user = users.find(u => u.email.toLowerCase() === email.toLowerCase());
    if (!user) {
      return res.status(401).render('pages/login', { error: 'Invalid email or password.', form });
    }
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) {
      return res.status(401).render('pages/login', { error: 'Invalid email or password.', form });
    }
    const token = jwt.sign({ id: user.id, name: user.name, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.cookie('token', token, { httpOnly: true, sameSite: 'lax' });
    res.redirect('/chat');
  } catch (e) {
    console.error(e);
    res.status(500).render('pages/login', { error: 'Something went wrong.', form });
  }
});

app.get('/logout', (req, res) => {
  res.clearCookie('token', { httpOnly: true, sameSite: 'lax' });
  res.redirect('/login');
});

// Chat page
app.get('/chat', requireAuth, async (req, res) => {
  const users = await getUsers();
  const others = users.filter(u => u.id !== req.user.id);
  const selected = req.query.to || (others[0]?.id || null);
  res.render('pages/chat', { others, selected });
});

// API: list users (excluding self)
app.get('/api/users', requireAuth, async (req, res) => {
  const users = await getUsers();
  const others = users.filter(u => u.id !== req.user.id).map(u => ({ id: u.id, name: u.name, email: u.email }));
  res.json(others);
});

// API: get messages between me and :otherId
app.get('/api/messages/:otherId', requireAuth, async (req, res) => {
  const otherId = req.params.otherId;
  const messages = await getMessages();
  const convo = messages
    .filter(m => (m.from === req.user.id && m.to === otherId) || (m.from === otherId && m.to === req.user.id))
    .sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
  res.json(convo);
});

// API: send message to :otherId
app.post('/api/messages/:otherId', requireAuth, async (req, res) => {
  const otherId = req.params.otherId;
  const { text } = req.body;
  if (!text || !text.trim()) return res.status(400).json({ error: 'Message cannot be empty.' });

  const messages = await getMessages();
  const message = {
    id: uuidv4(),
    from: req.user.id,
    to: otherId,
    text: text.trim(),
    timestamp: new Date().toISOString()
  };
  messages.push(message);
  await saveMessages(messages);
  res.json({ ok: true, message });
});

// 404
app.use((req, res) => {
  res.status(404).render('pages/404', {});
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
