const express = require('express'), fs = require('fs'), path = require('path');
const bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken');
const app = express(), PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'change-this-secret-in-production';
const DB_FILE = path.join(__dirname, 'data', 'db.json');

// ---- Simple JSON database (swap with MongoDB/MySQL later) ----
fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
let db = fs.existsSync(DB_FILE) ? JSON.parse(fs.readFileSync(DB_FILE)) : { users: [], donations: [] };
const save = () => fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
const uid = () => Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
const clean = u => ({ id: u.id, name: u.name, email: u.email, role: u.role, city: u.city, phone: u.phone });
const sign = u => jwt.sign(clean(u), SECRET, { expiresIn: '7d' });
const view = d => ({ ...d, status: d.status === 'available' && new Date(d.expiresAt) < new Date() ? 'expired' : d.status });

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ---- Auth middleware (optional role check) ----
const auth = roles => (req, res, next) => {
  try {
    const user = jwt.verify((req.headers.authorization || '').split(' ')[1], SECRET);
    if (roles && !roles.includes(user.role)) return res.status(403).json({ error: 'Your account type cannot do this.' });
    req.user = user; next();
  } catch { res.status(401).json({ error: 'Please log in first.' }); }
};

// ---- Auth routes ----
app.post('/api/register', async (req, res) => {
  const { name, email, password, role, city, phone } = req.body;
  if (!name || !email || !password || !city) return res.status(400).json({ error: 'Name, email, password and city are required.' });
  if (!['donor', 'ngo', 'needy'].includes(role)) return res.status(400).json({ error: 'Choose a valid account type.' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  if (db.users.some(u => u.email === email.toLowerCase())) return res.status(409).json({ error: 'This email is already registered.' });
  const u = { id: uid(), name, email: email.toLowerCase(), password: await bcrypt.hash(password, 10), role, city, phone: phone || '' };
  db.users.push(u); save();
  res.json({ token: sign(u), user: clean(u) });
});

app.post('/api/login', async (req, res) => {
  const u = db.users.find(x => x.email === (req.body.email || '').toLowerCase());
  if (!u || !(await bcrypt.compare(req.body.password || '', u.password))) return res.status(401).json({ error: 'Wrong email or password.' });
  res.json({ token: sign(u), user: clean(u) });
});

// ---- Donations ----
app.get('/api/donations', (req, res) => {
  const { q = '', city = '', category = '' } = req.query;
  const list = db.donations.map(view).filter(d => d.status === 'available' &&
    (!category || d.category === category) &&
    (!city || d.city.toLowerCase().includes(city.toLowerCase())) &&
    (!q || (d.title + d.description + d.address).toLowerCase().includes(q.toLowerCase())));
  res.json(list.sort((a, b) => new Date(a.expiresAt) - new Date(b.expiresAt)));
});

app.get('/api/my', auth(), (req, res) => {
  const key = req.user.role === 'donor' ? 'donorId' : 'claimedBy';
  res.json(db.donations.filter(d => d[key] === req.user.id).map(view).reverse());
});

app.post('/api/donations', auth(['donor']), (req, res) => {
  const { title, category, quantity, address, city, expiresAt, description } = req.body;
  if (!title || !quantity || !address || !city || !expiresAt) return res.status(400).json({ error: 'Fill in all required fields.' });
  if (new Date(expiresAt) < new Date()) return res.status(400).json({ error: 'Pickup deadline must be in the future.' });
  const d = { id: uid(), title, category: category || 'cooked', quantity: Number(quantity), address, city, expiresAt,
    description: description || '', donorId: req.user.id, donorName: req.user.name, donorPhone: req.user.phone || '',
    status: 'available', claimedBy: null, claimedByName: null, createdAt: new Date().toISOString() };
  db.donations.push(d); save(); res.json(d);
});

app.post('/api/donations/:id/claim', auth(['ngo', 'needy']), (req, res) => {
  const d = db.donations.find(x => x.id === req.params.id);
  if (!d) return res.status(404).json({ error: 'Donation not found.' });
  if (view(d).status !== 'available') return res.status(409).json({ error: 'This food is no longer available.' });
  Object.assign(d, { status: 'claimed', claimedBy: req.user.id, claimedByName: req.user.name, claimedPhone: req.user.phone || '' });
  save(); res.json(d);
});

app.post('/api/donations/:id/deliver', auth(['donor']), (req, res) => {
  const d = db.donations.find(x => x.id === req.params.id && x.donorId === req.user.id);
  if (!d || d.status !== 'claimed') return res.status(400).json({ error: 'Only claimed donations can be marked delivered.' });
  d.status = 'delivered'; save(); res.json(d);
});

app.delete('/api/donations/:id', auth(['donor']), (req, res) => {
  const i = db.donations.findIndex(x => x.id === req.params.id && x.donorId === req.user.id && x.status === 'available');
  if (i < 0) return res.status(400).json({ error: 'Only available donations can be deleted.' });
  db.donations.splice(i, 1); save(); res.json({ ok: true });
});

app.get('/api/stats', (req, res) => res.json({
  meals: db.donations.filter(d => d.status === 'delivered').reduce((s, d) => s + d.quantity, 0),
  donations: db.donations.length,
  donors: db.users.filter(u => u.role === 'donor').length,
  receivers: db.users.filter(u => u.role !== 'donor').length,
}));

app.listen(PORT, () => console.log(`FoodBridge running on http://localhost:${PORT}`));
