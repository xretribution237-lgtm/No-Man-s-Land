require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'nml-super-secret-key-change-in-prod';
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || bcrypt.hashSync(process.env.ADMIN_PASSWORD || 'admin123', 10);

// ── Middleware ─────────────────────────────────────────────────────────────────
app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  credentials: true
}));
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Serve frontend from /public if it exists
app.use(express.static(path.join(__dirname, 'public')));

// ── Upload config ──────────────────────────────────────────────────────────────
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `${uuidv4()}${ext}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
  fileFilter: (req, file, cb) => {
    const allowed = /jpeg|jpg|png|gif|webp/;
    cb(null, allowed.test(file.mimetype));
  }
});

// ── Data store (JSON file persistence) ────────────────────────────────────────
const DATA_FILE = path.join(__dirname, 'data.json');

function loadData() {
  if (!fs.existsSync(DATA_FILE)) {
    const initial = {
      products: [
        {
          id: uuidv4(),
          name: "Sample Digital Product",
          description: "This is a demo product. Edit or delete it from your admin panel.",
          price: 9.99,
          category: "Digital",
          image: null,
          badge: "NEW",
          stock: 999,
          createdAt: new Date().toISOString()
        }
      ]
    };
    fs.writeFileSync(DATA_FILE, JSON.stringify(initial, null, 2));
    return initial;
  }
  return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
}

function saveData(data) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}

// ── Auth middleware ────────────────────────────────────────────────────────────
function requireAdmin(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const decoded = jwt.verify(auth.split(' ')[1], JWT_SECRET);
    if (decoded.role !== 'admin') throw new Error();
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ── Routes ─────────────────────────────────────────────────────────────────────

// Health check
app.get('/api/health', (req, res) => res.json({ status: 'online', store: "No Man's Land" }));

// Admin login
app.post('/api/admin/login', async (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'Password required' });

  const valid = await bcrypt.compare(password, ADMIN_PASSWORD_HASH);
  if (!valid) return res.status(401).json({ error: 'Wrong password' });

  const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ token, expiresIn: '24h' });
});

// Get all products (public)
app.get('/api/products', (req, res) => {
  const data = loadData();
  res.json(data.products);
});

// Get single product (public)
app.get('/api/products/:id', (req, res) => {
  const data = loadData();
  const product = data.products.find(p => p.id === req.params.id);
  if (!product) return res.status(404).json({ error: 'Product not found' });
  res.json(product);
});

// Create product (admin only)
app.post('/api/products', requireAdmin, upload.single('image'), (req, res) => {
  const { name, description, price, category, badge, stock } = req.body;
  if (!name || !price) return res.status(400).json({ error: 'Name and price required' });

  const data = loadData();
  const product = {
    id: uuidv4(),
    name,
    description: description || '',
    price: parseFloat(price),
    category: category || 'Digital',
    image: req.file ? `/uploads/${req.file.filename}` : null,
    badge: badge || null,
    stock: parseInt(stock) || 999,
    createdAt: new Date().toISOString()
  };
  data.products.unshift(product);
  saveData(data);
  res.status(201).json(product);
});

// Update product (admin only)
app.put('/api/products/:id', requireAdmin, upload.single('image'), (req, res) => {
  const data = loadData();
  const idx = data.products.findIndex(p => p.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Product not found' });

  const { name, description, price, category, badge, stock } = req.body;
  const existing = data.products[idx];

  // Delete old image if new one uploaded
  if (req.file && existing.image) {
    const oldPath = path.join(__dirname, existing.image);
    if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
  }

  data.products[idx] = {
    ...existing,
    name: name || existing.name,
    description: description !== undefined ? description : existing.description,
    price: price !== undefined ? parseFloat(price) : existing.price,
    category: category || existing.category,
    badge: badge !== undefined ? badge : existing.badge,
    stock: stock !== undefined ? parseInt(stock) : existing.stock,
    image: req.file ? `/uploads/${req.file.filename}` : existing.image,
    updatedAt: new Date().toISOString()
  };

  saveData(data);
  res.json(data.products[idx]);
});

// Delete product (admin only)
app.delete('/api/products/:id', requireAdmin, (req, res) => {
  const data = loadData();
  const idx = data.products.findIndex(p => p.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Product not found' });

  // Delete image file
  const product = data.products[idx];
  if (product.image) {
    const imgPath = path.join(__dirname, product.image);
    if (fs.existsSync(imgPath)) fs.unlinkSync(imgPath);
  }

  data.products.splice(idx, 1);
  saveData(data);
  res.json({ success: true });
});

// Catch-all: serve frontend
app.get('*', (req, res) => {
  const indexPath = path.join(__dirname, 'public', 'index.html');
  if (fs.existsSync(indexPath)) {
    res.sendFile(indexPath);
  } else {
    res.json({ message: "No Man's Land API is running. Frontend not found in /public." });
  }
});

app.listen(PORT, () => {
  console.log(`\n🔫 No Man's Land Store running on port ${PORT}`);
  console.log(`   API: http://localhost:${PORT}/api`);
  console.log(`   Admin password: ${process.env.ADMIN_PASSWORD || 'admin123'} (change via ADMIN_PASSWORD env var)\n`);
});
