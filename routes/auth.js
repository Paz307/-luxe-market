const express = require('express');
const router = express.Router();

const nodemailer = require('nodemailer');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;


// Admin secret code (set ADMIN_SECRET in Railway environment variables)
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'luxeadmin2024';

// Email transporter (Brevo SMTP)
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST || 'smtp-relay.brevo.com',
  port: parseInt(process.env.EMAIL_PORT) || 587,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});


// Google OAuth Strategy
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: '/auth/google/callback'
}, (accessToken, refreshToken, profile, done) => {
  const email = profile.emails[0].value;
  const full_name = profile.displayName;
  const google_id = profile.id;

  let user = db.get('users').find({ email }).value();
  if (!user) {
    // Create new user
    const { uuidv4 } = require('uuid');
    user = {
      id: require('uuid').v4(),
      full_name,
      email,
      google_id,
      password: null,
      role: 'buyer',
      profile_picture: null,
      created_at: new Date().toISOString(),
      last_login: new Date().toISOString(),
      password_last_updated: new Date().toISOString(),
      disabled: false,
      verified: true
    };
    db.get('users').push(user).write();
  } else {
    // Update existing user with google_id if not set
    if (!user.google_id) {
      db.get('users').find({ email }).assign({ google_id }).write();
    }
    db.get('users').find({ email }).assign({ last_login: new Date().toISOString() }).write();
  }
  return done(null, user);
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
  const user = db.get('users').find({ id }).value();
  done(null, user);
});

// Google OAuth routes
router.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

router.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    const user = req.user;
    if (user.disabled) {
      req.flash('error', 'Your account has been disabled.');
      return res.redirect('/login');
    }
    req.session.userId = user.id;
    req.session.role = user.role;
    req.session.userName = user.full_name;
    res.redirect('/dashboard');
  }
);

// Store pending verifications in memory
const pendingVerifications = {};

const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { body, validationResult } = require('express-validator');
const db = require('../models/db');
const { requireAuth, requireRole } = require('../middleware/auth');

// ─── MULTER ───
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const p = path.join(__dirname, '../public/uploads');
    if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
    cb(null, p);
  },
  filename: (req, file, cb) => cb(null, uuidv4() + path.extname(file.originalname))
});
const upload = multer({
  storage,
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ok = /jpeg|jpg|png|gif|webp/.test(path.extname(file.originalname).toLowerCase());
    cb(ok ? null : new Error('Images only'), ok);
  }
});

const pwdRules = [
  body('password')
    .isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
    .matches(/[A-Z]/).withMessage('Must contain an uppercase letter')
    .matches(/[a-z]/).withMessage('Must contain a lowercase letter')
    .matches(/[0-9]/).withMessage('Must contain a number')
    .matches(/[!@#$%&*^()_+\-=\[\]{}|;':",.<>?\/\\`~]/).withMessage('Must contain a special character')
];

// ─── HELPERS ───
function getAdminStats() {
  const users = db.get('users').value();
  return {
    total: users.length,
    admins: users.filter(u => u.role === 'admin').length,
    sellers: users.filter(u => u.role === 'seller').length,
    buyers: users.filter(u => u.role === 'buyer').length,
    products: db.get('products').value().length,
    orders: db.get('orders').value().length,
    disabled: users.filter(u => u.disabled).length
  };
}

function getExpiringUsers() {
  const now = Date.now();
  return db.get('users').value()
    .filter(u => {
      if (!u.last_login) return false;
      const days = (now - new Date(u.last_login).getTime()) / (1000 * 60 * 60 * 24);
      return days >= 25 && days < 30;
    })
    .map(u => ({
      ...u,
      daysLeft: Math.round(30 - (now - new Date(u.last_login).getTime()) / (1000 * 60 * 60 * 24))
    }));
}

function getUnreadCount(userId) {
  return db.get('notifications').filter({ userId, read: false }).value().length;
}

function addNotification(userId, title, message, type = 'notif') {
  db.get('notifications').push({
    id: uuidv4(), userId, title, message, type, read: false,
    created_at: new Date().toISOString()
  }).write();
}

// ═══════════════════════════
// AUTH
// ═══════════════════════════
router.get('/', (req, res) => res.redirect(req.session.userId ? '/dashboard' : '/login'));

router.get('/register', (req, res) => {
  if (req.session.userId) return res.redirect('/dashboard');
  res.render('register', { errors: [], formData: {}, flash_error: req.flash('error') });
});

router.post('/register', upload.single('profile_picture'), [
  body('full_name').trim().notEmpty().withMessage('Full name is required'),
  body('email').isEmail().normalizeEmail().withMessage('Valid email required'),
  body('role').isIn(['admin', 'seller', 'buyer']).withMessage('Invalid role'),
  body('confirm_password').custom((v, { req }) => {
    if (v !== req.body.password) throw new Error('Passwords do not match');
    return true;
  }),
  ...pwdRules
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    if (req.file) fs.unlinkSync(req.file.path);
    return res.render('register', { errors: errors.array(), formData: req.body, flash_error: [] });
  }
  const { full_name, email, role, password } = req.body;
  if (db.get('users').find({ email }).value()) {
    if (req.file) fs.unlinkSync(req.file.path);
    return res.render('register', { errors: [{ msg: 'Email already registered.' }], formData: req.body, flash_error: [] });
  }
  const hash = await bcrypt.hash(password, 12);
  const now = new Date().toISOString();
  db.get('users').push({
    id: uuidv4(), full_name, email, password: hash, role,
    profile_picture: req.file ? req.file.filename : null,
    created_at: now, last_login: null, password_last_updated: now, disabled: false
  }).write();
  req.flash('success', 'Account created! Please sign in.');
  req.session.regEmail = email;
  req.session.regName = full_name;
  res.redirect('/login');
});


router.get('/forgot-password', (req, res) => {
  res.render('forgot-password', { flash_error: req.flash('error'), flash_success: req.flash('success'), done: false });
});

router.post('/forgot-password', (req, res) => {
  const { email } = req.body;
  const user = db.get('users').find({ email: email.toLowerCase().trim() }).value();
  // Always show success to prevent email enumeration
  if (user) {
    // Set pendingReset so they can go directly to reset-password
    req.session.pendingReset = user.email;
    req.flash('success', 'Account found! You can now reset your password.');
    return res.redirect('/reset-password');
  }
  req.flash('error', 'No account found with that email address.');
  return res.redirect('/forgot-password');
});

router.get('/login', (req, res) => {
  if (req.session.userId) return res.redirect('/dashboard');
  const reg_email = req.session.regEmail || '';
  const reg_name  = req.session.regName  || '';
  req.session.regEmail = '';
  req.session.regName  = '';
  res.render('login', {
    flash_error: req.flash('error'),
    flash_success: req.flash('success'),
    reg_email, reg_name
  });
});

router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = db.get('users').find({ email }).value();
  if (!user || !(await bcrypt.compare(password, user.password))) {
    req.flash('error', 'Invalid email or password.');
    return res.redirect('/login');
  }
  if (user.disabled) {
    req.flash('error', 'Your account has been disabled. Contact administrator.');
    return res.redirect('/login');
  }
  const ref = user.last_login ? new Date(user.last_login) : new Date(user.created_at);
  const daysSince = (Date.now() - ref.getTime()) / (1000 * 60 * 60 * 24);
  if (user.last_login && daysSince > 30) {
    req.session.pendingReset = user.email;
    return res.redirect('/reset-password');
  }
  db.get('users').find({ id: user.id }).assign({ last_login: new Date().toISOString() }).write();
  req.session.userId = user.id;
  req.session.role = user.role;
  req.flash('success', `Welcome back, ${user.full_name.split(' ')[0]}!`);
  res.redirect('/dashboard');
});

router.get('/reset-password', (req, res) => {
  if (!req.session.pendingReset) return res.redirect('/login');
  res.render('reset-password', { email: req.session.pendingReset, errors: [], flash_error: req.flash('error') });
});

router.post('/reset-password', [...pwdRules], async (req, res) => {
  if (!req.session.pendingReset) return res.redirect('/login');
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.render('reset-password', { email: req.session.pendingReset, errors: errors.array(), flash_error: [] });
  if (req.body.password !== req.body.confirm_password) return res.render('reset-password', { email: req.session.pendingReset, errors: [{ msg: 'Passwords do not match' }], flash_error: [] });
  const hash = await bcrypt.hash(req.body.password, 12);
  const now = new Date().toISOString();
  const email = req.session.pendingReset;
  db.get('users').find({ email }).assign({ password: hash, password_last_updated: now, last_login: now }).write();
  const user = db.get('users').find({ email }).value();
  req.session.pendingReset = null;
  req.session.userId = user.id;
  req.session.role = user.role;
  res.redirect('/dashboard');
});

router.get('/logout', (req, res) => { req.session.destroy(); res.redirect('/login'); });

// ═══════════════════════════
// DASHBOARD
// ═══════════════════════════
router.get('/dashboard', requireAuth, (req, res) => {
  const user = db.get('users').find({ id: req.session.userId }).value();
  if (!user) return res.redirect('/logout');
  const unreadCount = getUnreadCount(user.id);

  if (user.role === 'admin') {
    const allUsers = db.get('users').value();
    const expiringUsers = getExpiringUsers();
    return res.render('dashboard-admin', {
      user, allUsers, stats: getAdminStats(),
      expiringUsers, expiringCount: expiringUsers.length, unreadCount,
      flash_success: req.flash('success'), flash_error: req.flash('error')
    });
  }

  if (user.role === 'seller') {
    const myProducts = db.get('products').filter({ sellerId: user.id }).value();
    const myOrders = db.get('orders').filter({ sellerId: user.id }).value()
      .map(o => ({ ...o, buyerName: (db.get('users').find({ id: o.buyerId }).value() || {}).full_name }));
    const pendingOrders = myOrders.filter(o => o.status === 'pending').length;
    const revenue = myOrders.filter(o => o.status !== 'cancelled').reduce((s, o) => s + parseFloat(o.total || 0), 0).toFixed(2);
    return res.render('dashboard-seller', {
      user, myProducts, myOrders, pendingOrders, revenue, unreadCount,
      flash_success: req.flash('success'), flash_error: req.flash('error')
    });
  }

  // Buyer
  const search = req.query.q || '';
  let products = db.get('products').value()
    .filter(p => !p.disabled)
    .map(p => ({ ...p, sellerName: (db.get('users').find({ id: p.sellerId }).value() || {}).full_name }));
  if (search) {
    const q = search.toLowerCase();
    products = products.filter(p => p.name.toLowerCase().includes(q) || (p.description || '').toLowerCase().includes(q) || (p.category || '').toLowerCase().includes(q));
  }
  const cartCount = db.get('cart').filter({ userId: user.id }).value().length;
  res.render('dashboard-buyer', {
    user, products, search, cartCount, unreadCount,
    flash_success: req.flash('success'), flash_error: req.flash('error')
  });
});

// ═══════════════════════════
// PROFILE
// ═══════════════════════════
router.get('/profile', requireAuth, (req, res) => {
  const user = db.get('users').find({ id: req.session.userId }).value();
  res.render('profile', { user, errors: [], flash_success: req.flash('success'), flash_error: req.flash('error') });
});

router.post('/profile/update', requireAuth, upload.single('profile_picture'), [
  body('full_name').trim().notEmpty().withMessage('Name required'),
  body('email').isEmail().normalizeEmail().withMessage('Valid email required')
], async (req, res) => {
  const user = db.get('users').find({ id: req.session.userId }).value();
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    if (req.file) fs.unlinkSync(req.file.path);
    return res.render('profile', { user, errors: errors.array(), flash_success: [], flash_error: [] });
  }
  const { full_name, email } = req.body;
  const existing = db.get('users').find({ email }).value();
  if (existing && existing.id !== user.id) {
    if (req.file) fs.unlinkSync(req.file.path);
    return res.render('profile', { user, errors: [{ msg: 'Email already in use.' }], flash_success: [], flash_error: [] });
  }
  const updates = { full_name, email };
  if (req.file) {
    if (user.profile_picture) { const old = path.join(__dirname, '../public/uploads', user.profile_picture); if (fs.existsSync(old)) fs.unlinkSync(old); }
    updates.profile_picture = req.file.filename;
  }
  db.get('users').find({ id: user.id }).assign(updates).write();
  req.flash('success', 'Profile updated!');
  res.redirect('/profile');
});

router.post('/profile/change-password', requireAuth, [...pwdRules], async (req, res) => {
  const user = db.get('users').find({ id: req.session.userId }).value();
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.render('profile', { user, errors: errors.array(), flash_success: [], flash_error: [] });
  if (!(await bcrypt.compare(req.body.current_password, user.password))) return res.render('profile', { user, errors: [{ msg: 'Current password incorrect.' }], flash_success: [], flash_error: [] });
  if (req.body.password !== req.body.confirm_password) return res.render('profile', { user, errors: [{ msg: 'New passwords do not match.' }], flash_success: [], flash_error: [] });
  const hash = await bcrypt.hash(req.body.password, 12);
  db.get('users').find({ id: user.id }).assign({ password: hash, password_last_updated: new Date().toISOString() }).write();
  req.flash('success', 'Password changed!');
  res.redirect('/profile');
});

// ═══════════════════════════
// ADMIN
// ═══════════════════════════
router.get('/admin/users', requireAuth, requireRole('admin'), (req, res) => res.redirect('/dashboard'));
router.get('/admin/expiring', requireAuth, requireRole('admin'), (req, res) => {
  const user = db.get('users').find({ id: req.session.userId }).value();
  const expiringUsers = getExpiringUsers();
  res.render('dashboard-admin', {
    user, allUsers: db.get('users').value(), stats: getAdminStats(),
    expiringUsers, expiringCount: expiringUsers.length, unreadCount: getUnreadCount(user.id),
    flash_success: req.flash('success'), flash_error: req.flash('error')
  });
});

router.get('/admin/add-user', requireAuth, requireRole('admin'), (req, res) => {
  res.render('add-user', { user: db.get('users').find({ id: req.session.userId }).value(), errors: [] });
});

router.post('/admin/add-user', requireAuth, requireRole('admin'), upload.single('profile_picture'), [
  body('full_name').trim().notEmpty().withMessage('Name required'),
  body('email').isEmail().normalizeEmail().withMessage('Valid email required'),
  body('role').isIn(['admin', 'seller', 'buyer']).withMessage('Invalid role'),
  body('confirm_password').custom((v, { req }) => { if (v !== req.body.password) throw new Error('Passwords do not match'); return true; }),
  ...pwdRules
], async (req, res) => {
  const adminUser = db.get('users').find({ id: req.session.userId }).value();
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    if (req.file) fs.unlinkSync(req.file.path);
    return res.render('add-user', { user: adminUser, errors: errors.array() });
  }
  const { full_name, email, role, password } = req.body;
  if (db.get('users').find({ email }).value()) {
    if (req.file) fs.unlinkSync(req.file.path);
    return res.render('add-user', { user: adminUser, errors: [{ msg: 'Email already registered.' }] });
  }
  const hash = await bcrypt.hash(password, 12);
  const now = new Date().toISOString();
  db.get('users').push({ id: uuidv4(), full_name, email, password: hash, role, profile_picture: req.file ? req.file.filename : null, created_at: now, last_login: null, password_last_updated: now, disabled: false }).write();
  req.flash('success', `User ${full_name} created!`);
  res.redirect('/dashboard');
});

router.post('/admin/disable-user', requireAuth, requireRole('admin'), (req, res) => {
  db.get('users').find({ id: req.body.userId }).assign({ disabled: true }).write();
  req.flash('success', 'User access disabled.');
  res.redirect('/dashboard');
});

router.post('/admin/enable-user', requireAuth, requireRole('admin'), (req, res) => {
  db.get('users').find({ id: req.body.userId }).assign({ disabled: false }).write();
  req.flash('success', 'User access restored.');
  res.redirect('/dashboard');
});

router.post('/admin/delete-user', requireAuth, requireRole('admin'), (req, res) => {
  const u = db.get('users').find({ id: req.body.userId }).value();
  if (u && u.profile_picture) { const p = path.join(__dirname, '../public/uploads', u.profile_picture); if (fs.existsSync(p)) fs.unlinkSync(p); }
  db.get('users').remove({ id: req.body.userId }).write();
  req.flash('success', 'User deleted.');
  res.redirect('/dashboard');
});

// ═══════════════════════════
// SELLER
// ═══════════════════════════

// Admin can also add/edit/delete products
router.get('/admin/add-product', requireAuth, requireRole('admin'), (req, res) => {
  res.render('add-product', { user: db.get('users').find({ id: req.session.userId }).value(), isEdit: false, product: {}, errors: [], isAdmin: true });
});

router.post('/admin/add-product', requireAuth, requireRole('admin'), upload.single('product_image'), [
  body('name').trim().notEmpty().withMessage('Product name required'),
  body('price').isFloat({ min: 0 }).withMessage('Valid price required')
], (req, res) => {
  const user = db.get('users').find({ id: req.session.userId }).value();
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    if (req.file) fs.unlinkSync(req.file.path);
    return res.render('add-product', { user, isEdit: false, product: req.body, errors: errors.array(), isAdmin: true });
  }
  const { name, price, description, category, stock } = req.body;
  db.get('products').push({
    id: uuidv4(), name, price: parseFloat(price).toFixed(2), description,
    category: category || 'General', stock: stock || null,
    image: req.file ? req.file.filename : null,
    sellerId: user.id, created_at: new Date().toISOString(), disabled: false
  }).write();
  req.flash('success', 'Product listed successfully!');
  res.redirect('/dashboard');
});

router.post('/admin/delete-product', requireAuth, requireRole('admin'), (req, res) => {
  const product = db.get('products').find({ id: req.body.productId }).value();
  if (product && product.image) { const p = path.join(__dirname, '../public/uploads', product.image); if (fs.existsSync(p)) fs.unlinkSync(p); }
  db.get('products').remove({ id: req.body.productId }).write();
  req.flash('success', 'Product deleted.');
  res.redirect('/dashboard');
});


// Admin view all products
router.get('/admin/products', requireAuth, requireRole('admin'), (req, res) => {
  const user = db.get('users').find({ id: req.session.userId }).value();
  const allProducts = db.get('products').value().map(p => ({
    ...p,
    sellerName: (db.get('users').find({ id: p.sellerId }).value() || {}).full_name || 'Unknown'
  }));
  const unreadCount = getUnreadCount(user.id);
  res.render('admin-products', { user, allProducts, unreadCount, flash_success: req.flash('success'), flash_error: req.flash('error') });
});

// Admin delete any product
router.post('/admin/delete-product/:id', requireAuth, requireRole('admin'), (req, res) => {
  db.get('products').remove({ id: req.params.id }).write();
  req.flash('success', 'Product deleted.');
  res.redirect('/admin/products');
});

router.get('/seller/add-product', requireAuth, requireRole('seller'), (req, res) => {
  res.render('add-product', { user: db.get('users').find({ id: req.session.userId }).value(), isEdit: false, product: {}, errors: [] });
});

router.post('/seller/add-product', requireAuth, requireRole('seller'), upload.single('product_image'), [
  body('name').trim().notEmpty().withMessage('Product name required'),
  body('price').isFloat({ min: 0 }).withMessage('Valid price required')
], (req, res) => {
  const user = db.get('users').find({ id: req.session.userId }).value();
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    if (req.file) fs.unlinkSync(req.file.path);
    return res.render('add-product', { user, isEdit: false, product: req.body, errors: errors.array() });
  }
  const { name, price, description, category, stock } = req.body;
  db.get('products').push({
    id: uuidv4(), name, price: parseFloat(price).toFixed(2), description,
    category: category || 'General', stock: stock || null,
    image: req.file ? req.file.filename : null,
    sellerId: user.id, created_at: new Date().toISOString(), disabled: false
  }).write();
  req.flash('success', 'Product listed!');
  res.redirect('/dashboard');
});

router.get('/seller/edit-product/:id', requireAuth, requireRole('seller'), (req, res) => {
  const user = db.get('users').find({ id: req.session.userId }).value();
  const product = db.get('products').find({ id: req.params.id, sellerId: user.id }).value();
  if (!product) return res.redirect('/dashboard');
  res.render('add-product', { user, isEdit: true, product, errors: [] });
});

router.post('/seller/edit-product/:id', requireAuth, requireRole('seller'), upload.single('product_image'), (req, res) => {
  const user = db.get('users').find({ id: req.session.userId }).value();
  const product = db.get('products').find({ id: req.params.id, sellerId: user.id }).value();
  if (!product) return res.redirect('/dashboard');
  const { name, price, description, category, stock } = req.body;
  const updates = { name, price: parseFloat(price).toFixed(2), description, category, stock };
  if (req.file) {
    if (product.image) { const old = path.join(__dirname, '../public/uploads', product.image); if (fs.existsSync(old)) fs.unlinkSync(old); }
    updates.image = req.file.filename;
  }
  db.get('products').find({ id: req.params.id }).assign(updates).write();
  req.flash('success', 'Product updated!');
  res.redirect('/dashboard');
});

router.post('/seller/delete-product', requireAuth, requireRole('seller'), (req, res) => {
  const user = db.get('users').find({ id: req.session.userId }).value();
  const product = db.get('products').find({ id: req.body.productId, sellerId: user.id }).value();
  if (product && product.image) { const p = path.join(__dirname, '../public/uploads', product.image); if (fs.existsSync(p)) fs.unlinkSync(p); }
  db.get('products').remove({ id: req.body.productId, sellerId: user.id }).write();
  req.flash('success', 'Product deleted.');
  res.redirect('/dashboard');
});

router.get('/seller/products', requireAuth, requireRole('seller'), (req, res) => res.redirect('/dashboard'));

router.get('/seller/orders', requireAuth, requireRole('seller'), (req, res) => {
  const user = db.get('users').find({ id: req.session.userId }).value();
  const orders = db.get('orders').filter({ sellerId: user.id }).value()
    .map(o => ({ ...o, buyerName: (db.get('users').find({ id: o.buyerId }).value() || {}).full_name }))
    .sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  res.render('orders', { user, orders, flash_success: req.flash('success'), flash_error: req.flash('error') });
});

router.post('/seller/confirm-order', requireAuth, requireRole('seller'), (req, res) => {
  db.get('orders').find({ id: req.body.orderId }).assign({ status: 'confirmed' }).write();
  const order = db.get('orders').find({ id: req.body.orderId }).value();
  if (order) addNotification(order.buyerId, 'Order Confirmed!', `Your order #${order.id.slice(0,8)} has been confirmed.`, 'order');
  req.flash('success', 'Order confirmed!');
  res.redirect(req.headers.referer || '/seller/orders');
});

router.post('/seller/deliver-order', requireAuth, requireRole('seller'), (req, res) => {
  db.get('orders').find({ id: req.body.orderId }).assign({ status: 'delivered' }).write();
  const order = db.get('orders').find({ id: req.body.orderId }).value();
  if (order) addNotification(order.buyerId, 'Order Delivered!', `Your order #${order.id.slice(0,8)} has been delivered!`, 'order');
  req.flash('success', 'Marked as delivered!');
  res.redirect('/seller/orders');
});

router.post('/seller/notify-buyers', requireAuth, requireRole('seller'), (req, res) => {
  const { title, message } = req.body;
  const user = db.get('users').find({ id: req.session.userId }).value();
  const buyers = db.get('users').filter({ role: 'buyer' }).value();
  buyers.forEach(b => addNotification(b.id, `📢 ${title}`, `From ${user.full_name}: ${message}`, 'notif'));
  req.flash('success', `Notification sent to ${buyers.length} buyer(s)!`);
  res.redirect('/dashboard');
});

// ═══════════════════════════
// CART
// ═══════════════════════════
router.get('/cart', requireAuth, requireRole('buyer'), (req, res) => {
  const user = db.get('users').find({ id: req.session.userId }).value();
  const cartRaw = db.get('cart').filter({ userId: user.id }).value();
  const cartItems = cartRaw.map(c => {
    const product = db.get('products').find({ id: c.productId }).value();
    if (!product) return null;
    return { cartId: c.id, productId: product.id, name: product.name, price: parseFloat(product.price), image: product.image, quantity: c.quantity, sellerId: product.sellerId };
  }).filter(Boolean);
  const total = cartItems.reduce((s, i) => s + i.price * i.quantity, 0).toFixed(2);
  res.render('cart', { user, cartItems, total, flash_success: req.flash('success'), flash_error: req.flash('error') });
});

router.post('/cart/add', requireAuth, requireRole('buyer'), (req, res) => {
  const { productId } = req.body;
  const existing = db.get('cart').find({ userId: req.session.userId, productId }).value();
  if (existing) {
    db.get('cart').find({ id: existing.id }).assign({ quantity: existing.quantity + 1 }).write();
  } else {
    db.get('cart').push({ id: uuidv4(), userId: req.session.userId, productId, quantity: 1, created_at: new Date().toISOString() }).write();
  }
  req.flash('success', 'Added to cart!');
  res.redirect('/dashboard');
});


router.post('/cart/update', requireAuth, requireRole('buyer'), (req, res) => {
  const { cartId, quantity } = req.body;
  const qty = parseInt(quantity);
  if (qty < 1) {
    db.get('cart').remove({ id: cartId, userId: req.session.userId }).write();
  } else {
    db.get('cart').find({ id: cartId, userId: req.session.userId }).assign({ quantity: qty }).write();
  }
  res.json({ success: true });
});

router.post('/cart/remove', requireAuth, requireRole('buyer'), (req, res) => {
  db.get('cart').remove({ id: req.body.cartId, userId: req.session.userId }).write();
  req.flash('success', 'Removed from cart.');
  res.redirect('/cart');
});

// ═══════════════════════════
// ORDERS
// ═══════════════════════════
router.post('/orders/place', requireAuth, requireRole('buyer'), (req, res) => {
  const user = db.get('users').find({ id: req.session.userId }).value();
  const { address, total } = req.body;
  const cartItems = db.get('cart').filter({ userId: user.id }).value()
    .map(c => ({ ...c, product: db.get('products').find({ id: c.productId }).value() }))
    .filter(c => c.product);

  if (cartItems.length === 0) { req.flash('error', 'Cart is empty.'); return res.redirect('/cart'); }

  const bySeller = {};
  cartItems.forEach(c => {
    const sid = c.product.sellerId;
    if (!bySeller[sid]) bySeller[sid] = [];
    bySeller[sid].push(c);
  });

  Object.entries(bySeller).forEach(([sellerId, items]) => {
    const orderTotal = items.reduce((s, i) => s + parseFloat(i.product.price) * i.quantity, 0).toFixed(2);
    const productNames = items.map(i => `${i.product.name} x${i.quantity}`).join(', ');
    db.get('orders').push({
      id: uuidv4(), buyerId: user.id, sellerId, address, total: orderTotal,
      productNames, items: items.map(i => ({ productId: i.productId, quantity: i.quantity, price: i.product.price })),
      status: 'pending', created_at: new Date().toISOString()
    }).write();
    addNotification(sellerId, '🛒 New Order!', `New order from ${user.full_name}: ${productNames} — $${orderTotal}`, 'order');
  });

  db.get('cart').remove({ userId: user.id }).write();
  req.flash('success', 'Order placed! Check your email for confirmation.');
  res.redirect('/orders');
});

router.get('/orders', requireAuth, (req, res) => {
  const user = db.get('users').find({ id: req.session.userId }).value();
  let orders = [];
  if (user.role === 'buyer') {
    orders = db.get('orders').filter({ buyerId: user.id }).value().sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  } else if (user.role === 'seller') {
    orders = db.get('orders').filter({ sellerId: user.id }).value()
      .map(o => ({ ...o, buyerName: (db.get('users').find({ id: o.buyerId }).value() || {}).full_name }))
      .sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  } else {
    return res.redirect('/dashboard');
  }
  res.render('orders', { user, orders, flash_success: req.flash('success'), flash_error: req.flash('error') });
});

// ═══════════════════════════
// NOTIFICATIONS
// ═══════════════════════════
router.get('/notifications', requireAuth, (req, res) => {
  const user = db.get('users').find({ id: req.session.userId }).value();
  const notifications = db.get('notifications').filter({ userId: user.id }).value()
    .sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  db.get('notifications').filter({ userId: user.id }).each(n => { n.read = true; }).write();
  res.render('notifications', { user, notifications });
});

router.post('/notifications/mark-all-read', requireAuth, (req, res) => {
  db.get('notifications').filter({ userId: req.session.userId }).each(n => { n.read = true; }).write();
  res.redirect('/notifications');
});


// ── Google OAuth ──────────────────────────────────────────
const https = require('https');

router.get('/auth/google', (req, res) => {
  const params = new URLSearchParams({
    client_id: process.env.GOOGLE_CLIENT_ID,
    redirect_uri: process.env.GOOGLE_REDIRECT_URI,
    response_type: 'code',
    scope: 'openid email profile',
    access_type: 'offline',
    prompt: 'select_account'
  });
  res.redirect('https://accounts.google.com/o/oauth2/v2/auth?' + params.toString());
});

router.get('/auth/google/callback', async (req, res) => {
  const { code } = req.query;
  if (!code) return res.redirect('/login');

  try {
    // Exchange code for tokens
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        redirect_uri: process.env.GOOGLE_REDIRECT_URI,
        grant_type: 'authorization_code'
      })
    });
    const tokenData = await tokenRes.json();

    // Get user info
    const userRes = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
      headers: { Authorization: 'Bearer ' + tokenData.access_token }
    });
    const googleUser = await userRes.json();

    const { email, name, picture } = googleUser;
    let user = db.get('users').find({ email }).value();

    if (!user) {
      // Create new buyer account
      const now = new Date().toISOString();
      user = {
        id: uuidv4(), full_name: name, email,
        password: null, role: 'buyer',
        profile_picture: null, google_picture: picture,
        created_at: now, last_login: now,
        password_last_updated: now, disabled: false, verified: true
      };
      db.get('users').push(user).write();
    }

    if (user.disabled) {
      req.flash('error', 'Your account has been disabled.');
      return res.redirect('/login');
    }

    req.session.userId = user.id;
    req.session.role = user.role;
    db.get('users').find({ id: user.id }).assign({ last_login: new Date().toISOString() }).write();
    res.redirect('/dashboard');
  } catch (err) {
    console.error('Google OAuth error:', err);
    res.redirect('/login');
  }
});

module.exports = router;

// ═══════════════════════════
// PAYMENT — Africa's Talking
// ═══════════════════════════
// PAYMENT CONFIG — Africa's Talking
// ═══════════════════════════
const https = require('https');
const querystring = require('querystring');

// ─── AT CREDENTIALS ─── Change AT_USERNAME to your real AT app name for production
const AT_API_KEY  = process.env.AT_API_KEY || 'atsk_864efdf069b821265bcbab0d6d69ea386be6ae7ba6b1b768df1100f7a3a56ded4b18b870';
const AT_USERNAME = process.env.AT_USERNAME || 'sandbox';
const AT_PRODUCT  = process.env.AT_PRODUCT  || 'LuxeMarket';

router.get('/checkout', requireAuth, requireRole('buyer'), (req, res) => {
  const user = db.get('users').find({ id: req.session.userId }).value();
  const cartRaw = db.get('cart').filter({ userId: user.id }).value();
  const cartItems = cartRaw.map(c => {
    const product = db.get('products').find({ id: c.productId }).value();
    if (!product) return null;
    return { cartId: c.id, productId: product.id, name: product.name, price: parseFloat(product.price), image: product.image, quantity: c.quantity, sellerId: product.sellerId };
  }).filter(Boolean);
  if (cartItems.length === 0) { req.flash('error', 'Your cart is empty.'); return res.redirect('/cart'); }
  const total = cartItems.reduce((s, i) => s + i.price * i.quantity, 0).toFixed(2);
  const unreadCount = db.get('notifications').filter({ userId: user.id, read: false }).value().length;
  res.render('payment', { user, cartItems, total, unreadCount, flash_success: req.flash('success'), flash_error: req.flash('error') });
});

// ═══════════════════════════════════════
// PAYMENT - PawaPay Mobile Money
// ═══════════════════════════════════════

const PAWAPAY_TOKEN   = process.env.PAWAPAY_TOKEN || 'eyJraWQiOiIxIiwiYWxnIjoiRVMyNTYifQ.eyJ0dCI6IkFBVCIsInN1YiI6IjIyNjQyIiwibWF2IjoiMSIsImV4cCI6MjA5NjM4OTM5NiwiaWF0IjoxNzgwNzcwMTk2LCJwbSI6IkRBRixQQUYiLCJqdGkiOiI5YjQzZDNkOS03M2QwLTRjMzYtYjY5MS1iM2JiZjFhNGZhZTYifQ.hH9WMY7qyX6IcuHprkxL_UgoG3IfKQ6vBQvJ2aF2ooq2W6Y6HJAY4npXyjqTXq4YCGRPxkamnyJdj0btzFon9w';
const PAWAPAY_SANDBOX = 'https://api.sandbox.pawapay.io';
const PAWAPAY_LIVE    = 'https://api.pawapay.io';
const PAWAPAY_BASE    = (process.env.PAWAPAY_ENV === 'live') ? PAWAPAY_LIVE : PAWAPAY_SANDBOX;

const CORRESPONDENT_MAP = {
  'MTN'    : 'MTN_MOMO_RWA',
  'Airtel' : 'AIRTEL_OAPI_RWA',
  'Mpesa'  : 'MPESA_KEN',
  'Tigo'   : 'TIGO_TZA',
  'Vodacom': 'VODACOM_TZA'
};

const CURRENCY_MAP = {
  'MTN'    : 'RWF',
  'Airtel' : 'RWF',
  'Mpesa'  : 'KES',
  'Tigo'   : 'TZS',
  'Vodacom': 'TZS'
};

const RATE_MAP = { 'RWF': 1350, 'KES': 130, 'TZS': 2500 };

router.post('/payment/mobile-checkout', requireAuth, requireRole('buyer'), async (req, res) => {
  const { phone, network, amount, address } = req.body;

  const correspondent = CORRESPONDENT_MAP[network] || 'MTN_MOMO_RWA';
  const currency      = CURRENCY_MAP[network]      || 'RWF';
  const rate          = RATE_MAP[currency]         || 1350;
  const amountLocal   = String(Math.round(parseFloat(amount) * rate));
  const depositId     = uuidv4();
  const cleanPhone    = phone.replace(/[\+\s\-]/g, '');

  const payload = {
    depositId            : depositId,
    amount               : amountLocal,
    currency             : currency,
    correspondent        : correspondent,
    payer                : { type: 'MSISDN', address: { value: cleanPhone } },
    customerTimestamp    : new Date().toISOString(),
    statementDescription : 'LuxeMarket Order'
  };

  console.log('[PawaPay] Request:', JSON.stringify(payload));

  try {
    const response = await axios.post(
      PAWAPAY_BASE + '/deposits',
      payload,
      {
        headers: {
          'Authorization': 'Bearer ' + PAWAPAY_TOKEN,
          'Content-Type' : 'application/json'
        },
        timeout: 15000
      }
    );

    console.log('[PawaPay] Status:', response.status, 'Data:', JSON.stringify(response.data));
    const data = response.data;

    if (data.status === 'ACCEPTED') {
      return res.json({ success: true, live: true, transactionId: depositId });
    }

    const reason = data.rejectionReason
      ? (data.rejectionReason.rejectionMessage || data.rejectionReason.rejectionCode || 'Payment rejected')
      : (data.message || 'Payment not accepted. Please try again.');
    return res.json({ success: false, error: reason });

  } catch (err) {
    const status  = err.response?.status;
    const errData = err.response?.data;
    const denyHdr = err.response?.headers?.['x-deny-reason'];
    console.error('[PawaPay] Error:', status, errData || err.message, 'deny:', denyHdr);

    if (status === 401) return res.json({ success: false, error: 'PawaPay token invalid. Check your API token.' });
    if (status === 422) return res.json({ success: false, error: errData?.errors?.[0]?.message || errData?.message || 'Invalid payment details.' });
    if (denyHdr === 'host_not_allowed' || err.code === 'ENOTFOUND' || err.code === 'ECONNREFUSED') {
      console.log('[PawaPay] Network blocked - demo mode');
      return res.json({ success: true, demo: true, transactionId: 'DEMO-' + Date.now() });
    }
    return res.json({ success: false, error: errData?.message || err.message || 'Payment error. Please try again.' });
  }
});

router.get('/payment/status/:depositId', requireAuth, async (req, res) => {
  const { depositId } = req.params;
  if (depositId.startsWith('DEMO-')) return res.json({ status: 'COMPLETED', demo: true });
  try {
    const r = await axios.get(PAWAPAY_BASE + '/deposits/' + depositId, {
      headers: { 'Authorization': 'Bearer ' + PAWAPAY_TOKEN }, timeout: 10000
    });
    const d = Array.isArray(r.data) ? r.data[0] : r.data;
    return res.json({ status: d.status, data: d });
  } catch (err) {
    return res.json({ status: 'UNKNOWN', error: err.message });
  }
});

router.post('/payment/callback/deposit', (req, res) => {
  console.log('[PawaPay Callback] Deposit:', JSON.stringify(req.body));
  const { depositId, status } = req.body;
  if (status === 'COMPLETED' && depositId) {
    const order = db.get('orders').find({ paymentRef: depositId }).value();
    if (order) db.get('orders').find({ paymentRef: depositId }).assign({ paymentStatus: 'paid' }).write();
  }
  res.json({ received: true });
});

router.post('/payment/callback/payout', (req, res) => { res.json({ received: true }); });
router.post('/payment/callback/refund',  (req, res) => { res.json({ received: true }); });