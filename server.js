require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');

const app = express();

// ============================================================
//  CONNECTION STATUS TRACKING
// ============================================================
const connectionStatus = {
  mongodb: { connected: false, lastCheck: null, error: null },
  cloudinary: { connected: false, lastCheck: null, error: null }
};

// ============================================================
//  SECURITY MIDDLEWARE
// ============================================================
app.use(helmet());
app.use(cors({
  origin: ['http://localhost:3000', 'http://127.0.0.1:3000'],
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests, please try again later.' }
});
app.use('/api/', limiter);

// ============================================================
//  CLOUDINARY CONFIG
// ============================================================
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// Test Cloudinary connection
const testCloudinaryConnection = async () => {
  try {
    const result = await cloudinary.api.ping();
    connectionStatus.cloudinary.connected = true;
    connectionStatus.cloudinary.lastCheck = new Date().toISOString();
    connectionStatus.cloudinary.error = null;
    console.log('✅ Connected to Cloudinary');
    return true;
  } catch (err) {
    connectionStatus.cloudinary.connected = false;
    connectionStatus.cloudinary.lastCheck = new Date().toISOString();
    connectionStatus.cloudinary.error = err.message;
    console.error('❌ Cloudinary connection error:', err.message);
    return false;
  }
};

// Run Cloudinary test immediately
testCloudinaryConnection();

// Multer storage for Cloudinary
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'njalamarket',
    format: 'jpg',
    quality: 'auto:good'
  }
});
const upload = multer({ 
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) cb(null, true);
    else cb(new Error('Only images are allowed'), false);
  }
});

// ============================================================
//  MONGODB CONNECTION
// ============================================================
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/njalamarket', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => {
  connectionStatus.mongodb.connected = true;
  connectionStatus.mongodb.lastCheck = new Date().toISOString();
  connectionStatus.mongodb.error = null;
  console.log('✅ Connected to MongoDB');
})
.catch(err => {
  connectionStatus.mongodb.connected = false;
  connectionStatus.mongodb.lastCheck = new Date().toISOString();
  connectionStatus.mongodb.error = err.message;
  console.error('❌ MongoDB connection error:', err);
});

// Monitor MongoDB connection
mongoose.connection.on('disconnected', () => {
  connectionStatus.mongodb.connected = false;
  connectionStatus.mongodb.lastCheck = new Date().toISOString();
  connectionStatus.mongodb.error = 'Disconnected from MongoDB';
  console.warn('⚠️ MongoDB disconnected');
});

mongoose.connection.on('reconnected', () => {
  connectionStatus.mongodb.connected = true;
  connectionStatus.mongodb.lastCheck = new Date().toISOString();
  connectionStatus.mongodb.error = null;
  console.log('✅ MongoDB reconnected');
});

// ============================================================
//  MODELS
// ============================================================

// User Model
const User = mongoose.model('User', {
  name: { type: String, required: true },
  email: { type: String, unique: true, required: true },
  phone: { type: String, required: true },
  district: String,
  password: { type: String, required: true },
  role: { type: String, default: 'user' },
  isVerified: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

// Product Model
const Product = mongoose.model('Product', {
  title: { type: String, required: true },
  price: { type: Number, required: true },
  category: { type: String, required: true },
  condition: { type: String, required: true },
  location: { type: String, required: true },
  image: { type: String, required: true },
  phone: { type: String, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  views: { type: Number, default: 0 },
  status: { type: String, enum: ['active', 'sold', 'inactive'], default: 'active' },
  createdAt: { type: Date, default: Date.now }
});

// Property Model
const Property = mongoose.model('Property', {
  title: { type: String, required: true },
  type: { type: String, required: true },
  listingType: { type: String, required: true },
  price: { type: Number, required: true },
  bedrooms: { type: Number, default: 0 },
  bathrooms: { type: Number, default: 0 },
  location: { type: String, required: true },
  image: { type: String, required: true },
  phone: { type: String, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  views: { type: Number, default: 0 },
  status: { type: String, enum: ['active', 'inactive'], default: 'active' },
  createdAt: { type: Date, default: Date.now }
});

// Job Model
const Job = mongoose.model('Job', {
  title: { type: String, required: true },
  company: { type: String, required: true },
  employmentType: { type: String, required: true },
  salary: String,
  location: { type: String, required: true },
  description: String,
  requirements: String,
  phone: { type: String, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  status: { type: String, enum: ['active', 'closed'], default: 'active' },
  createdAt: { type: Date, default: Date.now }
});

// Site Settings Model
const SiteSettings = mongoose.model('SiteSettings', {
  key: { type: String, unique: true },
  value: mongoose.Schema.Types.Mixed
});

// ============================================================
//  AUTH MIDDLEWARE
// ============================================================
const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      return res.status(401).json({ error: 'Please authenticate' });
    }
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
    const user = await User.findById(decoded.userId).select('-password');
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }
    req.user = user;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
};

const isOwner = async (req, res, next) => {
  try {
    const { id } = req.params;
    let Model;
    if (req.baseUrl.includes('products')) Model = Product;
    else if (req.baseUrl.includes('properties')) Model = Property;
    else if (req.baseUrl.includes('jobs')) Model = Job;
    else return res.status(400).json({ error: 'Invalid resource' });

    const item = await Model.findById(id);
    if (!item) return res.status(404).json({ error: 'Not found' });
    
    if (item.userId.toString() !== req.user._id.toString() && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Not authorized' });
    }
    req.item = item;
    next();
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
};

// ============================================================
//  ROUTES
// ============================================================

// Health check with connection status
app.get('/api/health', (req, res) => {
  const allConnected = connectionStatus.mongodb.connected && connectionStatus.cloudinary.connected;
  const statusCode = allConnected ? 200 : 503;
  
  res.status(statusCode).json({
    status: allConnected ? 'ok' : 'degraded',
    timestamp: new Date().toISOString(),
    connections: {
      mongodb: {
        connected: connectionStatus.mongodb.connected,
        lastCheck: connectionStatus.mongodb.lastCheck,
        error: connectionStatus.mongodb.error
      },
      cloudinary: {
        connected: connectionStatus.cloudinary.connected,
        lastCheck: connectionStatus.cloudinary.lastCheck,
        error: connectionStatus.cloudinary.error
      }
    }
  });
});

// Status page - HTML with visual indicators
app.get('/status', (req, res) => {
  const mongoStatus = connectionStatus.mongodb.connected;
  const cloudStatus = connectionStatus.cloudinary.connected;
  const allConnected = mongoStatus && cloudStatus;
  
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Service Status - NjalaMarket</title>
      <style>
        * {
          margin: 0;
          padding: 0;
          box-sizing: border-box;
        }
        body {
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
          background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
          min-height: 100vh;
          display: flex;
          justify-content: center;
          align-items: center;
          padding: 20px;
        }
        .container {
          background: rgba(255, 255, 255, 0.05);
          backdrop-filter: blur(20px);
          border-radius: 24px;
          padding: 50px 40px;
          max-width: 600px;
          width: 100%;
          border: 1px solid rgba(255, 255, 255, 0.1);
          box-shadow: 0 25px 50px rgba(0, 0, 0, 0.5);
        }
        h1 {
          color: #f8fafc;
          font-size: 28px;
          margin-bottom: 8px;
          display: flex;
          align-items: center;
          gap: 12px;
        }
        .subtitle {
          color: #94a3b8;
          font-size: 14px;
          margin-bottom: 32px;
        }
        .status-badge {
          display: inline-block;
          padding: 6px 16px;
          border-radius: 20px;
          font-size: 13px;
          font-weight: 600;
          margin-left: 12px;
        }
        .status-badge.online {
          background: #22c55e20;
          color: #22c55e;
          border: 1px solid #22c55e40;
        }
        .status-badge.offline {
          background: #ef444420;
          color: #ef4444;
          border: 1px solid #ef444440;
        }
        .status-badge.degraded {
          background: #f59e0b20;
          color: #f59e0b;
          border: 1px solid #f59e0b40;
        }
        .services {
          display: flex;
          flex-direction: column;
          gap: 16px;
          margin: 32px 0;
        }
        .service {
          background: rgba(255, 255, 255, 0.05);
          border-radius: 16px;
          padding: 20px 24px;
          border: 1px solid rgba(255, 255, 255, 0.06);
          transition: all 0.3s ease;
        }
        .service:hover {
          background: rgba(255, 255, 255, 0.08);
        }
        .service-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
        }
        .service-name {
          display: flex;
          align-items: center;
          gap: 12px;
        }
        .service-name span {
          color: #e2e8f0;
          font-size: 16px;
          font-weight: 500;
        }
        .indicator {
          width: 12px;
          height: 12px;
          border-radius: 50%;
          display: inline-block;
          animation: pulse 2s infinite;
        }
        .indicator.online {
          background: #22c55e;
          box-shadow: 0 0 20px #22c55e60;
        }
        .indicator.offline {
          background: #ef4444;
          box-shadow: 0 0 20px #ef444460;
          animation: none;
        }
        .indicator.checking {
          background: #f59e0b;
          box-shadow: 0 0 20px #f59e0b60;
        }
        .service-status {
          font-size: 13px;
          font-weight: 500;
          padding: 4px 14px;
          border-radius: 12px;
        }
        .service-status.online {
          color: #22c55e;
          background: #22c55e20;
        }
        .service-status.offline {
          color: #ef4444;
          background: #ef444420;
        }
        .service-status.checking {
          color: #f59e0b;
          background: #f59e0b20;
        }
        .service-detail {
          color: #94a3b8;
          font-size: 13px;
          margin-top: 8px;
          display: flex;
          gap: 16px;
        }
        .service-detail .label {
          color: #64748b;
        }
        .error-msg {
          color: #ef4444;
          font-size: 13px;
          margin-top: 8px;
          padding: 8px 12px;
          background: #ef444420;
          border-radius: 8px;
          border-left: 3px solid #ef4444;
        }
        .overall-status {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 16px 20px;
          background: rgba(255, 255, 255, 0.05);
          border-radius: 12px;
          margin-top: 8px;
        }
        .overall-status .label {
          color: #94a3b8;
          font-size: 14px;
        }
        .overall-status .status {
          font-weight: 600;
          font-size: 16px;
        }
        .overall-status .status.online {
          color: #22c55e;
        }
        .overall-status .status.offline {
          color: #ef4444;
        }
        .overall-status .status.degraded {
          color: #f59e0b;
        }
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.5; }
        }
        .footer {
          margin-top: 24px;
          padding-top: 16px;
          border-top: 1px solid rgba(255, 255, 255, 0.06);
          display: flex;
          justify-content: space-between;
          align-items: center;
        }
        .footer span {
          color: #64748b;
          font-size: 12px;
        }
        .refresh-btn {
          background: rgba(255, 255, 255, 0.08);
          border: 1px solid rgba(255, 255, 255, 0.1);
          color: #e2e8f0;
          padding: 8px 20px;
          border-radius: 10px;
          cursor: pointer;
          font-size: 13px;
          transition: all 0.3s ease;
        }
        .refresh-btn:hover {
          background: rgba(255, 255, 255, 0.15);
        }
        .logo {
          display: flex;
          align-items: center;
          gap: 12px;
        }
        .logo-icon {
          width: 36px;
          height: 36px;
          background: linear-gradient(135deg, #22c55e, #16a34a);
          border-radius: 10px;
          display: flex;
          align-items: center;
          justify-content: center;
          color: white;
          font-weight: bold;
          font-size: 18px;
        }
        @media (max-width: 480px) {
          .container { padding: 30px 20px; }
          .service { padding: 16px; }
          .service-detail { flex-direction: column; gap: 4px; }
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="logo">
          <div class="logo-icon">NM</div>
          <h1>
            NjalaMarket
            <span class="status-badge ${allConnected ? 'online' : mongoStatus ? 'degraded' : 'offline'}">
              ${allConnected ? '● Online' : mongoStatus ? '⚠ Degraded' : '✕ Offline'}
            </span>
          </h1>
        </div>
        <p class="subtitle">Real-time service status dashboard</p>
        
        <div class="services">
          <!-- MongoDB -->
          <div class="service">
            <div class="service-header">
              <div class="service-name">
                <span class="indicator ${mongoStatus ? 'online' : 'offline'}"></span>
                <span>MongoDB</span>
              </div>
              <span class="service-status ${mongoStatus ? 'online' : 'offline'}">
                ${mongoStatus ? '● Connected' : '✕ Disconnected'}
              </span>
            </div>
            <div class="service-detail">
              <span><span class="label">Last Check:</span> ${connectionStatus.mongodb.lastCheck || 'Never'}</span>
            </div>
            ${connectionStatus.mongodb.error ? `<div class="error-msg">⚠ ${connectionStatus.mongodb.error}</div>` : ''}
          </div>

          <!-- Cloudinary -->
          <div class="service">
            <div class="service-header">
              <div class="service-name">
                <span class="indicator ${cloudStatus ? 'online' : 'offline'}"></span>
                <span>Cloudinary</span>
              </div>
              <span class="service-status ${cloudStatus ? 'online' : 'offline'}">
                ${cloudStatus ? '● Connected' : '✕ Disconnected'}
              </span>
            </div>
            <div class="service-detail">
              <span><span class="label">Last Check:</span> ${connectionStatus.cloudinary.lastCheck || 'Never'}</span>
            </div>
            ${connectionStatus.cloudinary.error ? `<div class="error-msg">⚠ ${connectionStatus.cloudinary.error}</div>` : ''}
          </div>
        </div>

        <div class="overall-status">
          <span class="label">Overall System Status</span>
          <span class="status ${allConnected ? 'online' : mongoStatus ? 'degraded' : 'offline'}">
            ${allConnected ? '✅ All Systems Operational' : mongoStatus ? '⚠ Partial Service' : '❌ Service Unavailable'}
          </span>
        </div>

        <div class="footer">
          <span>Updated: ${new Date().toLocaleString()}</span>
          <button class="refresh-btn" onclick="location.reload()">⟳ Refresh</button>
        </div>
      </div>
    </body>
    </html>
  `);
});

// ============================================================
//  AUTH ROUTES
// ============================================================

// Register
app.post('/api/auth/register', [
  body('name').notEmpty().withMessage('Name is required'),
  body('email').isEmail().withMessage('Valid email is required'),
  body('phone').notEmpty().withMessage('Phone is required'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { name, email, phone, district, password } = req.body;
    
    // Check if user exists
    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Create user
    const user = new User({
      name,
      email,
      phone,
      district,
      password: hashedPassword
    });
    await user.save();

    // Generate token
    const token = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '7d' }
    );

    res.status(201).json({
      success: true,
      token,
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        district: user.district,
        role: user.role
      }
    });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Server error during registration' });
  }
});

// Login
app.post('/api/auth/login', [
  body('email').isEmail().withMessage('Valid email is required'),
  body('password').notEmpty().withMessage('Password is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { email, password } = req.body;
    
    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check password
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate token
    const token = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      token,
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        district: user.district,
        role: user.role
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error during login' });
  }
});

// Get current user
app.get('/api/auth/me', auth, async (req, res) => {
  res.json({ user: req.user });
});

// ============================================================
//  PRODUCT ROUTES
// ============================================================

// Get all products
app.get('/api/products', async (req, res) => {
  try {
    const { category, location, search, sort = '-createdAt' } = req.query;
    const filter = { status: 'active' };
    if (category) filter.category = category;
    if (location) filter.location = new RegExp(location, 'i');
    if (search) filter.title = new RegExp(search, 'i');
    
    const products = await Product.find(filter)
      .sort(sort)
      .populate('userId', 'name phone')
      .lean();
    
    res.json({ products });
  } catch (err) {
    console.error('Get products error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get single product
app.get('/api/products/:id', async (req, res) => {
  try {
    const product = await Product.findByIdAndUpdate(
      req.params.id,
      { $inc: { views: 1 } },
      { new: true }
    ).populate('userId', 'name phone district');
    
    if (!product) return res.status(404).json({ error: 'Product not found' });
    res.json({ product });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Create product
app.post('/api/products', auth, upload.single('image'), async (req, res) => {
  try {
    const { title, price, category, condition, location, phone } = req.body;
    const image = req.file?.path || req.body.imageData || 'https://placehold.co/600x400/1e2f3d/white?text=Product';
    
    const product = new Product({
      title,
      price: parseFloat(price),
      category,
      condition,
      location,
      phone,
      image,
      userId: req.user._id
    });
    await product.save();
    
    res.status(201).json({ success: true, product });
  } catch (err) {
    console.error('Create product error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update product
app.put('/api/products/:id', auth, isOwner, upload.single('image'), async (req, res) => {
  try {
    const { title, price, category, condition, location, phone, status } = req.body;
    const image = req.file?.path || req.body.imageData;
    
    const updates = { title, price, category, condition, location, phone, status };
    if (image) updates.image = image;
    
    const product = await Product.findByIdAndUpdate(
      req.params.id,
      updates,
      { new: true, runValidators: true }
    );
    
    res.json({ success: true, product });
  } catch (err) {
    console.error('Update product error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete product
app.delete('/api/products/:id', auth, isOwner, async (req, res) => {
  try {
    await Product.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ============================================================
//  PROPERTY ROUTES
// ============================================================

// Get all properties
app.get('/api/properties', async (req, res) => {
  try {
    const { type, listingType, search, sort = '-createdAt' } = req.query;
    const filter = { status: 'active' };
    if (type) filter.type = type;
    if (listingType) filter.listingType = listingType;
    if (search) filter.title = new RegExp(search, 'i');
    
    const properties = await Property.find(filter)
      .sort(sort)
      .populate('userId', 'name phone')
      .lean();
    
    res.json({ properties });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get single property
app.get('/api/properties/:id', async (req, res) => {
  try {
    const property = await Property.findByIdAndUpdate(
      req.params.id,
      { $inc: { views: 1 } },
      { new: true }
    ).populate('userId', 'name phone district');
    
    if (!property) return res.status(404).json({ error: 'Property not found' });
    res.json({ property });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Create property
app.post('/api/properties', auth, upload.single('image'), async (req, res) => {
  try {
    const { title, type, listingType, price, bedrooms, bathrooms, location, phone } = req.body;
    const image = req.file?.path || req.body.imageData || 'https://placehold.co/600x400/2b4f5c/white?text=Property';
    
    const property = new Property({
      title,
      type,
      listingType,
      price: parseFloat(price),
      bedrooms: parseInt(bedrooms) || 0,
      bathrooms: parseInt(bathrooms) || 0,
      location,
      phone,
      image,
      userId: req.user._id
    });
    await property.save();
    
    res.status(201).json({ success: true, property });
  } catch (err) {
    console.error('Create property error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update property
app.put('/api/properties/:id', auth, isOwner, upload.single('image'), async (req, res) => {
  try {
    const { title, type, listingType, price, bedrooms, bathrooms, location, phone, status } = req.body;
    const image = req.file?.path || req.body.imageData;
    
    const updates = {
      title, type, listingType,
      price: parseFloat(price),
      bedrooms: parseInt(bedrooms) || 0,
      bathrooms: parseInt(bathrooms) || 0,
      location, phone, status
    };
    if (image) updates.image = image;
    
    const property = await Property.findByIdAndUpdate(
      req.params.id,
      updates,
      { new: true, runValidators: true }
    );
    
    res.json({ success: true, property });
  } catch (err) {
    console.error('Update property error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete property
app.delete('/api/properties/:id', auth, isOwner, async (req, res) => {
  try {
    await Property.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ============================================================
//  JOB ROUTES
// ============================================================

// Get all jobs
app.get('/api/jobs', async (req, res) => {
  try {
    const { employmentType, search, sort = '-createdAt' } = req.query;
    const filter = { status: 'active' };
    if (employmentType) filter.employmentType = employmentType;
    if (search) filter.title = new RegExp(search, 'i');
    
    const jobs = await Job.find(filter)
      .sort(sort)
      .populate('userId', 'name phone')
      .lean();
    
    res.json({ jobs });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get single job
app.get('/api/jobs/:id', async (req, res) => {
  try {
    const job = await Job.findById(req.params.id).populate('userId', 'name phone district');
    if (!job) return res.status(404).json({ error: 'Job not found' });
    res.json({ job });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Create job
app.post('/api/jobs', auth, async (req, res) => {
  try {
    const { title, company, employmentType, salary, location, description, requirements, phone } = req.body;
    
    const job = new Job({
      title,
      company,
      employmentType,
      salary,
      location,
      description,
      requirements,
      phone,
      userId: req.user._id
    });
    await job.save();
    
    res.status(201).json({ success: true, job });
  } catch (err) {
    console.error('Create job error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update job
app.put('/api/jobs/:id', auth, isOwner, async (req, res) => {
  try {
    const { title, company, employmentType, salary, location, description, requirements, phone, status } = req.body;
    
    const job = await Job.findByIdAndUpdate(
      req.params.id,
      { title, company, employmentType, salary, location, description, requirements, phone, status },
      { new: true, runValidators: true }
    );
    
    res.json({ success: true, job });
  } catch (err) {
    console.error('Update job error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete job
app.delete('/api/jobs/:id', auth, isOwner, async (req, res) => {
  try {
    await Job.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ============================================================
//  DASHBOARD ROUTE
// ============================================================

app.get('/api/dashboard', auth, async (req, res) => {
  try {
    const [products, properties, jobs] = await Promise.all([
      Product.find({ userId: req.user._id }),
      Property.find({ userId: req.user._id }),
      Job.find({ userId: req.user._id })
    ]);
    
    res.json({
      stats: {
        products: products.length,
        properties: properties.length,
        jobs: jobs.length
      },
      products,
      properties,
      jobs
    });
  } catch (err) {
    console.error('Dashboard error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============================================================
//  SITE SETTINGS ROUTES
// ============================================================

app.get('/api/settings/:key', async (req, res) => {
  try {
    const setting = await SiteSettings.findOne({ key: req.params.key });
    res.json({ value: setting?.value || null });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/settings', auth, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    const { key, value } = req.body;
    await SiteSettings.findOneAndUpdate(
      { key },
      { key, value },
      { upsert: true }
    );
    res.json({ success: true });
  } catch (err) {
    console.error('Update setting error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============================================================
//  START SERVER
// ============================================================

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`📡 API endpoint: http://localhost:${PORT}/api`);
  console.log(`📊 Status page: http://localhost:${PORT}/status`);
});