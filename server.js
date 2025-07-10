require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

// Initialize Express app
const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Database connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/gold_vault', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('MongoDB connected'))
.catch(err => console.log(err));

// Database Models
const UserSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  role: { type: String, enum: ['user', 'staff', 'admin'], default: 'user' },
  createdAt: { type: Date, default: Date.now }
});

UserSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

UserSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', UserSchema);

const AssetSchema = new mongoose.Schema({
  name: { type: String, default: 'Gold Trunk Boxes' },
  description: String,
  originalValue: { type: Number, default: 25800000 },
  currentValue: { type: Number, default: 36200000 },
  demurrageRate: { type: Number, default: 20 },
  depositDate: { type: Date, default: new Date(Date.now() - 5 * 365 * 24 * 60 * 60 * 1000) },
  status: { type: String, enum: ['stored', 'pending', 'released'], default: 'stored' },
  lastUpdated: { type: Date, default: Date.now }
});

const Asset = mongoose.model('Asset', AssetSchema);

const DocumentSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  type: String,
  fileUrl: String,
  uploadedAt: { type: Date, default: Date.now }
});

const Document = mongoose.model('Document', DocumentSchema);

const RequestSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  assetId: { type: mongoose.Schema.Types.ObjectId, ref: 'Asset' },
  documents: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Document' }],
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  createdAt: { type: Date, default: Date.now },
  processedAt: Date,
  processedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
});

const Request = mongoose.model('Request', RequestSchema);

// Auth Middleware
const authenticate = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).send('Access denied');

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET || 'goldvaultsecret');
    next();
  } catch (err) {
    res.status(400).send('Invalid token');
  }
};

const authorize = (role) => (req, res, next) => {
  if (req.user.role !== role) return res.status(403).send('Insufficient permissions');
  next();
};

// File Upload Configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'public/uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, `${uuidv4()}-${file.originalname}`);
  }
});

const upload = multer({ storage });

// Routes

// Auth Routes
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    const user = new User({ name, email, password, role });
    await user.save();
    
    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET || 'goldvaultsecret', {
      expiresIn: '1d'
    });
    
    res.status(201).send({ user: { id: user._id, name: user.name, email: user.email, role: user.role }, token });
  } catch (err) {
    res.status(400).send(err.message);
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).send('Invalid credentials');

    const isMatch = await user.comparePassword(password);
    if (!isMatch) return res.status(400).send('Invalid credentials');

    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET || 'goldvaultsecret', {
      expiresIn: '1d'
    });

    res.send({ user: { id: user._id, name: user.name, email: user.email, role: user.role }, token });
  } catch (err) {
    res.status(500).send('Server error');
  }
});

// Asset Routes
app.get('/api/assets', authenticate, async (req, res) => {
  try {
    const assets = await Asset.find();
    res.send(assets);
  } catch (err) {
    res.status(500).send('Server error');
  }
});

// Document Routes
app.post('/api/documents', authenticate, upload.single('document'), async (req, res) => {
  try {
    const { type } = req.body;
    const document = new Document({
      userId: req.user.id,
      type,
      fileUrl: `/uploads/${req.file.filename}`
    });
    await document.save();
    res.status(201).send(document);
  } catch (err) {
    res.status(500).send('Server error');
  }
});

app.get('/api/documents', authenticate, async (req, res) => {
  try {
    const documents = await Document.find({ userId: req.user.id });
    res.send(documents);
  } catch (err) {
    res.status(500).send('Server error');
  }
});

// Request Routes
app.post('/api/requests', authenticate, async (req, res) => {
  try {
    const { assetId, documentIds } = req.body;
    const request = new Request({
      userId: req.user.id,
      assetId,
      documents: documentIds
    });
    await request.save();
    
    // Update asset status
    await Asset.findByIdAndUpdate(assetId, { status: 'pending' });
    
    res.status(201).send(request);
  } catch (err) {
    res.status(500).send('Server error');
  }
});

// Admin Routes
app.get('/api/admin/requests', authenticate, authorize('admin'), async (req, res) => {
  try {
    const requests = await Request.find().populate('userId', 'name email').populate('assetId');
    res.send(requests);
  } catch (err) {
    res.status(500).send('Server error');
  }
});

app.put('/api/admin/requests/:id', authenticate, authorize('admin'), async (req, res) => {
  try {
    const { status } = req.body;
    const request = await Request.findByIdAndUpdate(
      req.params.id,
      { status, processedAt: Date.now(), processedBy: req.user.id },
      { new: true }
    );
    
    if (status === 'approved') {
      await Asset.findByIdAndUpdate(request.assetId, { status: 'released' });
    } else if (status === 'rejected') {
      await Asset.findByIdAndUpdate(request.assetId, { status: 'stored' });
    }
    
    res.send(request);
  } catch (err) {
    res.status(500).send('Server error');
  }
});

// Serve Frontend
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Initialize Sample Data
const initializeData = async () => {
  const count = await User.countDocuments();
  if (count === 0) {
    const admin = new User({
      name: 'Admin',
      email: 'admin@example.com',
      password: 'admin123',
      role: 'admin'
    });
    await admin.save();

    const staff = new User({
      name: 'Staff',
      email: 'staff@example.com',
      password: 'staff123',
      role: 'staff'
    });
    await staff.save();

    const user = new User({
      name: 'User',
      email: 'user@example.com',
      password: 'user123',
      role: 'user'
    });
    await user.save();

    const asset = new Asset({
      description: 'Two trunk boxes of gold deposited by Angela Saxe'
    });
    await asset.save();
  }
};

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, async () => {
  console.log(`Server running on port ${PORT}`);
  await initializeData();
});
