const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost/expense-tracker', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('MongoDB connected'))
.catch(err => console.error('MongoDB connection error:', err));

// Schemas
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  email: { type: String, required: true, unique: true }
});

const CategorySchema = new mongoose.Schema({
  name: { type: String, required: true },
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }
});

const ExpenseSchema = new mongoose.Schema({
  amount: { type: Number, required: true },
  description: { type: String, required: true },
  date: { type: Date, default: Date.now },
  category: { type: mongoose.Schema.Types.ObjectId, ref: 'Category', required: true },
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }
});

// Models
const User = mongoose.model('User', UserSchema);
const Category = mongoose.model('Category', CategorySchema);
const Expense = mongoose.model('Expense', ExpenseSchema);

// Authentication Middleware
const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization').replace('Bearer ', '');
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret');
    const user = await User.findById(decoded.userId);
    
    if (!user) {
      throw new Error();
    }
    
    req.user = user;
    next();
  } catch (error) {
    res.status(401).send({ error: 'Please authenticate' });
  }
};

// Routes
// User Registration
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 8);
    
    const user = new User({
      username,
      email,
      password: hashedPassword
    });
    
    await user.save();
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET || 'your_jwt_secret');
    
    res.status(201).send({ user, token });
  } catch (error) {
    res.status(400).send({ error: 'Registration failed' });
  }
});

// User Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    
    if (!user) {
      throw new Error('Invalid credentials');
    }
    
    const isMatch = await bcrypt.compare(password, user.password);
    
    if (!isMatch) {
      throw new Error('Invalid credentials');
    }
    
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET || 'your_jwt_secret');
    res.send({ user, token });
  } catch (error) {
    res.status(400).send({ error: 'Login failed' });
  }
});

// Category Routes
app.post('/api/categories', auth, async (req, res) => {
  try {
    const category = new Category({
      ...req.body,
      user: req.user._id
    });
    
    await category.save();
    res.status(201).send(category);
  } catch (error) {
    res.status(400).send({ error: 'Failed to create category' });
  }
});

app.get('/api/categories', auth, async (req, res) => {
  try {
    const categories = await Category.find({ user: req.user._id });
    res.send(categories);
  } catch (error) {
    res.status(500).send({ error: 'Failed to fetch categories' });
  }
});

// Expense Routes
app.post('/api/expenses', auth, async (req, res) => {
  try {
    const expense = new Expense({
      ...req.body,
      user: req.user._id
    });
    
    await expense.save();
    res.status(201).send(expense);
  } catch (error) {
    res.status(400).send({ error: 'Failed to create expense' });
  }
});

app.get('/api/expenses', auth, async (req, res) => {
  try {
    const expenses = await Expense.find({ user: req.user._id })
      .populate('category')
      .sort({ date: -1 });
    res.send(expenses);
  } catch (error) {
    res.status(500).send({ error: 'Failed to fetch expenses' });
  }
});

app.patch('/api/expenses/:id', auth, async (req, res) => {
  try {
    const expense = await Expense.findOne({ _id: req.params.id, user: req.user._id });
    
    if (!expense) {
      return res.status(404).send({ error: 'Expense not found' });
    }
    
    Object.assign(expense, req.body);
    await expense.save();
    res.send(expense);
  } catch (error) {
    res.status(400).send({ error: 'Failed to update expense' });
  }
});

app.delete('/api/expenses/:id', auth, async (req, res) => {
  try {
    const expense = await Expense.findOneAndDelete({ _id: req.params.id, user: req.user._id });
    
    if (!expense) {
      return res.status(404).send({ error: 'Expense not found' });
    }
    
    res.send(expense);
  } catch (error) {
    res.status(500).send({ error: 'Failed to delete expense' });
  }
});

// Server Start
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});