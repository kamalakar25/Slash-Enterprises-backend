// server/index.js
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const multer = require("multer");
const path = require("path");
require("dotenv").config();

const app = express();

// Multer Configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "uploads/"),
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(
      null,
      file.fieldname + "-" + uniqueSuffix + path.extname(file.originalname)
    );
  },
});

const fileFilter = (req, file, cb) => {
  const filetypes = /jpeg|jpg|png/;
  const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
  const mimetype = filetypes.test(file.mimetype);
  extname && mimetype
    ? cb(null, true)
    : cb(new Error("Only images (jpeg, jpg, png) are allowed"));
};

const upload = multer({
  storage,
  limits: { fileSize: 5000000 }, // 5MB limit
  fileFilter,
});

// Middleware
app.use(
  cors({
    origin: (origin, callback) => {
      const allowedOrigins = [
        "http://localhost:3000",
        "http://localhost:3001",
        "https://covercraft.vercel.app",
      ];
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true,
  })
);
app.use(express.json());
app.use("/uploads", express.static("uploads"));

// MongoDB Connection
mongoose
  .connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("MongoDB connection error:", err));

// Schemas
const productSchema = new mongoose.Schema({
  name: String,
  model: String,
  image: String,
  description: String,
  rentalRates: {
    daily: { type: Number, required: true },
    weekly: { type: Number, required: true },
    monthly: { type: Number, required: true },
  },
  category: String,
  inStock: { type: Boolean, default: true },
  rating: { type: Number, default: 4.5 },
  reviews: { type: Number, default: 0 },
  minimumRentalPeriod: { type: Number, default: 1 }, // In days
});

const cartSchema = new mongoose.Schema({
  userId: String,
  items: [
    {
      productId: { type: mongoose.Schema.Types.ObjectId, ref: "Product" },
      quantity: Number,
      rentalPeriod: { type: String, enum: ["daily", "weekly", "monthly"] },
      rentalDays: Number,
    },
  ],
});

const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true, minlength: 2 },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
  },
  password: { type: String, required: true, minlength: 8 },
  role: { type: String, enum: ["user", "admin"], default: "user" },
  createdAt: { type: Date, default: Date.now },
});

const orderSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  items: [
    {
      productId: { type: mongoose.Schema.Types.ObjectId, ref: "Product" },
      quantity: Number,
      rentalPeriod: String,
      rentalDays: Number,
      rate: Number,
    },
  ],
  totalAmount: Number,
  shippingAddress: {
    name: String,
    address: String,
    city: String,
    state: String,
    zipCode: String,
    phone: String,
  },
  paymentMethod: String,
  paymentStatus: { type: String, default: "Pending" },
  orderStatus: { type: String, default: "Processing" },
  createdAt: { type: Date, default: Date.now },
});

// Models
const Product = mongoose.model("Product", productSchema);
const Cart = mongoose.model("Cart", cartSchema);
const User = mongoose.model("User", userSchema);
const Order = mongoose.model("Order", orderSchema);

// Authentication Middleware
const authMiddleware = async (req, res, next) => {
  try {
    const token = req.header("Authorization")?.replace("Bearer ", "");
    if (!token) throw new Error("No token provided");

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user) throw new Error("User not found");

    req.user = user;
    req.token = token;
    next();
  } catch (error) {
    res.status(401).json({ error: "Please authenticate" });
  }
};

// Routes
// Authentication Routes
app.post("/api/auth/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser)
      return res.status(400).json({ error: "Email already registered" });

    const hashedPassword = await bcrypt.hash(password, 12);
    const user = new User({
      name,
      email,
      password: hashedPassword,
      role: email === "admin@example.com" ? "admin" : "user",
    });
    await user.save();

    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );
    res.status(201).json({
      message: "User created successfully",
      user: { id: user._id, name, email, role: user.role },
      token,
    });
  } catch (error) {
    res.status(500).json({ error: "Error creating user" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );
    res.json({
      user: { id: user._id, name: user.name, email, role: user.role },
      token,
    });
  } catch (error) {
    res.status(500).json({ error: "Error logging in" });
  }
});

app.get("/api/auth/me", authMiddleware, (req, res) => {
  res.json({
    user: {
      id: req.user._id,
      name: req.user.name,
      email: req.user.email,
      role: req.user.role,
    },
  });
});

app.post("/api/auth/logout", authMiddleware, (req, res) => {
  res.json({ message: "Logged out successfully" });
});

// Product Routes
app.get("/api/products", async (req, res) => {
  try {
    const products = await Product.find();
    res.json(products);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/products/:id", async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ message: "Product not found" });
    res.json(product);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/products/:category", async (req, res) => {
  try {
    const { category } = req.params;
    const query = category === "all" ? {} : { category };
    const products = await Product.find(query);
    res.json(products);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.get("/api/products/detail/:productId", async (req, res) => {
  try {
    const product = await Product.findById(req.params.productId);
    if (!product) return res.status(404).json({ error: "Product not found" });
    res.json(product);
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/add-products", upload.single("image"), async (req, res) => {
  try {
    const {
      name,
      model,
      description,
      dailyRate,
      weeklyRate,
      monthlyRate,
      category,
      inStock,
    } = req.body;
    const product = new Product({
      name,
      model,
      image: req.file ? `/uploads/${req.file.filename}` : "",
      description,
      rentalRates: {
        daily: Number(dailyRate),
        weekly: Number(weeklyRate),
        monthly: Number(monthlyRate),
      },
      category,
      inStock: inStock === "true",
    });
    await product.save();
    res.status(201).json({ message: "Product added successfully", product });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 3. PUT /api/products/:id - Update an existing product
app.put('/api/products/:id', upload.single('image'), async (req, res) => {
  try {
    console.log("PUT Request Body:", req.body, "File:", req.file);
    const { name, model, description, dailyRate, weeklyRate, monthlyRate, category, inStock, rating, reviews } = req.body;

    // Validate required fields
    if (!name || !model || !description || !dailyRate || !weeklyRate || !monthlyRate || !category) {
      return res.status(400).json({ message: "All fields except image are required" });
    }

    const updateData = {
      name,
      model,
      description,
      rentalRates: {
        daily: parseFloat(dailyRate) || 0,
        weekly: parseFloat(weeklyRate) || 0,
        monthly: parseFloat(monthlyRate) || 0,
      },
      category,
      inStock: inStock === "true",
      rating: parseFloat(rating) || 4.5,
      reviews: parseInt(reviews) || 0,
    };

    if (req.file) {
      updateData.image = `/uploads/${req.file.filename}`;
    } // Keep existing image if no new file uploaded

    const product = await Product.findByIdAndUpdate(req.params.id, updateData, { new: true });
    if (!product) {
      return res.status(404).json({ message: "Product not found" });
    }

    console.log("Updated Product:", product);
    res.json(product);
  } catch (err) {
    console.error("PUT Error:", err);
    res.status(500).json({ message: "Error updating product", error: err.message });
  }
});

// 4. DELETE /api/products/:id - Delete a product
app.delete('/api/products/:id', async (req, res) => {
  try {
    const product = await Product.findByIdAndDelete(req.params.id);
    if (!product) return res.status(404).json({ message: 'Product not found' });
    res.json({ message: 'Product deleted' });
  } catch (err) {
    res.status(500).json({ message: 'Error deleting product', error: err.message });
  }
});

// Cart Routes
app.post("/api/cart/add", async (req, res) => {
  try {
    const { userId, productId, quantity, rentalPeriod, rentalDays } = req.body;
    let cart =
      (await Cart.findOne({ userId })) || new Cart({ userId, items: [] });

    const existingItemIndex = cart.items.findIndex(
      (item) => item.productId.toString() === productId
    );
    if (existingItemIndex > -1) {
      cart.items[existingItemIndex].quantity += quantity;
      cart.items[existingItemIndex].rentalPeriod = rentalPeriod;
      cart.items[existingItemIndex].rentalDays = rentalDays;
    } else {
      cart.items.push({ productId, quantity, rentalPeriod, rentalDays });
    }

    await cart.save();
    res.json(cart);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.get('/api/cart/:userId', async (req, res) => {
  try {
    const userId = req.params.userId;
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ message: "Invalid user ID" });
    }
    const cart = await Cart.findOne({ userId }).populate('items.productId');
    if (!cart) {
      return res.status(404).json({ message: "Cart not found" });
    }
    res.json(cart);
  } catch (err) {
    console.error("Error in /cart/:userId:", err);
    res.status(500).json({ message: "Internal Server Error", error: err.message });
  }
});

app.patch("/api/cart/:userId/item/:productId", async (req, res) => {
  try {
    const { userId, productId } = req.params;
    const { quantity, rentalPeriod, rentalDays } = req.body;

    let cart =
      (await Cart.findOne({ userId })) || new Cart({ userId, items: [] });
    const itemIndex = cart.items.findIndex(
      (item) => item.productId.toString() === productId
    );

    if (itemIndex > -1) {
      cart.items[itemIndex].quantity = quantity;
      cart.items[itemIndex].rentalPeriod = rentalPeriod;
      cart.items[itemIndex].rentalDays = rentalDays;
    } else {
      cart.items.push({ productId, quantity, rentalPeriod, rentalDays });
    }

    await cart.save();
    res.json(cart);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.delete("/api/cart/:userId/item/:productId", async (req, res) => {
  try {
    const { userId, productId } = req.params;
    const cart = await Cart.findOne({ userId });
    if (!cart) return res.status(404).json({ message: "Cart not found" });

    cart.items = cart.items.filter(
      (item) => item.productId.toString() !== productId
    );
    await cart.save();
    res.json(cart);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Order Routes
app.post("/api/orders", authMiddleware, async (req, res) => {
  try {
    const { items, totalAmount, shippingAddress, paymentMethod } = req.body;
    const newOrder = new Order({
      userId: req.user._id,
      items: items.map((item) => ({
        productId: item.productId,
        quantity: item.quantity,
        rentalPeriod: item.rentalPeriod,
        rentalDays: item.rentalDays,
        rate: item.rate,
      })),
      totalAmount,
      shippingAddress,
      paymentMethod,
    });

    await newOrder.save();
    await Cart.findOneAndUpdate(
      { userId: req.user._id },
      { $set: { items: [] } }
    );
    newOrder.paymentStatus = "Paid";
    newOrder.orderStatus = "Confirmed";
    await newOrder.save();

    res
      .status(201)
      .json({ message: "Order placed successfully", orderId: newOrder._id });
  } catch (error) {
    res.status(500).json({ error: "Error creating order" });
  }
});

app.get("/api/orders", authMiddleware, async (req, res) => {
  try {
    const orders = await Order.find({ userId: req.user._id })
      .populate("items.productId")
      .sort({ createdAt: -1 });
    res.json(orders);
  } catch (error) {
    res.status(500).json({ error: "Error fetching orders" });
  }
});

app.get("/api/admin/orders", authMiddleware, async (req, res) => {
  try {
    if (req.user.role !== "admin")
      return res.status(403).json({ error: "Access denied" });
    const orders = await Order.find()
      .populate("userId", "name email")
      .populate("items.productId")
      .sort({ createdAt: -1 });
    res.json(orders);
  } catch (error) {
    res.status(500).json({ error: "Error fetching all orders" });
  }
});

app.patch("/api/admin/orders/:orderId", authMiddleware, async (req, res) => {
  try {
    if (req.user.role !== "admin")
      return res.status(403).json({ error: "Access denied" });
    const { orderId } = req.params;
    const { orderStatus } = req.body;

    const updatedOrder = await Order.findByIdAndUpdate(
      orderId,
      { orderStatus },
      { new: true }
    );
    if (!updatedOrder)
      return res.status(404).json({ error: "Order not found" });

    res.json(updatedOrder);
  } catch (error) {
    res.status(500).json({ error: "Error updating order status" });
  }
});

// Password Reset Routes
app.post("/api/forgot-password", async (req, res) => {
  const { email } = req.body;
  try {
    const oldUser = await User.findOne({ email });
    if (!oldUser) return res.json({ status: "User Not Exists!!" });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const secret = process.env.JWT_SECRET + oldUser.password;
    const token = jwt.sign(
      { email: oldUser.email, id: oldUser._id.toString(), otp },
      secret,
      { expiresIn: "5m" }
    );

    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: { user: "kamalakar1625@gmail.com", pass: "pyfzkqrourkbdnix" },
    });

    const mailOptions = {
      from: "kamalakar1625@gmail.com",
      to: email,
      subject: "Password Reset OTP",
      text: `Your OTP for password reset is: ${otp}. This OTP is valid for 5 minutes.`,
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.log(error);
        return res.json({ status: "Error sending OTP" });
      }
      res.json({
        status: "Success",
        message: "OTP sent to email",
        token,
        id: oldUser._id.toString(),
      });
    });
  } catch (error) {
    res.json({ status: "Something Went Wrong" });
  }
});

app.post("/api/verify-otp/:id/:token", async (req, res) => {
  const { id, token } = req.params;
  const { otp } = req.body;

  const oldUser = await User.findOne({ _id: id });
  if (!oldUser) return res.json({ status: "User Not Exists!!" });

  const secret = process.env.JWT_SECRET + oldUser.password;
  try {
    const verify = jwt.verify(token, secret);
    if (verify.otp !== otp) return res.json({ status: "Invalid OTP" });
    res.json({ status: "verified", email: verify.email, token });
  } catch (error) {
    res.json({ status: "OTP Expired or Invalid" });
  }
});

app.post("/api/reset-password/:id/:token", async (req, res) => {
  const { id, token } = req.params;
  const { password } = req.body;

  const oldUser = await User.findOne({ _id: id });
  if (!oldUser) return res.json({ status: "User Not Exists!!" });

  const secret = process.env.JWT_SECRET + oldUser.password;
  try {
    const verify = jwt.verify(token, secret);
    const encryptedPassword = await bcrypt.hash(password, 10);
    await User.updateOne(
      { _id: id },
      { $set: { password: encryptedPassword } }
    );
    res.json({
      status: "Success",
      message: "Password reset successful",
      email: verify.email,
    });
  } catch (error) {
    res.json({ status: "Something Went Wrong" });
  }
});

// Utility Routes
app.get("/api/users/getUserId/:email", async (req, res) => {
  try {
    const user = await User.findOne({ email: req.params.email });
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json({ userId: user._id });
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
});

// Server Start
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
