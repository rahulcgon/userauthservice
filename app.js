const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const validator = require("validator");

require('dotenv').config();
const jwtSecret = process.env.JWT_SECRET;


const app = express();
app.use(bodyParser.json());

// Connect to MongoDB
mongoose.connect("mongodb://localhost:27017/mydatabase", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});
const User = mongoose.model("User", {
    email: String,
    password: String,
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

// User registration API endpoint
app.post("/api/register", async (req, res) => {
    const { email, password } = req.body;

    // Validate input data
    if (!validator.isEmail(email)) {
        return res.status(400).json({ message: "Invalid email address" });
    }
    // Password strength validation
    if (!isStrongPassword(password)) {
        return res.status(400).json({ message: "Password is not strong" });
    }

    try {
        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: "User already exists" });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create a new user
        const newUser = new User({ email, password: hashedPassword });
        await newUser.save();

        res.status(201).json({ message: "User registered successfully" });
    } catch (error) {
        res.status(500).json({ message: "Internal server error" });
    }
});

function isStrongPassword(password) {
    // Define a regular expression to enforce password strength rules
    const regex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*()_+[\]{};':"\\|,.<>\/?]).{8,}$/;
    return regex.test(password);
}

const jwt = require('jsonwebtoken');

// User login API endpoint
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    // Validate input data
    if (!validator.isEmail(email)) {
        return res.status(400).json({ message: 'Invalid email address' });
    }

    try {
        // Find user by email
        const user = await User.findOne({ email });

        // Check if user exists
        if (!user) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        // Validate password
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        // Generate JWT token
        const token = jwt.sign({ userId: user._id }, jwtSecret, { expiresIn: '1h' });

        // Send token to the client
        res.status(200).json({ token });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
});

// User details fetching API endpoint
app.get('/api/user', authenticate, async (req, res) => {
    try {
        const user = await User.findById(req.userId);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.status(200).json(user);
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Authentication middleware
function authenticate(req, res, next) {
    const token = req.headers.authorization;

    if (!token) {
        return res.status(401).json({ message: 'Unauthorized: No token provided' });
    }

    jwt.verify(token, jwtSecret, (err, decoded) => {
        if (err) {
            return res.status(401).json({
                jwt: token,
                message: 'Unauthorized: Invalid token',
                jwtSecret: jwtSecret,
                err: err
            });
        }

        req.userId = decoded.userId;
        next();
    });
}

// const cors = require('cors');

// app.use(cors({
//     origin: 'https://yourdomain.com' // Replace with your allowed domain
// }));
