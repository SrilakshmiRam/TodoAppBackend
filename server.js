const express = require('express');
const { open } = require('sqlite');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const sqlite3 = require('sqlite3');
const app = express();
const path = require('path');

app.use(cors({
    origin: 'http://localhost:3000',
    methods: ['POST', 'GET'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

const dbPath = path.join(__dirname, 'todoAppData.db');

let db = null;

const initiateAndStartDatabaseServer = async () => {
    try {
        db = await open({
            filename: dbPath,
            driver: sqlite3.Database
        });
        app.listen(3000, () => {
            console.log('Backend Server is Running at http://localhost:3000/');
        });
    } catch (e) {
        console.log(`Db Error ${e.message}`);
        process.exit(1);
    }
};

initiateAndStartDatabaseServer();

// Middleware for JWT Authentication
const authenticateJWT = (req, res, next) => {
    const token = req.headers.authorization && req.headers.authorization.split(' ')[1];
    if (!token) {
        return res.sendStatus(401);
    }

    jwt.verify(token, 'secret_token', (err, user) => {
        if (err) {
            return res.sendStatus(403);
        }
        req.user = user; // Save user info for later use
        next();
    });
};

// User Signup
app.post('/Signup', async (request, response) => {
    const { username, email, password } = request.body;
    try {
        const insertQuery = `INSERT INTO users (username, email, password) VALUES (?, ?, ?)`;
        const hashedPassword = await bcrypt.hash(password, 10);
        await db.run(insertQuery, [username, email, hashedPassword]);
        response.status(201).json({ message: "Data received successfully" });
    } catch (e) {
        console.error(e);
        response.status(401).json({ message: 'Failed to store the data' });
    }
});

// User Login
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const selectUserQuery = `SELECT * FROM users WHERE username = ?;`;
        const dbUser = await db.get(selectUserQuery, [username]);
        if (dbUser === undefined) {
            res.status(400).json({ message: 'Invalid User or password' });
        } else {
            const isMatchedPassword = await bcrypt.compare(password, dbUser.password);
            if (isMatchedPassword === true) {
                const payload = { username: username };
                const jwtToken = jwt.sign(payload, 'secret_token', { expiresIn: '1h' });
                res.status(200).json({ jwtToken });
            } else {
                res.status(400).json({ message: 'Invalid User or password' });
            }
        }
    } catch (e) {
        res.status(500).json({ error: `Error processing request: ${e.message}` });
    }
});

// Add Task
app.post('/add', authenticateJWT, async (req, res) => {
    const { id, title, description } = req.body; 
    try {
        const insertQuery = `INSERT INTO todo (id, title, description) VALUES (?, ?, ?);`;
        await db.run(insertQuery, [id, title, description]);
        res.status(201).json({ message: "Data received successfully" });
    } catch (e) {
        console.error(e);
        res.status(401).json({ message: 'Failed to store the data' });
    }
});

// Get All Tasks
app.get('/todos', authenticateJWT, async (req, res) => {
    try {
        const selectQuery = `SELECT * FROM todo;`;
        const data = await db.all(selectQuery);
        res.status(200).json(data);
    } catch (e) {
        console.error(e);
        res.status(401).json({ message: 'Failed to get the data' });
    }
});

// Edit Task
app.post('/edit/:id', authenticateJWT, async (req, res) => {
    const { id } = req.params;
    const { title, description } = req.body;
    try {
        const updateQuery = `UPDATE todo SET title = ?, description = ? WHERE id = ?`;
        await db.run(updateQuery, [title, description, id]);
        res.status(200).json({ message: "Data updated successfully" });
    } catch (e) {
        console.error(e);
        res.status(401).json({ message: 'Failed to update the data' });
    }
});

// Delete Task
app.post('/delete/:id', authenticateJWT, async (req, res) => {
    const { id } = req.params;
    try {
        const deleteQuery = `DELETE FROM todo WHERE id = ?;`;
        await db.run(deleteQuery, [id]);
        res.status(200).json({ message: "Deleted successfully" });
    } catch (e) {
        console.error(e);
        res.status(401).json({ message: 'Failed to delete the data' });
    }
});


//userProfile 
app.get('/users/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const userQuery = `SELECT * FROM users WHERE id = ?;`;
        const data = await db.get(userQuery, [id]); // Pass id as a parameter
        
        if (data) {
            res.status(200).json({
                message: 'Data fetched successfully',
                user: data, // Include user data in the response
            });
        } else {
            res.status(404).json({ message: 'User not found' }); // Handle case where user is not found
        }
    } catch (e) {
        console.error(e);
        res.status(500).json({ message: 'Failed to retrieve the data' });
    }
});

