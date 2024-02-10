require("dotenv").config();

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');

const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const { Pool } = require('pg');

const { NotFoundError } = require("./expressError");

const app = express();
const port = +process.env.PORT;
const SECRET_KEY = process.env.JWT_SECRET;

module.exports = app;

app.use(bodyParser.json());
app.use(cors());


// PostgreSQL connection configuration
const pool = new Pool({
  connectionString: process.env.DATABASE_URL, 
  ssl: {
    rejectUnauthorized: process.env.NODE_ENV === 'production',
  },
});

pool.connect((err, client, done) => {
  if (err) throw err;
  console.log('Connected to PostgreSQL database');
});


// Middleware to help with JWT token
const authenticateUser = async (req, res, next) => {
  try {
    const token = req.headers.authorization.split(' ')[1];
    const decoded = jwt.verify(token, SECRET_KEY);

    req.user = {
      userId: decoded.userId,
      username: decoded.username,
    };

    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired' });
    }

    console.error('Token verification failed:', err);
    return res.status(401).json({ error: 'Unauthorized' });
  }
};


// API Routes

// User endpoints
app.post('/sign-up', async (req, res, next) => {
  try {
    const { username, password, adventurerName } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert the user into the database
    const result = await pool.query(
      'INSERT INTO users (username, password_hash, adventurer_name) VALUES ($1, $2, $3) RETURNING id, username, adventurer_name',
      [username, hashedPassword, adventurerName]
    );

    const user = result.rows[0];

    // Create a JWT token
    const token = jwt.sign({ userId: user.id, username: user.username }, SECRET_KEY);

    await pool.query('UPDATE users SET token = $1 WHERE id = $2', [token, user.id]);

    return res.json({ user: { user, token } });
  } catch (err) {
    return next(err);
  }
});

app.post('/login', async (req, res, next) => {
  try {
    const { username, password } = req.body;

    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];

    if (!user) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    // Check if the password is correct
    const passwordMatch = await bcrypt.compare(password, user.password_hash);

    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    // Update the user's token in the database
    const newToken = jwt.sign({ userId: user.id, username: user.username }, SECRET_KEY);
    
    await pool.query('UPDATE users SET token = $1 WHERE id = $2', [newToken, user.id]);

    const final = res.json({ user: { ...user, token: newToken } });

    return final;
  } catch (err) {
    return next(err);
  }
});


app.post('/logout', authenticateUser, async (req, res, next) => {
  try {
    // Clear the token from the user table
    await pool.query('UPDATE users SET token = NULL WHERE id = $1', [req.user.userId]);

    return res.json({ message: 'Logout successful' });
  } catch (err) {
    console.error('Error during logout:', err);
        return res.status(500).json({ error: 'Internal Server Error' });
  }
});


app.get('/game', authenticateUser, async (req, res, next) => {
  try {
    const userId = req.user.userId;
    const username = req.user.username;

    return res.json({ userId, username });
  } catch (err) {
    return next(err);
  }
});

// Game endpoints
app.get('/chapter/:chapterId', authenticateUser, async function(req, res, next) {
    const { chapterId } = req.params;
    try {
        const result = await pool.query(
            'SELECT s.* FROM stories s WHERE s.chapter_id = $1'
        , [chapterId]);
        return res.json(result.rows);
    } catch (err) {
        return next(err);
    }
});

app.get('/item/:chapterId', authenticateUser, async function(req, res, next) {
    const { chapterId } = req.params;
    try {
        const result = await pool.query(
            'SELECT i.*, e.* FROM stories s LEFT JOIN story_item si ON s.chapter_id = si.chapter_id LEFT JOIN item i ON si.item_id = i.item_id LEFT JOIN effect e ON i.effect_id = e.effect_id WHERE s.chapter_id = $1'
        , [chapterId]);
        return res.json(result.rows);
    } catch (err) {
        return next(err);
    }
});

app.get('/enemy/:chapterId', authenticateUser, async function(req, res, next) {
    const { chapterId } = req.params;
    try {
        const result = await pool.query(
            'SELECT m.* FROM stories s LEFT JOIN story_monster sm ON s.chapter_id = sm.chapter_id LEFT JOIN monster m ON sm.monster_id = m.monster_id WHERE s.chapter_id = $1'
        , [chapterId]);
        return res.json(result.rows);
    } catch (err) {
        return next(err);
    }
});

// Game progress and updates 

app.post('/save-progress', authenticateUser, async function(req, res, next) {
  try {
    const { userId, storyId, chapterId, gameState, inventory, saveName } = req.body;
  
    const result = await pool.query(
      'INSERT INTO user_progress (user_id, story_id, chapter_id, game_state, inventory, save_name) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, save_name',
      [userId, storyId, chapterId, gameState, inventory, saveName]
    );
    const savedProgress = result.rows[0];

    return res.status(200).json({ savedProgress });
  } catch (err) {
    console.error('Error saving progress:', err);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/load-progress', authenticateUser, async function(req, res, next) {
  try {

    const result = await pool.query(
      'SELECT * FROM user_progress WHERE user_id = $1 ORDER BY id DESC LIMIT 1',
      [req.user.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'No saved game found.' });
    }

    const savedGameData = result.rows[0];
    return res.status(200).json({ savedGameData });
  } catch (err) {
    console.error('Error loading saved game:', err);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.delete('/delete-progress/:progressId', authenticateUser, async function(req, res, next) {
  try {
    const { progressId } = req.params;

    // Check if the user owns the saved game (progressId) before deleting
    const result = await pool.query(
      'DELETE FROM user_progress WHERE id = $1 AND user_id = $2 RETURNING id, save_name',
      [progressId, req.user.userId]
    );

    if (result.rows.length !== 1) {
      return res.status(404).json({ error: 'Saved game not found or unauthorized to delete.' });
    }

    return res.status(200).json({ message: 'Saved game deleted successfully.' });
  } catch (err) {
    console.error('Error deleting saved game:', err);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.post('/update-player', authenticateUser, async (req, res, next) => {
  try {
    const { newAdventurerName } = req.body;

    const result = await pool.query(
      'UPDATE users SET adventurer_name = $1 WHERE id = $2 RETURNING id, adventurer_name', 
      [newAdventurerName, req.user.userId]
    );

    const updatedUser = result.rows[0];
    return res.json({ message: 'Saved Adventurer Name successfully.'});
  } catch (err) {
    return next(err);
  }
});



/** Handle 404 errors -- this matches everything */
app.use(function (req, res, next) {
    return next(new NotFoundError());
  });

/** Generic error handler; anything unhandled goes here. */
app.use(function (err, req, res, next) {
    if (process.env.NODE_ENV !== "test") console.error(err.stack);
    const status = err.status || 500;
    const message = err.message;
  
    return res.status(status).json({
      error: { message, status },
    });
  });

// Start the server
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
