const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');

const app = express();
const port = 3000;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

const db = mysql.createConnection({
  host: 'localhost',
  user: 'Task1',
  password: '',
  database: 'compTask',
});

db.connect((err) => {
  if (err) {
    console.error('Error connecting to MySQL:', err);
  } else {
    console.log('Connected to MySQL database');
  }
});



// User Registration
app.post('/register', async (req, res) => {
  const { email, password } = req.body;

  // Hash the password before saving
  const hashedPassword = await bcrypt.hash(password, 10);

  // Check if email is unique
  db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
    if (err) {
      res.status(500).send('Internal Server Error');
    } else if (results.length > 0) {
      res.status(409).send('Email already exists');
    } else {
      db.query('INSERT INTO users (email, password) VALUES (?, ?)', [email, hashedPassword], (err) => {
        if (err) {
          res.status(500).send('Internal Server Error');
        } else {
          res.status(201).send('User registered successfully');
        }
      });
    }
  });
});

// User Login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  // Check if the email exists
  db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (err) {
      res.status(500).send('Internal Server Error');
    } else if (results.length === 0) {
      res.status(401).send('Invalid email or password');
    } else {
      // Compare hashed password
      const match = await bcrypt.compare(password, results[0].password);
      if (match) {
        res.status(200).send('Login successful');
      } else {
        res.status(401).send('Invalid email or password');
      }
    }
  });
});

// Profile Update
app.put('/update-profile', authenticateUser, async (req, res) => {
  const { email, firstName, lastName, age, newPassword } = req.body;

  // Check if the user exists
  db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (err) {
      res.status(500).send('Internal Server Error');
    } else if (results.length === 0) {
      res.status(404).send('User not found');
    } else {
      // Update profile information
      const updateQuery = 'UPDATE users SET first_name = ?, last_name = ?, age = ?';
      const queryParams = [firstName, lastName, age];

      // Update password if a new one is provided
      if (newPassword) {
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        updateQuery += ', password = ?';
        queryParams.push(hashedPassword);
      }

      updateQuery += ' WHERE email = ?';
      queryParams.push(email);

      db.query(updateQuery, queryParams, (err) => {
        if (err) {
          res.status(500).send('Internal Server Error');
        } else {
          res.status(200).send('Profile updated successfully');
        }
      });
    }
  });
});

// Get Profile
app.get('/get-profile/:email', authenticateUser, (req, res) => {
  const email = req.params.email;

  // Retrieve profile information
  db.query('SELECT email, first_name, last_name, age FROM users WHERE email = ?', [email], (err, results) => {
    if (err) {
      res.status(500).send('Internal Server Error');
    } else if (results.length === 0) {
      res.status(404).send('User not found');
    } else {
      const profile = results[0];
      res.status(200).json(profile);
    }
  });
});

// Delete Profile
app.delete('/delete-profile/:email', authenticateUser, (req, res) => {
  const email = req.params.email;

  // Delete user and associated data
  db.query('DELETE FROM users WHERE email = ?', [email], (err, results) => {
    if (err) {
      res.status(500).send('Internal Server Error');
    } else if (results.affectedRows === 0) {
      res.status(404).send('User not found');
    } else {
      res.status(200).send('Profile deleted successfully');
    }
  });
});

app.listen(3000, () => {
  console.log(`Server is running on port ${port}`);
});
