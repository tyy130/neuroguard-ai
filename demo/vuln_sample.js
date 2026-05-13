/**
 * vuln_sample.js — intentionally vulnerable Express app for NeuroGuard demo.
 *
 * Vulnerabilities:
 *   1. SQL injection via template literal
 *   2. eval() on user input (RCE)
 *   3. Hardcoded API key
 *   4. innerHTML assignment (XSS)
 *   5. Math.random() for security token
 *   6. child_process.exec with user input (command injection)
 *   7. Debug/stack traces exposed to client
 */

const express = require("express");
const { exec } = require("child_process");
const mysql = require("mysql2");
const app = express();

// Vulnerability 1: Hardcoded secret
const API_KEY = "sk-prod-a1b2c3d4e5f6g7h8i9j0";
const DB_PASSWORD = "SuperSecret123!";

const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: DB_PASSWORD,
  database: "app_db",
});

app.use(express.json());

// Vulnerability 2: SQL injection via template literal
app.get("/user", (req, res) => {
  const username = req.query.username;
  const query = `SELECT * FROM users WHERE username = '${username}'`;
  db.query(query, (err, results) => {
    if (err) {
      // Vulnerability 7: Stack traces exposed
      return res.status(500).json({ error: err.message, stack: err.stack });
    }
    res.json(results);
  });
});

// Vulnerability 3: eval() on user input — RCE
app.post("/calculate", (req, res) => {
  const expression = req.body.expression;
  try {
    const result = eval(expression);
    res.json({ result });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// Vulnerability 4: innerHTML (XSS)
app.get("/profile", (req, res) => {
  const name = req.query.name;
  res.send(`
    <html>
      <body>
        <div id="welcome"></div>
        <script>
          document.getElementById('welcome').innerHTML = 'Hello, ${name}!';
        </script>
      </body>
    </html>
  `);
});

// Vulnerability 5: Math.random() for session token
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  // ... auth check omitted ...
  const sessionToken = Math.random().toString(36).substring(2);
  res.json({ token: sessionToken });
});

// Vulnerability 6: Command injection via exec
app.get("/ping", (req, res) => {
  const host = req.query.host;
  exec(`ping -c 1 ${host}`, (err, stdout, stderr) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ output: stdout });
  });
});

app.listen(3000, () => {
  console.log(`Server running on port 3000 with API_KEY=${API_KEY}`);
});
