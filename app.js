const express = require("express");
const app = express();

const sqlite3 = require("sqlite3");
const { open } = require("sqlite");

const path = require("path");
const dbPath = path.join(__dirname, "userData.db");
const bcrypt = require("bcrypt");

app.use(express.json());

let db = null;

//  Connecting Database
const connectDatabase = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });
    app.listen(3000, () => {
      console.log("Server is Running at http://localhost:3000");
    });
  } catch (e) {
    console.log(`Error Found On Database: ${e.message}`);
    process.exit(1);
  }
};
connectDatabase();

// API -1 register.....

app.post("/register", async (request, response) => {
  const { username, name, password, gender, location } = request.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const selectQuery = `
  SELECT 
  *
  FROM
  user
  WHERE
  username = ?;
  `;
  const dbUser = await db.get(selectQuery, [username]);
  if (dbUser === undefined) {
    if (password.length >= 6) {
      const createUserQuery = `
      INSERT INTO user
      (username, name, password, gender, location)
      VALUES(?,?,?,?,?);
      `;
      await db.run(createUserQuery, [
        username,
        name,
        hashedPassword,
        gender,
        location,
      ]);
      response.status(200);
      response.send("User created successfully");
    } else {
      response.status(400);
      response.send("Password is too short");
    }
  } else {
    response.status(400);
    response.send("User already exists");
  }
});

// API -2 login...

app.post("/login", async (request, response) => {
  const { username, password } = request.body;
  const selectQuery = `
  SELECT
  *
  FROM
  user
  WHERE
  username = ?;
  `;
  const userdb = await db.get(selectQuery, [username]);
  if (userdb !== undefined) {
    const ispassword = await bcrypt.compare(password, userdb.password);
    if (ispassword === true) {
      response.status(200);
      response.send("Login success!");
    } else {
      response.status(400);
      response.send("Invalid password");
    }
  } else {
    response.status(400);
    response.send("Invalid user");
  }
});

// update password.....
app.put("/change-password", async (request, response) => {
  const { username, oldPassword, newPassword } = request.body;
  const selectQuery = `
  SELECT 
  * 
  FROM
  user
  WHERE
  username = ?;
  `;
  const userdb = await db.get(selectQuery, [username]);
  if (userdb !== undefined) {
    const checkOldPassword = await bcrypt.compare(oldPassword, userdb.password);
    if (checkOldPassword === true) {
      if (newPassword.length > 5) {
        const newhasedPass = await bcrypt.hash(newPassword, 10);
        const selectQuery = `
        UPDATE user
        SET
        password = ?
        WHERE username = ?;
        `;
        await db.run(selectQuery, [newhasedPass, username]);
        response.status(200);
        response.send("Password updated");
      } else {
        response.status(400);
        response.send("Password is too short");
      }
    } else {
      response.status(400);
      response.send("Invalid current password");
    }
  }
});

module.exports = app;
