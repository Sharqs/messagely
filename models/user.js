/** User class for message.ly */
const bcrypt = require('bcryptjs')
const ExpressError = require('../expressError')
const jwt = require('jsonwebtoken')
const { SECRET_KEY } = require("../config");
const OPTIONS = { expiresIn: 600 * 60 }; // 1 hour
const db = require("../db");

/** User of the site. */
class User {

  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */
  static async register({ username, password, first_name, last_name, phone, email }) {
    const hashedPassword = await bcrypt.hash(password, 12)
    await db.query(
      `INSERT INTO users (username, password, first_name, last_name, phone, email, join_at)
           VALUES ($1, $2, $3, $4, $5, $6, LOCALTIMESTAMP)
           RETURNING username, first_name, last_name, phone, email`,
      [username, hashedPassword, first_name, last_name, phone, email])
    let token = jwt.sign({ username }, SECRET_KEY, OPTIONS);
    return token;
  }

  /** Authenticate: is this username/password valid? Returns boolean. */
  static async authenticate(username, password) {
    try {
      const result = await db.query(
        "SELECT password FROM users WHERE username = $1",
        [username]);
      let user = result.rows[0];

      if (user) {
        if (await bcrypt.compare(password, user.password)) {
          let token = jwt.sign({ username }, SECRET_KEY, OPTIONS);
          return res.json({ token });
        }
      }
      throw new ExpressError("Invalid user/password", 401);
    } catch (err) {
      return next(err);
    }
  }

  /** Update last_login_at for user */
  static async updateLoginTimestamp(username) {
    const result = await db.query(
      `UPDATE users
      SET last_login_at=LOCALTIMESTAMP
      WHERE id = $1
      RETURNING username, last_login_at`[username]
    )
    return result
  }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */
  static async all() {
    const result = await db.query(`SELECT username, first_name, last_name, phone
      FROM users`);
    return result.rows;
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */
  static async get(username) {
    const result = await db.query(
      `SELECT username, first_name, last_name, phone
      FROM users WHERE username = $1`, [username]
    )
    return result.rows[0];
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */
  static async messagesFrom(username) {
    const result = await db.query(
      `SELECT id, body, sent_at, read_at, users.username, first_name, last_name, phone
      FROM messages 
      JOIN users 
      ON from_username = users.username 
      WHERE users.username = $1`, [username]
    )
    let toUsers = []
    for (let i = 0; i < result.rows.length; i++) {
      let u = result.row[i]
      toUsers.push({
        id: u.id, 
        to_user: {
          username: u.username,
          first_name: u.first_name,
          last_name: u.last_name,
          phone: u.phone
        },
        body: u.body,
        sent_at: u.sent_at,
        read_at: u.read_at
      })
    }
    return toUsers
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {id, first_name, last_name, phone}
   */
  static async messagesTo(username) {
    const result = await db.query(
      `SELECT id, body, sent_at, read_at, users.username, first_name, last_name, phone
      FROM messages 
      JOIN users 
      ON to_username = users.username 
      WHERE users.username = $1`, [username]
    )
    let fromUsers = []
    for (let i = 0; i < result.rows.length; i++) {
      let u = result.row[i]
      fromUsers.push({
        id: u.id,
        from_user: {
          username: u.username,
          first_name: u.first_name,
          last_name: u.last_name,
          phone: u.phone
        },
        body: u.body,
        sent_at: u.sent_at,
        read_at: u.read_at
      })
    }
    return fromUsers
  }
}

module.exports = User;