const express = require("express")
const router = new express.Router();
const User = require("../models/user")
const { ensureLoggedIn } = require("../middleware/auth");


/** GET / - get list of users.
 *
 * => {users: [{username, first_name, last_name, phone}, ...]}
 *
 **/
router.get("/",
    ensureLoggedIn,
    async function (req, res, next) {
        try {
            let users = await User.all();
            return res.json(users);
        } catch (err) {
            next(err);
        }
});

/** GET /:username - get detail of users.
 *
 * => {user: {username, first_name, last_name, phone, join_at, last_login_at}}
 *
 **/
router.get("/:username",
    ensureLoggedIn,
    async function (req, res, next) {
        try {
            let user = await User.get(req.params.username);
            return res.json(user);
        } catch (err) {
            next(err);
        }
});

/** GET /:username/to - get messages to user
 *
 * => {messages: [{id,
 *                 body,
 *                 sent_at,
 *                 read_at,
 *                 from_user: {username, first_name, last_name, phone}}, ...]}
 *
 **/
router.get("/:username/to",
    ensureLoggedIn,
    async function (req, res, next) {
        try {
            let msgs = await User.messagesTo(req.params.username);
            return res.json(msgs);
        } catch (err) {
            next(err);
        }
});

/** GET /:username/from - get messages from user
 *
 * => {messages: [{id,
 *                 body,
 *                 sent_at,
 *                 read_at,
 *                 to_user: {username, first_name, last_name, phone}}, ...]}
 *
 **/
router.get("/:username/from",
    ensureLoggedIn,
    async function (req, res, next) {
        try {
            let msgs = await User.messagesFrom(req.params.username);
            return res.json(msgs);
        } catch (err) {
            next(err);
        }
});

module.exports = router;