const express = require("express")
const router = new express.Router();
const User = require("../models/user")
// const { ensureLoggedIn } = require("../middleware/auth");


/** POST /login - login: {username, password} => {token}
 *
 * Make sure to update their last-login!
 *
 **/
router.post("/login", async function (req, res, next) {
    try {
        const { username, password } = req.body;
        let token = await User.authenticate(username, password);
        if (token) {
            await User.updateLoginTimestamp(username);
            return res.send(token);
        }
    } catch (err) {
        next(err);
    }
});

/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Make sure to update their last-login!
 */
router.post("/register", async function (req, res, next) {
    try {
        let token = await User.register(req.body);
        return res.json({"token": token});
    } catch (err) {
        next(err);
    }
});

module.exports = router;