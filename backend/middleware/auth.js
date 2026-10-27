// middleware/auth.js

// guarda la configuracion de como es que un usuario se puede o no autenticar, trabaja con una propiedad y lo unico que valida si el usuario esta isAuth
const User = require('../models/user');

let auth = (req, res, next) => {
    let token = req.cookies.auth;

    User.findByToken(token, (err, user) => {
        if (err) throw err;
        if (!user) return res.json({ isAuth: false, error: true });

        req.token = token;
        req.user = user;
        next();
    });
};

module.exports = { auth };