const jwt = require('jsonwebtoken');
const {promisify} = require('util');
const mysql = require('mysql');
const { db } = require('./mysql');
const NodeCache = require('node-cache');

const cache = new NodeCache();

exports.isLoggedIn = async(req, res, next) => {
    if(req.cookies.jwt) {
        try {
            //verify token
            const decoded = await promisify(jwt.verify)(req.cookies.jwt, process.env.JWT_SECRET);
            
            //check if user still exists
            db.query('SELECT * FROM profiles WHERE id = ?', [decoded.id], (err, result) => {
                if(!result) {
                    return next();
                }

                req.user = result[0];
                return next();
            });
        } catch(err) {
            console.log(err);
        }
    } else {
        next();
    }
}

exports.logout = async (req, res) => {
    res.cookie('jwt', 'logout', {
        expires: new Date(Date.now()),
        httpOnly: true
    });

    res.status(200).redirect('/');
}

exports.getOrders = (userId) => {
    const cacheKey = `orders_${userId}`;
    
    // Try to fetch orders from cache
    let userOrders = cache.get(cacheKey);
    
    if (!userOrders) {
      // Fetch orders from database
      db.query('SELECT * FROM orders WHERE user_id = ?', [userId], async (err, result) => {
        if(err) return console.log(err);
        userOrders = result;

        //Store for future use ;)
        cache.set(cacheKey, userOrders);

      });
    } 
    return userOrders;
}

exports.saveOrders = (userId) => {
    const cacheKey = `orders_${userId}`;
    var userOrders;
    
    db.query('SELECT * FROM orders WHERE user_id = ?', [userId], async (err, result) => {
        if(err) return console.log(err);

        userOrders = result;

        //store for future use yeays
        cache.set(cacheKey, userOrders);
      });
    
    return userOrders;
}