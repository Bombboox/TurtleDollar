const express = require('express');
const mysql = require('mysql');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { name } = require('ejs');
const authController = require('../controllers/auth');
const router = express.Router();
const { db } = require('../controllers/mysql');
const url = require('url');
const crypto = require('crypto'); 
const utf8 = require('utf8');
const nodemailer = require('nodemailer');

router.get('/', authController.isLoggedIn, (req, res) => {
    res.render('index', {user: req.user});
});

router.get('/privacy_policy', (req, res) => {
    res.redirect('https://www.iubenda.com/privacy-policy/67902300');
});

router.get('/terms_of_service', (req, res) => {
    res.render('terms');
});

router.get('/surveys', authController.isLoggedIn, (req, res) => {
    if(!req.user) return res.redirect('/');
    res.render('surveys', {user: req.user});
});

router.get('/payout', authController.isLoggedIn, (req, res) => {
    if(!req.user) return res.redirect('/');
    res.render('payout', {user: req.user, url: 'https://' + req.get('host')});
});

router.get('/about',  authController.isLoggedIn, (req, res) => {
    res.render('about', {user: req.user});
});

router.get('/login', authController.isLoggedIn, (req, res) => {
    if(req.user) {
        res.redirect('profile');
    } else {
        res.render('login');
    }
});

router.get('/register', authController.isLoggedIn, (req, res) => {
    if(req.user) {
        res.redirect('profile');
    } else {
        res.render('register');
    }
});

router.get('/logout', authController.logout);

router.get('/profile', authController.isLoggedIn, (req, res) => {
    if(req.user) {
        let orders = authController.getOrders(req.user.id);
        res.render('profile', {user: req.user, orders: orders});
    } else {
        res.redirect('/login');
    }
})

router.get('/file/cpx', (req, res) => {
    const {status, trans_id, user_id, sub_id, sub_id_2, amount_local, amount_us, offer_id, hash, ip_click} = req.query;

    const requestHash = crypto.createHash('md5').update(`${trans_id}-${process.env.MY_SECURE_HASH}`).digest('hex');
    if(requestHash != hash) return res.status(500).send('Invalid hash');

    if(status == 1 && user_id && amount_local) {
        db.query('SELECT * FROM profiles WHERE id = ?', [user_id], async (err, result) => {
            const points = parseInt(result[0].points);

            db.query('UPDATE profiles SET points = ? WHERE id = ?', [points + parseInt(amount_local), parseInt(user_id)], async (err, result) => {
                if(err) return res.status(500).send('Internal server error!');
                return res.status(200).send('Postback recieved and processed.');
            });
        });
    } else {
        res.status(500).send('Error, user information not recieved');
    }
});

/*router.get('/file/tr', (req, res) => {
    const {reward, currency, user_id, tx_id, hash, debug} = req.query;
    const text = req.protocol + '://' + req.get('host') + req.originalUrl;
    const key = process.env.MY_SECRET_KEY_TR;

    const requestHash = crypto.createHmac('sha1', key).update(text).digest('hex');
    const finalHash = requestHash.replace('+', '-').replace('/', '_').replace('=', '');

    if(finalHash != hash) return res.status(500).send(`${hash}, ${requestHash}`);

    if(user_id && reward) {
        db.query('SELECT * FROM profiles WHERE id = ?', [user_id], async (err, result) => {
            const points = parseInt(result[0].points);

            db.query('UPDATE profiles SET points = ? WHERE id = ?', [points + parseInt(reward), parseInt(user_id)], async (err, result) => {
                if(err) return res.status(500).send('Internal server error!');
                return res.status(200).send('Postback recieved and processed.');
            });
        });
    } else {
        res.status(500).send('Error, user information not recieved.');
    }
});*/

router.post('/request_product', authController.isLoggedIn, (req, res) => {
    const {order} = req.body;

    if(!req.user) { //User trying to order while not logged in lol
        res.send('Must be logged in to order product.');
    } else { //GOOD user is logged in

        var user_id = req.user.id;
        var product;
        var date = new Date().toISOString().slice(0, 19).replace('T', ' ');
        var amount;

        switch(order) {
            default:
            case 0: 
                product = "$5.00 SEETURTLES Donation"
                amount = 600;
            break;

            case 1:
                product = "$5.00 TURTLE-FOUNDATION Donation"
                amount = 600;
            break;
        }

        db.query('SELECT * FROM profiles WHERE id = ?', [user_id], async (err, result) => {
            const points = parseInt(result[0].points);

            if(points > amount) {
                db.query('UPDATE profiles SET points = ? WHERE id = ?', [points - amount, user_id], async(err, result) => {
                    if(err) return console.log(err);
                });

                db.query('INSERT INTO orders SET ?', {user_id: user_id, product: product, date: date, amount: amount}, (err, result) => {
                    if(err) return console.log(err);
                });

                authController.saveOrders(user_id);

                res.status(200).send('Order placed successfully!');
            } else {
                res.send('Insufficient points!');
            }
        });
    }
});

router.post('/register', (req, res) => {
    const {name, email, password} = req.body;

    db.query('SELECT * FROM profiles WHERE name = ?', [name], async (err, result) => {
        if(err) return console.log(err);

        if(result.length > 0) {
            //username is in use
            return res.render('register', {message: 'username is already in use'});
        } else {
            //create user
            let hashed_password = await bcrypt.hash(password, 8);

            var transporter = nodemailer.createTransport({
                host: "mail.privateemail.com",
                port: 587,
                secure: false,
                auth: {
                  user: "contact@turtle-dollar.com",
                  pass: process.env.CONTACT_PASS
                }
              });

            const mailOptions = {
                from: 'contact@turtle-dollar.com',
                to: email,
                subject: 'Turtle Dollar Email Verification',
                text: 'Please verify your email with the following link:}',
                html: `<a href="https://www.turtle-dollar.com/verify/?hash=${crypto.createHash('md5').update(`${name}-${process.env.MY_SECURE_VERIFICATION}`).digest('hex')}&name=${name}">Verify Email</a>`
            }

            transporter.sendMail(mailOptions, (err, info) => {
                if(err) {
                    console.log(err);
                    return res.send('Error completing your request!');
                }

                console.log(`Email successfully sent: ${info.response}`);
                
                db.query('INSERT INTO profiles SET ?', {name: name, email: email, password: hashed_password}, (err, result) => {
                    if(err) return console.log(err);
                    
                    //user successfully created
                    return res.render('register', {message: 'GOOD! Verification email sent!'});
                });
            });
        }
    });
})


router.get('/verify', (req, res) => {
    const {hash, name} = req.query;
    if(!hash || !name) return res.status(400).send('Username and Hash required for verification.');
    const requestHash = crypto.createHash('md5').update(`${name}-${process.env.MY_SECURE_VERIFICATION}`).digest('hex');

    if(requestHash != hash) return res.status(500).send('Invalid code.');

    try {
        db.query('SELECT * FROM profiles WHERE name = ?', [name], async (err, result) => {
            if(err) return console.log(err);
            if(!result[0]) return res.status(400).send('User does not exist.');
            if(result[0].verified == 1) return res.status(400).send('User already verified');

            db.query('UPDATE profiles SET verified = ? WHERE name = ?', [1, name], async(err, result) => {
                if(err) return console.log(err);
                return res.status(200).send('User verified.');
            });
        });
    } catch(err) {
        console.log(err);
    }
});

router.post('/login', async (req, res) => {
    try {
        const {name, password} = req.body;

        if(!name || !password) {
            return res.status(400).render('login', {message: 'please enter valid credentials'})
        }

        db.query('SELECT * FROM profiles WHERE name = ?', [name], async (err, result) => {
            if(err) return console.log(err);
            if(!result[0]) return res.status(400).render('login', {message: 'user does not exist'})
            if(!result || !await bcrypt.compare(password, result[0].password)) {
                res.status(401).render('login', {message: 'invalid credentials'});
            } else {
                if(result[0].verified == 0) return res.status(400).render('login', {message: 'you must verify your email first!'});

                const id = result[0].id;
                const token = jwt.sign({id}, process.env.JWT_SECRET, {
                    expiresIn: "90d"
                });
    
                const cookieOptions = {
                    expires: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000),
                    httpOnly: true,
                };
    
                res.cookie('jwt', token, cookieOptions);
                res.status(200).redirect('/');
            }
        });
    } catch(err) {
        console.log(err);
    }
});

module.exports.router = router;