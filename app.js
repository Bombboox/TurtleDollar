const express = require('express');
const dotenv = require('dotenv');
const cookieParser = require('cookie-parser');

dotenv.config({path: './e.env'});

const app = express();
const PORT = process.env.PORT || 3000;


app.set('view engine', 'ejs');
app.use(express.static(__dirname + '/styles'));

//parse url encoded body
app.use(express.urlencoded({extended: false}));
//parse json bodies
app.use(express.json());
app.use(cookieParser());

app.use('/', require('./routes/pages').router);

app.listen(PORT, () => {
    console.log(`Listening on port ${PORT}...`);
});