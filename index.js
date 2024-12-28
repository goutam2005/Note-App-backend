// import express from 'express';
const dotenv  = require('dotenv')
const passport = require('passport');
const express = require('express');
const mongoconn = require('./db');
require('./middleware/passport_jwt');
const cors = require('cors');
const cookieParser = require('cookie-parser');
dotenv.config();

const app = express();
const port = process.env.PORT || 8000;




const corsOption = {
  origin: process.env.CLIENT_URL,
  credentials: true,
  optionSuccessStatus: 200
}

app.use(cookieParser());
app.use(cors(corsOption));
app.use(express.json());

app.use(passport.initialize());
app.use(`/api/auth`, require(`./Routes/Auth`));
app.use(`/api/notes`, require(`./Routes/Notes`));




mongoconn(process.env.MONGO_URL);

app.get('/', (req, res) => {
    res.send('Hello World!');
});



app.listen(port, () => {
    console.log(`Example app listening at http://localhost:${port}`)
})
