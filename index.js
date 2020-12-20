const mongoose = require('mongoose');
const express = require('express');
const app = express();
const users = require('./routes/users');
const auth = require('./routes/auth');
const bodyParser = require('body-parser');


 
mongoose.connect('mongodb://localhost:27017/task2')
    .then(() => console.log('Now connected to MongoDB!'))
    .catch(err => console.error('Something went wrong', err));
 
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
    extended: true
}));
app.use('/api/users', users);
app.use('/api/auth', auth);
 
const port = process.env.PORT || 4000;
app.listen(port, () => console.log(`Listening on port ${port}...`));