const express = require('express');
const router = express.Router();
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const config = require('../config');
const User = require('../model/userSchema');

router.use(bodyParser.urlencoded({extended:true}))
router.use(bodyParser.json());

//get all the users
router.get('/users', async (req, res) => {
    try {
      const data = await User.find({}).exec();
      res.send(data);
    } catch (err) {
      console.error(err);
      res.status(500).send('Internal Server Error');
    }
  });

//register users
router.post('/register', async (req, res) => {
    try {
      const hashpassword = bcrypt.hashSync(req.body.password, 8);
  
      await User.create({
        name: req.body.name,
        email: req.body.email,
        password: hashpassword,
        phone: req.body.phone,
        role: req.body.role ? req.body.role : 'User'
      });
  
      res.status(200).send('Register Successful');
    } catch (err) {
      console.error(err);
      res.status(500).send('Internal Server Error');
    }
  });

//login User
router.post('/login', async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });

    if (!user) {
      return res.status(201).send({ auth: false, token: 'No User Found. Register First' });
    }

    const passIsValid = bcrypt.compareSync(req.body.password, user.password);

    if (!passIsValid) {
      return res.status(201).send({ auth: false, token: 'Invalid Password' });
    }

    const token = jwt.sign({ id: user._id }, config.secret, { expiresIn: 86400 });
    return res.status(200).send({ auth: true, token });
  } catch (err) {
    console.error(err);
    return res.status(500).send({ auth: false, token: 'Error while logging in' });
  }
});

//userInfo
router.get('/userInfo', async (req, res) => {
  try {
    const token = req.headers['x-access-token'];
    
    if (!token) {
      return res.status(201).send({ auth: false, token: 'No Token Provided' });
    }

    const data = await jwt.verify(token, config.secret);
    const user = await User.findById(data.id);

    if (!user) {
      return res.send({ auth: false, token: 'User not found' });
    }

    res.send(user);
  } catch (err) {
    console.error(err);
    return res.status(500).send({ auth: false, token: 'Error while fetching user' });
  }
});

module.exports=router;