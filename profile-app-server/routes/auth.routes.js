const router = require('express').Router();
const bcrypt = require('bcrypt');
const saltRounds = 10;
const User = require('../models/User.model');
const isLoggedOut = require('../middleware/isLoggedOut');
const isLoggedIn = require('../middleware/isLoggedIn');
const jwt = require('jsonwebtoken');

router.get('/loggedin', (req, res) => {
  res.json(req.user);
});

router.post('/signup', isLoggedOut, (req, res) => {
  const { username, password, campus, course } = req.body;

  if (!username || !password || !campus || !course) {
    return res
      .status(400)
      .json({ errorMessage: 'Please provide your username.' });
  }

  if (password.length < 8) {
    return res.status(400).json({
      errorMessage: 'Your password needs to be at least 8 characters long.',
    });
  }

  const regex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}/;

  if (!regex.test(password)) {
    return res.status(400).json({
      errorMessage:
        'Password needs to have at least 8 chars and must contain at least one number, one lowercase and one uppercase letter.',
    });
  }

  User.findOne({ username }).then((found) => {
    if (found) {
      return res.status(400).json({ errorMessage: 'Username already in use.' });
    }

    return bcrypt
      .genSalt(saltRounds)
      .then((salt) => bcrypt.hash(password, salt))
      .then((hashedPassword) => {
        return User.create({
          username,
          password: hashedPassword,
          campus,
          course,
        });
      })
      .then((user) => {
        const { username, campus, course } = createdUser;
        const user = { username, campus, course };
        req.session.user = user;
        res.status(201).json({ user: user });
      })
      .catch((err) => console.log(err));
  });
});

router.post('/login', isLoggedOut, (req, res, next) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res
      .status(400)
      .json({ errorMessage: 'Please provide your username/password.' });
  }

  if (password.length < 8) {
    return res.status(400).json({
      errorMessage: 'Your password needs to be at least 8 characters long.',
    });
  }

  User.findOne({ username })
    .then((user) => {
      if (!user) {
        return res.status(400).json({ errorMessage: 'Something is wrong' });
      }

      bcrypt.compare(password, user.password).then((isCorrectPassword) => {
        if (!isCorrectPassword) {
          return res.status(400).json({ errorMessage: 'Wrong credentials.' });
        }
        req.session.user = user._id; // ! better and safer but in this case we saving the entire user object
        return res.json(user);
      });
    })

    .catch((err) => {
      // in this case we are sending the error handling to the error handling middleware that is defined in the error handling file
      // you can just as easily run the res.status that is commented out below
      next(err);
      // return res.status(500).render("login", { errorMessage: err.message });
    });
});

// router.get('/logout', isLoggedIn, (req, res) => {
//   req.session.destroy((err) => {
//     if (err) {
//       return res.status(500).json({ errorMessage: err.message });
//     }
//     res.json({ message: 'Done' });
//   });
// });

router.get('/verify', (req, res) => {
  res.status(200).json(req.payload);
});

module.exports = router;
