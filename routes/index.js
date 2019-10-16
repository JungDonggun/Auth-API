import express from 'express';
import { createHash, randomBytes, pbkdf2 } from 'crypto'

import models from '../database/models'

const router = express.Router();

const ejsTitle = { title: 'Integrator One' }

router.get('/', function (req, res) {
  const session = req.session

  console.log("in true session = ", session)

  return session.user ? res.redirect('/') : res.render('auth/login', ejsTitle);
});

router.get('/auth/logout', (req, res) => {
  const session = req.session

  if (session.nickName) {
    session.destroy((err) => {
      if (err) throw err
      res.redirect('/')
    })
  } else {
    res.redirect('/')
  }
})

router.get('/auth/login', function(req, res, next) {
  res.render('auth/login', ejsTitle);
});

router.post('/auth/login', async (req, res, next) => {
  const { identity, password } = req.body

  const user = models.user.findOne({ where: { identity }})

  const userPassword = user.dataValues.password
  const salt = user.dataValues.salt
  const hashedPassword = createHash('sha512').update(password + salt).digest('hex')

  if (userPassword === hashedPassword) {
    res.status(200).json({ message: 'Login approval.' })
  } else {
    res.status(400).json({ message: 'password do not match.'})
  }
});

router.get('/auth/register', function(req, res, next) {
  res.render('auth/register', ejsTitle);
});

router.post('/auth/register', function(req, res, next) {
  const { nickname, identity, password, re_password, division } = req.body

  if (password !== re_password) {
    return res.status(400).json({ message: 'password do not match.'})
  }

  if(!nickname || !identity || !password || !division) {
    console.log({ nickname, identity, password, division })
    return res.status(400).json({ message: 'Some parameters are lost' })
  }


  randomBytes(64, (err, buf) => {
    pbkdf2(password, buf.toString('base64'), 100000, 64, 'sha512', (err, key) => {
      if (err) throw err

      models.user.findOrCreate({
        where: { identity },
        defaults: { 
          nickname,
          division,
          password: key.toString('base64'),
          salt: buf.toString('base64')
        }
      }).spread((user, created) => {
        if (!created) {
          return res.status(200).json({ message: 'a saved user info'})
        } else {
          return res.status(412).json({ message: 'user identity duplicated'})
        }
      })
    })
  })
});

module.exports = router;
