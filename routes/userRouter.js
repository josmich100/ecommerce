const router = require('express').Router()
const userCtrl = require('../controllers/userCtrl')

router.post('/register', userCtrl.register)
router.get('/refresh_token', userCtrl.refreshToken)

module.exports = router 