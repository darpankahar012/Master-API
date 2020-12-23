const express = require('express')
const { register, login, logout,
    getMe, forgetPassword,
    resetPassword, updateDetails,
    updatePassword } = require('../controllers/auth')

const router = express.Router();

const { protect } = require('../middleware/auth');

router.route('/register').post(register)
router.route('/login').post(login)
router.route('/logout').get(logout)
router.route('/me').get(protect, getMe)
router.route('/updateDetails').put(protect, updateDetails)
router.route('/forgetPassword').post(forgetPassword)
router.route('/resetpassword/:resettoken').put(resetPassword)
router.route('/updatepassword').put(protect, updatePassword)

module.exports = router;