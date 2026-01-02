const express = require('express')
const { register, login, refreshTokens, logout, getProfile, getAddresses, addAddress, deleteAddress } = require('../controllers/auth.controller')
const authenticate = require('../middleware/auth.middleware')

const router = express.Router()

router.post('/register',register)

router.post('/login',login)
router.post('/refresh',refreshTokens)

router.post('/logout',authenticate,logout)
router.get('/profile',authenticate,getProfile)

router.get('/users/profile/addresses',authenticate,getAddresses)
router.post('/users/profile/addresses',authenticate,addAddress)
router.delete('/users/profile/addresses/:id',authenticate,deleteAddress)



module.exports = router
