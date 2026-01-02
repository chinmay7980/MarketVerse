const jwt = require('jsonwebtoken')
const userModel = require('../models/user.model')

const authenticate = async (req,res,next)=>{
    try {
        const authHeader = req.headers.authorization
        if(!authHeader || !authHeader.startsWith('Bearer ')){
             return res.status(401).json({message:"Access Denied"})
        }

        const token = authHeader.split(" ")[1]

        if(!token){
            return res.status(401).json({message:"Access Denied"})
        }

        const decoded = jwt.verify(token,process.env.ACCESS_TOKEN_SECRET)

        const user = await userModel.findById(decoded.id)
        
        if(!user){
            return res.status(401).json({message:"Invalid Token"})
        }

        req.user = user
        next()
    } catch (error) {
        res.status(401).json({message:"Invalid Token"})
    }
}

module.exports = authenticate
