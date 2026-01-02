const userModel = require('../models/user.model')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')

const generateAccessAndRefreshTokens = async(userId) =>{
    try {
        const user = await userModel.findById(userId)
        
        const accessToken = jwt.sign(
            {
                id:user._id,
                email:user.email,
                role:user.role
            },
            process.env.ACCESS_TOKEN_SECRET,
            {expiresIn:'15m'}
        )
        const refreshToken = jwt.sign(
            {
                id:user._id
            },
            process.env.REFRESH_TOKEN_SECRET,
            {expiresIn:'7d'}
        )

        // Save the refresh token in the database
        // We skip validation because we are only updating one field
        user.refreshToken = refreshToken
        await user.save({validateBeforeSave:false})

        return {accessToken,refreshToken}

    } catch (error) {
        return null;
    }
}

const register = async(req,res)=>{
    const {email,password,username,role, fullName} = req.body

    const firstName = fullName?.firstName || req.body.firstName
    const lastName = fullName?.lastName || req.body.lastName

    if(!email || !password || !firstName || !lastName || !username){
        return res.status(400).json({message:"All fields are required"})
    }

    if(password.length < 8){
        return res.status(400).json({message:"Password must be at least 8 characters"})
    }

    const existingUser = await userModel.findOne({
        $or:[{email},{username}]
    })

    if(existingUser){
        return res.status(400).json({message:"User already exists"})
    }

    const hashedPassword = await bcrypt.hash(password,10)

    const user = await userModel.create({
        email,
        password:hashedPassword,
        fullName:{
            firstName,
            lastName
        },
        username,
        role: role || 'user'
    })

    const {accessToken,refreshToken} = await generateAccessAndRefreshTokens(user._id)

    const options = {
        httpOnly:true,
        secure:true
    }

    return res
    .status(201)
    .cookie("refreshToken",refreshToken,options)
    .json({
        message:"User registered successfully",
        user
    })
}

const login = async(req,res)=>{
    const {email,password} = req.body

    if(!email || !password){
        return res.status(400).json({message:"All fields are required"})
    }

    const user = await userModel.findOne({email})

    if(!user){
        return res.status(404).json({message:"User not found"})
    }

    const isPasswordCorrect = await bcrypt.compare(password,user.password)

    if(!isPasswordCorrect){
        return res.status(401).json({message:"Invalid credentials"})
    }

    const {accessToken,refreshToken} = await generateAccessAndRefreshTokens(user._id)

    const options = {
        httpOnly:true,
        secure:true
    }

    return res
    .status(200)
    .cookie("refreshToken",refreshToken,options)
    .json({
        message:"User logged in successfully",
        accessToken
    })
}

const refreshTokens = async(req,res)=>{
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken

    if(!incomingRefreshToken){
        return res.status(401).json({message:"Unauthorized request"})
    }

    try {
        const decodedToken = jwt.verify(
            incomingRefreshToken,
            process.env.REFRESH_TOKEN_SECRET
        )
    
        const user = await userModel.findById(decodedToken?.id)
    
        if(!user){
            return res.status(401).json({message:"Invalid refresh token"})
        }
    
        if(incomingRefreshToken !== user?.refreshToken){
            return res.status(401).json({message:"Refresh token is expired or used"})
        }
    
        const {accessToken,refreshToken} = await generateAccessAndRefreshTokens(user._id)
    
        const options = {
            httpOnly:true,
            secure:true
        }
    
        return res
        .status(200)
        .cookie("refreshToken",refreshToken,options)
        .json({
            accessToken,
            refreshToken,
            message:"Access token refreshed"
        })
    } catch (error) {
        return res.status(401).json({message:"Invalid refresh token"})   
    }
}

const logout = async(req,res)=>{
    await userModel.findByIdAndUpdate(
        req.user._id,
        {
            $unset:{
                refreshToken:1
            }
        },
        {
            new:true
        }
    )

    const options = {
        httpOnly:true,
        secure:true
    }

    return res
    .status(200)
    .clearCookie("refreshToken",options)
    .json({message:"User logged out"})
}

const getProfile = async(req,res)=>{
    const user = req.user
    return res.status(200).json({user})
}

const getAddresses = async(req,res)=>{
    const id = req.user.id
    const user = await userModel.findById(id).select("addresses")

    if (!user){
        return res.status(404).json({message:"User not found"})
    }
    return res.status(200).json({
        message:"User addresses fetched successfully",
        addresses:user.addresses
    })
}

const addAddress = async(req,res)=>{
    const id = req.user.id
    const {street,city,state,zip,country} = req.body

    if (!street || !city || !state || !zip || !country){
        return res.status(400).json({message:"All fields are required"})
    }

    const user = await userModel.findOneAndUpdate({_id:id},{
        $push:{
            addresses:{
                street,
                city,
                state,
                zip,
                country
            }
        }
    },
    {
        new:true
    })

    if (!user){
        return res.status(404).json({message:"User not found"})
    }

    return res.status(200).json({
        message:"Address added successfully",
        addresses:user.addresses
    })
}

const deleteAddress = async(req,res)=>{
    const id = req.user.id
    const { id: addressId } = req.params

    if (!addressId){
        return res.status(400).json({message:"Address ID is required"})
    }

    const user = await userModel.findOneAndUpdate({_id:id},{
        $pull:{
            addresses:{
                _id:addressId
            }
        }
    },
    {
        new:true
    })

    if (!user){
        return res.status(404).json({message:"User not found"})
    }

    const addressexists = user.addresses.some((address)=>address._id.toString() === addressId)

    if (!addressexists){
        return res.status(404).json({message:"Address not found"})
    }

    return res.status(200).json({
        message:"Address deleted successfully",
        addresses:user.addresses
    })
}

module.exports = {
    register,
    login,
    refreshTokens,
    logout,
    getProfile,
    getAddresses,
    addAddress,
    deleteAddress                       
}
