const crypto = require('crypto')
const ErrorResponse = require('../utils/errorResponse')
const sendEmail = require('../utils/sendEmail')
const asyncHandler = require('../middleware/async')
const User = require('../models/User')

// @desc        Register User
// @route       POST /api/v1/auth/register
exports.register = asyncHandler(async (req, res, next) => {
    const { name, email, password, role } = req.body;

    // create user
    const user = await User.create({
        name,
        email,
        password,
        role
    });
    sendTokenResponse(user, 200, res)
})

// "email": {"$gt":""},
// @desc        Login User
// @route       POST /api/v1/auth/login
exports.login = asyncHandler(async (req, res, next) => {
    const { email, password } = req.body;

    // validate email & password
    if (!email || !password) {
        return next(new ErrorResponse('Please provide an email and password', 400))
    }

    // check for user
    const user = await User.findOne({ email }).select('+password');

    if (!user) {
        return next(new ErrorResponse('Invalid credentials[Email]', 400))
    }

    // Check if password matched
    const isMatch = await user.matchPassword(password);

    if (!isMatch) {
        return next(new ErrorResponse('Invalid credentials[Password]', 400))
    }

    sendTokenResponse(user, 200, res)
});


// @desc      Log user out / clear cookie
// @route     GET /api/v1/auth/logout
exports.logout = asyncHandler(async (req, res, next) => {
    res.cookie('token', 'none', {
        expires: new Date(Date.now() + 10 * 1000),
        httpOnly: true
    })
    res.status(200).json({
        success: true,
        data: {}
    });
});



// @desc      Get current logged in user
// @route     POST /api/v1/auth/me
exports.getMe = asyncHandler(async (req, res, next) => {
    const user = await User.findById(req.user.id);

    res.status(200).json({
        success: true,
        data: user
    });
});



// @desc       Update user Details
// @route       PUT /api/v1/auth/updatedetails
exports.updateDetails = asyncHandler(async (req, res, next) => {

    const fieldsToUpdate = {
        name: req.body.name,
        email: req.body.email
    }

    const user = await User.findByIdAndUpdate(req.user.id, fieldsToUpdate, {
        new: true,
        runValidators: true
    });

    res.status(200).json({
        success: true,
        data: user
    })
})



// @desc        Update Password
// @route       PUT /api/v1/auth/updatepassword
exports.updatePassword = asyncHandler(async (req, res, next) => {
    const user = await User.findById(req.user.id).select('+password');

    // Check current password
    if (!(await user.matchPassword(req.body.currentPassword))) {
        return next(new ErrorResponse('Password is incorrect', 401))
    }
    user.password = req.body.newPassword;
    await user.save();
    sendTokenResponse(user, 200, res)
})



// @desc        Forgot password
// @route       POST /api/v1/auth/forgetpassword
exports.forgetPassword = asyncHandler(async (req, res, next) => {
    const user = await User.findOne({ email: req.body.email });

    if (!user) {
        return next(new ErrorResponse('There is No user With that Email_ID', 400))
    }
    // Get reset Token
    const resetToken = user.getResetPasswordToken();

    // console.log(resetToken);
    await user.save({ validateBeforeSave: false })

    // Create reset url
    const resetUrl = `${req.protocol}://${req.get('host')}/api/v1/auth/resetpassword/${resetToken}`;

    const message = `${resetUrl}`;

    try {
        await sendEmail({
            email: user.email,
            subject: 'Password reset Token',
            message
        })
        res.status(200).json({ success: true, data: 'Email sent' })
    } catch (err) {
        console.log(err)
        user.resetPasswordToken = undefined;
        user.resetPasswordExpire = undefined;

        await user.save({ validateBeforeSave: false })

        return next(new ErrorResponse('Email could not be sent', 500));
    }

    res.status(200).json({
        success: true,
        data: user
    })
})

// @desc        Reset Password
// @route       PUT /api/v1/auth/resetpassword/:resettoken
exports.resetPassword = asyncHandler(async (req, res, next) => {

    // Get hashed token
    const resetPasswordToken = crypto
        .createHash('sha256')
        .update(req.params.resettoken)
        .digest('hex')
    const user = await User.findOne({
        resetPasswordToken,
        resetPasswordExpire: { $gt: Date.now() }
    });

    if (!user) {
        return next(new ErrorResponse('Invalid token', 400));
    }
    //  SET new password
    user.password = req.body.password;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;
    await user.save();

    sendTokenResponse(user, 200, res)

})


// Get Token from model, create cookie and send respond
const sendTokenResponse = (user, statusCode, res) => {
    const token = user.getSignedJwtToken();

    const option = {
        expires: new Date(Date.now() + process.env.JWT_COOKIE_EXPIRE * 24 * 60 * 60 * 1000),
        httpOnly: true
    }
    res.status(statusCode)
        .cookie('token', token, option)
        .json({
            success: true,
            token
        })
}
