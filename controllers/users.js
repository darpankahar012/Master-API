const ErrorResponse = require('../utils/errorResponse')
const asyncHandler = require('../middleware/async')
const User = require('../models/User')

// @desc        Get All users
// @route       GET /api/v1/auth/users
exports.getUsers = asyncHandler(async (req, res, next) => {
    res.status(200).json(res.advancedResults);
})


// @desc        Get Single users
// @route       GET /api/v1/auth/users/:id
exports.getUser = asyncHandler(async (req, res, next) => {
    const user = await User.findById(req.params.id);

    res.status(200).json({
        success: true,
        data: user
    });
})


// @desc        Create users
// @route       POST /api/v1/auth/users/:id
exports.createUser = asyncHandler(async (req, res, next) => {
    const user = await User.create(req.body);

    res.status(201).json({
        success: true,
        data: user
    });
})


// @desc        Update users
// @route       PUT /api/v1/auth/users/:id
exports.updateUser = asyncHandler(async (req, res, next) => {
    const user = await User.findByIdAndUpdate(req.params.id, req.body, {
        new: true,
        runValidators: true
    });

    res.status(201).json({
        success: true,
        data: user
    });
})


// @desc        Delete users
// @route       DELETE /api/v1/auth/users/:id
exports.deleteUser = asyncHandler(async (req, res, next) => {
    await User.findByIdAndDelete(req.params.id);

    res.status(201).json({
        success: true,
        data: {}
    });
})