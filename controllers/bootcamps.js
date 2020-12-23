const path = require('path')
const ErrorResponse = require('../utils/errorResponse')
const asyncHandler = require('../middleware/async')
const geocoder = require('../utils/geocoder')
const Bootcamp = require('../models/Bootcamp')



// @desc        Get All Bootcamps
// @route       GET /api/v1/bootcamps
exports.getBootcamps = asyncHandler(async (req, res, next) => {
    res.status(200).json(res.advancedResults);
})



// @desc        Get single Bootcamps
// @route       GET /api/v1/bootcamps/:id
exports.getBootcamp = asyncHandler(async (req, res, next) => {
    const bootcamp = await Bootcamp.findById(req.params.id);

    if (!bootcamp) {
        return next(
            new ErrorResponse(`Bootcamp not found with id of ${req.params.id}`, 404)
        )
    }
    res.status(200).json({ success: true, data: bootcamp })
})




// @desc        create new Bootcamps
// @route       POST /api/v1/bootcamps
exports.createBootcamps = asyncHandler(async (req, res, next) => {
    req.body.user = req.user.id;

    // check for published bootcamp
    const publishedBootcamp = await Bootcamp.findOne({ user: req.user.id });

    if (publishedBootcamp && req.user.role !== 'admin') {
        return next(
            new ErrorResponse(`The user with ID ${req.user.id} has already published bootcamp`, 400)
        )
    }

    const bootcamp = await Bootcamp.create(req.body);


    res.status(201).json({
        success: true,
        data: bootcamp
    })

})


// @desc        Update Bootcamps
// @route       PUT /api/v1/bootcamps/:id
exports.updateBootcamps = asyncHandler(async (req, res, next) => {
    let bootcamp = await Bootcamp.findById(req.params.id);
    if (!bootcamp) {
        return next(
            new ErrorResponse(`Bootcamp not found with id of ${req.params.id}`, 404)
        )
    }
    // Make sure user is Bootcamp owner
    if (bootcamp.user.toString() !== req.user.id && req.user.role !== 'admin') {
        return next(
            new ErrorResponse(`User ${req.params.id} is not authorized to update this bootcamp`, 401)
        )
    }
    bootcamp = await Bootcamp.findByIdAndUpdate(req.params.id, req.body, {
        new: true,
        runValidators: true
    })

    res.status(200).json({ success: true, data: bootcamp })
})


// @desc        Delete Bootcamps
// @route       DELETE /api/v1/bootcamps/:id
exports.deleteBootcamps = asyncHandler(async (req, res, next) => {

    const bootcamp = await Bootcamp.findById(req.params.id);
    if (!bootcamp) {
        return next(
            new ErrorResponse(`Bootcamp not found with id of ${req.params.id}`, 404)
        )
    }

    // Make sure user is Bootcamp owner
    if (bootcamp.user.toString() !== req.user.id && req.user.role !== 'admin') {
        return next(
            new ErrorResponse(`User ${req.params.id} is not authorized to delete this bootcamp`, 401)
        )
    }

    bootcamp.remove();
    res.status(200).json({ success: true, data: {} })

})


// @desc      Get bootcamps within a radius
// @route     GET /api/v1/bootcamps/radius/:zipcode/:distance
exports.getBootcampsInRadius = asyncHandler(async (req, res, next) => {
    const { zipcode, distance } = req.params;

    // Get lat/lng from geocoder
    const loc = await geocoder.geocode(zipcode);
    const lat = loc[0].latitude;
    const lng = loc[0].longitude;

    // Calc radius using radians
    // Divide dist by radius of Earth
    // Earth Radius = 3,963 mi / 6,378 km
    const radius = distance / 3963;

    const bootcamps = await Bootcamp.find({
        location: { $geoWithin: { $centerSphere: [[lng, lat], radius] } }
    });

    res.status(200).json({
        success: true,
        count: bootcamps.length,
        data: bootcamps
    });
});


// @desc        Upload photo for Bootcamps
// @route       PUT /api/v1/bootcamps/:id/photo
exports.bootcampPhotoUpload = asyncHandler(async (req, res, next) => {
    const bootcamp = await Bootcamp.findById(req.params.id);

    if (!bootcamp) {
        return next(
            new ErrorResponse(`Bootcamp not found with id of ${req.params.id}`, 404)
        )
    }
    // Make sure user is Bootcamp owner
    if (bootcamp.user.toString() !== req.user.id && req.user.role !== 'admin') {
        return next(
            new ErrorResponse(`User ${req.params.id} is not authorized to delete this bootcamp`, 401)
        )
    }
    if (!req.files) {
        return next(
            new ErrorResponse(`Please upload a file`, 400)
        )
    }
    const file = req.files.file;

    // Make sure the image is a photo
    if (!file.mimetype.startsWith('image')) {
        return next(
            new ErrorResponse(`Please upload a Image file`, 400)
        )
    }

    // check filesize
    if (!file.size > process.env.MAX_FILE_UPLOAD) {
        return next(
            new ErrorResponse(`Please upload a Image less then ${process.env.MAX_FILE_UPLOAD}`, 400)
        )
    }

    // Add customs file name
    file.name = `photo_${bootcamp._id}${path.parse(file.name).ext}`;

    file.mv(`${process.env.FILE_UPLOAD_PATH}/${file.name}`, async err => {
        if (err) {
            console.log(err)
            return next(
                new ErrorResponse(`Problem with file upload`, 500)
            )
        }

        await Bootcamp.findByIdAndUpdate(req.params.id, { photo: file.name });
        res.status(200).json({
            success: true,
            data: file.name
        })
    })

    console.log(file.name)

})