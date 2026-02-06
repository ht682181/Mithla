const Joi = require("joi");
const mongoose = require("mongoose");
const ExpressError = require("../utils/ExpressError.js");




 const feedSchema = Joi.object({
  data: Joi.object({
    // studentId: Joi.string()
    //   .required()
    //   .custom(objectId, "ObjectId validation"),

    content: Joi.string()
      .trim()
      .min(1)
      .max(300)   // 🔥 80 characters limit
      .required(),

    isRead: Joi.boolean().optional()
  }).required()
});


const validateFeed = (req, res, next) => {
  const { error } = feedSchema.validate(req.body);

 if (error) {
    const msg = error.details.map((e) => e.message).join(",");
    return next(new ExpressError(400,msg));
  }

  next();
};

module.exports = validateFeed;