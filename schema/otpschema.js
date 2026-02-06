const Joi = require("joi");
const ExpressError = require("../utils/ExpressError");

const otpSchema = Joi.object({
  otp: Joi.string()
    .pattern(/^[0-9]{6}$/)   // 6 digit numeric OTP
    .required()
    .messages({
      "string.empty": "OTP is required",
      "string.pattern.base": "OTP must be a 6-digit number",
      "any.required": "OTP is required"
    }),

  userId: Joi.string()
    .required()
    .messages({
      "string.empty": "User ID is required",
      "any.required": "User ID is required"
    }),
});

// Middleware
const validateOTP = (req, res, next) => {
  const { error } = otpSchema.validate(req.body);
  if (error) {
    const msg = error.details.map(e => e.message).join(", ");
    return next(new ExpressError(400,msg));
  }
  next();
};

module.exports = validateOTP;
