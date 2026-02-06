const Joi = require("joi");
const ExpressError = require("../utils/ExpressError.js");


const editTeacherSchema = Joi.object({
  data:Joi.object({

    name: Joi.string().required(),
  email: Joi.string().email().required(),
  mobile: Joi.string()
    .pattern(/^[0-9]{10}$/)
    .required()
    .messages({
      "string.pattern.base": "Mobile number must be exactly 10 digits",
    }),
  username: Joi.string().required(),
   password: Joi.string()
  .allow("", null)        // empty ya null allowed
  .min(6)                 // agar value hai, toh minimum 6 char
  .optional()
  .messages({
    "string.min": "Password must be at least 6 characters",
  }),

  image: Joi.any().optional(), // multer handles file
  class: Joi.array().optional(),
  subject: Joi.array().optional(),

  }).required(),
});

const validateTeacherEdit = (req, res, next) => {
  const { error } = editTeacherSchema.validate(req.body);

 if (error) {
    const msg = error.details.map((e) => e.message).join(",");
    return next(new ExpressError(400,msg));
  }

  next();
};

module.exports = validateTeacherEdit