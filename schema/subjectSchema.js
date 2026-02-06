const Joi = require("joi");
const ExpressError= require("../utils/ExpressError");

const subjectSchema = Joi.object({
   data: Joi.object({
  
    name: Joi.string()
    .required()
    .messages({
      "string.empty": "Name is required",
      "any.required": "Name is required",
    }),

  code: Joi.string()
    .required()
    .messages({
      "string.empty": "Code is required",
      "any.required": "Code is required",
    }),

  course: Joi.string()
    .required()
    .messages({
      "string.empty": "Course is required",
      "any.required": "Course is required",
    }),

  semester: Joi.string()
    .required()
    .messages({
      "string.empty": "Semester is required",
      "any.required": "Semester is required",
    }),

  maxMarks: Joi.number()
    .required()
    .messages({
      "number.base": "Max Marks must be a number",
      "any.required": "Max Marks is required",
    }),

  minMarks: Joi.number()
    .required()
    .messages({
      "number.base": "Min Marks must be a number",
      "any.required": "Min Marks is required",
    }),

  subjectType: Joi.string()
    .required()
    .messages({
      "string.empty": "Subject type is required",
      "any.required": "Subject type is required", 
   })

    }).required(),
})

const validateSubject = (req, res, next) => {
const {error} = subjectSchema.validate(req.body);


 if (error) {
    const msg = error.details.map((e) => e.message).join(",");
    return next(new ExpressError(400,msg));
  }

  next();

};

module.exports = validateSubject;