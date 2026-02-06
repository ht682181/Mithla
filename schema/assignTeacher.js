const Joi = require("joi");
const ExpressError = require("../utils/ExpressError");
const assignTeacherSchema = Joi.object({
  data: Joi.object({
    username: Joi.string()
      .trim()
      .required()
      .messages({
        "string.empty": "Teacher username is required"
      }),

    className: Joi.string()
      .trim()
      .required()
      .messages({
        "string.empty": "Class is required"
      }),

    semester: Joi.number()
      .integer()
      .min(1)
      .max(8)
      .required()
      .messages({
        "number.base": "Semester must be a number",
        "any.required": "Semester is required"
      }),

    section: Joi.string()
      .valid("A", "B")
      .required()
      .messages({
        "any.only": "Section must be A or B"
      }),

    subject: Joi.string()
      .trim()
      .required()
      .messages({
        "string.empty": "Subject is required"
      })

  }).required()
});


const validateAssignTeacher = (req, res, next) => {
  const { error } = assignTeacherSchema.validate(req.body);

  if (error) {
    const msg = error.details.map(e => e.message).join(",");
    return next(new ExpressError(400, msg));
  }

  next();
};

module.exports = validateAssignTeacher;
