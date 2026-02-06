const Joi = require("joi");
const ExpressError = require("../utils/ExpressError.js");

const sectionSchema = Joi.object({
  section: Joi.string().required(),
  subjects: Joi.array().items(Joi.string()).default([]),
});

const semesterSchema = Joi.object({
  semester: Joi.string().required(),
  sections: Joi.array().items(sectionSchema).default([]),
});

const classSchema = Joi.object({
  className: Joi.string().required(),
  semesters: Joi.array().items(semesterSchema).default([]),
});

const teacherSchema = Joi.object({
  name: Joi.string().required(),
  email: Joi.string().email().required(),
  mobile: Joi.string()
    .pattern(/^[0-9]{10}$/)
    .required()
    .messages({
      "string.pattern.base": "Mobile number must be exactly 10 digits",
    }), // 10 digit mobile

  image: Joi.object({
    url: Joi.string().uri().allow(null, ""),
    filename: Joi.string().allow(null, ""),
  }).optional(),

  class: Joi.array().items(classSchema).default([]),

  // subject: Joi.array().items(Joi.string()).default([]),

  // passport-local-mongoose fields
  username: Joi.string().required(),
  password: Joi.string().min(6).required(),
});


const validateTeacher = (req, res, next) => {
  const { error } = teacherSchema.validate(req.body.data);

  if (error) {
    const msg = error.details.map((e) => e.message).join(",");
    return next(new ExpressError(400,msg));
  }

  next();
};

module.exports = validateTeacher;