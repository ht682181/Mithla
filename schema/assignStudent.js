const Joi = require("joi");
const ExpressError = require("../utils/ExpressError");

const assignStudentSchema = Joi.object({
  data: Joi.object({
  class: Joi.string().required(),
    semester: Joi.number().min(1).max(8).required(),

    subjects: Joi.array()
      .items(Joi.string())
      .min(1)
      .required(),

    students: Joi.array()
      .items(Joi.string().length(24))
      .min(1)
      .required()
  }).required()
});

const validateAssignStudent = (req, res,next)=>{
    const {error} = assignStudentSchema.validate(req.body);
    
if (error) {
    const msg = error.details.map((e) => e.message).join(",");
    return next(new ExpressError(400,msg));
  }

  next();
};

module.exports =validateAssignStudent;

