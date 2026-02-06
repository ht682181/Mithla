const Joi = require("joi");
const ExpressError = require("../utils/ExpressError");

const classSchema = Joi.object({
  data: Joi.object({
    
    class: Joi.string().required(),
  
}).required(),
});

const validateClass = (req, res,next)=>{
    const {error} = classSchema.validate(req.body);
    
if (error) {
    const msg = error.details.map((e) => e.message).join(",");
    return next(new ExpressError(400,msg));
  }

  next();
};

module.exports = validateClass;
