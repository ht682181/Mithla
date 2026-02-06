
const ExpressError = require("./utils/ExpressError.js");

module.exports.isLoggedIn =(req, res, next)=>{
  if (!res.locals.curruser) {
    req.flash("error","You must be logged in");
   return res.redirect("/student/attendance/login")
  }
  next();

}
