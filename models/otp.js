const mongoose = require("mongoose");
const Schema = mongoose.Schema;
 

const otpSchema = new Schema ({
  otp:{
    type:String,
    requred:true,
  },

  userId:{
    type:String,
    requred:true,
  },

   createdAt: { 
    type: Date, 
    default: Date.now 
  },

});

const OTP = mongoose.model("OTP", otpSchema);
 otpSchema.index({ createdAt: 1 }, { expireAfterSeconds: 30 });

 module.exports =OTP;