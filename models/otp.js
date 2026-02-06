const mongoose = require("mongoose");
const Schema = mongoose.Schema;
 

const otpSchema = new Schema ({
  otp:{
    type:String,
    required:true,
  },

  userId:{
    type:String,
    required:true,
  },

   createdAt: { 
    type: Date, 
    default: Date.now 
  },

});

const OTP = mongoose.model("OTP", otpSchema);
 otpSchema.index({ createdAt: 1 }, { expireAfterSeconds: 30 });

 module.exports =OTP;