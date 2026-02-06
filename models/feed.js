const mongoose = require("mongoose");
const Student = require("../models/studentData.js");
const Schema = mongoose.Schema;


const feedSchema = new Schema({
  studentId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Student",
    required: true
  },
  content: {
    type: String,
    required: true
  },
   isRead:{ type:Boolean, default:false }, 
   
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const Feed = mongoose.model("Feed",feedSchema);
module.exports = Feed;
