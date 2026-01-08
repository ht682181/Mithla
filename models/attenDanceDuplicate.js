


const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const Student = require("./studentData.js");

// 🔹 Student reference
const AttendenceSchema = new Schema({
  studentId: { type: mongoose.Schema.Types.ObjectId, ref: "Student", required: true },

  createdAt: { type: Date, default: Date.now }, // used for TTL auto-delete

  attendance: [
    {
       date: { type: Date, default: Date.now,}, 
       studentId:String,
      status: String,
      periods: Number,
      class:String,
      section:String,
      unit:String,
      description:String,
      subject:String,
      semester:String,
      teacherId:String,
      teacherName:String,
      // createdAt: { type: Date, default: Date.now }, // used for 24-hour update check
    },
  ],
});

// 🔥 Auto delete document after 24 hours
AttendenceSchema.index({ createdAt: 1 }, { expireAfterSeconds: 86400 });

const AttendenceDuplicate = mongoose.model("AttendenceDuplicate", AttendenceSchema);
module.exports = AttendenceDuplicate;
