const mongoose = require("mongoose");
const Student = require("../models/studentData.js");
const Schema = mongoose.Schema;

const attendanceSchema = new Schema({
  // date: { type: Date, default: Date.now },

  studentId: {
    type: Schema.Types.ObjectId,
    ref: "Student",
    required: true
  },
  date: {
    type: Date,
    required: true, // ONLY DATE (normalized)
  },

  status: String,
  period: Number,
  subject: String,
  unit: String,
  description: String,
  teacherName:String,
});

const Attendance =   mongoose.model("Attendance", attendanceSchema);
module.exports = Attendance;

