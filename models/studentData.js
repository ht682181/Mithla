const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const studentSchema = new Schema({
  rollNo: { type: Number, required: true },
  name: { type: String, required: true },
  fatherName: { type: String, required: true },
  section: { type: String, required: true },
  class: { type: String, required: true },
  session: { type: String, required: true },
  semester: { type: String, required: true },
  email: { type: String, required: true },
  image: {
    url: String,
    filename: String
  },
 subject: [
    {
      name: String,
      code: String,
      maxMarks: Number,
      minMarks: Number,
      subjectType: String,
    },
  ],
   
  createdAt: {
    type: Date,
    default: Date.now,
  },

  expireAt: {
    type: Date,
  },
});

/* 🔥 THIS IS MANDATORY — TTL INDEX */
studentSchema.index({ expireAt: 1 }, { expireAfterSeconds: 0 });


studentSchema.post("findOneAndDelete", async function (doc) {
  if (doc) {
    await mongoose.model("Attendance").deleteMany({
      studentId: doc._id
    });

    console.log(`🧹 Attendance deleted for student ${doc._id}`);
  }
});

const Student = mongoose.model("Student", studentSchema);
module.exports = Student;






