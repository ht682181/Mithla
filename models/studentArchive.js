const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const studentArchiveSchema = new Schema({

  // 🔗 Original student reference
  originalStudentId: {
    type: Schema.Types.ObjectId,
    required: true
  },

  rollNo: Number,
  name: String,
  fatherName: String,
  section: String,
  class: String,
  session: String,
  semester: String,
  email: String,

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
      subjectType: String
    }
  ],

  // 🗓️ Kab archive hua
  archivedAt: {
    type: Date,
    default: Date.now
  },

  // 🎓 Passout year (optional but useful)
  passoutYear: {
    type: Number
  }

});

module.exports = mongoose.model("StudentArchive", studentArchiveSchema);
