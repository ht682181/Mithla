const mongoose = require("mongoose");
const Schema = mongoose.Schema;
const passportLocalMongoose = require("passport-local-mongoose");

// 🧩 Define nested schemas

const sectionSchema = new Schema({
  section: {
    type: String,
    required: true,
  },
  subjects: {
    type: [String],
    default: [],
  },
});

const semesterSchema = new Schema({
  semester: {
    type: String,
    required: true,
  },
  sections: {
    type: [sectionSchema],
    default: [],
  },
});

const classSchema = new Schema({
  className: {
    type: String,
    required: true,
  },
  semesters: {
    type: [semesterSchema],
    default: [],
  },
});

// 🧑‍🏫 Main Teacher Schema
const teacherSchema = new Schema({
  name: {
    type: String,
    required: true,
  },

  email: {
    type: String,
    required: true,
  },

  mobile: {
    type: String,
    required: true,
  },

  image:{
    url:String,
    filename:String,
  },

  // 🔥 Nested class structure
  class: {
    type: [classSchema],
    default: [],
  },

  // Optional top-level subjects if you want to track teacher's overall subjects
  // subject: {
  //   type: [String],
  //   default: [],
  // },
});

// 🪪 Add Passport plugin (handles username, password hashing)
teacherSchema.plugin(passportLocalMongoose);

// 📦 Export model
const Teacher = mongoose.model("Teacher", teacherSchema);
module.exports = Teacher;
