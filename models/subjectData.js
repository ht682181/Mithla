const mongoose = require("mongoose");
const Schema = mongoose.Schema;


const SubjectSchema = new Schema({
  name: { type: String, required: true }, // like "Math"
  code: { type: String, required: true, unique: true },
  course:{type:String, required:true},
  semester:{type:String, required:true},
   maxMarks:{type:Number, required:true},
    minMarks:{type:Number, required:true},
     subjectType:{type:String, required:true},
});

const Subject = mongoose.model("Subject", SubjectSchema);
module.exports = Subject;
