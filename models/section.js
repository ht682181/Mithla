// const { required } = require("joi");
const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const sectionSchema = new Schema({
    name: {
    type: String,
    required: [true, "Section name is required"],
    trim: true,
    uppercase: true,
    minlength: [1, "Section must be 1 character"],
    maxlength: [1, "Section must be 1 character"],
    match: [/^[A-Z]$/, "Section must be a single letter (A–Z)"]  ,    // 🔥 sirf 1 character
    unique:true
  }
});

const Section = mongoose.model("Section",sectionSchema);
module.exports =Section;

