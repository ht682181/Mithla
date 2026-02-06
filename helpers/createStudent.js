const Student = require("../models/studentData.js");

const courseDurations = {
  BCA: 3,
  MCA: 2,
  BBA: 3,
  MBA: 2,
};

function getCourseName(className) {
  // "BCA 1ST YEAR" → "BCA"
  return className.trim().split(/\s+/)[0].toUpperCase();
}

async function createStudent(data) {
  let expireAt = null;

  const course = getCourseName(data.class);
  const duration = courseDurations[course];

  if (duration) {
    if (data.session && data.session.includes("-")) {
      const endYear = parseInt(data.session.split("-")[1]);
      expireAt = new Date(`${endYear}-06-30`);
    } else {
      const now = new Date();
      expireAt = new Date(
        now.setFullYear(now.getFullYear() + duration)
      );
    }
  }

  const student = new Student({
    ...data,
    expireAt,
  });

  await student.save();
  return student;
}

module.exports = createStudent;
