if (process.env.NODE_ENV != "production") {
  require("dotenv").config();
}

const express = require("express");
const app = express();
const mongoose = require("mongoose");
const ExpressError = require("./utils/ExpressError.js");
const WrapAsync = require("./utils/WrapAsync.js");
const path = require("path");
const ejsmate = require("ejs-mate");
const methodOverride = require("method-override");
const multer = require("multer");
const { storage } = require("./cloudStorage.js");
const upload = multer({ storage });

const nodemailer = require("nodemailer");
const AttendenceDuplicate = require("./models/attenDanceDuplicate.js");
const Student = require("./models/studentData.js");
const Teacher = require("./models/teacherRecord.js");
const Subject = require("./models/subjectData.js");
const Class = require("./models/classRecord.js");
const Attendance = require("./models/attendanceRecord.js");
const OTP = require("./models/otp.js");
const { isLoggedIn } = require("./middleware.js");
const PDFDocument = require("pdfkit");
const flash = require("connect-flash");
const passport = require("passport");
const localStrategy = require("passport-local");
const dayjs = require("dayjs"); /////// date filter
const utc = require("dayjs/plugin/utc"); /////// date filter
dayjs.extend(utc);
const normalizeDate = require("./utils/normalizeDate.js");


const validateTeacher = require("./schema/teacherSchema.js");
const validateTeacherEdit = require("./schema/editTeacherSchema.js");
const validateStudent = require("./schema/studentSchema.js");
const validateClass = require("./schema/classSchema.js");


  





// ------------------ MongoStore + Session Setup ------------------

const session = require("express-session");
const MONGO_URL = "mongodb://127.0.0.1:27017/FinalAttendance";

main()
  .then(() => {
    console.log("connected to DB");
  })
  .catch((err) => {
    console.log(err);
  });

async function main() {
  await mongoose.connect(MONGO_URL);
}

const sessionOption = {
  secret: "lala",
  resave: false,
  saveUninitialized: true,
  cookie: {
    expires: Date.now() + 7 * 24 * 60 * 60 * 1000,
    maxAge: 7 * 24 * 60 * 60 * 1000,
    httpOnly: true,
  },
};

app.use(session(sessionOption));



app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "/public")));
app.use(methodOverride("_method"));
app.engine("ejs", ejsmate);
const createStudent = require("./helpers/createStudent.js");

app.use(passport.initialize());
app.use(passport.session());
passport.use(new localStrategy(Teacher.authenticate()));

passport.serializeUser(Teacher.serializeUser());
passport.deserializeUser(Teacher.deserializeUser());
app.use(flash());

app.use((req, res, next) => {
  res.locals.success = req.flash("success");
  res.locals.error = req.flash("error");
  res.locals.curruser = req.user;
  next();
});




// session function for verify the user

function verifiedAny(req, res, next) {
  if (req.session.adminVerified || req.session.otpVerified) {
    return next();
  }

  req.flash("error", "Please login now!");
   return res.redirect("/student/attendance/login");
}



const isAdminOrTeacher = (req, res, next) => {
  if (req.isAuthenticated() || req.session.adminVerified) {
    return next();
  }
  req.flash("error", "Please login now");
  return res.redirect("/student/attendance/login");
};

// to remove attendance when student is delete

setInterval(async () => {
  try {
    // 🔹 All valid student ObjectIds
    const studentIds = await Student.distinct("_id");

    // 🔹 Find orphan attendances
    const orphanAttendances = await Attendance.find({
      studentId: { $nin: studentIds },
    }).select("_id");

    if (orphanAttendances.length === 0) {
      // console.log("✅ No orphan attendance found");
      return;
    }

    // 🔹 Delete only orphans
    const idsToDelete = orphanAttendances.map((a) => a._id);

    const result = await Attendance.deleteMany({
      _id: { $in: idsToDelete },
    });

    console.log(`🧹 Deleted ${result.deletedCount} orphan attendance records`);
  } catch (err) {
    console.error("❌ Attendance cleanup error:", err);
  }
}, 1 * 60 * 1000); // every 2 minutes

app.post(
  "/student/add",
  WrapAsync(async (req, res) => {
    const student = await createStudent(req.body);

    if (!student) {
      return res.status(400).json({ success: false, message: "Invalid student data" });
    }

    return res.status(201).json({
      success: true,
      message: "Student added with TTL ✅",
      expireAt: student.expireAt || null,
    });
  })
);


console.log("Mongo URL:", process.env.ATLASDB_URL);

// users login

app.get("/student/attendance/login", (req, res) => {
  res.render("users/login.ejs");
});



app.post(
  "/student/attendance/login",
  WrapAsync(async (req, res) => {
    try {
      const { role, username, password } = req.body;
      const studentPassword = process.env.STUDENT_PASSWORD;
      const adminUsername = process.env.ADMIN_USERNAME;
      const adminPassword = process.env.ADMIN_PASSWORD;
      const adminRole = process.env.ROLE_1;
      const teacherRole = process.env.ROLE_2;
      const studentRole = process.env.ROLE_3;

      req.session.adminVerified = false;

      // ===== Admin Login =====
      if (adminRole === role) {
        if (adminUsername === username && adminPassword === password) {
          req.session.adminVerified = true;
          req.flash("success", "Login successfully");
          return res.redirect("/admin/student/attendance");
        } else {
          req.flash("error", "Admin credentials incorrect");
          return res.redirect("/student/attendance/login");
        }
      }

      // ===== Teacher Login =====
      if (teacherRole === role) {
        return res.redirect(307, "/login/modal"); // preserves POST body
      }

      // ===== Student Login =====
      if (studentRole === role && studentPassword === password) {
        const newStudent = await Student.findOne({ rollNo: username });

        if (!newStudent) {
          req.flash("error", "Student not found for this username");
          return res.redirect("/student/attendance/login");
        }

        req.session.rollNo = username;
        req.session.otpVerified = false;

        // Generate OTP
        let otp = "";
        for (let i = 0; i < 6; i++) {
          otp += Math.floor(Math.random() * 10);
        }

        const newOtp = new OTP({
          userId: newStudent._id,
          otp,
        });
        await newOtp.save();

        // Send email
        const transporter = nodemailer.createTransport({
          host: "smtp.gmail.com",
          port: 587,
          secure: false,
          auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS,
          },
        });

        await transporter.sendMail({
          from: process.env.EMAIL_USER,
          to: newStudent.email,
          subject: "Attendance Verification Code",
          text: `Dear Student,\nYour verification code is ${otp}. Please enter it within 30 seconds. Keep it confidential.`,
        });

        return res.redirect("/otp");
      }

      // ===== Invalid Role =====
      req.flash("error", "Role not matched");
      return res.redirect("/student/attendance/login");

    } catch (err) {
      console.error("Login Error:", err);
      req.flash("error", "Something went wrong, please try again");
      return res.redirect("/student/attendance/login");
    }
  })
);

//  admin main route

app.get(
  "/admin/student/attendance",
  verifiedAny,
  WrapAsync(async (req, res) => {
    let teacherData = await Teacher.find({});
    let classData = await Class.find({});
    let subjectData = await Subject.find({});
    let studentData = await Student.find({});

    res.render("admin/main.ejs", {
      teacherData,
      classData,
      subjectData,
      studentData,
    });
  })
);




// logout admin
app.get("/admin/logout", verifiedAny, (req, res) => {
  req.session.adminVerified = false;
  req.flash("success", "Logout successfuly");
  res.redirect("/student/attendance/login");
});

// search box teacher
app.post(
  "/search/teacher",
  WrapAsync(async (req, res) => {
    let { search } = req.body;
    let datas = await Teacher.find({
      name: { $regex: search, $options: "i" },
    });
    if (datas.length === 0) {
      req.flash("error", "Teacher not found!");
      res.redirect("/show/teacher");
    } else {
      res.render("admin/searchTeacher.ejs", { datas });
    }
  })
);

// teachers

// add teacherData

app.get("/add/teacherData", verifiedAny, (req, res) => {
  res.render("admin/createTeacher.ejs");
});

app.post(
  "/add/teacherData",
  upload.single("data[image]"),
  validateTeacher,
  WrapAsync(async (req, res) => {
    let { data } = req.body;
    try {
      let url = req.file.path;
      let filename = req.file.filename;
      const newTeacher = new Teacher(req.body.data);
      newTeacher.image = { url, filename };
      let registerUser = await Teacher.register(newTeacher, data.password);
      req.login(registerUser, (err) => {
        if (err) {
          return next(err);
        }
        if (!req.session.adminVerified) {
          req.session.adminVerified = true;
        }
        req.flash("success", "Add Teacher successfully");
        res.redirect("/add/teacherData");
      });
    } catch (e) {
      req.flash("error", e.message);
      res.redirect("/add/teacherData");
    }
  })
);

// show teacher page

app.get(
  "/show/teacher",
  verifiedAny,
  WrapAsync(async (req, res) => {
    let datas = await Teacher.find({});
    res.render("admin/showTeacher.ejs", { datas });
  })
);

//  show teacher profile

app.get(
  "/teacher/profile/:id",
  verifiedAny,
  WrapAsync(async (req, res) => {
    let { id } = req.params;
    let data = await Teacher.findById(id);
    res.render("admin/teacherProfile.ejs", { data });
  })
);

// /show /assign/teacher/class/subject/secrtion/semester

app.get(
  "/show/teacher/class/:id",
  verifiedAny,
  WrapAsync(async (req, res) => {
    let { id } = req.params;
    req.session.teacherId = id;
    let datas = await Teacher.findById(id);
    res.render("admin/showTeacherClass.ejs", { datas });
  })
);

// /delete/teacher/class/ /subject/secrtion/semester

app.delete(
  "/delete/teacher/class/:classId/semester/:semesterId/section/:sectionId",
  verifiedAny,
  WrapAsync(async (req, res) => {
    const { classId, semesterId, sectionId } = req.params;
    const teacherId = req.session.teacherId;

    await Teacher.findOneAndUpdate(
      {
        _id: teacherId,
        "class._id": classId,
        "class.semesters._id": semesterId,
      },
      {
        $pull: {
          "class.$[cls].semesters.$[sem].sections": { _id: sectionId },
        },
      },
      {
        arrayFilters: [{ "cls._id": classId }, { "sem._id": semesterId }],
      }
    );

    req.flash("success", "Section deleted successfully");
    res.redirect(`/show/teacher/class/${teacherId}`);
  })
);

// edit teacher

app.get(
  "/edit/teacher/:id",
  verifiedAny,
  WrapAsync(async (req, res) => {
    let { id } = req.params;
    let data = await Teacher.findById(id);
    res.render("admin/editTeacher.ejs", { id, data });
  })
);

app.put(
  "/edit/teacher/:id",
  upload.single("data[image]"),
  validateTeacherEdit,
  WrapAsync(async (req, res) => {
    let { id } = req.params;
    let { name, email, username, mobile, password } = req.body.data;
    console.log(password);

    let teacher = await Teacher.findById(id);


    if (!teacher) {
      req.flash("error", "Teacher not found");
      return res.redirect("/show/teacher");
    }

    // Normal fields update
    teacher.name = name;
    teacher.email = email;
    teacher.username = username;
    teacher.mobile = mobile;

    // Agar password change karna hai
    if (password && password.trim() !== "") {
      await teacher.setPassword(password); // <-- passport-local-mongoose ka method
    }

    if (typeof req.file !== "undefined") {
      let url = req.file.path;
      let filename = req.file.filename;
      teacher.image = { url, filename };
    }

    await teacher.save();

    req.flash("success", "Edit teacher successfully");
    res.redirect("/show/teacher");
  })
);

// DELETE TEACHER

app.delete(
  "/delete/teacher/:id",
  verifiedAny,
  WrapAsync(async (req, res) => {
    let { id } = req.params;
    let teacher = await Teacher.findByIdAndDelete(id);
    req.flash("success", "Teacher deleted successfully");
    res.redirect("/show/teacher");
  })
);

// student/

// add/StudentData

app.get(
  "/add/studentData",
  verifiedAny,
  WrapAsync(async (req, res) => {
    let classData = await Class.find({});
    res.render("admin/createStudent.ejs", { classData });
  })
);

app.post(
  "/add/studentData",
  upload.single("data[image]"),
  validateStudent,
  WrapAsync(async (req, res) => {
    let { data } = req.body;

    let url = req.file.path;
    let filename = req.file.filename;

    let newStudent = new Student(data);
    newStudent.image = { url, filename };
    await newStudent.save();

    if (!req.session.adminVerified) {
      req.session.adminVerified = true;
    }

    req.flash("success", "Add Student successfully");
    return res.redirect("/add/studentData");
  })
);

//  show student  page

app.get(
  "/show/student",
  verifiedAny,
  WrapAsync(async (req, res) => {
    let datas = await Student.find({});
    let course = await Class.find({});
    res.render("admin/showStudent.ejs", { datas, course });
  })
);

// student profile

app.get(
  "/student/profile/:id",
  verifiedAny,
  WrapAsync(async (req, res) => {
    let { id } = req.params;
    let student = await Student.findById(id);
    res.render("admin/studentProfile.ejs", { student });
  })
);

// edit student

app.get(
  "/edit/student/:id",
  verifiedAny,
  WrapAsync(async (req, res) => {
    let { id } = req.params;
    let data = await Student.findById(id);
    let classData = await Class.find({});
    res.render("admin/editStudent.ejs", { id, data, classData });
  })
);

app.put(
  "/edit/student/:id",
  upload.single("data[image]"),
  validateStudent,
  WrapAsync(async (req, res) => {
    let { id } = req.params;
    let student = await Student.findByIdAndUpdate(id, { ...req.body.data });

    if (typeof req.file !== "undefined") {
      let url = req.file.path;
      let filename = req.file.filename;
      student.image = { url, filename };
    }

    await student.save();
    req.flash("success", "Edit student successfully");
    res.redirect("/show/student");
  })
);

// DELETE student

app.delete(
  "/delete/student/:id",
  verifiedAny,
  WrapAsync(async (req, res) => {
    let { id } = req.params;
    let student = await Student.findByIdAndDelete(id);
    req.flash("success", "Student deleted successfully");
    res.redirect("/show/student");
  })
);

// search box student
app.post(
  "/search/student",
  WrapAsync(async (req, res) => {
    let { data } = req.body;

    let query = {};

    if (data.name) {
      query.name = { $regex: data.name, $options: "i" };
    }

    if (data.class) {
      query.class = data.class;
    }

    let datas = await Student.find(query);

    if (datas.length === 0) {
      req.flash("error", "Student not find");
      return res.redirect("/show/student");
    }

    res.render("admin/searchStudent.ejs", { datas });
  })
);

// show student subject

app.get(
  "/show/student/subject/:rollNo",
  verifiedAny,
  WrapAsync(async (req, res) => {
    const { rollNo } = req.params;

    if (!rollNo) {
      req.flash("error", "Something went wrong");
      return res.redirect("/add/studentData");
    }

    // 🔹 Student sirf info ke liye
    const datas = await Student.findOne({ rollNo: parseInt(rollNo) });

    if (!datas) {
      req.flash("error", "Student not found");
      return res.redirect("/add/studentData");
    }

    return res.render("admin/showStudentSubject.ejs", { datas });
  })
);

// delete student subject/

app.delete(
  "/delete/:studentId/subject/:subjectId",
  verifiedAny,
  WrapAsync(async (req, res) => {
    const { studentId, subjectId } = req.params;

    let data = await Student.findByIdAndUpdate(studentId, {
      $pull: { subject: { _id: subjectId } },
    });

    req.flash("success", "Subject removed successfully!");
    res.redirect(`/show/student/subject/${data.rollNo}`);
  })
);

//  show student status

app.get(
  "/student/status/:rollNo",
  verifiedAny,
  WrapAsync(async (req, res) => {
    const { rollNo } = req.params;
    req.session.rollno = rollNo;

    if (!rollNo) {
      req.flash("error", "Something went wrong");
      return res.redirect("/add/studentData");
    }

    // 🔹 Student sirf info ke liye
    const student = await Student.findOne({ rollNo: parseInt(rollNo) });

    if (!student) {
      req.flash("error", "Student not found");
      return res.redirect("/add/studentData");
    }

    return res.render("admin/studentStatus.ejs", { student });
  })
);

// ----------------- singele student status Filter routes -----------------

app.get(
  "/attendance/:studentId/:filter",
  verifiedAny,
  WrapAsync(async (req, res) => {
    const { studentId, filter } = req.params;
    req.session.studentId = studentId;

    let dateQuery = {};
    const now = new Date();

    // ===== TODAY (UTC SAFE) =====
    if (filter === "today") {
      const start = new Date(
        Date.UTC(
          now.getUTCFullYear(),
          now.getUTCMonth(),
          now.getUTCDate(),
          0,
          0,
          0,
          0
        )
      );

      const end = new Date(
        Date.UTC(
          now.getUTCFullYear(),
          now.getUTCMonth(),
          now.getUTCDate(),
          23,
          59,
          59,
          999
        )
      );

      dateQuery = { $gte: start, $lte: end };
    }

    // ===== WEEKLY (Sun–Sat, UTC SAFE) =====
    if (filter === "weekly") {
      const day = now.getUTCDay(); // 0=Sun
      const startOfWeek = new Date(
        Date.UTC(
          now.getUTCFullYear(),
          now.getUTCMonth(),
          now.getUTCDate() - day,
          0,
          0,
          0,
          0
        )
      );

      const endOfWeek = new Date(
        Date.UTC(
          startOfWeek.getUTCFullYear(),
          startOfWeek.getUTCMonth(),
          startOfWeek.getUTCDate() + 6,
          23,
          59,
          59,
          999
        )
      );

      dateQuery = { $gte: startOfWeek, $lte: endOfWeek };
    }

    // ===== MONTHLY (1st → last day, UTC SAFE) =====
    if (filter === "monthly") {
      const startOfMonth = new Date(
        Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1, 0, 0, 0, 0)
      );

      const endOfMonth = new Date(
        Date.UTC(
          now.getUTCFullYear(),
          now.getUTCMonth() + 1,
          0,
          23,
          59,
          59,
          999
        )
      );

      dateQuery = { $gte: startOfMonth, $lte: endOfMonth };
    }

    const attendance = await Attendance.find({
      studentId,
      ...(filter !== "all" && { date: dateQuery }),
    }).sort({ date: 1, period: 1 });

    res.json({
      success: true,
      filter,
      range: dateQuery,
      count: attendance.length,
      data: attendance,
    });
  })
);

function parseIndianDate(dateStr) {
  // expected: YYYY-MM-DD (HTML input)
  const [year, month, day] = dateStr.split("-");
  const d = new Date(year, month - 1, day);
  d.setHours(0, 0, 0, 0);
  return d;
}
app.post(
  "/admin/search/student/attendance/date",
  verifiedAny,
  WrapAsync(async (req, res) => {
    const rollNo = req.session.rollno;
    const studentId = req.session.studentId;
    const { from, to } = req.body.data;

    if (!from || !to) {
      req.flash("error", "Please select From & To date");
      return res.redirect(`/student/status/${rollNo}`);
    }

    // ✅ FIXED DATE PARSING
    const fromDate = parseIndianDate(from);

    const toDate = parseIndianDate(to);
    toDate.setHours(23, 59, 59, 999);

    const student = await Student.findOne({ rollNo: parseInt(rollNo) });
    if (!student) {
      req.flash("error", "Student not found");
      return res.redirect(`/student/status/${rollNo}`);
    }

    const attendanceRecords = await Attendance.find({
      studentId,
      date: {
        $gte: fromDate,
        $lte: toDate,
      },
    }).sort({ date: 1, period: 1 });

    if (!attendanceRecords || !attendanceRecords.length) {
  req.flash("error", "No attendance found");
  return res.redirect(`/student/status/${rollNo}`);
}

    const dayMap = new Map();

    attendanceRecords.forEach((att) => {
      const key = new Date(att.date).toDateString();
      if (!dayMap.has(key)) dayMap.set(key, []);
      dayMap.get(key).push(att.status);
    });

    let totalDays = dayMap.size;
    let presentDays = 0;
    let absentDays = 0;

    dayMap.forEach((statuses) => {
      if (statuses.includes("Present")) presentDays++;
      else absentDays++;
    });

    // ---------- RENDER ----------
    res.render("admin/DateWiseStatus.ejs", {
      attendanceRecords,
      total: totalDays,
      present: presentDays,
      absent: absentDays,
      from,
      to,
      student,
    });
  })
);
// subjects

// add subjectData

app.get(
  "/add/subjectData",
  verifiedAny,
  WrapAsync(async (req, res) => {
    let classData = await Class.find({});
    res.render("admin/createSubject.ejs", { classData });
  })
);

app.post(
  "/add/subjectData",
  WrapAsync(async (req, res) => {
    let newSubject = new Subject(req.body.data);
    await newSubject.save();
    if (!req.session.adminVerified) {
      req.session.adminVerified = true;
    }
    req.flash("success", "Add subject succefully");
    res.redirect("/add/subjectData");
  })
);

// show subject page

app.get(
  "/show/subject",
  verifiedAny,
  WrapAsync(async (req, res) => {
    let datas = await Subject.find({});
    res.render("admin/showSubject.ejs", { datas });
  })
);

// edit subject page//

app.get(
  "/edit/subject/:subjectId",
  verifiedAny,
  WrapAsync(async (req, res) => {
    let subjectId = req.params.subjectId;
    let data = await Subject.findById(subjectId);
    let classData = await Class.find({});
    res.render("admin/editSubject", { data, classData });
  })
);

app.put(
  "/edit/subject/:subjectId",
  verifiedAny,
  WrapAsync(async (req, res) => {
    let subjectId = req.params.subjectId;
    let subject = await Subject.findByIdAndUpdate(subjectId, {
      ...req.body.data,
    });
    await subject.save();
    req.flash("success", "Subject edit successfully");
    res.redirect("/show/subject");
  })
);

// delete subject

app.delete(
  "/delete/subject/:id",
  verifiedAny,
  WrapAsync(async (req, res) => {
    let { id } = req.params;
    let subject = await Subject.findByIdAndDelete(id);
    req.flash("success", "Subject deleted successfully");
    res.redirect("/show/subject");
  })
);

// search page for subject

app.post(
  "/search/subject",
  WrapAsync(async (req, res) => {
    let { search } = req.body;
    let datas = await Subject.find({
      name: { $regex: search, $options: "i" },
    });
    if (datas.length === 0) {
      req.flash("error", "Subject not found!");
      res.redirect("/show/subject");
    } else {
      res.render("admin/searchSubject.ejs", { datas });
    }
  })
);

// classes//

// add/class

app.get("/add/class", verifiedAny, (req, res) => {
  res.render("admin/createClass.ejs");
});

app.post(
  "/add/class",
  verifiedAny,
  validateClass,
  WrapAsync(async (req, res) => {
    let { class: className } = req.body.data;

    // Auto format (uppercase + trim + single space)
    className = className.toUpperCase().trim().replace(/\s+/g, " ");

    // ✅ Allowed formats (B.TECH only — no BTECH)
    const classFormat =
      /^(B\.TECH(\s(CSE|IT|ECE|EEE|EE|ME|CIVIL|AI\/ML|DS))?|BCA|BBA|B\.SC|M\.SC|MCA|MBA|DIPLOMA(\s(CIVIL|ME|EE|CSE))?|BA|MA|ITI|POLYTECHNIC)\s(1ST|2ND|3RD|4TH)\sYEAR$/;

    // ❌ Reject if BTECH without dot typed
    if (/^BTECH/.test(className)) {
      req.flash("error", "Use proper format: B.TECH (not BTECH)");
      return res.redirect("/add/class");
    }

    // ❌ Invalid format check
    if (!classFormat.test(className)) {
      req.flash(
        "error",
        "Invalid format! Examples:\n• B.TECH CSE 1ST YEAR\n• BCA 2ND YEAR\n• BA 1ST YEAR"
      );
      return res.redirect("/add/class");
    }

    // ✅ Duplicate check before save
    const exists = await Class.findOne({ class: className });
    if (exists) {
      req.flash("error", "This class already exists!");
      return res.redirect("/add/class");
    }

    // Save formatted class
    req.body.data.class = className;
    await new Class(req.body.data).save();

    req.flash("success", "Class added successfully");
    res.redirect("/add/class");
  })
);

// show class page

app.get(
  "/show/class",
  verifiedAny,
  WrapAsync(async (req, res) => {
    let datas = await Class.find({});
    res.render("admin/showClass.ejs", { datas });
  })
);

app.delete(
  "/delete/class/:id",
  verifiedAny,
  WrapAsync(async (req, res) => {
    let { id } = req.params;
    let data = await Class.findByIdAndDelete(id);
    req.flash("success", "  Class deleted successfully");
    res.redirect("/show/class");
  })
);

// assign

// ajax find teacher subject option?

app.get(
  "/get-subjects/:className/:semester",
  verifiedAny,
  WrapAsync(async (req, res) => {
    const { className, semester } = req.params;

    const subjects = await Subject.find({
      course: className,
      semester: semester
    });

    res.json(subjects);
  })
);


// assign/teacher/subject/class

app.get(
  "/assign/teacher/subject/class",
  verifiedAny,
  WrapAsync(async (req, res) => {
    let teacherData = await Teacher.find({});
    let classData = await Class.find({});
    let subjectData = await Subject.find({});

    res.render("admin/teacherAssign.ejs", {
      teacherData,
      classData,
      subjectData,
    });
  })
);

app.post(
  "/assign/teacher/subject/class",
  WrapAsync(async (req, res) => {
    const { data } = req.body;

    // Find teacher
    const teacher = await Teacher.findOne({ username: data.username });
    if (!teacher) {
      req.flash("error", "Teacher not found");
      return res.redirect("/assign/teacher/subject/class");
    }

    // Step 1️⃣: Find class
    let classObj = teacher.class.find(
      (cls) => cls.className === data.className
    );

    if (!classObj) {
      // Class not found — create new one
      classObj = {
        className: data.className,
        semesters: [
          {
            semester: data.semester,
            sections: [
              {
                section: data.section,
                subjects: [data.subject],
              },
            ],
          },
        ],
      };
      teacher.class.push(classObj);
    } else {
      // Step 2️⃣: Find semester
      let semesterObj = classObj.semesters.find(
        (sem) => sem.semester === data.semester
      );

      if (!semesterObj) {
        // Add new semester
        classObj.semesters.push({
          semester: data.semester,
          sections: [
            {
              section: data.section,
              subjects: [data.subject],
            },
          ],
        });
      } else {
        // Step 3️⃣: Find section
        let sectionObj = semesterObj.sections.find(
          (sec) => sec.section === data.section
        );

        if (!sectionObj) {
          // Add new section
          semesterObj.sections.push({
            section: data.section,
            subjects: [data.subject],
          });
        } else {
          // Step 4️⃣: Add subject if not exists
          if (!sectionObj.subjects.includes(data.subject)) {
            sectionObj.subjects.push(data.subject);
          }
        }
      }
    }

    await teacher.save();
    req.flash("success", "Assigned successfully");
    res.redirect("/assign/teacher/subject/class");
  })
);

// Assign student

// ajax find student subject option?

app.get(
  "/get-subjects/:className/:semester",
  verifiedAny,
  WrapAsync(async (req, res) => {
    const { className, semester } = req.params;
    const subjects = await Subject.find({
      course: className,
      semester: semester,
    });
    res.json(subjects);
  })
);

// Get by ajax students by class & semester

app.get(
  "/get-students/:className/:semester",
  verifiedAny,
  WrapAsync(async (req, res) => {
    let { className, semester } = req.params;
    let students = await Student.find({ class: className, semester: semester });
    res.json(students);
  })
);

// assign/student/subject/

app.get(
  "/assign/student/subject",
  verifiedAny,
  WrapAsync(async (req, res) => {
    let teacherData = await Teacher.find({});
    let classData = await Class.find({});
    let subjectData = await Subject.find({});
    let studentData = await Student.find({});
    res.render("admin/studentAssign.ejs", {
      teacherData,
      classData,
      subjectData,
      studentData,
    });
  })
);

app.post(
  "/assign/student/subject",
  WrapAsync(async (req, res) => {
    try {
      let { students, subjects } = req.body.data;

      // Validation
      if (!students || !subjects) {
        req.flash("error", "Students and subjects are missing!");
        return res.redirect("/assign/student/subject");
      }

      // Ensure arrays
      if (!Array.isArray(students)) students = [students];
      if (!Array.isArray(subjects)) subjects = [subjects];

      // Convert JSON string → object
      subjects = subjects.map((s) => {
        try {
          return JSON.parse(s);
        } catch (err) {
          return s; // fallback agar already object ho
        }
      });

      // Assign subjects to each student
      for (let stuId of students) {
        const student = await Student.findById(stuId);

        // filter out subjects that already exist
        const newSubjects = subjects.filter(
          (subj) => !student.subject.some((s) => s.name === subj.name)
        );

        if (newSubjects.length > 0) {
          await Student.findByIdAndUpdate(
            stuId,
            { $push: { subject: { $each: newSubjects } } }, // add only filtered ones
            { new: true }
          );
        }
      }

      req.flash("success", "Subjects assigned successfully ✅");
      res.redirect("/assign/student/subject");
    } catch (err) {
      console.error("Error in assigning subjects:", err);
      req.flash("error", "Something went wrong!");
      res.redirect("/assign/student/subject");
    }
  })
);

// Attendance status//

//  check today attendance record

app.get(
  "/show/status/today/attendance",
  verifiedAny,
  WrapAsync(async (req, res) => {
    let classData = await Class.find({});
    res.render("admin/todayAttendancelogin.ejs", { classData });
  })
);

app.post(
  "/show/status/today/attendance",
  WrapAsync(async (req, res) => {
    let { data } = req.body;

    if (!data.class || !data.semester || !data.section) {
      req.flash("error", "Class, semester, or section not found ");
      return res.redirect("/show/status/today/attendance");
    }

    const datas = await Student.find({
      class: data.class,
      semester: data.semester,
      section: data.section,
    });

    if (datas.length === 0) {
      req.flash("error", "No students datas found");
      return res.redirect("/show/status/today/attendance");
    }

    let dupDatas = await AttendenceDuplicate.find().populate({
      path: "studentId",
      match: {
        class: data.class,
        semester: data.semester,
        section: data.section,
      },
    });
    dupDatas = dupDatas.filter((d) => d.studentId);

    return res.render("admin/showTodayRecord.ejs", { datas, dupDatas });
  })
);

// check all status of Totalstudent

app.get(
  "/show/allStudent/status",
  verifiedAny,
  WrapAsync(async (req, res) => {
    let classData = await Class.find({});
    res.render("admin/AllstudentAttendanceStatuslogin.ejs", { classData });
  })
);

// ---------------------filter---------
app.post(
  "/show/allStudent/status/filter",
  WrapAsync(async (req, res) => {
    let { class: className, semester, section, filter } = req.body;

    // default filter
    if (!filter) filter = "all";

    let dateQuery = {};
    const now = new Date();

    // ===== TODAY =====
    if (filter === "today") {
      const start = new Date(
        Date.UTC(
          now.getUTCFullYear(),
          now.getUTCMonth(),
          now.getUTCDate(),
          0,
          0,
          0,
          0
        )
      );
      const end = new Date(
        Date.UTC(
          now.getUTCFullYear(),
          now.getUTCMonth(),
          now.getUTCDate(),
          23,
          59,
          59,
          999
        )
      );
      dateQuery = { $gte: start, $lte: end };
    }

    // ===== WEEKLY (Sun–Sat) =====
    if (filter === "weekly") {
      const day = now.getUTCDay(); // Sunday = 0
      const startOfWeek = new Date(
        Date.UTC(
          now.getUTCFullYear(),
          now.getUTCMonth(),
          now.getUTCDate() - day,
          0,
          0,
          0,
          0
        )
      );
      const endOfWeek = new Date(
        Date.UTC(
          startOfWeek.getUTCFullYear(),
          startOfWeek.getUTCMonth(),
          startOfWeek.getUTCDate() + 6,
          23,
          59,
          59,
          999
        )
      );
      dateQuery = { $gte: startOfWeek, $lte: endOfWeek };
    }

    // ===== MONTHLY =====
    if (filter === "monthly") {
      const start = new Date(
        Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1, 0, 0, 0, 0)
      );
      const end = new Date(
        Date.UTC(
          now.getUTCFullYear(),
          now.getUTCMonth() + 1,
          0,
          23,
          59,
          59,
          999
        )
      );
      dateQuery = { $gte: start, $lte: end };
    }

    // ===== STUDENTS =====
    const students = await Student.find({
      class: className,
      semester,
      section,
    });

    const studentIds = students.map((s) => s._id);

    // ===== ATTENDANCE =====
    const attendanceQuery = {
      studentId: { $in: studentIds },
    };

    if (filter !== "all") {
      attendanceQuery.date = dateQuery;
    }

    const attendance = await Attendance.find(attendanceQuery);

    // ===== REPORT =====
    const report = students.map((student) => {
      const records = attendance.filter(
        (a) => a.studentId.toString() === student._id.toString()
      );

      // 🔹 PERIOD COUNTS
      const totalPeriods = records.length;
      const presentPeriods = records.filter(
        (r) => r.status === "Present"
      ).length;

      // 🔹 DAY-WISE COUNTS
      const dayMap = {};

      records.forEach((r) => {
        const day = r.date.toISOString().split("T")[0];

        if (!(day in dayMap)) {
          dayMap[day] = "Absent";
        }

        // ek bhi present → pura din present
        if (r.status === "Present") {
          dayMap[day] = "Present";
        }
      });

      const totalDays = Object.keys(dayMap).length;
      const presentDays = Object.values(dayMap).filter(
        (v) => v === "Present"
      ).length;

      const percentage =
        totalDays === 0 ? 0 : Math.round((presentDays / totalDays) * 100);

      let status = "SHORT";
      if (percentage >= 75) status = "GOOD";
      else if (percentage >= 60) status = "WARNING";

      return {
        rollNo: student.rollNo,
        name: student.name,

        // day-wise
        presentDays,
        totalDays,
        percentage,
        status,

        // period-wise
        presentPeriods,
        totalPeriods,
      };
    });

    res.json(report);
  })
);

app.post(
  "/show/allStudent/status",
  WrapAsync(async (req, res) => {
    const { data } = req.body;
    const { class: className, semester, section } = data;

    if (!className || !semester || !section) {
      req.flash("error", "Class, semester, or section not found");
      return res.redirect("/show/allStudent/status");
    }

    // ===== STUDENTS =====
    const students = await Student.find({
      class: className,
      semester,
      section,
    });

    if (!students.length) {
      req.flash("error", "No student datas found");
      return res.redirect("/show/allStudent/status");
    }

    const studentIds = students.map((s) => s._id);

    // ===== ATTENDANCE (ALL DATA) =====
    const attendance = await Attendance.find({
      studentId: { $in: studentIds },
    });

    // ===== REPORT (SAME AS FILTER ROUTE) =====
    const report = students.map((student) => {
      const records = attendance.filter(
        (a) => a.studentId.toString() === student._id.toString()
      );

      // 🔹 PERIOD COUNTS
      const totalPeriods = records.length;
      const presentPeriods = records.filter(
        (r) => r.status === "Present"
      ).length;

      // 🔹 DAY-WISE LOGIC (6 period → 1 present = present day)
      const dayMap = {};

      records.forEach((r) => {
        const day = r.date.toISOString().split("T")[0];

        if (!(day in dayMap)) {
          dayMap[day] = "Absent";
        }

        if (r.status === "Present") {
          dayMap[day] = "Present";
        }
      });

      const totalDays = Object.keys(dayMap).length;
      const presentDays = Object.values(dayMap).filter(
        (v) => v === "Present"
      ).length;

      const percentage =
        totalDays === 0 ? 0 : Math.round((presentDays / totalDays) * 100);

      let status = "SHORT";
      if (percentage >= 75) status = "GOOD";
      else if (percentage >= 60) status = "WARNING";

      return {
        rollNo: student.rollNo,
        name: student.name,

        // day-wise
        presentDays,
        totalDays,
        percentage,
        status,

        // period-wise
        presentPeriods,
        totalPeriods,
      };
    });

    // ===== RENDER =====
    res.render("admin/AllstudentAttendanceStatus.ejs", {
      report,
      className,
      semester,
      section,
    });
  })
);

// pdf for student status

app.get(
  "/show/allStudent/status/pdf",
  verifiedAny,
  WrapAsync(async (req, res) => {
    let { class: className, semester, section, filter } = req.query;

    if (!filter) filter = "all";

    let dateQuery = {};
    const now = new Date();

    // ===== DATE FILTER =====
    if (filter === "today") {
      const start = new Date(
        Date.UTC(
          now.getUTCFullYear(),
          now.getUTCMonth(),
          now.getUTCDate(),
          0,
          0,
          0,
          0
        )
      );
      const end = new Date(
        Date.UTC(
          now.getUTCFullYear(),
          now.getUTCMonth(),
          now.getUTCDate(),
          23,
          59,
          59,
          999
        )
      );
      dateQuery = { $gte: start, $lte: end };
    }

    if (filter === "weekly") {
      const day = now.getUTCDay();
      const start = new Date(
        Date.UTC(
          now.getUTCFullYear(),
          now.getUTCMonth(),
          now.getUTCDate() - day,
          0,
          0,
          0,
          0
        )
      );
      const end = new Date(
        Date.UTC(
          start.getUTCFullYear(),
          start.getUTCMonth(),
          start.getUTCDate() + 6,
          23,
          59,
          59,
          999
        )
      );
      dateQuery = { $gte: start, $lte: end };
    }

    if (filter === "monthly") {
      const start = new Date(
        Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1, 0, 0, 0, 0)
      );
      const end = new Date(
        Date.UTC(
          now.getUTCFullYear(),
          now.getUTCMonth() + 1,
          0,
          23,
          59,
          59,
          999
        )
      );
      dateQuery = { $gte: start, $lte: end };
    }

    // ===== STUDENTS =====
    const students = await Student.find({
      class: className,
      semester,
      section,
    });

    const studentIds = students.map((s) => s._id);

    // ===== ATTENDANCE =====
    const attendanceQuery = {
      studentId: { $in: studentIds },
    };

    if (filter !== "all") {
      attendanceQuery.date = dateQuery;
    }

    const attendance = await Attendance.find(attendanceQuery);

    // ===== REPORT (SAME LOGIC AS FILTER ROUTE) =====
    const report = students.map((student) => {
      const records = attendance.filter(
        (a) => a.studentId.toString() === student._id.toString()
      );

      // 🔹 PERIOD COUNTS
      const totalPeriods = records.length;
      const presentPeriods = records.filter(
        (r) => r.status === "Present"
      ).length;

      // 🔹 DAY-WISE COUNTS
      const dayMap = {};

      records.forEach((r) => {
        const day = r.date.toISOString().split("T")[0];

        if (!(day in dayMap)) {
          dayMap[day] = "Absent";
        }

        if (r.status === "Present") {
          dayMap[day] = "Present";
        }
      });

      const totalDays = Object.keys(dayMap).length;
      const presentDays = Object.values(dayMap).filter(
        (v) => v === "Present"
      ).length;

      const percentage =
        totalDays === 0 ? 0 : Math.round((presentDays / totalDays) * 100);

      let status = "SHORT";
      if (percentage >= 75) status = "GOOD";
      else if (percentage >= 60) status = "WARNING";

      return {
        rollNo: student.rollNo,
        name: student.name,

        presentDays,
        totalDays,
        presentPeriods,
        totalPeriods,
        percentage,
        status,
      };
    });

    // ===== PDF =====
    const doc = new PDFDocument({ size: "A4", margin: 40 });
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename=Attendance_Status_${className}.pdf`
    );

    doc.pipe(res);

    // ===== HEADER =====
    doc
      .fontSize(18)
      .text("Student Attendance Status Report", { align: "center" });
    doc.moveDown(0.5);
    doc
      .fontSize(11)
      .text(`Class: ${className} | Sem: ${semester} | Sec: ${section}`, {
        align: "center",
      });
    doc
      .fontSize(11)
      .text(`Filter: ${filter.toUpperCase()}`, { align: "center" });
    doc.moveDown(1);

    // ===== TABLE HEADER =====
    let y = doc.y;
    doc.fontSize(10).font("Helvetica-Bold");

    doc.text("Adm.no", 40, y);
    doc.text("Name", 80, y);
    doc.text("P Days", 230, y);
    doc.text("T Days", 280, y);
    doc.text("P Per.", 330, y);
    doc.text("T Per.", 380, y);
    doc.text("%", 430, y);
    doc.text("Status", 470, y);

    doc.moveDown(0.3);
    doc.font("Helvetica").moveTo(40, doc.y).lineTo(550, doc.y).stroke();
    doc.moveDown(0.5);

    // ===== TABLE ROWS =====
    report.forEach((r) => {
      let rowY = doc.y;

      doc.text(r.rollNo, 40, rowY);
      doc.text(r.name, 80, rowY);
      doc.text(r.presentDays, 240, rowY);
      doc.text(r.totalDays, 290, rowY);
      doc.text(r.presentPeriods, 340, rowY);
      doc.text(r.totalPeriods, 390, rowY);
      doc.text(`${r.percentage}%`, 430, rowY);
      doc.text(r.status, 470, rowY);

      doc.moveDown(0.6);

      if (doc.y > 750) doc.addPage();
    });

    // ===== FOOTER =====
    doc.moveDown(2);
    doc
      .fontSize(9)
      .text(`Generated on: ${new Date().toLocaleString()}`, { align: "right" });

    doc.end();
  })
);

//////////////////////////// admin folder closed//////////////////////////////////////////////////////////////////

///////////////////////////// teachers folders starts///////////////////////////////////////////////////////////////////

// login  teacher

app.post(
  "/login/modal",

  passport.authenticate("local", {
    failureRedirect: "/student/attendance/login",
    failureFlash: true,
  }),
  async (req, res) => {
    req.flash("success", "Login Successfully");
    res.redirect("/teacher/student/attendance");
  }
);

// teacher profile


app.get(
  "/teacher/profile",
  isLoggedIn,
  WrapAsync(async (req, res) => {
    let data = await Teacher.findById(req.user._id);
    res.render("teachers/profile.ejs", { data });
  })
);

// profile edit

app.get(
  "/teacher/profile/edit/:id",
  isLoggedIn,
  WrapAsync(async (req, res) => {
    let { id } = req.params;
    let data = await Teacher.findById(id);
    res.render("teachers/editProfile.ejs", { id, data });
  })
);

app.put(
  "/teacher/profile/edit/:id",
  upload.single("data[image]"),
  WrapAsync(async (req, res) => {
    let { id } = req.params;
    let teacher = await Teacher.findByIdAndUpdate(id, { ...req.body.data });
    if (typeof req.file !== "undefined") {
      let url = req.file.path;
      let filename = req.file.filename;
      teacher.image = { url, filename };
    }
    await teacher.save();
    req.flash("success", "Profile Update successfully");
    res.redirect(`/teacher/profile`);
  })
);

// main page //

app.get(
  "/teacher/student/attendance",
  isLoggedIn,
  WrapAsync(async (req, res) => {
    let teacherData = await Teacher.findById(req.user._id);
    let studentData = await Student.find({});
    res.render("teachers/main.ejs", { teacherData, studentData });
  })
);


// show subject class section details

app.get(
  "/show/teacher/class/subject/:id",
  isLoggedIn,
  WrapAsync(async (req, res) => {
    let { id } = req.params;
    req.session.teacherId = id;
    let datas = await Teacher.findById(id);
    res.render("teachers/showClassSubjectAndothers.ejs", { datas });
  })
);




// take attendance

app.get(
  "/add/student/attendance",
  isLoggedIn,
  WrapAsync(async (req, res) => {
    let classData = await Teacher.findById(req.user._id);
    req.session.teacherName = classData.name;
    // console.log(classData);
    res.render("teachers/attendanceLogin.ejs", { classData });
  })
);

app.post(
  "/add/student/attendance",
  WrapAsync(async (req, res) => {
    const { data } = req.body;
    const { class: className, semester, section } = data;

    // Save selected data in session
    req.session.class = className;
    req.session.semester = semester;
    req.session.section = section;

    // 🔹 Find teacher having that class
    let teacher = await Teacher.findById(req.user._id);

    // 🔹 Find matching class inside teacher's class array
    const classObj = teacher.class.find((c) => c.className === className);
    if (!classObj) {
      req.flash("error", "Class not assigned to you");
      return res.redirect("/add/student/attendance");
    }

    // 🔹 Find matching semester inside that class
    const semObj = classObj.semesters.find((s) => s.semester === semester);
    if (!semObj) {
      req.flash("error", "Enter matching semester according to assigned class");
      return res.redirect("/add/student/attendance");
    }

    // 🔹 Find matching section inside that semester
    const secObj = semObj.sections.find((s) => s.section === section);
    if (!secObj) {
      req.flash("error", "Section not assigned to you");
      return res.redirect("/add/student/attendance");
    }

    // 🔹 Get all students of that class + semester + section
    const students = await Student.find({
      class: className,
      semester,
      section,
    });

    if (students.length === 0) {
      req.flash("error", "No students found for this selection");
      return res.redirect("/add/student/attendance");
    }

    // 🔹 Flatten student subjects
    const studentSubjects = students.flatMap((s) =>
      s.subject.map((sub) => (typeof sub === "string" ? sub : sub.name))
    );

    // 🔹 Teacher subjects for this specific section
    const teacherSubjects = secObj.subjects; // teacher's assigned subjects in this section

    // 🔹 Find common subjects
    const commonSubjects = teacherSubjects.filter((sub) =>
      studentSubjects.includes(sub)
    );

    // 🔹 Render attendance page if subjects match
    if (commonSubjects.length > 0) {
      return res.render("teachers/attendancePage.ejs", {
        students,
        commonSubjects,
      });
    } else {
      req.flash("error", "Subject not matched according to student subject");
      return res.redirect("/add/student/attendance");
    }
  })
);

app.post(
  "/attendance/saveAll",
  WrapAsync(async (req, res) => {
    const { students, period, unit, description, subject } = req.body;

    const section = req.session.section;
    const classes = req.session.class;
    const semester = req.session.semester;
    const teacherName = req.session.teacherName;

    // 🔹 Step 1: Duplicate check (same as before)
    const existingAttendance = await AttendenceDuplicate.findOne({
      "attendance.periods": period,
      "attendance.class": classes,
      "attendance.section": section,
      "attendance.semester": semester,
    });

    if (existingAttendance) {
      req.flash("error", `⚠️ Attendance already exists for Period ${period}`);
      return res.redirect("/add/student/attendance");
    }

    try {
      // 🔹 Step 2: Save attendance for each student
      const ops = Object.entries(students).map(async ([studentId, status]) => {
        // ✅ Create attendance (single source of truth)
        await Attendance.create({
          studentId: studentId, // ObjectId reference
          date: normalizeDate(new Date()),
          status,
          period,
          unit,
          description,
          subject,
        });

        // ✅ Update duplicate-tracking collection
        await AttendenceDuplicate.findOneAndUpdate(
          { studentId },
          {
            $push: {
              attendance: {
                status,
                periods: period,
                unit,
                description,
                section,
                subject,
                class: classes,
                semester,
                teacherId: req.user._id,
                teacherName,
              },
            },
            $setOnInsert: { studentId },
          },
          { upsert: true }
        );
      });

      await Promise.all(ops);

      req.flash("success", "✅ Attendance saved successfully!");
      res.redirect("/add/student/attendance");
    } catch (err) {
      console.error("❌ Error saving attendance:", err);
      req.flash("error", "Something went wrong while saving attendance!");
      res.redirect("/add/student/attendance");
    }
  })
);

app.get(
  "/search/attendance/student",
  isLoggedIn,
  WrapAsync(async (req, res) => {
    const classes = req.session.class;
    const semester = req.session.semester;
    const section = req.session.section;

    const { name } = req.query;

    let today = new Date().toISOString().slice(0, 10);

    // 🔁 Base query (ALL students)
    let query = {
      class: classes,
      semester,
      section,
    };

    // 🔍 If search name provided
    if (name && name.trim()) {
      query.name = { $regex: name.trim(), $options: "i" };
    }

    let students = await Student.find(query);

    // ❌ If name was searched but no student found
    if (name && name.trim() && !students.length) {
      return res.json({
        success: false,
        message: `❌ Student "${name}" not found`,
      });
    }

    // ❌ Safety (no students at all)
    if (!students.length) {
      return res.json({
        success: false,
        message: "⚠️ No students found in this class",
      });
    }

    // ✅ Prepare response
    let result = students.map((s) => {
      let todayStatus = "";
      if (s.attendance?.length) {
        let record = s.attendance.find(
          (a) => a.date?.toISOString().slice(0, 10) === today
        );
        if (record) todayStatus = record.status || "";
      }

      return {
        _id: s._id,
        rollNo: s.rollNo,
        name: s.name,
        fatherName: s.fatherName,
        attendanceToday: todayStatus,
      };
    });

    res.json({
      success: true,
      data: result,
    });
  })
);

// update attendance

app.get(
  "/update/student/attendance",
  isLoggedIn,
  WrapAsync(async (req, res) => {
    let classData = await Teacher.findById(req.user._id);
    // console.log(classData);
    res.render("teachers/updateAttenLogin.ejs", { classData });
  })
);

// get semester

app.get("/get-semesters", isLoggedIn, async (req, res) => {
  try {
    const { class: className } = req.query;
    if (!className) return res.json([]);

    const teacher = await Teacher.findById(req.user._id);
    if (!teacher || !teacher.class?.length) return res.json([]);

    const cls = teacher.class.find(
      (c) => c.className.toLowerCase() === className.toLowerCase()
    );
    if (!cls || !cls.semesters?.length) return res.json([]);

    const semesters = cls.semesters.map((s) => s.semester);
    res.json(semesters);
  } catch (err) {
    console.error("SEMESTER AJAX ERROR:", err);
    res.status(500).json([]);
  }
});

// find section according class and semeater wise

// ✅ Route: Get Sections by Class + Semester
app.get("/get-sections", async (req, res) => {
  try {
    const { class: className, semester } = req.query;

    const teacher = await Teacher.findById(req.user._id);
    if (!teacher) return res.json([]);

    const cls = teacher.class.find((c) => c.className === className);
    if (!cls) return res.json([]);

    const sem = cls.semesters.find((s) => s.semester === semester);
    if (!sem) return res.json([]);

    const sections = sem.sections.map((sec) => sec.section);
    res.json(sections);
  } catch (err) {
    console.error(err);
    res.status(500).json([]);
  }
});

// find subject according class and semeater and section  wise

// ✅ Route: Get Subjects by Class + Semester + Section
app.get("/get-subjects", async (req, res) => {
  try {
    const { class: className, semester, section } = req.query;

    const teacher = await Teacher.findById(req.user._id);
    if (!teacher) return res.json([]);

    const cls = teacher.class.find((c) => c.className === className);
    if (!cls) return res.json([]);

    const sem = cls.semesters.find((s) => s.semester === semester);
    if (!sem) return res.json([]);

    const sec = sem.sections.find((sec) => sec.section === section);
    if (!sec) return res.json([]);

    // 👇 YAHAN SUBJECTS RETURN HO RAHE HAIN
    const subjects = sec.subjects || [];
    res.json(subjects);
  } catch (err) {
    console.error(err);
    res.status(500).json([]);
  }
});

//////////////////////////

app.post(
  "/update/student/attendance",
  WrapAsync(async (req, res) => {
    const { data } = req.body;
    const { class: className, semester, section, subject } = data;

    // ===== Save session =====
    req.session.class = className;
    req.session.semester = semester;
    req.session.section = section;
    req.session.subject = subject;

    // ===== Teacher check =====
    const teacher = await Teacher.findById(req.user._id);
    if (!teacher) {
      req.flash("error", "Teacher not found");
      return res.redirect("/update/student/attendance");
    }

    const classObj = teacher.class?.find((c) => c.className === className);
    const semObj = classObj?.semesters?.find((s) => s.semester === semester);
    const secObj = semObj?.sections?.find((s) => s.section === section);

    if (!classObj || !semObj || !secObj) {
      req.flash("error", "Class / Semester / Section not assigned to you");
      return res.redirect("/update/student/attendance");
    }

    // ===== Find attendance records =====
    const records = await AttendenceDuplicate.find({
      attendance: {
        $elemMatch: {
          teacherId: req.user._id,
          class: className,
          semester,
          section,
          subject,
        },
      },
    });

    if (!records.length) {
      req.flash("error", "No attendance found for update");
      return res.redirect("/update/student/attendance");
    }

    // ===== Filter valid (within 24 hours) =====
    const now = new Date();
    const validAttendances = records.flatMap((r) =>
      r.attendance.filter(
        (att) =>
          att.teacherId.toString() === req.user._id.toString() &&
          att.class === className &&
          att.semester === semester &&
          att.section === section &&
          att.subject?.toLowerCase() === subject.toLowerCase() &&
          (now - new Date(att.date)) / (1000 * 60 * 60) <= 24
      )
    );

    if (!validAttendances.length) {
      req.flash("error", "Update allowed only within 24 hours");
      return res.redirect("/update/student/attendance");
    }

    // ===== Latest attendance for period/unit/description =====
    const latest = validAttendances.sort(
      (a, b) => new Date(b.date) - new Date(a.date)
    )[0];

    const currentAttendance = {
      periods: latest.periods,
      unit: latest.unit,
      description: latest.description,
      date: latest.date,
    };

    // ===== Fetch students =====
    const students = await Student.find({
      class: className,
      semester,
      section,
    });

    if (!students.length) {
      req.flash("error", "No students found");
      return res.redirect("/update/student/attendance");
    }

    // ===== Build status map =====
    const statusMap = {};
    for (const record of records) {
      const att = record.attendance.find(
        (a) =>
          a.teacherId.toString() === req.user._id.toString() &&
          a.class === className &&
          a.semester === semester &&
          a.section === section &&
          a.subject?.toLowerCase() === subject.toLowerCase()
      );

      if (att) {
        statusMap[record.studentId.toString()] = att.status || "Not marked";
      }
    }

    const studentsWithStatus = students.map((stu) => ({
      ...stu.toObject(),
      attendanceToday: statusMap[stu._id.toString()] || "Not marked",
    }));

    // ===== Subject permission =====
    const studentSubjects = students.flatMap((s) =>
      s.subject.map((sub) => (typeof sub === "string" ? sub : sub.name))
    );

    const teacherSubjects = secObj.subjects || [];
    const commonSubjects = teacherSubjects.filter((sub) =>
      studentSubjects.includes(sub)
    );

    if (!commonSubjects.includes(subject)) {
      req.flash("error", "You are not allowed for this subject");
      return res.redirect("/update/student/attendance");
    }

    // ===== Render =====
    res.render("teachers/updateAttenPage.ejs", {
      students: studentsWithStatus,
      subject,
      commonSubjects,
      currentAttendance,
    });
  })
);

// POST: update all attendance
app.post(
  "/attendance/updateAll",
  WrapAsync(async (req, res) => {
    const { students, period, unit, description, subject } = req.body;
    const section = req.session.section;
    const classes = req.session.class;
    const semester = req.session.semester;

    try {
      const now = new Date();
      const todayStart = new Date(now.setHours(0, 0, 0, 0));

      let updatedCount = 0;
      let deniedCount = 0;
      let notFoundCount = 0;

      for (const [studentId, status] of Object.entries(students)) {
        // 🔹 1. Find duplicate tracker
        const dup = await AttendenceDuplicate.findOne({ studentId });
        if (!dup) {
          notFoundCount++;
          continue;
        }

        // 🔹 2. Find correct attendance entry
        const record = dup.attendance.find(
          (a) =>
            a.periods == period &&
            a.class === classes &&
            a.section === section &&
            a.semester === semester &&
            a.subject === subject
        );

        if (!record) {
          notFoundCount++;
          continue;
        }

        // 🔹 3. 24 hour rule
        const createdTime = record.createdAt || record.date;
        const diffHours =
          (Date.now() - new Date(createdTime)) / (1000 * 60 * 60);

        if (diffHours > 24) {
          deniedCount++;
          continue;
        }

        // 🔹 4. Update AttendenceDuplicate (ARRAY FILTER SAFE)
        await AttendenceDuplicate.updateOne(
          { studentId },
          {
            $set: {
              "attendance.$[elem].status": status,
              "attendance.$[elem].unit": unit,
              "attendance.$[elem].description": description,
              "attendance.$[elem].updatedAt": new Date(),
            },
          },
          {
            arrayFilters: [
              {
                "elem.periods": period,
                "elem.class": classes,
                "elem.section": section,
                "elem.semester": semester,
                "elem.subject": subject,
              },
            ],
          }
        );

        // 🔹 5. Update Attendance collection (ObjectId based)
        const updated = await Attendance.findOneAndUpdate(
          {
            studentId: studentId, // ✅ CORRECT FIELD
            period: Number(period),
            subject,
            date: { $gte: new Date(new Date().setHours(0, 0, 0, 0)) }, // today
          },
          {
            $set: {
              status,
              unit,
              description,
              date: new Date(),
            },
          },
          { upsert: false } // ❌ upsert FALSE (update only)
        );

        if (!updated) {
          notFoundCount++;
          continue;
        }

        updatedCount++;
      }

      // 🔹 FLASH MESSAGES
      if (updatedCount)
        req.flash(
          "success",
          `✅ ${updatedCount} attendance updated successfully`
        );

      if (deniedCount)
        req.flash("error", `⚠️ ${deniedCount} records older than 24 hours`);

      if (notFoundCount)
        req.flash("info", `ℹ️ ${notFoundCount} records not found`);

      return res.redirect("/add/student/attendance");
    } catch (err) {
      console.error("❌ UPDATE ERROR:", err);
      req.flash("error", "Something went wrong while updating attendance");
      return res.redirect("/add/student/attendance");
    }
  })
);

// show attendance route

app.get(
  "/student/attendance/record",
  isLoggedIn,
  WrapAsync(async (req, res) => {
    const classes = req.session.class;
    const semester = req.session.semester;
    const section = req.session.section;

    if (!classes || !semester || !section) {
      req.flash("error", "Class, semester, or section not found in session");
      return res.redirect("/add/student/attendance");
    }

    const datas = await Student.find({
      class: classes,
      semester: semester,
      section: section,
    });

    if (datas.length === 0) {
      req.flash("error", "No students found  something is wrong");
      return res.redirect("/add/student/attendance");
    }

    let dupDatas = await AttendenceDuplicate.find().populate({
      path: "studentId",
      match: {
        class: classes,
        semester: semester,
        section: section,
      },
    });

    // req.session.class = null;
    // req.session.semester = null;
    // req.session.section = null;

    dupDatas = dupDatas.filter((d) => d.studentId);

    return res.render("teachers/showAttendance.ejs", { datas, dupDatas });
  })
);

// logout teacher

app.get("/logout", isLoggedIn, (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }

    req.flash("success", "You are logged out");
    res.redirect("/student/attendance/login");
  });
});

////////////////////////// teacher folder closed/////////////////////////////////////////////////

//////////////////////////// student folder start//////////////////////////////////////////////

// otp

app.get("/otp", (req, res) => {
  res.render("listings/otp.ejs");
});

app.post("/verify-otp", async (req, res) => {
  const { otp } = req.body;
  let otpRecord = await OTP.findOne({ otp: otp });

  if (otpRecord) {
    req.session.otpVerified = true;
    req.flash("success", "Login successfully");
    return res.redirect("/student/attendance");
  } else {
    req.flash("error", "Invalid-OTP!");
    return res.redirect("/otp");
  }
});

// student profile

app.get(
  "/profile",
  verifiedAny,
  WrapAsync(async (req, res) => {
    let rollNo = req.session.rollNo;

    if (!rollNo) {
      req.flash("error", "Something went wrong");
      return res.redirect("/student/attendance/login");
    }
    let student = await Student.findOne({ rollNo: parseInt(rollNo) });

    if (!student) {
      req.flash("error", "Something went wrong");
      return res.redirect("/student/attendance/login");
    }
    res.render("students/profile.ejs", { student });
  })
);

// edit profile
app.get(
  "/profile/edit/:id",
  verifiedAny,
  WrapAsync(async (req, res) => {
    let { id } = req.params;
    let data = await Student.findById(id);
    res.render("students/editProfile.ejs", { data, id });
  })
);

app.put(
  "/profile/edit/:id",
  upload.single("data[image]"),
  verifiedAny,
  WrapAsync(async (req, res) => {
    let { id } = req.params;
    let student = await Student.findByIdAndUpdate(id, { ...req.body.data });
    if (typeof req.file !== "undefined") {
      let url = req.file.path;
      let filename = req.file.filename;
      student.image = { url, filename };
    }
    await student.save();
    req.flash("success", "Profile Update successfully");
    res.redirect(`/profile`);
  })
);

//  student main page

app.get(
  "/student/attendance",
  verifiedAny,
  WrapAsync(async (req, res) => {
    let rollNo = req.session.rollNo;

    if (!rollNo) {
      req.flash("error", "Something went wrong");
      return res.redirect("/student/attendance/login");
    }
    let student = await Student.findOne({ rollNo: parseInt(rollNo) });

    if (!student) {
      req.flash("error", "Something went wrong");
      return res.redirect("/student/attendance/login");
    }
    res.render("students/main.ejs", { student });
  })
);
// subject check

app.get(
  "/student/attendance/subject/check",
  verifiedAny,
  WrapAsync(async (req, res) => {
    let rollNo = req.session.rollNo;

    if (!rollNo) {
      req.flash("error", "Something went wrong");
      return res.redirect("/student/attendance/login");
    }

    // ek student ke document ko nikaalo
    let student = await Student.findOne({ rollNo: parseInt(rollNo) });

    if (!student) {
      req.flash("error", "Something went wrong");
      return res.redirect("/student/attendance");
    }
    res.render("students/checkSubject.ejs", { student });
  })
);

// show status//

app.get(
  "/student/attendance/status/check",
  verifiedAny,
  WrapAsync(async (req, res) => {
    let rollNo = req.session.rollNo;
    if (!rollNo) {
      req.flash("error", "Something went wrong");
      return res.redirect("/student/attendance/login");
    }

    // ek student ke document ko nikaalo
    let student = await Student.findOne({ rollNo: parseInt(rollNo) });

    if (!student) {
      req.flash("error", "Something went wrong");
      return res.redirect("/student/attendance");
    }
    res.render("students/showstatus.ejs", { student });
  })
);

//////  filter attendance

app.get(
  "/student/attendance/:studentId/:filter",
  verifiedAny,
  WrapAsync(async (req, res) => {
    const { studentId, filter } = req.params;
    req.session.studentId = studentId;

    let dateQuery = {};
    const now = new Date();

    // ===== TODAY (UTC SAFE) =====
    if (filter === "today") {
      const start = new Date(
        Date.UTC(
          now.getUTCFullYear(),
          now.getUTCMonth(),
          now.getUTCDate(),
          0,
          0,
          0,
          0
        )
      );

      const end = new Date(
        Date.UTC(
          now.getUTCFullYear(),
          now.getUTCMonth(),
          now.getUTCDate(),
          23,
          59,
          59,
          999
        )
      );

      dateQuery = { $gte: start, $lte: end };
    }

    // ===== WEEKLY (Sun–Sat, UTC SAFE) =====
    if (filter === "weekly") {
      const day = now.getUTCDay(); // 0=Sun
      const startOfWeek = new Date(
        Date.UTC(
          now.getUTCFullYear(),
          now.getUTCMonth(),
          now.getUTCDate() - day,
          0,
          0,
          0,
          0
        )
      );

      const endOfWeek = new Date(
        Date.UTC(
          startOfWeek.getUTCFullYear(),
          startOfWeek.getUTCMonth(),
          startOfWeek.getUTCDate() + 6,
          23,
          59,
          59,
          999
        )
      );

      dateQuery = { $gte: startOfWeek, $lte: endOfWeek };
    }

    // ===== MONTHLY (1st → last day, UTC SAFE) =====
    if (filter === "monthly") {
      const startOfMonth = new Date(
        Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1, 0, 0, 0, 0)
      );

      const endOfMonth = new Date(
        Date.UTC(
          now.getUTCFullYear(),
          now.getUTCMonth() + 1,
          0,
          23,
          59,
          59,
          999
        )
      );

      dateQuery = { $gte: startOfMonth, $lte: endOfMonth };
    }

    const attendance = await Attendance.find({
      studentId,
      ...(filter !== "all" && { date: dateQuery }),
    }).sort({ date: 1, period: 1 });

    res.json({
      success: true,
      filter,
      range: dateQuery,
      count: attendance.length,
      data: attendance,
    });
  })
);
// ----------------- Date-wise search -----------------
app.post(
  "/search/student/attendance/date",
  verifiedAny,
  WrapAsync(async (req, res) => {
    const studentId = req.session.studentId;
    const { from, to } = req.body.data; // "YYYY-MM-DD"

    let rollNo = req.session.rollNo;
    if (!rollNo) {
      req.flash("error", "Something went wrong");
      return res.redirect("/student/attendance/status/check");
    }

    if (!from || !to) {
      req.flash("error", "Please select From & To date");
      return res.redirect("/student/attendance/status/check");
    }
    const fromDate = parseIndianDate(from);

    const toDate = parseIndianDate(to);
    toDate.setHours(23, 59, 59, 999);

    // ek student ke document ko nikaalo
    let student = await Student.findOne({ rollNo: parseInt(rollNo) });

    if (!student) {
      req.flash("error", "Something went wrong");
      return res.redirect("/student/attendance/status/check");
    }

    // ---------- FETCH ATTENDANCE ----------
    const attendanceRecords = await Attendance.find({
      studentId,
      date: {
        $gte: fromDate,
        $lt: toDate, // IMPORTANT
      },
    }).sort({ date: 1, period: 1 });

    if (!attendanceRecords.length) {
      req.flash("error", "No attendance found in selected range");
      return res.redirect("/student/attendance/status/check");
    }

    // ---------- DAY WISE CALCULATION ----------
    const dayMap = new Map();

    attendanceRecords.forEach((att) => {
      const key = new Date(att.date).toDateString();
      if (!dayMap.has(key)) dayMap.set(key, []);
      dayMap.get(key).push(att.status);
    });

    let totalDays = dayMap.size;
    let presentDays = 0;
    let absentDays = 0;

    dayMap.forEach((statuses) => {
      if (statuses.includes("Present")) presentDays++;
      else absentDays++;
    });

    // ---------- RENDER ----------
    res.render("students/DateWiseStatus.ejs", {
      attendanceRecords,
      total: totalDays,
      present: presentDays,
      absent: absentDays,
      from,
      to,
      student,
    });
  })
);

// logout student route
app.get("/student/logout", verifiedAny, (req, res) => {
  req.session.otpVerified = false;
  req.flash("success", "Logout successfuly");
  res.redirect("/student/attendance/login");
});

// ////  student folder closed////

app.use((req, res, next) => {
  next(new ExpressError(404, "page not found"));
});



app.use((err, req, res, next) => {
  const statusCode = err.statusCode || 500;
  const message = err.message || "Something went wrong";
    console.log(statusCode);
    console.log(message);

  if (res.headersSent) {
    return next(err);
  }

  return res.status(statusCode).render("listings/error.ejs", {
    message,
    statusCode,
  });
});




app.listen(5000, (req, res) => {
  console.log(`All clear ${5000}`);
});

///  working atendance


const SibApiV3Sdk = require("sib-api-v3-sdk");

app.post(
  "/student/attendance/login",
  WrapAsync(async (req, res) => {
    try {
      const { role, username, password } = req.body;

      const studentPassword = process.env.STUDENT_PASSWORD;
      const adminUsername = process.env.ADMIN_USERNAME;
      const adminPassword = process.env.ADMIN_PASSWORD;

      const adminRole = process.env.ROLE_1;
      const teacherRole = process.env.ROLE_2;
      const studentRole = process.env.ROLE_3;

      req.session.adminVerified = false;

      // ===== Admin Login =====
      if (adminRole === role) {
        if (adminUsername === username && adminPassword === password) {
          req.session.adminVerified = true;
          req.flash("success", "Login successfully");
          return res.redirect("/admin/student/attendance");
        } else {
          req.flash("error", "Admin credentials incorrect");
          return res.redirect("/student/attendance/login");
        }
      }

      // ===== Teacher Login =====
      if (teacherRole === role) {
        return res.redirect(307, "/login/modal");
      }

      // ===== Student Login =====
      if (studentRole === role && studentPassword === password) {

        const newStudent = await Student.findOne({ rollNo: username });

        if (!newStudent) {
          req.flash("error", "Student not found for this username");
          return res.redirect("/student/attendance/login");
        }

        req.session.rollNo = username;
        req.session.otpVerified = false;

        // ===== OTP Generate =====
        let otp = "";
        for (let i = 0; i < 6; i++) {
          otp += Math.floor(Math.random() * 10);
        }

        const newOtp = new OTP({
          userId: newStudent._id,
          otp,
        });
        await newOtp.save();

        // ===== BREVO EMAIL SEND =====
        let defaultClient = SibApiV3Sdk.ApiClient.instance;
        let apiKey = defaultClient.authentications["api-key"];
        apiKey.apiKey = process.env.BREVO_API_KEY;

        let apiInstance = new SibApiV3Sdk.TransactionalEmailsApi();

        let sendSmtpEmail = {
          to: [{ email: newStudent.email }],
          sender: { email: process.env.EMAIL_USER, name: "Attendance System" },
          subject: "Attendance Verification Code",
          textContent: `Dear Student,

Your OTP is: ${otp}

This code is valid for 30 seconds.
Do not share this code with anyone.

Regards,
Attendance System`,
        };

        await apiInstance.sendTransacEmail(sendSmtpEmail);

        return res.redirect("/otp");
      }

      // ===== Invalid Role =====
      req.flash("error", "Role not matched");
      return res.redirect("/student/attendance/login");

    } catch (err) {
      console.error("Login Error:", err);
      req.flash("error", "Something went wrong, please try again");
      return res.redirect("/student/attendance/login");
    }
  })
);
