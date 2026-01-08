if (process.env.NODE_ENV !== "production") {
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
const flash = require("connect-flash");
const session = require("express-session");
const passport = require("passport");
const localStrategy = require("passport-local");
const dayjs = require("dayjs");
const utc = require("dayjs/plugin/utc");
dayjs.extend(utc);

const AttendenceDuplicate = require("./models/attenDanceDuplicate.js");
const Student = require("./models/studentData.js");
const Teacher = require("./models/teacherRecord.js");
const Attendance = require("./models/attendanceRecord.js");
const OTP = require("./models/otp.js");

const { isLoggedIn } = require("./middleware.js");
const MongoStore = require("connect-mongo");
const createStudent = require("./helpers/createStudent.js");

const dbUrl = process.env.ATLASDB_URL;

const store = MongoStore.create({
  mongoUrl: dbUrl,
  crypto: { secret: process.env.SECRET },
  touchAfter: 24 * 3600,
});

store.on("error", (err) => {
  console.log("Session store error:", err);
});

const sessionOption = {
  store,
  secret: process.env.SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: {
    expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    maxAge: 7 * 24 * 60 * 60 * 1000,
    httpOnly: true,
  },
};

app.use(session(sessionOption));
app.use(flash());

main().then(() => console.log("MongoDB connection successful")).catch((err) => console.log(err));
async function main() {
  await mongoose.connect(dbUrl);
}

app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "/public")));
app.use(methodOverride("_method"));
app.engine("ejs", ejsmate);

// Passport setup
app.use(passport.initialize());
app.use(passport.session());
passport.use(new localStrategy(Teacher.authenticate()));
passport.serializeUser(Teacher.serializeUser());
passport.deserializeUser(Teacher.deserializeUser());

app.use((req, res, next) => {
  res.locals.success = req.flash("success");
  res.locals.error = req.flash("error");
  res.locals.curruser = req.user;
  next();
});

// Session verification
function verifiedAny(req, res, next) {
  if (req.session.adminVerified || req.session.otpVerified) return next();
  req.flash("error", "Please login now!");
  return res.redirect("/student/attendance/login");
}

// Cleanup orphan attendance every 2 minutes
setInterval(async () => {
  try {
    const studentIds = await Student.distinct("_id");
    const orphanAttendances = await Attendance.find({ studentId: { $nin: studentIds } }).select("_id");

    if (!orphanAttendances.length) {
      console.log("✅ No orphan attendance found");
      return;
    }

    const idsToDelete = orphanAttendances.map(a => a._id);
    const result = await Attendance.deleteMany({ _id: { $in: idsToDelete } });
    console.log(`🧹 Deleted ${result.deletedCount} orphan attendance records`);
  } catch (err) {
    console.error("❌ Attendance cleanup error:", err);
  }
}, 2 * 60 * 1000); // every 2 minutes

// Add student route
app.post("/student/add", WrapAsync(async (req, res) => {
  const student = await createStudent(req.body);
  if (!student) return res.status(400).json({ success: false, message: "Invalid student data" });

  return res.status(201).json({
    success: true,
    message: "Student added with TTL ✅",
    expireAt: student.expireAt || null,
  });
}));


// ================= LOGIN ROUTES =================
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
        for (let i = 0; i < 6; i++) otp += Math.floor(Math.random() * 10);

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

// ================= ADMIN MAIN =================
app.get(
  "/admin/student/attendance",
  verifiedAny,
  WrapAsync(async (req, res) => {
    let teacherData = (await Teacher.find({})) || [];
    let classData = (await Class.find({})) || [];
    let subjectData = (await Subject.find({})) || [];
    let studentData = (await Student.find({})) || [];

    return res.render("admin/main.ejs", {
      teacherData,
      classData,
      subjectData,
      studentData,
    });
  })
);

// ================= ADMIN LOGOUT =================
app.get("/admin/logout", verifiedAny, (req, res) => {
  req.session.adminVerified = false;
  req.flash("success", "Logout successfully");
  return res.redirect("/student/attendance/login");
});

// ================= SEARCH TEACHER =================
app.post(
  "/search/teacher",
  WrapAsync(async (req, res) => {
    const { search } = req.body;
    const datas =
      (await Teacher.find({ name: { $regex: search, $options: "i" } })) || [];

    if (!datas.length) {
      req.flash("error", "Teacher not found!");
      return res.redirect("/show/teacher");
    }

    return res.render("admin/searchTeacher.ejs", { datas });
  })
);

// ================= ADD TEACHER =================
app.get("/add/teacherData", verifiedAny, (req, res) => {
  return res.render("admin/createTeacher.ejs");
});

app.post(
  "/add/teacherData",
  upload.single("data[image]"),
  WrapAsync(async (req, res, next) => {
    const { data } = req.body;
    try {
      const newTeacher = new Teacher(data);

      if (req.file) {
        const { path: url, filename } = req.file;
        newTeacher.image = { url, filename };
      }

      const registerUser = await Teacher.register(newTeacher, data.password);

      req.login(registerUser, (err) => {
        if (err) return next(err);
        if (!req.session.adminVerified) req.session.adminVerified = true;
        req.flash("success", "Add Teacher successfully");
        return res.redirect("/add/teacherData");
      });
    } catch (e) {
      req.flash("error", e.message);
      return res.redirect("/add/teacherData");
    }
  })
);

// ================= SHOW TEACHER =================
app.get(
  "/show/teacher",
  verifiedAny,
  WrapAsync(async (req, res) => {
    const datas = (await Teacher.find({})) || [];
    return res.render("admin/showTeacher.ejs", { datas });
  })
);

// ================= SHOW TEACHER PROFILE =================
app.get(
  "/teacher/profile/:id",
  verifiedAny,
  WrapAsync(async (req, res) => {
    const { id } = req.params;
    const data = await Teacher.findById(id);
    if (!data) {
      req.flash("error", "Teacher not found");
      return res.redirect("/show/teacher");
    }
    return res.render("admin/teacherProfile.ejs", { data });
  })
);

// ================= SHOW TEACHER CLASS =================
app.get(
  "/show/teacher/class/:id",
  verifiedAny,
  WrapAsync(async (req, res) => {
    const { id } = req.params;
    req.session.teacherId = id;
    const datas = await Teacher.findById(id);
    if (!datas) {
      req.flash("error", "Teacher not found");
      return res.redirect("/show/teacher");
    }
    return res.render("admin/showTeacherClass.ejs", { datas });
  })
);

// ================= DELETE TEACHER SECTION =================
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
    return res.redirect(`/show/teacher/class/${teacherId}`);
  })
);

// ================= EDIT TEACHER =================
app.get(
  "/edit/teacher/:id",
  verifiedAny,
  WrapAsync(async (req, res) => {
    const { id } = req.params;
    const data = await Teacher.findById(id);
    if (!data) {
      req.flash("error", "Teacher not found");
      return res.redirect("/show/teacher");
    }
    return res.render("admin/editTeacher.ejs", { id, data });
  })
);

app.put(
  "/edit/teacher/:id",
  upload.single("data[image]"),
  WrapAsync(async (req, res) => {
    const { id } = req.params;
    const { name, email, username, mobile, password } = req.body.data;

    const teacher = await Teacher.findById(id);
    if (!teacher) {
      req.flash("error", "Teacher not found");
      return res.redirect("/show/teacher");
    }

    teacher.name = name;
    teacher.email = email;
    teacher.username = username;
    teacher.mobile = mobile;

    if (password && password.trim() !== "") {
      await teacher.setPassword(password);
    }

    if (req.file) {
      const { path: url, filename } = req.file;
      teacher.image = { url, filename };
    }

    await teacher.save();
    req.flash("success", "Edit teacher successfully");
    return res.redirect("/show/teacher");
  })
);

// ================= DELETE TEACHER =================
app.delete(
  "/delete/teacher/:id",
  verifiedAny,
  WrapAsync(async (req, res) => {
    const { id } = req.params;
    await Teacher.findByIdAndDelete(id);
    req.flash("success", "Teacher deleted successfully");
    return res.redirect("/show/teacher");
  })
);

// ================= ADD STUDENT =================
app.get(
  "/add/studentData",
  verifiedAny,
  WrapAsync(async (req, res) => {
    const classData = (await Class.find({})) || [];
    return res.render("admin/createStudent.ejs", { classData });
  })
);

app.post(
  "/add/studentData",
  upload.single("data[image]"),
  WrapAsync(async (req, res) => {
    const { data } = req.body;

    const newStudent = new Student(data);

    if (req.file) {
      const { path: url, filename } = req.file;
      newStudent.image = { url, filename };
    }

    await newStudent.save();
    req.flash("success", "Add Student successfully");
    return res.redirect("/add/studentData");
  })
);

// ---------------- SHOW STUDENT PAGE ----------------
app.get(
  "/show/student",
  verifiedAny,
  WrapAsync(async (req, res) => {
    const datas = (await Student.find({})) || [];
    const course = (await Class.find({})) || [];
    return res.render("admin/showStudent.ejs", { datas, course });
  })
);

// ---------------- STUDENT PROFILE ----------------
app.get(
  "/student/profile/:id",
  verifiedAny,
  WrapAsync(async (req, res) => {
    const { id } = req.params;
    const student = await Student.findById(id);
    if (!student) {
      req.flash("error", "Student not found");
      return res.redirect("/show/student");
    }
    return res.render("admin/studentProfile.ejs", { student });
  })
);

// ---------------- EDIT STUDENT ----------------
app.get(
  "/edit/student/:id",
  verifiedAny,
  WrapAsync(async (req, res) => {
    const { id } = req.params;
    const data = await Student.findById(id);
    if (!data) {
      req.flash("error", "Student not found");
      return res.redirect("/show/student");
    }
    const classData = (await Class.find({})) || [];
    return res.render("admin/editStudent.ejs", { id, data, classData });
  })
);

app.put(
  "/edit/student/:id",
  upload.single("data[image]"),
  WrapAsync(async (req, res) => {
    const { id } = req.params;
    const studentData = req.body.data || {};
    const student = await Student.findById(id);
    if (!student) {
      req.flash("error", "Student not found");
      return res.redirect("/show/student");
    }

    Object.assign(student, studentData);

    if (req.file) {
      const { path: url, filename } = req.file;
      student.image = { url, filename };
    }

    await student.save();
    req.flash("success", "Edit student successfully");
    return res.redirect("/show/student");
  })
);

// ---------------- DELETE STUDENT ----------------
app.delete(
  "/delete/student/:id",
  verifiedAny,
  WrapAsync(async (req, res) => {
    const { id } = req.params;
    const student = await Student.findByIdAndDelete(id);
    if (!student) {
      req.flash("error", "Student not found");
      return res.redirect("/show/student");
    }
    req.flash("success", "Student deleted successfully");
    return res.redirect("/show/student");
  })
);

// ---------------- SEARCH STUDENT ----------------
app.post(
  "/search/student",
  WrapAsync(async (req, res) => {
    const { data } = req.body;
    const query = {};

    if (data?.name) query.name = { $regex: data.name, $options: "i" };
    if (data?.class) query.class = data.class;

    const datas = (await Student.find(query)) || [];

    if (!datas.length) {
      req.flash("error", "Student not found");
      return res.redirect("/show/student");
    }

    return res.render("admin/searchStudent.ejs", { datas });
  })
);

// ---------------- SHOW STUDENT SUBJECT ----------------
app.get(
  "/show/student/subject/:rollNo",
  verifiedAny,
  WrapAsync(async (req, res) => {
    const { rollNo } = req.params;
    if (!rollNo) {
      req.flash("error", "Something went wrong");
      return res.redirect("/add/studentData");
    }

    const datas = await Student.findOne({ rollNo: parseInt(rollNo) });
    if (!datas) {
      req.flash("error", "Student not found");
      return res.redirect("/add/studentData");
    }

    return res.render("admin/showStudentSubject.ejs", { datas });
  })
);

// ---------------- DELETE STUDENT SUBJECT ----------------
app.delete(
  "/delete/:studentId/subject/:subjectId",
  verifiedAny,
  WrapAsync(async (req, res) => {
    const { studentId, subjectId } = req.params;
    const student = await Student.findByIdAndUpdate(studentId, {
      $pull: { subject: { _id: subjectId } },
    });
    if (!student) {
      req.flash("error", "Student not found");
      return res.redirect("/show/student");
    }
    req.flash("success", "Subject removed successfully!");
    return res.redirect(`/show/student/subject/${student.rollNo}`);
  })
);

// ---------------- STUDENT STATUS ----------------
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

    const student = await Student.findOne({ rollNo: parseInt(rollNo) });
    if (!student) {
      req.flash("error", "Student not found");
      return res.redirect("/add/studentData");
    }

    return res.render("admin/studentStatus.ejs", { student });
  })
);

// ---------------- FILTERED ATTENDANCE ----------------
app.get(
  "/attendance/:studentId/:filter",
  verifiedAny,
  WrapAsync(async (req, res) => {
    const { studentId, filter } = req.params;
    req.session.studentId = studentId;

    const now = new Date();
    let dateQuery = {};

    if (filter === "today") {
      const start = new Date(
        Date.UTC(
          now.getUTCFullYear(),
          now.getUTCMonth(),
          now.getUTCDate(),
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
      const startOfWeek = new Date(
        Date.UTC(
          now.getUTCFullYear(),
          now.getUTCMonth(),
          now.getUTCDate() - day,
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

    if (filter === "monthly") {
      const startOfMonth = new Date(
        Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1, 0, 0, 0)
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

    return res.json({
      success: true,
      filter,
      range: dateQuery,
      count: attendance.length,
      data: attendance,
    });
  })
);

// ---------------- ADD SUBJECT ----------------
app.get(
  "/add/subjectData",
  verifiedAny,
  WrapAsync(async (req, res) => {
    const classData = (await Class.find({})) || [];
    return res.render("admin/createSubject.ejs", { classData });
  })
);

app.post(
  "/add/subjectData",
  WrapAsync(async (req, res) => {
    const newSubject = new Subject(req.body.data);
    await newSubject.save();

    if (!req.session.adminVerified) req.session.adminVerified = true;
    req.flash("success", "Add subject successfully");
    return res.redirect("/add/subjectData");
  })
);

// ---------------- SHOW SUBJECT ----------------
app.get(
  "/show/subject",
  verifiedAny,
  WrapAsync(async (req, res) => {
    const datas = (await Subject.find({})) || [];
    return res.render("admin/showSubject.ejs", { datas });
  })
);

// ---------------- EDIT SUBJECT ----------------
app.get(
  "/edit/subject/:subjectId",
  verifiedAny,
  WrapAsync(async (req, res) => {
    const { subjectId } = req.params;
    const data = await Subject.findById(subjectId);
    const classData = (await Class.find({})) || [];

    if (!data) {
      req.flash("error", "Subject not found");
      return res.redirect("/show/subject");
    }

    return res.render("admin/editSubject.ejs", { data, classData });
  })
);

app.put(
  "/edit/subject/:subjectId",
  verifiedAny,
  WrapAsync(async (req, res) => {
    const { subjectId } = req.params;
    const subject = await Subject.findById(subjectId);
    if (!subject) {
      req.flash("error", "Subject not found");
      return res.redirect("/show/subject");
    }

    Object.assign(subject, req.body.data);
    await subject.save();

    req.flash("success", "Subject edited successfully");
    return res.redirect("/show/subject");
  })
);

// ---------------- DELETE SUBJECT ----------------
app.delete(
  "/delete/subject/:id",
  verifiedAny,
  WrapAsync(async (req, res) => {
    const { id } = req.params;
    const subject = await Subject.findByIdAndDelete(id);
    if (!subject) {
      req.flash("error", "Subject not found");
      return res.redirect("/show/subject");
    }
    req.flash("success", "Subject deleted successfully");
    return res.redirect("/show/subject");
  })
);

// ---------------- SEARCH SUBJECT ----------------
app.post(
  "/search/subject",
  WrapAsync(async (req, res) => {
    const { search } = req.body;
    const datas =
      (await Subject.find({ name: { $regex: search, $options: "i" } })) || [];

    if (!datas.length) {
      req.flash("error", "Subject not found!");
      return res.redirect("/show/subject");
    }

    return res.render("admin/searchSubject.ejs", { datas });
  })
);

// ---------------- ADD CLASS ----------------
app.get("/add/class", verifiedAny, (req, res) => {
  return res.render("admin/createClass.ejs");
});

app.post(
  "/add/class",
  WrapAsync(async (req, res) => {
    let className = req.body.data?.class || "";
    className = className.toUpperCase().trim().replace(/\s+/g, " ");

    const classFormat =
      /^(B\.TECH(\s(CSE|IT|ECE|EEE|EE|ME|CIVIL|AI\/ML|DS))?|BCA|BBA|B\.SC|M\.SC|MCA|MBA|DIPLOMA(\s(CIVIL|ME|EE|CSE))?|BA|MA|ITI|POLYTECHNIC)\s(1ST|2ND|3RD|4TH)\sYEAR$/;

    if (/^BTECH/.test(className)) {
      req.flash("error", "Use proper format: B.TECH (not BTECH)");
      return res.redirect("/add/class");
    }

    if (!classFormat.test(className)) {
      req.flash(
        "error",
        "Invalid format! Examples:\n• B.TECH CSE 1ST YEAR\n• BCA 2ND YEAR\n• BA 1ST YEAR"
      );
      return res.redirect("/add/class");
    }

    const exists = await Class.findOne({ class: className });
    if (exists) {
      req.flash("error", "This class already exists!");
      return res.redirect("/add/class");
    }

    req.body.data.class = className;
    await new Class(req.body.data).save();

    req.flash("success", "Class added successfully");
    return res.redirect("/add/class");
  })
);
// ---------------- SHOW STUDENT PAGE ----------------
app.get(
  "/show/student",
  verifiedAny,
  WrapAsync(async (req, res) => {
    const datas = (await Student.find({})) || [];
    const course = (await Class.find({})) || [];
    return res.render("admin/showStudent.ejs", { datas, course });
  })
);

// ---------------- STUDENT PROFILE ----------------
app.get(
  "/student/profile/:id",
  verifiedAny,
  WrapAsync(async (req, res) => {
    const { id } = req.params;
    const student = await Student.findById(id);
    if (!student) {
      req.flash("error", "Student not found");
      return res.redirect("/show/student");
    }
    return res.render("admin/studentProfile.ejs", { student });
  })
);

// ---------------- EDIT STUDENT ----------------
app.get(
  "/edit/student/:id",
  verifiedAny,
  WrapAsync(async (req, res) => {
    const { id } = req.params;
    const data = await Student.findById(id);
    if (!data) {
      req.flash("error", "Student not found");
      return res.redirect("/show/student");
    }
    const classData = (await Class.find({})) || [];
    return res.render("admin/editStudent.ejs", { id, data, classData });
  })
);

app.put(
  "/edit/student/:id",
  upload.single("data[image]"),
  WrapAsync(async (req, res) => {
    const { id } = req.params;
    const studentData = req.body?.data || {};
    const student = await Student.findById(id);
    if (!student) {
      req.flash("error", "Student not found");
      return res.redirect("/show/student");
    }

    Object.assign(student, studentData);

    if (req.file) {
      const { path: url, filename } = req.file;
      student.image = { url, filename };
    }

    await student.save();
    req.flash("success", "Edit student successfully");
    return res.redirect("/show/student");
  })
);

// ---------------- DELETE STUDENT ----------------
app.delete(
  "/delete/student/:id",
  verifiedAny,
  WrapAsync(async (req, res) => {
    const { id } = req.params;
    const student = await Student.findByIdAndDelete(id);
    if (!student) {
      req.flash("error", "Student not found");
      return res.redirect("/show/student");
    }
    req.flash("success", "Student deleted successfully");
    return res.redirect("/show/student");
  })
);

// ---------------- SEARCH STUDENT ----------------
app.post(
  "/search/student",
  WrapAsync(async (req, res) => {
    const { data } = req.body;
    const query = {};

    if (data?.name) query.name = { $regex: data.name, $options: "i" };
    if (data?.class) query.class = data.class;

    const datas = (await Student.find(query)) || [];
    if (!datas.length) {
      req.flash("error", "Student not found");
      return res.redirect("/show/student");
    }

    return res.render("admin/searchStudent.ejs", { datas });
  })
);

// ---------------- SHOW STUDENT SUBJECT ----------------
app.get(
  "/show/student/subject/:rollNo",
  verifiedAny,
  WrapAsync(async (req, res) => {
    const { rollNo } = req.params;
    if (!rollNo) {
      req.flash("error", "Something went wrong");
      return res.redirect("/add/studentData");
    }

    const roll = parseInt(rollNo);
    if (isNaN(roll)) {
      req.flash("error", "Invalid Roll Number");
      return res.redirect("/add/studentData");
    }

    const datas = await Student.findOne({ rollNo: roll });
    if (!datas) {
      req.flash("error", "Student not found");
      return res.redirect("/add/studentData");
    }

    return res.render("admin/showStudentSubject.ejs", { datas });
  })
);

// ---------------- DELETE STUDENT SUBJECT ----------------
app.delete(
  "/delete/:studentId/subject/:subjectId",
  verifiedAny,
  WrapAsync(async (req, res) => {
    const { studentId, subjectId } = req.params;
    const student = await Student.findByIdAndUpdate(studentId, {
      $pull: { subject: { _id: subjectId } },
    });
    if (!student) {
      req.flash("error", "Student not found");
      return res.redirect("/show/student");
    }

    req.flash("success", "Subject removed successfully!");
    return res.redirect(`/show/student/subject/${student.rollNo}`);
  })
);

// ---------------- STUDENT STATUS ----------------
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

    const roll = parseInt(rollNo);
    if (isNaN(roll)) {
      req.flash("error", "Invalid Roll Number");
      return res.redirect("/add/studentData");
    }

    const student = await Student.findOne({ rollNo: roll });
    if (!student) {
      req.flash("error", "Student not found");
      return res.redirect("/add/studentData");
    }

    return res.render("admin/studentStatus.ejs", { student });
  })
);

// ---------------- FILTERED ATTENDANCE ----------------
app.get(
  "/attendance/:studentId/:filter",
  verifiedAny,
  WrapAsync(async (req, res) => {
    const { studentId, filter } = req.params;
    req.session.studentId = studentId;

    const now = new Date();
    let dateQuery = {};

    if (filter === "today") {
      const start = new Date(
        Date.UTC(
          now.getUTCFullYear(),
          now.getUTCMonth(),
          now.getUTCDate(),
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
      const startOfWeek = new Date(
        Date.UTC(
          now.getUTCFullYear(),
          now.getUTCMonth(),
          now.getUTCDate() - day,
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

    if (filter === "monthly") {
      const startOfMonth = new Date(
        Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1, 0, 0, 0)
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

    return res.json({
      success: true,
      filter,
      range: dateQuery,
      count: attendance.length,
      data: attendance,
    });
  })
);

// ---------------- ADD SUBJECT ----------------
app.get(
  "/add/subjectData",
  verifiedAny,
  WrapAsync(async (req, res) => {
    const classData = (await Class.find({})) || [];
    return res.render("admin/createSubject.ejs", { classData });
  })
);

app.post(
  "/add/subjectData",
  WrapAsync(async (req, res) => {
    const newSubject = new Subject(req.body?.data || {});
    await newSubject.save();

    if (!req.session.adminVerified) req.session.adminVerified = true;
    req.flash("success", "Add subject successfully");
    return res.redirect("/add/subjectData");
  })
);

// ---------------- SHOW SUBJECT ----------------
app.get(
  "/show/subject",
  verifiedAny,
  WrapAsync(async (req, res) => {
    const datas = (await Subject.find({})) || [];
    return res.render("admin/showSubject.ejs", { datas });
  })
);

// ---------------- EDIT SUBJECT ----------------
app.get(
  "/edit/subject/:subjectId",
  verifiedAny,
  WrapAsync(async (req, res) => {
    const { subjectId } = req.params;
    const data = await Subject.findById(subjectId);
    const classData = (await Class.find({})) || [];

    if (!data) {
      req.flash("error", "Subject not found");
      return res.redirect("/show/subject");
    }

    return res.render("admin/editSubject.ejs", { data, classData });
  })
);

app.put(
  "/edit/subject/:subjectId",
  verifiedAny,
  WrapAsync(async (req, res) => {
    const { subjectId } = req.params;
    const subject = await Subject.findById(subjectId);
    if (!subject) {
      req.flash("error", "Subject not found");
      return res.redirect("/show/subject");
    }

    Object.assign(subject, req.body?.data || {});
    await subject.save();

    req.flash("success", "Subject edited successfully");
    return res.redirect("/show/subject");
  })
);

// ---------------- DELETE SUBJECT ----------------
app.delete(
  "/delete/subject/:id",
  verifiedAny,
  WrapAsync(async (req, res) => {
    const { id } = req.params;
    const subject = await Subject.findByIdAndDelete(id);
    if (!subject) {
      req.flash("error", "Subject not found");
      return res.redirect("/show/subject");
    }

    req.flash("success", "Subject deleted successfully");
    return res.redirect("/show/subject");
  })
);

// ---------------- SEARCH SUBJECT ----------------
app.post(
  "/search/subject",
  WrapAsync(async (req, res) => {
    const { search } = req.body;
    const datas =
      (await Subject.find({ name: { $regex: search, $options: "i" } })) || [];
    if (!datas.length) {
      req.flash("error", "Subject not found!");
      return res.redirect("/show/subject");
    }

    return res.render("admin/searchSubject.ejs", { datas });
  })
);

// ---------------- ADD CLASS ----------------
app.get("/add/class", verifiedAny, (req, res) => {
  return res.render("admin/createClass.ejs");
});

app.post(
  "/add/class",
  WrapAsync(async (req, res) => {
    let className = req.body?.data?.class || "";
    className = className.toUpperCase().trim().replace(/\s+/g, " ");

    const classFormat =
      /^(B\.TECH(\s(CSE|IT|ECE|EEE|EE|ME|CIVIL|AI\/ML|DS))?|BCA|BBA|B\.SC|M\.SC|MCA|MBA|DIPLOMA(\s(CIVIL|ME|EE|CSE))?|BA|MA|ITI|POLYTECHNIC)\s(1ST|2ND|3RD|4TH)\sYEAR$/;

    if (/^BTECH/.test(className)) {
      req.flash("error", "Use proper format: B.TECH (not BTECH)");
      return res.redirect("/add/class");
    }

    if (!classFormat.test(className)) {
      req.flash(
        "error",
        "Invalid format! Examples:\n• B.TECH CSE 1ST YEAR\n• BCA 2ND YEAR\n• BA 1ST YEAR"
      );
      return res.redirect("/add/class");
    }

    const exists = await Class.findOne({ class: className });
    if (exists) {
      req.flash("error", "This class already exists!");
      return res.redirect("/add/class");
    }

    req.body.data.class = className;
    await new Class(req.body.data).save();

    req.flash("success", "Class added successfully");
    return res.redirect("/add/class");
  })
);

//////////////////////////// ADMIN: STUDENT STATUS PDF ////////////////////////////

app.get(
  "/show/allStudent/status/pdf",
  verifiedAny,
  WrapAsync(async (req, res) => {
    let { class: className, semester, section, filter } = req.query;
    filter = filter || "all";

    const now = new Date();
    let dateQuery = {};

    // ===== DATE FILTER =====
    if (filter === "today") {
      const start = new Date(
        Date.UTC(
          now.getUTCFullYear(),
          now.getUTCMonth(),
          now.getUTCDate(),
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
    } else if (filter === "weekly") {
      const day = now.getUTCDay();
      const start = new Date(
        Date.UTC(
          now.getUTCFullYear(),
          now.getUTCMonth(),
          now.getUTCDate() - day,
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
    } else if (filter === "monthly") {
      const start = new Date(
        Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1, 0, 0, 0)
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
    const attendanceQuery = { studentId: { $in: studentIds } };
    if (filter !== "all") attendanceQuery.date = dateQuery;

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
        if (!(day in dayMap)) dayMap[day] = "Absent";
        if (r.status === "Present") dayMap[day] = "Present";
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

    // HEADER
    doc
      .fontSize(18)
      .text("Student Attendance Status Report", { align: "center" });
    doc.moveDown(0.5);
    doc
      .fontSize(11)
      .text(`Class: ${className} | Sem: ${semester} | Sec: ${section}`, {
        align: "center",
      });
    doc.text(`Filter: ${filter.toUpperCase()}`, { align: "center" });
    doc.moveDown(1);

    // TABLE HEADER
    let y = doc.y;
    doc.fontSize(10).font("Helvetica-Bold");
    doc.text("Admin.No", 40, y);
    doc.text("Name", 80, y);
    doc.text("P Days", 230, y);
    doc.text("T Days", 280, y);
    doc.text("P Per.", 330, y);
    doc.text("T Per.", 380, y);
    doc.text("%", 430, y);
    doc.text("Status", 470, y);

    doc
      .moveDown(0.3)
      .font("Helvetica")
      .moveTo(40, doc.y)
      .lineTo(550, doc.y)
      .stroke();
    doc.moveDown(0.5);

    // TABLE ROWS
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

    // FOOTER
    doc
      .moveDown(2)
      .fontSize(9)
      .text(`Generated on: ${new Date().toLocaleString()}`, { align: "right" });
    doc.end();
  })
);

//////////////////////////// TEACHER ROUTES ////////////////////////////

// teacher profile
app.get(
  "/teacher/profile",
  isLoggedIn,
  WrapAsync(async (req, res) => {
    const data = await Teacher.findById(req.user._id);
    res.render("teachers/profile.ejs", { data });
  })
);

// profile edit
app.get(
  "/teacher/profile/edit/:id",
  isLoggedIn,
  WrapAsync(async (req, res) => {
    const { id } = req.params;
    const data = await Teacher.findById(id);
    res.render("teachers/editProfile.ejs", { id, data });
  })
);

app.put(
  "/teacher/profile/edit/:id",
  upload.single("data[image]"),
  WrapAsync(async (req, res) => {
    const { id } = req.params;
    const teacher = await Teacher.findById(id);
    if (!teacher) {
      req.flash("error", "Teacher not found");
      return res.redirect("/teacher/profile");
    }

    Object.assign(teacher, req.body.data);
    if (req.file) {
      teacher.image = { url: req.file.path, filename: req.file.filename };
    }

    await teacher.save();
    req.flash("success", "Profile updated successfully");
    res.redirect("/teacher/profile");
  })
);

// main teacher page
app.get(
  "/teacher/student/attendance",
  isLoggedIn,
  WrapAsync(async (req, res) => {
    const teacherData = await Teacher.findById(req.user._id);
    const studentData = await Student.find({});
    res.render("teachers/main.ejs", { teacherData, studentData });
  })
);

// login teacher
app.post(
  "/login/modal",
  passport.authenticate("local", {
    failureRedirect: "/student/attendance/login",
    failureFlash: true,
  }),
  (req, res) => {
    req.flash("success", "Login Successfully");
    res.redirect("/teacher/student/attendance");
  }
);

// add attendance login page
app.get(
  "/add/student/attendance",
  isLoggedIn,
  WrapAsync(async (req, res) => {
    const classData = await Teacher.findById(req.user._id);
    req.session.teacherName = classData.name;
    res.render("teachers/attendanceLogin.ejs", { classData });
  })
);

// select students for attendance
app.post(
  "/add/student/attendance",
  WrapAsync(async (req, res) => {
    const { class: className, semester, section } = req.body.data;
    req.session.class = className;
    req.session.semester = semester;
    req.session.section = section;

    const teacher = await Teacher.findById(req.user._id);
    const classObj = teacher.class.find((c) => c.className === className);
    if (!classObj)
      return (
        req.flash("error", "Class not assigned to you") &&
        res.redirect("/add/student/attendance")
      );

    const semObj = classObj.semesters.find((s) => s.semester === semester);
    if (!semObj)
      return (
        req.flash("error", "Semester not assigned to you") &&
        res.redirect("/add/student/attendance")
      );

    const secObj = semObj.sections.find((s) => s.section === section);
    if (!secObj)
      return (
        req.flash("error", "Section not assigned to you") &&
        res.redirect("/add/student/attendance")
      );

    const students = await Student.find({
      class: className,
      semester,
      section,
    });
    if (!students.length)
      return (
        req.flash("error", "No students found") &&
        res.redirect("/add/student/attendance")
      );

    const studentSubjects = students.flatMap((s) =>
      s.subject.map((sub) => (typeof sub === "string" ? sub : sub.name))
    );
    const teacherSubjects = secObj.subjects;
    const commonSubjects = teacherSubjects.filter((sub) =>
      studentSubjects.includes(sub)
    );

    if (!commonSubjects.length)
      return (
        req.flash("error", "No matching subjects") &&
        res.redirect("/add/student/attendance")
      );

    res.render("teachers/attendancePage.ejs", { students, commonSubjects });
  })
);

// save attendance
app.post(
  "/attendance/saveAll",
  WrapAsync(async (req, res) => {
    const { students, period, unit, description, subject } = req.body;
    const section = req.session.section;
    const classes = req.session.class;
    const semester = req.session.semester;
    const teacherName = req.session.teacherName;

    const existingAttendance = await AttendenceDuplicate.findOne({
      "attendance.periods": period,
      "attendance.class": classes,
      "attendance.section": section,
      "attendance.semester": semester,
    });

    if (existingAttendance)
      return (
        req.flash("error", `Attendance already exists for period ${period}`) &&
        res.redirect("/add/student/attendance")
      );

    try {
      await Promise.all(
        Object.entries(students).map(async ([studentId, status]) => {
          await Attendance.create({
            studentId,
            date: normalizeDate(new Date()),
            status,
            period,
            unit,
            description,
            subject,
          });
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
        })
      );
      req.flash("success", "Attendance saved successfully!");
      res.redirect("/add/student/attendance");
    } catch (err) {
      console.error(err);
      req.flash("error", "Error saving attendance!");
      res.redirect("/add/student/attendance");
    }
  })
);

// AJAX helpers: semesters, sections, subjects
app.get("/get-semesters", isLoggedIn, async (req, res) => {
  try {
    const { class: className } = req.query;
    if (!className) return res.json([]);
    const teacher = await Teacher.findById(req.user._id);
    const cls = teacher.class.find(
      (c) => c.className.toLowerCase() === className.toLowerCase()
    );
    res.json(cls?.semesters.map((s) => s.semester) || []);
  } catch (err) {
    console.error(err);
    res.status(500).json([]);
  }
});

app.get("/get-sections", isLoggedIn, async (req, res) => {
  try {
    const { class: className, semester } = req.query;
    const teacher = await Teacher.findById(req.user._id);
    const cls = teacher.class.find((c) => c.className === className);
    const sem = cls?.semesters.find((s) => s.semester === semester);
    res.json(sem?.sections.map((s) => s.section) || []);
  } catch (err) {
    console.error(err);
    res.status(500).json([]);
  }
});

app.get("/get-subjects", isLoggedIn, async (req, res) => {
  try {
    const { class: className, semester, section } = req.query;
    const teacher = await Teacher.findById(req.user._id);
    const cls = teacher.class.find((c) => c.className === className);
    const sem = cls?.semesters.find((s) => s.semester === semester);
    const sec = sem?.sections.find((s) => s.section === section);
    res.json(sec?.subjects || []);
  } catch (err) {
    console.error(err);
    res.status(500).json([]);
  }
});
////////////////////////// TEACHER UPDATE ATTENDANCE //////////////////////////

// Update attendance page (select class/semester/section/subject)
app.post(
  "/update/student/attendance",
  WrapAsync(async (req, res) => {
    const { data } = req.body;
    const { class: className, semester, section, subject } = data;

    // Save session
    req.session.class = className;
    req.session.semester = semester;
    req.session.section = section;
    req.session.subject = subject;

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

    const latest = validAttendances.sort(
      (a, b) => new Date(b.date) - new Date(a.date)
    )[0];

    const currentAttendance = {
      periods: latest.periods,
      unit: latest.unit,
      description: latest.description,
      date: latest.date,
    };

    const students = await Student.find({
      class: className,
      semester,
      section,
    });
    if (!students.length) {
      req.flash("error", "No students found");
      return res.redirect("/update/student/attendance");
    }

    // Build status map
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
      if (att)
        statusMap[record.studentId.toString()] = att.status || "Not marked";
    }

    const studentsWithStatus = students.map((stu) => ({
      ...stu.toObject(),
      attendanceToday: statusMap[stu._id.toString()] || "Not marked",
    }));

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

    res.render("teachers/updateAttenPage.ejs", {
      students: studentsWithStatus,
      subject,
      commonSubjects,
      currentAttendance,
    });
  })
);

// POST: Update all attendance
app.post(
  "/attendance/updateAll",
  WrapAsync(async (req, res) => {
    const { students, period, unit, description, subject } = req.body;
    const section = req.session.section;
    const classes = req.session.class;
    const semester = req.session.semester;

    try {
      const now = new Date();

      let updatedCount = 0,
        deniedCount = 0,
        notFoundCount = 0;

      for (const [studentId, status] of Object.entries(students)) {
        const dup = await AttendenceDuplicate.findOne({ studentId });
        if (!dup) {
          notFoundCount++;
          continue;
        }

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

        const createdTime = record.createdAt || record.date;
        const diffHours =
          (Date.now() - new Date(createdTime)) / (1000 * 60 * 60);
        if (diffHours > 24) {
          deniedCount++;
          continue;
        }

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

        const updated = await Attendance.findOneAndUpdate(
          {
            studentId,
            period: Number(period),
            subject,
            date: { $gte: new Date(new Date().setHours(0, 0, 0, 0)) },
          },
          { $set: { status, unit, description, date: new Date() } },
          { upsert: false }
        );

        if (!updated) {
          notFoundCount++;
          continue;
        }
        updatedCount++;
      }

      if (updatedCount)
        req.flash(
          "success",
          `✅ ${updatedCount} attendance updated successfully`
        );
      if (deniedCount)
        req.flash("error", `⚠️ ${deniedCount} records older than 24 hours`);
      if (notFoundCount)
        req.flash("info", `ℹ️ ${notFoundCount} records not found`);

      res.redirect("/add/student/attendance");
    } catch (err) {
      console.error("❌ UPDATE ERROR:", err);
      req.flash("error", "Something went wrong while updating attendance");
      res.redirect("/add/student/attendance");
    }
  })
);

// Show attendance records
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

    const datas = await Student.find({ class: classes, semester, section });
    if (!datas.length) {
      req.flash("error", "No students found");
      return res.redirect("/add/student/attendance");
    }

    let dupDatas = await AttendenceDuplicate.find().populate({
      path: "studentId",
      match: { class: classes, semester, section },
    });

    dupDatas = dupDatas.filter((d) => d.studentId);

    res.render("teachers/showAttendance.ejs", { datas, dupDatas });
  })
);

// Teacher logout
app.get("/logout", isLoggedIn, (req, res, next) => {
  req.logout((err) => {
    if (err) return next(err);
    req.flash("success", "You are logged out");
    res.redirect("/student/attendance/login");
  });
});

//////////////////////// STUDENT FOLDER ////////////////////////

// OTP login
app.get("/otp", (req, res) => res.render("listings/otp.ejs"));
app.post(
  "/verify-otp",
  WrapAsync(async (req, res) => {
    const { otp } = req.body;
    const otpRecord = await OTP.findOne({ otp });
    if (!otpRecord) {
      req.flash("error", "Invalid OTP");
      return res.redirect("/otp");
    }

    req.session.otpVerified = true;
    req.flash("success", "Login successfully");
    res.redirect("/student/attendance");
  })
);

// Student profile & edit
app.get(
  "/profile",
  verifiedAny,
  WrapAsync(async (req, res) => {
    const rollNo = req.session.rollNo;
    if (!rollNo) {
      req.flash("error", "Something went wrong");
      return res.redirect("/student/attendance/login");
    }
    const student = await Student.findOne({ rollNo: parseInt(rollNo) });
    if (!student) {
      req.flash("error", "Something went wrong");
      return res.redirect("/student/attendance/login");
    }
    res.render("students/profile.ejs", { student });
  })
);

app.get(
  "/profile/edit/:id",
  verifiedAny,
  WrapAsync(async (req, res) => {
    const { id } = req.params;
    const data = await Student.findById(id);
    res.render("students/editProfile.ejs", { data, id });
  })
);

app.put(
  "/profile/edit/:id",
  upload.single("data[image]"),
  verifiedAny,
  WrapAsync(async (req, res) => {
    const { id } = req.params;
    const student = await Student.findByIdAndUpdate(id, { ...req.body.data });
    if (req.file)
      student.image = { url: req.file.path, filename: req.file.filename };
    await student.save();
    req.flash("success", "Profile updated successfully");
    res.redirect("/profile");
  })
);

// Student main page
app.get(
  "/student/attendance",
  verifiedAny,
  WrapAsync(async (req, res) => {
    const rollNo = req.session.rollNo;
    if (!rollNo) {
      req.flash("error", "Something went wrong");
      return res.redirect("/student/attendance/login");
    }
    const student = await Student.findOne({ rollNo: parseInt(rollNo) });
    if (!student) {
      req.flash("error", "Something went wrong");
      return res.redirect("/student/attendance/login");
    }
    res.render("students/main.ejs", { student });
  })
);

// Student logout
app.get("/student/logout", verifiedAny, (req, res) => {
  req.session.otpVerified = false;
  req.flash("success", "Logout successful");
  res.redirect("/student/attendance/login");
});

//////////////////// ERROR HANDLER ////////////////////
app.use((req, res, next) => next(new ExpressError(404, "Page not found")));
app.use((err, req, res, next) => {
  const { statuscode = 500, message = "Something went wrong" } = err;
  console.log(statuscode, message);
  res.status(statuscode).render("listings/error.ejs", { message, statuscode });
});

app.listen(5000, () => console.log("Server running on 5000 ✅"));
