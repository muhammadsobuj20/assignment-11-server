require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
console.log("Stripe key:", process.env.STRIPE_SECRET_KEY);
const admin = require("firebase-admin");
const jwt = require("jsonwebtoken");
const port = process.env.PORT || 3000;

// Firebase Admin Init
const serviceAccount = JSON.parse(
  Buffer.from(process.env.FB_SERVICE_KEY, "base64").toString("utf-8")
);
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const app = express();

app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "http://localhost:5174",
      "https://e-tuition-bd.web.app",
    ],
    credentials: true,
  })
);

app.use(express.json());

// MongoDB Client
const client = new MongoClient(process.env.MONGODB_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    await client.connect();
    const db = client.db("eTuitionBD");
    const usersCollection = db.collection("users");
    const tuitionsCollection = db.collection("tuitions");
    const applicationsCollection = db.collection("applications");
    const paymentsCollection = db.collection("payments");
    const tutorsCollection = db.collection("tutors");
    const bookingsCollection = db.collection("bookings");
    const messagesCollection = db.collection("messages");
    console.log("MongoDB Connected Successfully!");

    // JWT & Firebase Verify Middleware 



const verifyToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).send({ message: "No Authorization Header" });
  }

  const token = authHeader.split(" ")[1];
  if (!token) {
    return res.status(401).send({ message: "Token missing" });
  }

  try {
    const decoded = await admin.auth().verifyIdToken(token);
    // decoded.email, decoded.uid available
    req.user = decoded;
    next();
  } catch (error) {
    console.error("❌ Firebase token invalid:", error.message);
    return res.status(401).send({ message: "Invalid Firebase Token" });
  }
};


    // Role-based middlewares
    const verifyStudent = async (req, res, next) => {
      const user = await usersCollection.findOne({ email: req.user.email });
      if (user?.role !== "student") {
        return res.status(403).send({ message: "Forbidden: Student only" });
      }
      req.currentUser = user;
      next();
    };

    const verifyTutor = async (req, res, next) => {
      const user = await usersCollection.findOne({ email: req.user.email });
      if (user?.role !== "tutor") {
        return res.status(403).send({ message: "Forbidden: Tutor only" });
      }
      req.currentUser = user;
      next();
    };

    const verifyAdmin = async (req, res, next) => {
      const user = await usersCollection.findOne({ email: req.user.email });
      if (user?.role !== "admin") {
        return res.status(403).send({ message: "Forbidden: Admin only" });
      }
      req.currentUser = user;
      next();
    };

    const verifyJWT = (req, res, next) => {
      const authHeader = req.headers.authorization;
      if (!authHeader) return res.status(401).send({ message: "Unauthorized" });

      const token = authHeader.split(" ")[1];
      jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).send({ message: "Unauthorized" });
        req.user = decoded;
        next();
      });
    };

    //  User Routes 

    // Save or update user after Firebase login
    app.put("/users", async (req, res) => {
      try {
        const user = req.body;

        if (!user.email) {
          return res.status(400).send({ message: "Email is required" });
        }

        const filter = { email: user.email };

        const updateDoc = {
          $set: {
            name: user.name || "",
            email: user.email,
            photoURL: user.photoURL || "",
            phone: user.phone || "",
            lastLoginAt: new Date(),
          },
          $setOnInsert: {
            role: "student",
            createdAt: new Date(),
          },
        };

        const result = await usersCollection.updateOne(filter, updateDoc, {
          upsert: true,
        });
        res.send(result);
      } catch (error) {
        console.error("PUT /users Error:", error);
        res.status(500).send({ error: error.message });
      }
    });

    app.get("/users/role", verifyToken, async (req, res) => {
      const user = await usersCollection.findOne({ email: req.user.email });
      res.send({ role: user?.role || "student" });
    });

    app.get("/users", verifyToken, verifyAdmin, async (req, res) => {
      const result = await usersCollection.find().toArray();
      res.send(result);
    });

    app.post("/user", async (req, res) => {
      const user = req.body;
      const result = await usersCollection.insertOne(user);
      res.send(result);
    });

    app.patch("/users/:email", verifyToken, verifyAdmin, async (req, res) => {
      const email = req.params.email;
      const update = req.body;
      const result = await usersCollection.updateOne(
        { email },
        { $set: update }
      );
      res.send(result);
    });

    app.delete("/users/:email", verifyToken, verifyAdmin, async (req, res) => {
      const email = req.params.email;
      const result = await usersCollection.deleteOne({ email });
      res.send(result);
    });

    //  Tuition Routes 

    // Create Tuition Post (Student only
    app.post("/tuitions", verifyToken, verifyStudent, async (req, res) => {
      const tuition = {
        ...req.body,
        studentEmail: req.user.email,
        status: "pending", // pending | approved | rejected
        createdAt: new Date(),
      };
      const result = await tuitionsCollection.insertOne(tuition);
      res.send(result);
    });

    // Get all approved tuitions (public)
    app.get("/tuitions", async (req, res) => {
      const {
        page = 1,
        limit = 10,
        search,
        location,
        class: className,
        subject,
        sort = "latest",
      } = req.query;

      let query = { status: "approved" };

      if (search) query.$text = { $search: search };
      if (location) query.location = new RegExp(location, "i");
      if (className) query.class = className;
      if (subject) query.subject = new RegExp(subject, "i");

      const sortObj = sort === "oldest" ? { createdAt: 1 } : { createdAt: -1 };

      const result = await tuitionsCollection
        .find(query)
        .sort(sortObj)
        .skip((page - 1) * limit)
        .limit(parseInt(limit))
        .toArray();

      const total = await tuitionsCollection.countDocuments(query);

      res.send({
        tuitions: result,
        total,
        page: parseInt(page),
        limit: parseInt(limit),
      });
    });

    app.get("/tuitions", async (req, res) => {
      const email = req.query.email;
      const result = await tuitionsCollection
        .find({ studentEmail: email })
        .toArray();
      res.send(result);
    });

    // Get single tuition
    app.get("/tuitions/:id", async (req, res) => {
      const id = req.params.id;
      const result = await tuitionsCollection.findOne({
        _id: new ObjectId(id),
      });
      res.send(result);
    });

    // Update tuition (student only)
    app.patch("/tuitions/:id", verifyToken, verifyStudent, async (req, res) => {
      const id = req.params.id;
      const update = req.body;
      const result = await tuitionsCollection.updateOne(
        { _id: new ObjectId(id), studentEmail: req.user.email },
        { $set: update }
      );
      res.send(result);
    });

    // Delete tuition (student only)
    app.delete(
      "/tuitions/:id",
      verifyToken,
      verifyStudent,
      async (req, res) => {
        const id = req.params.id;
        const result = await tuitionsCollection.deleteOne({
          _id: new ObjectId(id),
          studentEmail: req.user.email,
        });
        // Also delete related applications
        await applicationsCollection.deleteMany({ tuitionId: id });
        res.send(result);
      }
    );

    // Admin: Approve/Reject Tuition
    app.patch(
      "/admin/tuitions/:id/status",
      verifyToken,
      verifyAdmin,
      async (req, res) => {
        const { status } = req.body; // "approved" or "rejected"
        const result = await tuitionsCollection.updateOne(
          { _id: new ObjectId(req.params.id) },
          { $set: { status } }
        );
        res.send(result);
      }
    );

    // Admin: Get all tuitions (for moderation)
    app.get("/admin/tuitions", verifyToken, verifyAdmin, async (req, res) => {
      const result = await tuitionsCollection.find().toArray();
      res.send(result);
    });

    // Application Routes (Tutor Apply) 

    // Tutor applies to a tuition
    app.post("/applications", verifyToken, verifyTutor, async (req, res) => {
      const application = {
        ...req.body,
        tutorEmail: req.user.email,
        tuitionId: req.body.tuitionId,
        status: "pending", // pending | approved | rejected
        appliedAt: new Date(),
      };

      // Prevent duplicate application
      const exists = await applicationsCollection.findOne({
        tutorEmail: req.user.email,
        tuitionId: req.body.tuitionId,
      });
      if (exists) return res.status(400).send({ message: "Already applied" });

      const result = await applicationsCollection.insertOne(application);
      res.send(result);
    });

    // Get applications for a tuition (Student sees who applied)
    app.get(
      "/applications/tuition/:tuitionId",
      verifyToken,
      verifyStudent,
      async (req, res) => {
        const { tuitionId } = req.params;
        const tuition = await tuitionsCollection.findOne({
          _id: new ObjectId(tuitionId),
          studentEmail: req.user.email,
        });
        if (!tuition)
          return res.status(403).send({ message: "Not your tuition" });

        const result = await applicationsCollection
          .find({ tuitionId })
          .toArray();
        res.send(result);
      }
    );

    // Student: Approve/Reject application
    app.patch(
      "/applications/:id/status",
      verifyToken,
      verifyStudent,
      async (req, res) => {
        const { status } = req.body;
        const appId = req.params.id;

        const application = await applicationsCollection.findOne({
          _id: new ObjectId(appId),
        });

        if (!application)
          return res.status(404).send({ message: "Application not found" });

        // Only the owner of the tuition can approve
        const tuition = await tuitionsCollection.findOne({
          _id: new ObjectId(application.tuitionId),
          studentEmail: req.user.email,
        });
        if (!tuition) return res.status(403).send({ message: "Forbidden" });

        const result = await applicationsCollection.updateOne(
          { _id: new ObjectId(appId) },
          { $set: { status } }
        );

        // If approved → auto reject others (optional)
        if (status === "approved") {
          await applicationsCollection.updateMany(
            {
              tuitionId: application.tuitionId,
              _id: { $ne: new ObjectId(appId) },
            },
            { $set: { status: "rejected" } }
          );
        }

        res.send(result);
      }
    );

    app.get(
      "/applications/my-tuitions",
      verifyToken,
      verifyStudent,
      async (req, res) => {
        const myTuitions = await tuitionsCollection
          .find({ studentEmail: req.user.email }, { projection: { _id: 1 } })
          .toArray();

        const tuitionIds = myTuitions.map((t) => t._id.toString());

        if (tuitionIds.length === 0) return res.send([]);

        const applications = await applicationsCollection
          .find({ tuitionId: { $in: tuitionIds } })
          .toArray();

        res.send(applications);
      }
    );
    app.get("/applications/my", async (req, res) => {
      const email = req.query.email;
      const result = await applicationsCollection
        .find({ studentEmail: email })
        .toArray();
      res.send(result);
    });

    //  Payment Routes (Stripe) 

app.post("/create-payment-intent", async (req, res) => {
  const { price, studentEmail, tutorEmail, tuitionId } = req.body;

  const amount = Math.round(price * 100);

  const paymentIntent = await stripe.paymentIntents.create({
    amount,
    currency: "usd",
    payment_method_types: ["card"],
    metadata: {
      tuitionId,
      studentEmail,
      tutorEmail,
    },
  });

  res.send({
    clientSecret: paymentIntent.client_secret,
  });
});


app.patch("/payment-success", async (req, res) => {
  const sessionId = req.query.session_id;

  const session = await stripe.checkout.sessions.retrieve(sessionId);

  const payment = {
    transactionId: session.payment_intent,
    tuitionId: session.metadata.tuitionId,
    studentEmail: session.metadata.email,
    amount: session.amount_total / 100,
    paidAt: new Date(),
  };

  await paymentsCollection.insertOne(payment);

  res.send({
    transactionId: payment.transactionId,
    trackingId: new ObjectId().toString().slice(-8),
  });
});


    app.post("/payments", async (req, res) => {
      const payment = req.body;

      await paymentsCollection.insertOne(payment);

      await tuitionsCollection.updateOne(
        { _id: new ObjectId(payment.tuitionId) },
        { $set: { status: "paid", hiredTutor: payment.tutorEmail } }
      );

      res.send({ success: true });
    });



    // Get payment history (student/tutor)
    app.get("/payments/my", verifyToken, async (req, res) => {
      const query = {
        $or: [{ studentEmail: req.user.email }, { tutorEmail: req.user.email }],
      };
      const result = await paymentsCollection
        .find(query)
        .sort({ paidAt: -1 })
        .toArray();
      res.send(result);
    });

    // Admin: Reports & Analytics
    app.get("/admin/reports", verifyToken, verifyAdmin, async (req, res) => {
      const totalEarnings = await paymentsCollection
        .aggregate([{ $group: { _id: null, total: { $sum: "$amount" } } }])
        .toArray();

      const transactions = await paymentsCollection
        .find()
        .sort({ paidAt: -1 })
        .toArray();

      res.send({
        totalEarnings: totalEarnings[0]?.total || 0,
        transactionCount: transactions.length,
        transactions,
      });
    });

    const parsePagination = (req) => {
      const page = Math.max(1, parseInt(req.query.page || "1", 10));
      const limit = Math.min(50, parseInt(req.query.limit || "12", 10));
      const skip = (page - 1) * limit;
      return { page, limit, skip };
    };

    // Public: Get tutors (pagination + filters + search) 
    app.get("/tutors", async (req, res) => {
      try {
        const { page, limit, skip } = parsePagination(req);
        const {
          subject,
          district,
          class: className,
          q: search,
          sort,
        } = req.query;

        const query = {};
        if (subject) query.subjectTags = { $in: [subject] };
        if (district) query.district = new RegExp(district, "i");
        if (className) query.classLevels = className;
        if (search) query.$text = { $search: search };

        // only approved tutors
        query.approved = true;

        const sortObj = sort === "rating" ? { rating: -1 } : { createdAt: -1 };

        const [total, tutors] = await Promise.all([
          tutorsCollection.countDocuments(query),
          tutorsCollection
            .find(query)
            .project({ bio: 0, availability: 0 }) // omit heavy fields for list
            .sort(sortObj)
            .skip(skip)
            .limit(limit)
            .toArray(),
        ]);

        res.send({ tutors, total, page, limit });
      } catch (err) {
        console.error("GET /tutors Error:", err);
        res.status(500).send({ message: "Server error" });
      }
    });

    // Public: Get single tutor profile
    app.get("/tutors/:id", async (req, res) => {
      try {
        const id = req.params.id;
        if (!ObjectId.isValid(id))
          return res.status(400).send({ message: "Invalid ID" });
        const tutor = await tutorsCollection.findOne({
          _id: new ObjectId(id),
          approved: true,
        });
        if (!tutor) return res.status(404).send({ message: "Tutor not found" });
        res.send(tutor);
      } catch (err) {
        console.error("GET /tutors/:id Error:", err);
        res.status(500).send({ message: "Server error" });
      }
    });

    // Student Booking: create booking request (student only)
    app.post(
      "/tutors/:id/book",
      verifyToken,
      verifyStudent,
      async (req, res) => {
        try {
          const tutorId = req.params.id;
          if (!ObjectId.isValid(tutorId))
            return res.status(400).send({ message: "Invalid tutor id" });

          const tutor = await tutorsCollection.findOne({
            _id: new ObjectId(tutorId),
            approved: true,
          });
          if (!tutor)
            return res.status(404).send({ message: "Tutor not found" });

          const { subject, message, startAt, duration, price } = req.body;

          if (!startAt || !duration) {
            return res
              .status(400)
              .send({ message: "startAt and duration are required" });
          }

          // basic overlap check (optional) - checks if student already has a booking with same tutor at the same time
          const startDate = new Date(startAt);
          const overlap = await bookingsCollection.findOne({
            tutorId,
            startAt: startDate,
            status: { $in: ["pending", "accepted"] },
          });
          if (overlap) {
            return res
              .status(409)
              .send({ message: "Requested slot already booked or pending" });
          }

          const booking = {
            tutorId,
            tutorEmail: tutor.email || null,
            studentUid: req.user.uid || req.user.email, // depends on your auth
            studentEmail: req.user.email || null,
            subject:
              subject || (tutor.subjectTags && tutor.subjectTags[0]) || "",
            message: message || "",
            startAt: startDate,
            duration,
            price: price || tutor.hourlyRate || 0,
            status: "pending", // pending | accepted | rejected | cancelled
            paymentStatus: "unpaid",
            createdAt: new Date(),
          };

          const result = await bookingsCollection.insertOne(booking);
          res.send({ insertedId: result.insertedId, booking });
        } catch (err) {
          console.error("POST /tutors/:id/book Error:", err);
          res.status(500).send({ message: "Server error" });
        }
      }
    );

    //  Get my bookings (student or tutor) 
    app.get("/bookings/my", verifyToken, async (req, res) => {
      try {
        // if tutor: show bookings where tutorEmail matches (or tutorId for uid)
        // if student: show bookings where studentEmail matches
        const isTutor =
          (await usersCollection.findOne({ email: req.user.email }))?.role ===
          "tutor";
        const query = isTutor
          ? { tutorEmail: req.user.email }
          : { studentEmail: req.user.email };

        const bookings = await bookingsCollection
          .find(query)
          .sort({ createdAt: -1 })
          .toArray();
        res.send(bookings);
      } catch (err) {
        console.error("GET /bookings/my Error:", err);
        res.status(500).send({ message: "Server error" });
      }
    });

    // Messaging: send message to tutor (authenticated)
    app.post("/tutors/:id/message", verifyToken, async (req, res) => {
      try {
        const tutorId = req.params.id;
        if (!ObjectId.isValid(tutorId))
          return res.status(400).send({ message: "Invalid tutor id" });

        const { text, bookingId } = req.body;
        if (!text || !text.trim())
          return res.status(400).send({ message: "Message text required" });

        // store message
        const message = {
          tutorId,
          bookingId: bookingId || null,
          senderUid: req.user.uid || req.user.email,
          senderEmail: req.user.email || null,
          text: text.trim(),
          timestamp: new Date(),
        };

        const result = await messagesCollection.insertOne(message);
        res.send({ insertedId: result.insertedId, message });
      } catch (err) {
        console.error("POST /tutors/:id/message Error:", err);
        res.status(500).send({ message: "Server error" });
      }
    });

    // Fetch messages for a tutor or booking 
    
    app.get("/messages", verifyToken, async (req, res) => {
      try {
        const { tutorId, bookingId, limit = 50 } = req.query;
        const q = {};
        if (bookingId) q.bookingId = bookingId;
        else if (tutorId) q.tutorId = tutorId;
        else
          return res
            .status(400)
            .send({ message: "tutorId or bookingId required" });

        const messages = await messagesCollection
          .find(q)
          .sort({ timestamp: 1 })
          .limit(Math.min(200, parseInt(limit, 10)))
          .toArray();

        res.send(messages);
      } catch (err) {
        console.error("GET /messages Error:", err);
        res.status(500).send({ message: "Server error" });
      }
    });

    //  Admin: Approve tutor (example) 
    app.patch(
      "/admin/tutors/:id/approve",
      verifyToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const id = req.params.id;
          if (!ObjectId.isValid(id))
            return res.status(400).send({ message: "Invalid id" });
          const result = await tutorsCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: { approved: true } }
          );
          res.send(result);
        } catch (err) {
          console.error("PATCH /admin/tutors/:id/approve Error:", err);
          res.status(500).send({ message: "Server error" });
        }
      }
    );

    //  Health Check 
    app.get("/", (req, res) => {
      res.send("eTuitionBD Server is Running!");
    });
  } catch (error) {
    console.error("DB Connection Failed:", error);
  }
}

run().catch(console.dir);

app.listen(port, () => {
  console.log(`eTuitionBD Server running on port ${port}`);
});
