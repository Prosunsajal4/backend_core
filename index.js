import express from "express";
import dotenv from "dotenv";
import { MongoClient, ObjectId } from "mongodb";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
dotenv.config();
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret";
const app = express();
const port = process.env.PORT || "3000";
const client = new MongoClient(process.env.DATABASE_URL);

app.use(express.json());

const verifyToken = (req, res, next) => {
  const authHeader = req.headers && req.headers.authorization;
  const token =
    authHeader && authHeader.startsWith("Bearer ")
      ? authHeader.split(" ")[1]
      : authHeader;
  if (!token) {
    return res.status(401).json({ message: "Not authorized" });
  }

  jwt.verify(token, JWT_SECRET, (err, decodedData) => {
    if (err) {
      console.error("JWT verify error:", err);
      return res.status(401).json({ message: "Invalid token" });
    }

    req.user = decodedData;
    next();
  });
};

async function run() {
  try {
    await client.connect();
    console.log("Database connected!!!");

    const db = client.db("backend_core");
    const usersCollection = db.collection("users");

    app.get("/", (req, res) => {
      res.send("Hello World!");
    });

    app.post("/register", async (req, res) => {
      try {
        const { name, email, password } = req.body || {};
        if (!name || !email || !password) {
          return res
            .status(400)
            .json({ message: "Missing name, email or password" });
        }

        const existing = await usersCollection.findOne({ email });
        if (existing) {
          return res.status(409).json({ message: "Email already exists" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const result = await usersCollection.insertOne({
          name,
          email,
          password: hashedPassword,
        });
        res.status(201).json({ message: "User created successfully!", result });
      } catch (err) {
        console.error("Register error:", err);
        res.status(500).json({ message: "Failed to create user" });
      }
    });

    app.post("/login", async (req, res) => {
      try {
        const { email, password } = req.body || {};
        if (!email || !password) {
          return res.status(400).json({ message: "Missing email or password" });
        }

        const user = await usersCollection.findOne({ email });
        if (!user) {
          return res.status(404).json({ message: "User not found" });
        }

        const isMatchedPassword = await bcrypt.compare(password, user.password);
        if (!isMatchedPassword) {
          return res.status(401).json({ message: "Password incorrect" });
        }

        const token = jwt.sign(
          { email: user.email, _id: user._id },
          JWT_SECRET,
          { expiresIn: "3h" }
        );

        res.status(200).json({ message: "Logged in successfully!", token });
      } catch (err) {
        console.error("Login error:", err);
        res.status(500).json({ message: "Login failed" });
      }
    });

    app.get("/me", verifyToken, async (req, res) => {
      try {
        const user = req.user;
        const userData = await usersCollection.findOne(
          { _id: new ObjectId(user._id) },
          { projection: { password: 0 } }
        );
        if (!userData)
          return res.status(404).json({ message: "User not found" });
        res.status(200).json(userData);
      } catch (err) {
        console.error("Fetch profile error:", err);
        res.status(500).json({ message: "Failed to fetch profile data" });
      }
    });
  } catch (err) {
    console.error(err);
  }
}

run().catch(console.dir);

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
