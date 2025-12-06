import express from 'express';
import dotenv from 'dotenv';
import mongodb, { MongoClient, ObjectId } from 'mongodb';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
dotenv.config();
const app = express()
const port = process.env.PORT || "3000";
const client = new MongoClient(process.env.DATABASE_URL);

app.use(express.json());

const verifyToken = (req, res, next) => {
    const token = req?.headers?.authorization || undefined;
    if (!token) {
        return res.status(400).json({
            message: "Your are not authorized"
        })
    }

    jwt.verify(token, "qwertyuoosklsf", (err, decodedData) => {
        if (err) {
            return res.status(400).json({
                message: "Your are not authorized",
                err
            })
        }

        req.user = decodedData;
        next()
    })
}

async function run() {
    try {
        await client.connect();
        console.log("Database connected!!!");

        const db = client.db("backend_session");
        const usersCollection = db.collection("users");

        app.post("/register", async (req, res) => {
            try {
                const { name, email, password } = req.body;

                const existing = await usersCollection.findOne({
                    email
                })
                if (existing) {
                    return res.status(409).json({
                        message: "Email already exists"
                    });
                }

                const hashedPassword = await bcrypt.hash(password, 10);

                const result = await usersCollection.insertOne({
                    name,
                    email,
                    password: hashedPassword
                });
                res.status(201).json({
                    message: "User created successfully!",
                    result
                })
            } catch (err) {
                res.status(400).json({
                    message: "Failed to create user!",
                    err
                })
            }
        })

        app.post("/login", async (req, res) => {
            try {
                const { email, password } = req.body;
                const user = await usersCollection.findOne({
                    email
                })

                const isMatchedPassword = await bcrypt.compare(password, user.password);

                if (!isMatchedPassword) {
                    return res.status(400).json({
                        message: "Password incorrect!"
                    });
                }

                const token = jwt.sign({
                    email: user.email,
                    _id: user._id
                }, "qwertyuoosklsf", { expiresIn: "3h" })


                res.status(200).json({
                    message: "Logged in successfully!",
                    token
                })

            } catch (err) {
                res.status(400).json({
                    message: "Login failed!",
                    err
                })
            }
        })

        app.get("/me", verifyToken, async (req, res) => {
            try {
                const user = req.user;
                const userData = await usersCollection.findOne({
                    _id: new ObjectId(user._id)
                }, {
                    projection: { password: 0 }
                })

                res.status(200).json(userData);
            } catch (err) {
                res.status(400).json({
                    message: "Failed to fetch profile data!",
                    err
                })
            }
        })
    } catch (err) {
        console.error(err)
    }
}

run().catch(console.dir);

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})
