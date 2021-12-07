import express from "express"
import { MongoClient } from "mongodb"
import jwt from "jsonwebtoken"
import { ObjectId } from "bson";
import bcrypt from "bcrypt"
import nodemailer from "nodemailer"
import dotenv from "dotenv"

dotenv.config()
const app = express()
const PORT = process.env.PORT

app.use(express.json())

const JWT_SECRET = process.env.JWT_SECRET

const MONGO_URL = process.env.MONGO_URL

async function createConnection() {
    const client = new MongoClient(MONGO_URL)
    await client.connect()
    console.log("Mongodb connected!")
    return client
}
export const client = await createConnection()

app.get("/", async (request, response) => {
    const users = await client.db("stack-overflow").collection("users").find({}).toArray()
    const questionsdata = await client.db("stack-overflow").collection("questionsdata").find({}).toArray()
    response.send({ users, questionsdata })
})

app.get("/companies", async (request, response) => {
    const companies = await client.db("stack-overflow").collection("companies").find({}).toArray()
    response.send(companies)
})
app.post("/companies", async (request, response) => {
    const data = request.body
    const companies = await client.db("stack-overflow").collection("companies").insertMany(data)
    response.send(companies)
})
app.post("/ask-question", async (request, response) => {
    const data = request.body
    const companies = await client.db("stack-overflow").collection("companies").insertMany(data)
    response.send(companies)
})

app.post("/add-user", async (request, response) => {
    const data = request.body
    const result = await client.db("reset-password").collection("users").insertOne(data)
    response.send(result)
})

app.post("/signup", async (request, response) => {
    const { username, password } = request.body

    const userFormDB = await client.db("reset-password").collection("users").findOne({ username: username })
    if (userFormDB) {
        response.status(400).send({ message: "username already exists" })
        return
    }
    if (password.length < 8) {
        response.status(400).send({ message: "password must be longer" })
    }
    if (!/^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@!#%&]).{8,}$/g.test(password)) {
        response.status(400).send({ message: "password pattern doesn't match" })
    }

    const hashedPassword = await genPassword(password)
    const result = await createUser({ username, password: hashedPassword })
    response.send(result)
})


app.post("/login", async (request, response) => {
    const { username, password } = request.body

    //check for username
    const userFormDB = await client.db("reset-password").collection("users").findOne({ username: username })
    if (!userFormDB) {
        response.status(401).send({ message: "Invalid credentials" })
        return
    }

    //if password is match then
    const storedPassword = userFormDB.password

    const isPasswordMatch = await bcrypt.compare(password, storedPassword)
    if (isPasswordMatch) {
        const token = jwt.sign({ id: userFormDB._id }, JWT_SECRET) //hide secret key
        response.send({ message: "successful login", token: token })
    } else {
        response.status(401).send({ message: "Invalid credentials" })
    }
    response.send(isPasswordMatch)
})

app.post("/forgot-password", async (request, response) => {
    const { username } = request.body

    const user = await client.db("reset-password").collection("users").findOne({ username: username })
    if (!user) {
        response.send("User not found")
        return
    }

    const secret = JWT_SECRET + user.password
    const payload = {
        username: user.username,
        id: user._id
    }
    const token = jwt.sign(payload, secret, { expiresIn: '15m' })
    const link = `http://localhost:8000/reset-password/${user._id}/${token}`
    console.log(link)
    sendLink(link, user.username)
    const insertToken = await client.db("reset-password").collection("users").updateOne({ _id: ObjectId(user._id) }, { $set: { token } })
    console.log({ token })
    response.send("link has been sent to ur email")
})
app.get("/reset-password/:id/:token", async (request, response) => {
    const { id, token } = request.params
    // response.send(request.params)
    const user = await client.db("reset-password").collection("users").findOne({ token: token })
    if (!user) {
        response.send("Invalid id")
        return
    }
    console.log(user)
    const secret = JWT_SECRET + user.password
    try {
        const payload = jwt.verify(token, secret)
        response.send(user.username)
    }
    catch (error) {
        console.log(error.message)
        response.send(error.message)
    }
})
app.post("/reset-password/:id/:token", async (request, response) => {
    const { id, token } = request.params
    const data = request.body
    let { password, password2 } = request.body
    const user = await client.db("reset-password").collection("users").findOne({ _id: ObjectId(id) })
    if (!user) {
        response.send("Invalid id")
        return
    }
    const secret = JWT_SECRET + user.password

    try {
        if (password.length < 8) {
            response.status(400).send({ message: "password must be longer" })
            return
        }
        if (!/^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@!#%&]).{8,}$/g.test(password)) {
            response.status(400).send({ message: "password pattern doesn't match" })
            return
        }
        async function genPassword(pwd) {
            const NO_OF_ROUNDS = 10
            const salt = await bcrypt.genSalt(NO_OF_ROUNDS)
            const password = await bcrypt.hash(pwd, salt)
            return { password }
        }
        password = await genPassword(password)
        console.log(password)
        const payload = jwt.verify(token, secret)
        const x = await client.db("reset-password").collection("users").updateOne({ _id: ObjectId(id) }, { $set: password })
        // user.password = password
        const deleteToken = await client.db("reset-password").collection("users").updateOne({ _id: ObjectId(id) }, { $unset: { token: 1 } })
        response.send(x)
    }
    catch (error) {
        console.log(error.message)
        response.send("Invalid link")
    }
})


function sendLink(link, toUser) {
    
    let transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL, // TODO: your gmail account
            pass: process.env.PASSWORD // TODO: your gmail password
        }
    });

    
    let mailOptions = {
        from: process.env.EMAIL, // TODO: email sender
        to: toUser, // TODO: email receiver
        subject: 'Reset your password',
        text: link
    };

    
    transporter.sendMail(mailOptions, (err, data) => {
        if (err) {
            return 'Error occurs'
        }
        return 'Email sent!!!'
    });
}


app.listen(PORT, () => console.log("App started in ", PORT))