import "dotenv/config";
import express from "express";
import bodyParser from "body-parser";
import mongoose from "mongoose";
import middleware from "./middleware/middleware.js";
import authRoute from "./routes/auth.route.js"

const app = express();

//memanggil port dari .env
const port = process.env.PORT || 3000

//membatasi ukuran payload
app.use(bodyParser.json({limit: '30mb', extended: true}));
app.use(bodyParser.urlencoded({limit: '30mb', extended: true}));

//call router
app.use("/auth",authRoute)

//ErrorHandler Middleware
app.use(middleware.errorHandler)
app.use(middleware.notFound)

//setup connect to mongodb
const connect = async() => {
    try {
        mongoose.connect(process.env.MONGO_URL)
        console.log("Connected on mongodb");
    } catch (err) {
        console.log(err);
    }
}

app.listen(port, ()=> {
    connect();
    console.log(`Server listening on ${port}`);
})
