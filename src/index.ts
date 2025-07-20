import dotenv from "dotenv";
dotenv.config();

import cors from "cors";
import express, { Request, Response } from "express";
import dashboardRoute from "./routes/dashboardRoute";

const ORIGIN = process.env.ORIGIN;
const PORT = process.env.PORT;

const allowedOrigins = [ORIGIN].filter(Boolean);

const app = express();

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        console.warn(`CORS blocked request from ${origin}`);
        callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true,
    exposedHeaders: ["Access-Control-Allow-Origin"], // Ensure headers are exposed
  })
);

// Add middleware to explicitly set CORS headers for all responses
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && allowedOrigins.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  }
  res.setHeader("Access-Control-Allow-Credentials", "true");
  next();
});

app.use(express.json());

//Routes
app.use("/dashboard", dashboardRoute);

app.get("/", (req: Request, res: Response) => {
  res.send("Backend!");
});

app.listen(PORT, () => {
  console.log(`Server is running on: ${PORT}`);
});
