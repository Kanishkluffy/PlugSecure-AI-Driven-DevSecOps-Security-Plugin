import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import userRoutes from "./routes/user.routes";

dotenv.config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
// Routes

app.use("/api/security", userRoutes);

export default app;
