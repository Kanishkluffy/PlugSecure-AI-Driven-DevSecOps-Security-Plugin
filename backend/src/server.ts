import dotenv from "dotenv";
import app from "./app";
import { connectDB } from "./config/db";
import http from "http";

dotenv.config();

const PORT = process.env.PORT || 5000;

const server = http.createServer(app);

connectDB()

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});