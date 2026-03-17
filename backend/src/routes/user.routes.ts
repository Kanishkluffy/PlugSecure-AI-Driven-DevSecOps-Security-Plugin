import express from "express";
import { savebanditIssues, savetrivyIssues, calculateRiskForScan } from "../controllers/user.controller";

const router = express.Router();

router.post("/bandit-results", savebanditIssues);
router.post("/trivy-results", savetrivyIssues);
router.post("/risk-scores/:scanId", calculateRiskForScan);

export default router;