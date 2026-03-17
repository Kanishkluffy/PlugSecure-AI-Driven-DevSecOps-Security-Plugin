import mongoose from "mongoose";
import { readlinkSync } from "node:fs";
import { title } from "node:process";

const banditSchema = new mongoose.Schema({
    issue_number: { type: Number, required: true },
    filename: { type: String, required: true },
    line_number: { type: Number, required: true },
    issue_text: { type: String, required: true },
    issue_severity: { type: String, required: true },
    issue_confidence: { type: String, required: true },
    scan_id: { type: String, required: true }, 
});

banditSchema.index({ scan_id: 1, issue_number: 1 }, { unique: true });

const trivySchema = new mongoose.Schema({
    VulNumber: { type: Number, required: true },
    PkgName: { type: String, required: true },
    InstalledVersion: { type: String, required: true },
    FixedVersion: { type: String, required: true },
    Title: { type: String, required: true },
    Description: { type: String, required: true },
    Severity: { type: String, required: true },
    scan_id: { type: String, required: true },
    cve_id: { type: String, required: true },
    cvss_score: { type: Number, required: true },
    epss_score: { type: Number},
    epss_percentile: { type: Number},
});

trivySchema.index({ scan_id: 1, VulNumber: 1 }, { unique: true });

const riskSchema = new mongoose.Schema({
    scan_id: { type: String, required: true },
    source:{
        type: String,
        enum: ['bandit', 'trivy'],
        required: true
    },
    vulnerability_id: { type: String, required: false },
    title: { type: String, required: true },
    severity:{ type: String, required: true },
    cvss_score: { type: Number, required: true },
    epss_score: { type: Number, required: true },
    risk_score: { type: Number, required: true },
    metadata : { type:Object}
});

export const Bandit = mongoose.model("Bandit", banditSchema);
export const Trivy = mongoose.model("Trivy", trivySchema);
export const Risk = mongoose.model("Risk", riskSchema);