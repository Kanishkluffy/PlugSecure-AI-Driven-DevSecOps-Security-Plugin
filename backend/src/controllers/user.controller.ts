import {Request, Response} from 'express';
import {Bandit, Risk, Trivy} from '../models/user.model';
import { runRiskEngine } from './riskEngine';

export interface BanditIssue {
    issue_number: number;
    filename: string;
    line_number: number;
    issue_text: string;
    issue_severity: string;
    issue_confidence: string;
    scan_id: string;
}

export interface TrivyIssue {
    VulNumber: number;
    PkgName: string;
    InstalledVersion: string;
    FixedVersion: string;
    Title: string;
    Description: string;
    Severity: string;
    scan_id: string;
    cve_id: string;
    cvss_score: number;
    epss_score: number;
    epss_percentile: number;
}

export const savebanditIssues = async (req: Request, res: Response) => {
    try {
        const banditIssues: BanditIssue[] = req.body.banditIssues;
        await Bandit.insertMany(banditIssues);

        res.status(201).json({
            message: 'Bandit issues saved successfully'
        });

    } catch (error) {

        console.error('Error saving Bandit issues:', error);

        res.status(500).json({
            message: 'Failed to save Bandit issues'
        });
    }
};

export const savetrivyIssues = async (req: Request, res: Response) => {

    try {

        const trivyIssues: TrivyIssue[] = req.body.trivyIssues;

        await Trivy.insertMany(trivyIssues);

        for (const issue of trivyIssues) {

            const cveId = issue.cve_id;

            if (!cveId) continue;

            const response = await fetch(`https://api.first.org/data/v1/epss?cve=${cveId}`);
            const data = await response.json();

            const epssScore = Number(data.data?.[0]?.epss || 0);
            const epssPercentile = Number(data.data?.[0]?.percentile || 0);

            await Trivy.updateOne(
                { VulNumber: issue.VulNumber, scan_id: issue.scan_id },
                {
                    $set: {
                        epss_score: epssScore,
                        epss_percentile: epssPercentile
                    }
                }
            );
        }

        // ONLY respond after EPSS enrichment is done
        res.status(201).json({
            message: "Trivy issues saved with EPSS enrichment"
        });

    } catch (error) {

        console.error(error);

        res.status(500).json({
            message: "Failed to save Trivy issues"
        });

    }

};

export const calculateRiskForScan = async (req: Request, res: Response) => {

    const scanId = req.params.scanId as string;

    try {

        const trivyCheck = await Trivy.find({ scan_id: scanId }).lean();
        const results = await runRiskEngine(scanId);

        await Risk.insertMany(results);

        res.json({
            message: "Risk analysis completed",
            vulnerabilities: results
        });

    } catch (error) {

    res.status(500).json({
        error: error instanceof Error ? error.message : String(error)
    });

    }
};



