import {Bandit, Trivy} from '../models/user.model';

const severityWeight: Record<string, number> = {
  LOW: 3,
  MEDIUM: 6,
  HIGH: 9,
  CRITICAL: 10
};

const banditRiskMap: Record<string, number> = {
    LOW: 4,
    MEDIUM: 6,
    HIGH: 8
};

function calculateRisk(cvss: number, epss: number, severityScore: number) {
    return (0.5 * cvss) + (0.3 * (epss * 10)) + (0.2 * severityScore);
}

export const runRiskEngine = async (scanId: string) => {
    const banditResults = await Bandit.find({ scan_id: scanId });
    const trivyResults = await Trivy.find({ scan_id: scanId }).lean();

    const riskEntries: any[] = [];

    for (const issue of banditResults) {

        const riskScore = banditRiskMap[issue.issue_severity.toUpperCase()] || 3;

        riskEntries.push({
            scan_id: scanId,
            source: "bandit",
            title: issue.issue_text,
            severity: issue.issue_severity,
            cvss_score: 0,
            epss_score: 0,
            risk_score: riskScore,
            metadata: {
                filename: issue.filename,
                line: issue.line_number
            }
        });
    }

    //Trivy issues

    for (const vuln of trivyResults) {
        const severityScore =
        severityWeight[vuln.Severity.toUpperCase()] || 1;

        const riskScore = calculateRisk(
            vuln.cvss_score || 0,
            vuln.epss_score || 0,
            severityScore
        );

        riskEntries.push({
            scan_id: scanId,
            source: "trivy",
            vulnerability_id: vuln.cve_id,
            title: vuln.Title,
            severity: vuln.Severity,
            cvss_score: vuln.cvss_score,
            epss_score: vuln.epss_score,
            risk_score: riskScore,
            metadata: {
                package: vuln.PkgName,
                installed: vuln.InstalledVersion,
                fixed: vuln.FixedVersion
            }
        });
    }

    const sorted = riskEntries.sort(
        (a, b) => b.risk_score - a.risk_score
    );

    return sorted;
};