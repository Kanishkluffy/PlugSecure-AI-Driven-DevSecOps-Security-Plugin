import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { exec } from "child_process";
import * as http from 'http';

interface BanditIssue {
    issue_number: number;
    // filename: string;
    // line_number: number;
    issue_text: string;
    issue_severity: string;
    issue_confidence: string;
    scan_id: string;
    // code: string;
    metadata: {
        filename: string;
        line_number: number;
        code: string;
    }
}

interface TrivyVulnerability {
    VulNumber: number;
    // PkgName: string;
    // InstalledVersion: string;
    // FixedVersion: string;
    Severity: string;
    Title: string;
    Description: string;
    scan_id: string;
    cve_id: string;
    cvss_score:number;
    metadata: {
        PkgName: string;
        InstalledVersion: string;
        FixedVersion: string;
    }
}

interface RiskScore {
    scan_id: string;
    source: 'bandit' | 'trivy';
    vulnerability_id: string;
    title: string;
    severity: string;
    cvss_score: number;
    epss_score: number;
    risk_score: number;
    metadata: any;
    description: string;
}

const baseUrl = 'http://localhost:3000';

let globalRiskScores: RiskScore[] = [];

export function activate(context: vscode.ExtensionContext) {

    const disposable = vscode.commands.registerCommand(
        'plugsecure.scanProject',
        async () => {
            const workspaceFolders = vscode.workspace.workspaceFolders;

            if(!workspaceFolders){
                vscode.window.showErrorMessage('No workspace folder is open.');
                return;
            }


            const projectPath = workspaceFolders[0].uri.fsPath;

            const projectName = path.basename(projectPath);
            const scanId = await createScanSession(context, projectName);

            const projectType = detectProjectType(projectPath);

            if (projectType !== 'unknown') {
                scanProject(projectPath, projectType, context, scanId);
            } else {
                vscode.window.showWarningMessage(
                    'Could not detect the project type.'
                );
            }
        }
    );

    const signupCommand = vscode.commands.registerCommand(
        'plugsecure.signup',
        async () => {
            const username = await vscode.window.showInputBox({
                prompt: 'Enter your username for PlugSecure login',
            });
            const email = await vscode.window.showInputBox({
                prompt: 'Enter your email for PlugSecure login',
            });

            const password = await vscode.window.showInputBox({
                prompt: 'Enter your password',
                password: true
            });

            if(!email || !password || !username){
                vscode.window.showErrorMessage('All fields are required for login.');
                return;
            }

            signupUser(email, password, username);
        }
    );
    
    const loginCommand = vscode.commands.registerCommand(
        'plugsecure.login',
        async () => {
            const username = await vscode.window.showInputBox({
                prompt: 'Enter your username for PlugSecure login',
            });

            const password = await vscode.window.showInputBox({
                prompt: 'Enter your password',
                password: true
            });

            if(!password || !username){
                vscode.window.showErrorMessage('All fields are required for login.');
                return;
            }

            loginUser(password, username, context);
        }
    );

    const logoutCommand = vscode.commands.registerCommand(
        'plugsecure.logout',
        async () => {
            await context.globalState.update('userSession', undefined);
            vscode.window.showInformationMessage('Logged out successfully.');
        }
    );

    context.subscriptions.push(disposable);
    context.subscriptions.push(signupCommand);
    context.subscriptions.push(loginCommand);
    context.subscriptions.push(logoutCommand);
}

async function createScanSession(context: vscode.ExtensionContext, projectName: string): Promise<string> {

    const session = context.globalState.get<{ token: string, username: string }>("userSession");

    if(!session){
        vscode.window.showErrorMessage('No authentication token found. Please login first.');
        return '';
    }

    const postData = JSON.stringify({username: session.username, projectName});

    const options = {
        hostname: 'localhost',
        port: 3000,
        path: '/api/auth/create-scan',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(postData),
        }
    };

    return new Promise((resolve) => {
        const req = http.request(options, (res) => {

            let body = '';

            res.on('data', (chunk) => {
                body += chunk.toString();
            });

            res.on('end', async () => {
                if (res.statusCode === 200 || res.statusCode === 201) {
                    const data = JSON.parse(body);
                    vscode.window.showInformationMessage('Scan session created successfully.');
                    resolve(data.scan_id || '');
                } else {
                    vscode.window.showErrorMessage('Failed to create scan session.');
                    resolve('');
                }
            });
        });

        req.on('error', (error) => {
            vscode.window.showErrorMessage(`Error creating scan session: ${error.message}`);
            resolve('');
        });

        req.write(postData);
        req.end();
    });
}

function signupUser(email:string, password:string, username:string) {

    const postData = JSON.stringify({ email, password, username });

    const options ={
        hostname: 'localhost',
        port: 3000,
        path: '/api/auth/signup',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(postData),
        }
    };

    const req = http.request(options, (res)=>{

        let body = '';

        res.on('data', (chunk) => {
            body += chunk.toString();
        });

        res.on('end', async () =>{
            if(res.statusCode === 201){
                vscode.window.showInformationMessage('Signup successful!');
            } else {
                vscode.window.showErrorMessage('Signup failed. Please check your credentials.');
            }
        });
    });

    req.on('error', (error) => {
        vscode.window.showErrorMessage(`Signup error: ${error.message}`);
    });

    req.write(postData);
    req.end();
}

async function loginUser(password:string, username:string, context: vscode.ExtensionContext) {

    const postData = JSON.stringify({ password, username });

    const isAlreadyLoggedIn = await checkUserLoggedIn(username, context);

    if(isAlreadyLoggedIn){
        vscode.window.showInformationMessage(`User ${username} is already logged in.`);
        return;
    }

    const options ={
        hostname: 'localhost',
        port: 3000,
        path: '/api/auth/login',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(postData),
        }
    };

    const req = http.request(options, (res)=>{

        let body = '';

        res.on('data', (chunk) => {
            body += chunk.toString();
        });

        res.on('end', async () =>{
            const data = JSON.parse(body);

            if(res.statusCode === 200 && data.token){
                await context.globalState.update('userSession',{
                        token: data.token,
                        username: data.username
                });

                vscode.window.showInformationMessage('Login successful!');
            } else {
                vscode.window.showErrorMessage('Please check your credentials or User does not exist.');
            }
        });
    });

    req.on('error', (error) => {
        vscode.window.showErrorMessage(`Login error: ${error.message}`);
    });``

    req.write(postData);
    req.end();
}

function checkUserLoggedIn(
    username: string,
    context: vscode.ExtensionContext
){

    const session = context.globalState.get<{ token: string, username: string }>("userSession");

    if (!session || session.username !== username) {
        return false;
    }

    return new Promise((resolve) => {

        const options = {
            hostname: 'localhost',
            port: 3000,
            path: '/api/auth/check-login',
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${session.token}`
            }
        };

        const req = http.request(options, (res) => {

            let body = '';

            res.on('data', (chunk) => body += chunk.toString());

            res.on('end', () => {

                try {
                    const data = JSON.parse(body);

                    if (res.statusCode === 200 && data.loggedIn) {
                        resolve(true);
                    } else {
                        resolve(false);
                    }

                } catch {
                    resolve(false);
                }
            });
        });

        req.on('error', () => resolve(false));

        req.end();
    });
}

function detectProjectType(projectPath:string): 'flask' | 'python' | 'unknown' {
    const files = fs.readdirSync(projectPath);
    
    //Python project indicators
    const pythonFiles = files.some(file => file.endsWith('.py'));
    const requirementsTxt = files.includes('requirements.txt');
    const setupPy = files.includes('setup.py');
    const pyprojectToml = files.includes('pyproject.toml');

    //Flask specific detection
    if(pythonFiles){
        for(const file of files){
            if(file.endsWith('.py')){
                const filePath = path.join(projectPath, file);
                const content = fs.readFileSync(filePath, 'utf-8');
                if(content.includes('from flask') || content.includes('import flask')){
                    return 'flask';
                }
            }
        }
    }

    if(pythonFiles || requirementsTxt || setupPy || pyprojectToml){
        return 'python';
    }

    return 'unknown';
}


async function scanProject(
    projectPath: string,
    projectType: "flask" | "python",
    context: vscode.ExtensionContext,
    scanId: string
) {

    const session = context.globalState.get<{ token: string, username: string }>("userSession");

    if(!session){
        vscode.window.showErrorMessage('No user session found. Please login first.');
        return;
    }
    const isAlreadyLoggedIn = await checkUserLoggedIn(session.username, context);

    if(!isAlreadyLoggedIn){
        vscode.window.showInformationMessage(`User Invalid!`);
        return;
    }

    const token = context.globalState.get<{ token: string, username: string }>("userSession")?.token;

    vscode.window.showInformationMessage(
        `Scanning ${projectType.toUpperCase()} project at: ${projectPath}`
    );

    const isWindows = process.platform === "win32";

    const banditPath = isWindows
        ? path.join(projectPath, "bandit-env", "Scripts", "bandit.exe")
        : path.join(projectPath, "bandit-env", "bin", "bandit");

    // STEP 1: Install Bandit if missing
    if (!fs.existsSync(banditPath)) {
        vscode.window.showInformationMessage(
            "Bandit not found. Installing in virtual environment..."
        );

        const installCommand = isWindows
        ? `python -m venv bandit-env && bandit-env\\Scripts\\pip install bandit`
        : `python3 -m venv bandit-env && bandit-env/bin/pip3 install bandit`;

        exec(installCommand, { cwd: projectPath }, (error) => {
            if (error) {
                vscode.window.showErrorMessage(
                    "Failed to install Bandit. Please ensure Python is installed."
                );
                return;
            }

            vscode.window.showInformationMessage(
                "Bandit installed successfully. Please re-run the scan."
            );
        });

        return;
    }

    // STEP 2: Run Bandit scan (JSON output)
    vscode.window.showInformationMessage("Running Bandit security scan...");
    
    const excludeDirs = "venv,bandit-env,__pycache__,.git";
    const scanCommand = `"${banditPath}" -r "${projectPath}" -x "${excludeDirs}" -f json`;
    const outputChannel = vscode.window.createOutputChannel("PlugSecure Scan Results");

    exec(scanCommand, { maxBuffer: 1024 * 1024 }, (error, stdout) => {
        if (error && !stdout) {
            vscode.window.showErrorMessage("Bandit scan failed.");
            return;
        }

        outputChannel.clear();
        outputChannel.show();

        try {
            const jsonStart = stdout.indexOf('{');
            const cleanJson = stdout.slice(jsonStart);

            const result = JSON.parse(cleanJson);
            const issues = result.results;

            if (!issues || issues.length === 0) {
                outputChannel.appendLine("✅ No security issues found.");
                return;
            }
            outputChannel.appendLine('Bandit Security Issue Detected:');
            const banditIssues: BanditIssue[] = [];
            issues.forEach((issue: any, index: number) => {
                const banditIssue: BanditIssue = {
                    issue_number: index + 1,
                    // filename: issue.filename,
                    // line_number: issue.line_number,
                    issue_text: issue.issue_text,
                    issue_severity: issue.issue_severity,
                    issue_confidence: issue.issue_confidence,
                    scan_id: scanId,
                    // code: issue.code || ""
                    metadata: {
                        filename: issue.filename,
                        line_number: issue.line_number,
                        code: issue.code || ""
                    }
                }
                banditIssues.push(banditIssue);
                outputChannel.appendLine(`Issue ${index + 1}`);
                outputChannel.appendLine(`Severity : ${issue.issue_severity}`);
                outputChannel.appendLine(`Confidence: ${issue.issue_confidence}`);
                outputChannel.appendLine(`File     : ${issue.filename}`);
                outputChannel.appendLine(`Line     : ${issue.line_number}`);
                outputChannel.appendLine(`Issue    : ${issue.issue_text}`);
                outputChannel.appendLine(`Code Snippet:\n${issue.code || "N/A"}`);
                outputChannel.appendLine("----------------------------------------\n");
            });
            
            const postData = JSON.stringify({ banditIssues });
            const options = {
                hostname: 'localhost',
                port: 3000,
                path: '/api/security/bandit-results',
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(postData),
                    'Authorization': `Bearer ${token}`
                }
            };

            const req = http.request(options, (res) => {
                if (res.statusCode === 200 || res.statusCode === 201) {
                    vscode.window.showInformationMessage('Bandit issues successfully sent to the backend.');
                } else {
                    vscode.window.showErrorMessage('Failed to send Bandit issues to the backend.');
                }
            });

            req.on('error', (error) => {
                vscode.window.showErrorMessage(`Error sending data: ${error.message}`);
            });

            req.write(postData);
            req.end();
            
        } catch(error) {
            vscode.window.showErrorMessage(`Error parsing Bandit output: ${error instanceof Error ? error.message : 'Unknown error'}`);
            console.error("Bandit Error:", error);

        }
    });

    // STEP 3: Check Trivy
    exec("trivy --version", (error) => {

        if (error) {
            vscode.window.showWarningMessage(
                "Trivy is not installed. Please install Trivy to enable dependency scanning."
            );
            return;
        }

        vscode.window.showInformationMessage(
            "Trivy detected. Running dependency scan..."
        );

        const trivyCommand = `trivy fs --severity HIGH,CRITICAL --format json "${projectPath}"`;

        exec(trivyCommand, { maxBuffer: 1024 * 1024 }, (scanError, stdout) => {

            if (scanError && !stdout) {
                vscode.window.showErrorMessage("Trivy scan failed.");
                return;
            }

            try {
                const result = JSON.parse(stdout);

                outputChannel.appendLine("\nTrivy Dependency Scan Results:\n");

                if (!result.Results || result.Results.length === 0) {
                    outputChannel.appendLine("No HIGH or CRITICAL vulnerabilities found.");
                    return;
                }
                
                const trivyIssues: TrivyVulnerability[] = [];
                let vulCounter = 1;

                result.Results.forEach((res: any) => {
                if (res.Vulnerabilities) {

                    res.Vulnerabilities.forEach((vuln: any) => {

                        const trivyIssue: TrivyVulnerability = {
                            VulNumber: vulCounter,
                            // PkgName: vuln.PkgName,
                            // InstalledVersion: vuln.InstalledVersion,
                            // FixedVersion: vuln.FixedVersion || "N/A",
                            Severity: vuln.Severity,
                            Title: vuln.Title,
                            Description: vuln.Description,
                            scan_id: scanId,
                            cve_id: vuln.VulnerabilityID,
                            cvss_score: vuln.CVSS?.nvd?.V3Score || 0,
                            metadata: {
                                PkgName: vuln.PkgName,
                                InstalledVersion: vuln.InstalledVersion,
                                FixedVersion: vuln.FixedVersion || "N/A",
                            }
                        };

                        trivyIssues.push(trivyIssue);

                        outputChannel.appendLine(`Vulnerability ${vulCounter}`);
                        outputChannel.appendLine(`Package   : ${vuln.PkgName}`);
                        outputChannel.appendLine(`Severity  : ${vuln.Severity}`);
                        outputChannel.appendLine(`Installed : ${vuln.InstalledVersion}`);
                        outputChannel.appendLine(`Fixed     : ${vuln.FixedVersion || "N/A"}`);
                        outputChannel.appendLine(`Title     : ${vuln.Title}`);
                        outputChannel.appendLine(`Description: ${vuln.Description}`);
                        outputChannel.appendLine("--------------------------------------\n");

                        vulCounter++;
                    });

                }
                });

                const postData = JSON.stringify({ trivyIssues });
                const options = {
                    hostname: 'localhost',
                    port: 3000,
                    path: '/api/security/trivy-results',
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Content-Length': Buffer.byteLength(postData),
                        'Authorization': `Bearer ${token}`
                    }
                };

                const req = http.request(options, (res) => {

                    let responseBody = '';

                    res.on('data', (chunk) => {
                        responseBody += chunk.toString();
                    });

                    res.on('end', async () => {

                        if (res.statusCode === 200 || res.statusCode === 201) {

                            vscode.window.showInformationMessage(
                                'Trivy issues successfully sent to the backend.'
                            );

                            const risks = await callRiskEngine(scanId, outputChannel);
                            
                            showQuickPick(risks, outputChannel, context.extensionUri);

                        } else {

                            vscode.window.showErrorMessage(
                                'Failed to send Trivy issues to the backend.'
                            );

                        }

                    });

                });

                req.on('error', (error) => {
                    vscode.window.showErrorMessage(`Error sending data: ${error.message}`);
                });

                req.write(postData);
                req.end();

            } catch(error) {
                vscode.window.showErrorMessage(`Error parsing Trivy output: ${error instanceof Error ? error.message : 'Unknown error'}`);
                console.error("Trivy Error:", error);
            }

        });

    });


}

function callRiskEngine(scanId: string, outputChannel: vscode.OutputChannel): Promise<RiskScore[]> {

    return new Promise((resolve, reject) => {

        const scan_id = scanId;
        const optionsForRisk = {
            hostname: 'localhost',
            port: 3000,
            path: `/api/security/risk-scores/${scan_id}`,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            }
        };

        const reqForRisk = http.request(optionsForRisk, (res) => {

            let body = '';

            res.on('data', (chunk) => {
                body += chunk.toString();
            });

            res.on('end', () => {

                const data = JSON.parse(body);
                const riskScores: RiskScore[] = data.vulnerabilities || [];

                outputChannel.appendLine("\nRisk Scores:\n");

                riskScores.forEach((score) => {
                    outputChannel.appendLine(`Source: ${score.source}`);
                    outputChannel.appendLine(`Vulnerability ID: ${score.vulnerability_id ?? "N/A"}`);
                    outputChannel.appendLine(`Title: ${score.title}`);
                    outputChannel.appendLine(`Severity: ${score.severity}`);
                    outputChannel.appendLine(`CVSS Score: ${score.cvss_score ?? 0}`);
                    outputChannel.appendLine(`EPSS Score: ${score.epss_score ?? 0}`);
                    outputChannel.appendLine(`Risk Score: ${score.risk_score ?? 0}`);
                    outputChannel.appendLine(`Description: ${score.description ?? "N/A"}`);
                    outputChannel.appendLine(`Metadata: ${JSON.stringify(score.metadata)}`);
                    outputChannel.appendLine("--------------------------------------\n");
                });

                resolve(riskScores);
            });
        });

        reqForRisk.on('error', (error) => {
            vscode.window.showErrorMessage(`Error fetching risk scores: ${error.message}`);
            reject(error);
        });

        reqForRisk.end();
    });
}

function showQuickPick(risks: RiskScore[], outputChannel: vscode.OutputChannel, extensionUri: vscode.Uri){
    const risksBase64 = Buffer.from(JSON.stringify(risks), "utf8").toString("base64");
    const nonce = getNonce();

    const panel = vscode.window.createWebviewPanel(
        'riskResults',
        'Risk Results',
        vscode.ViewColumn.One,
        {
            enableScripts: true
        }
    );

    const htmlPath = path.join(extensionUri.fsPath, 'media', 'index.html');
    let htmlContent = fs.readFileSync(htmlPath, 'utf-8');

    const cssUri = panel.webview.asWebviewUri(
        vscode.Uri.joinPath(extensionUri, 'media', 'styles.css')
    );
    const scriptUri = panel.webview.asWebviewUri(
        vscode.Uri.joinPath(extensionUri, 'media', 'script.js')
    );

    htmlContent = htmlContent.replace(/%%RISKS_DATA%%/g, risksBase64);
    htmlContent = htmlContent.replace(/%%CSS_URI%%/g, cssUri.toString());
    htmlContent = htmlContent.replace(/%%SCRIPT_URI%%/g, scriptUri.toString());
    htmlContent = htmlContent.replace(/%%CSP_SOURCE%%/g, panel.webview.cspSource);
    htmlContent = htmlContent.replace(/%%NONCE%%/g, nonce);

    panel.webview.html = htmlContent;

    panel.webview.onDidReceiveMessage(async message => {
        if(message.command === "getSuggestion"){
            const risk = message.risk;
            const suggestion = await fetchAISuggestion(risk);
            

            panel.webview.postMessage({command: "showSuggestion", suggestion: suggestion});
        }
    });
}

async function fetchAISuggestion(risk: any): Promise<string> {

    const res = await fetch(`${baseUrl}/api/security/ai-suggestion`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ risk })
    });

    if(res.ok){
        const data = await res.json() as { suggestion?: string };
        console.log("AI Suggestion Response:", data);
        return data.suggestion || "No suggestion available.";
    } else {
        return "Failed to fetch AI suggestion.";
    }
}

function getNonce() {
    let text = "";
    const possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    for (let i = 0; i < 32; i++) {
        text += possible.charAt(Math.floor(Math.random() * possible.length));
    }

    return text;
}

export function deactivate() {}