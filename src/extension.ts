import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { exec } from "child_process";


export function activate(context: vscode.ExtensionContext) {

    const disposable = vscode.commands.registerCommand(
        'plugsecure.scanProject',
        () => {

            const workspaceFolders = vscode.workspace.workspaceFolders;

            if(!workspaceFolders){
                vscode.window.showErrorMessage('No workspace folder is open.');
                return;
            }

            const projectPath = workspaceFolders[0].uri.fsPath;

            const projectType = detectProjectType(projectPath);

            if (projectType !== 'unknown') {
                scanProject(projectPath, projectType);
            } else {
                vscode.window.showWarningMessage(
                    'Could not detect the project type.'
                );
            }
        }
    );

    context.subscriptions.push(disposable);
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


export function scanProject(
    projectPath: string,
    projectType: "flask" | "python"
) {

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
            : `python -m venv bandit-env && bandit-env/bin/pip install bandit`;

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
    const scanCommand = `"${banditPath}" -r "${projectPath}" -x "${excludeDirs}" -f json`
    const outputChannel = vscode.window.createOutputChannel("PlugSecure Scan Results");

    exec(scanCommand, { maxBuffer: 1024 * 1024 }, (error, stdout) => {
        if (error && !stdout) {
            vscode.window.showErrorMessage("Bandit scan failed.");
            return;
        }

        outputChannel.clear();
        outputChannel.show();

        try {
            const result = JSON.parse(stdout);
            const issues = result.results;

            if (!issues || issues.length === 0) {
                outputChannel.appendLine("✅ No security issues found.");
                return;
            }
            outputChannel.appendLine('Bandit Security Issue Detected:');
            issues.forEach((issue: any, index: number) => {
                outputChannel.appendLine(`Issue ${index + 1}`);
                outputChannel.appendLine(`Severity : ${issue.issue_severity}`);
                outputChannel.appendLine(`Confidence: ${issue.issue_confidence}`);
                outputChannel.appendLine(`File     : ${issue.filename}`);
                outputChannel.appendLine(`Line     : ${issue.line_number}`);
                outputChannel.appendLine(`Issue    : ${issue.issue_text}`);
                outputChannel.appendLine("----------------------------------------\n");
            });
        } catch {
            outputChannel.appendLine(stdout);
        }
    });

    //STEP 3: Install Trivy If missing


    //STEP 4: Check for Dockerfile and run Trivy scan
    
    // const dockerfilePath = path.join(projectPath, "Dockerfile");
    // if (fs.existsSync(dockerfilePath)) {
    //     vscode.window.showInformationMessage("Dockerfile detected. Running Trivy container scan...");
    //     //get image name from dockerfile
    //     const dockerfileContent = fs.readFileSync(dockerfilePath, 'utf-8');
    //     const fromLine = dockerfileContent.split('\n').find(line => line.trim().startsWith('FROM'));
    //     if (fromLine) {
    //         const imageName = fromLine.split(' ')[1].trim();
    //         const trivyScanCommand = `trivy image ${imageName}`;
    //         exec(trivyScanCommand, { maxBuffer: 1024 * 1024 }, (error, stdout) => {
    //             if (error) {
    //                 vscode.window.showErrorMessage("Trivy scan failed. Please ensure the Docker image is built and accessible.");
    //                 return;
    //             }
    //             outputChannel.appendLine('Trivy Container Scan Results:');
    //             outputChannel.appendLine(stdout);
    //         });
    //     } else {
    //         vscode.window.showWarningMessage("No valid FROM instruction found in Dockerfile. Skipping Trivy scan.");
    //     }
    // } else {
    //     vscode.window.showInformationMessage("No Dockerfile found. Skipping container scan.");
    // } 

    // STEP 3: Check Trivy
    exec("trivy --version", (error) => {

        if (error) {
            vscode.window.showWarningMessage(
                "Trivy is not installed. Please install Trivy to enable dependency scanning."
            );
            return; // STOP here
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

                result.Results.forEach((res: any) => {
                    if (res.Vulnerabilities) {
                        res.Vulnerabilities.forEach((vuln: any, index: number) => {
                            outputChannel.appendLine(`Vulnerability ${index + 1}`);
                            outputChannel.appendLine(`Package   : ${vuln.PkgName}`);
                            outputChannel.appendLine(`Severity  : ${vuln.Severity}`);
                            outputChannel.appendLine(`Installed : ${vuln.InstalledVersion}`);
                            outputChannel.appendLine(`Fixed     : ${vuln.FixedVersion || "N/A"}`);
                            outputChannel.appendLine(`Title     : ${vuln.Title}`);
                            outputChannel.appendLine("--------------------------------------\n");
                        });
                    }
                });

            } catch {
                outputChannel.appendLine(stdout);
            }

        });

    });
}


export function deactivate() {}
