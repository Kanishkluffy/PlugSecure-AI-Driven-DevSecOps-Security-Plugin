const vscode = acquireVsCodeApi();
const risks = JSON.parse(atob(window.RISKS_DATA));
console.log("Loaded risks:", risks);
console.log(risks.length);

const listDiv = document.getElementById("list");
const detailsDiv = document.getElementById("details");

function escapeHtml(text) {
    return String(text || "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;");
}

function copyCode(button) {
    const codeContainer = button.parentElement;
    //select the inner elemtn text of codeContainer
    const codeElement = codeContainer.querySelector("code");
    if (codeElement) {
        const codeText = codeElement.innerText;
        navigator.clipboard.writeText(codeText).then(() => {
            button.innerText = "Copied!";
            setTimeout(() => {
                button.innerText = "Copy";
            }, 2000);
        }).catch(err => {
            console.error("Failed to copy text: ", err);
        });
    } else {
        console.error("Code element not found for copying.");
    }
}

function formatAIResponse(response) {

    const lines = response.split('\n');

    let html = "";
    let inCodeBlock = false;
    let codeBuffer = "";

    lines.forEach(line => {

        const trimmed = line.trim();

        if (trimmed.startsWith("```")) {
            if (!inCodeBlock) {
                inCodeBlock = true;
                codeBuffer = "";
            } else {
                // closing block
                html+="<div class='code-container'>";
                html += "<button class='copy-btn' onClick='copyCode(this)'>Copy</button>";
                html += "<pre><code class= 'aiCode'>" + escapeHtml(codeBuffer) + "</code></pre>";
                html+="</div>";
                inCodeBlock = false;
            }
            return;
        }

        if (inCodeBlock) {
            codeBuffer += line + "\n";
            return;
        }

        // ✅ HEADING (**text**)
        if (trimmed.startsWith("**") && trimmed.endsWith("**")) {
            const text = trimmed.replace(/\*\*/g, "").replace(":", "");
            html += "<h3>" + escapeHtml(text) + "</h3>";
            return;
        }

        // ✅ NUMBERED LIST (1. 2. 3.)
        if (/^\d+\.\s/.test(trimmed)) {
            html += "<li>" + escapeHtml(trimmed) + "</li>";
            return;
        }

        // ✅ BULLET LIST (* text)
        if (trimmed.startsWith("* ")) {
            html += "<li>" + escapeHtml(trimmed.substring(2)) + "</li>";
            return;
        }

        // ✅ NORMAL TEXT
        if (trimmed.length > 0) {
            html += "<p>" + escapeHtml(trimmed) + "</p>";
        }

    });

    // Wrap all <li> inside <ul>
    html = html.replace(/(<li>.*<\/li>)/g, "<ul>$1</ul>");

    return `
        <div class="ai-card">
            <h2>AI Suggestion</h2>
            ${html}
        </div>
    `;
}

risks.forEach(function(risk) {
    const item = document.createElement("div");

    item.className = "item";
    item.style.color =
        risk.risk_score >= 9 ? "red" :
        risk.risk_score >= 7 ? "orange" :
        risk.risk_score >= 4 ? "yellow" : "green";

    item.innerText = risk.title + " [" + risk.severity + "]";

    item.onclick = function() {
        let html = "";
        html += "<h2>" + escapeHtml(risk.title) + "</h2>";
        html += "<p><b>Severity:</b> " + escapeHtml(risk.severity) + "</p>";
        html += "<p><b>CVSS:</b> " + escapeHtml(risk.cvss_score) + "</p>";
        html += "<p><b>EPSS:</b> " + escapeHtml(risk.epss_score) + "</p>";
        html += "<p><b>Risk Score:</b> " + escapeHtml(risk.risk_score) + "</p>";
        html += "<p><b>Source:</b> " + escapeHtml(risk.source) + "</p>";
        html += "<p><b>Vulnerability ID:</b> " + escapeHtml(risk.vulnerability_id || "N/A") + "</p>";
        html += "<p><b>Description:</b><br>" + escapeHtml(risk.description || "N/A") + "</p>";
        html += "<p><b>Metadata:</b><br>" + escapeHtml(JSON.stringify(risk.metadata || {})) + "</p>";
        html += "<button id='aiBtn'>Get AI Suggestion</button>";
        html += "<div id='aiResult'></div>";

        detailsDiv.innerHTML = html;

        document.getElementById("aiBtn").onclick = function() {
            document.getElementById("aiResult").innerHTML = "<p>Loading...</p>";
            vscode.postMessage({
                command: "getSuggestion",
                risk: risk
            });
        };
    };

    listDiv.appendChild(item);
});

window.addEventListener("message", function(event) {
    const message = event.data;

    if (message.command === "showSuggestion") {
        const aiResultDiv = document.getElementById("aiResult");
        if (aiResultDiv) {
            aiResultDiv.innerHTML = formatAIResponse(message.suggestion);
        }
    }
});

const codeElement = document.getElementById("aiCode");

if(codeElement) {
    const codetext = codeElement.innerText;
    console.log("Original code text:", codetext);
}