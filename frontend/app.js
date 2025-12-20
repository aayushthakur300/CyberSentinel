// Global State
let currentAnalysisData = null; 
let attackChartInstance = null;

const API_BASE = "http://127.0.0.1:8001"; // 🔥 FIX
// --- 1. Main Analyze Logic ---
document.getElementById("analyzeBtn").addEventListener("click", async () => {
    // Check which tab is active
    const isBinaryTab = document.getElementById("binary-tab").classList.contains("active");

    let url = "http://127.0.0.1:8001/analyze";
    let bodyData;
    let headers = {};

    // --- PREPARE DATA ---
    if (isBinaryTab) {
        // Binary Mode: Use FormData for file upload
        url = "http://127.0.0.1:8001/analyze/binary";
        const fileInput = document.getElementById("fileInput");
        
        if (fileInput.files.length === 0) {
            alert("Please select a file to analyze.");
            return;
        }
        
        const formData = new FormData();
        formData.append("file", fileInput.files[0]);
        bodyData = formData;
        // NOTE: Content-Type header must be undefined for FormData (browser sets it)
        
    } else {
        // Source Code Mode: Use JSON
        const code = document.getElementById("codeInput").value;
        if (!code.trim()) {
            alert("Please paste some code first.");
            return;
        }
        headers = { "Content-Type": "application/json" };
        bodyData = JSON.stringify({ code });
    }

    toggleLoading(true);

    try {
        const res = await fetch(url, {
            method: "POST",
            headers: headers,
            body: bodyData
        });

        if (!res.ok) throw new Error("Server returned error: " + res.statusText);
        
        const data = await res.json();
        currentAnalysisData = data; // Store for PDF export

        // --- UPDATE UI ---
        document.getElementById("riskScoreDisplay").textContent = data.risk_score;
        document.getElementById("malwareTypeLabel").textContent = data.malware_type;
        document.getElementById("malwareTypeLabel").className = `badge fs-6 ${getRiskColor(data.risk_score)}`;
        
        renderAttackChart(data.behaviors);
        renderBehaviors(data.behaviors);
        document.getElementById("aiExplanation").innerHTML = marked.parse(data.explanation);

        // 🔥 IMPORTANT: If it was a binary, populate the text area with the result
        // This allows the "Chat" and "Deobfuscate" buttons to work on the extracted strings!
        if (isBinaryTab) {
            document.getElementById("codeInput").value = data.code; 
            // Switch tab view back to code so user can see the extracted strings
            document.getElementById("code-tab").click();
            alert("Analysis Complete! Switched to 'Source Code' tab to show extracted strings.");
        }

        toggleLoading(false);

    } catch (e) {
        console.error(e);
        alert("Analysis failed. See console for details.");
        toggleLoading(false);
    }
});

// --- 2. Chat Feature ---
document.getElementById("sendChatBtn").addEventListener("click", async () => {
    const code = document.getElementById("codeInput").value; // Reads from textarea
    const question = document.getElementById("chatInput").value;
    const chatHistory = document.getElementById("chatHistory");

    if (!question.trim()) return;
    if (!code.trim()) return alert("No code/analysis context available. Run analysis first.");

    // Add User Message
    chatHistory.innerHTML += `<div class="text-end mb-2"><span class="badge bg-primary p-2">${question}</span></div>`;
    document.getElementById("chatInput").value = "";

    try {
        const res = await fetch("http://127.0.0.1:8001/chat", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ code, question })
        });
        const data = await res.json();

        // Add Bot Message
        chatHistory.innerHTML += `<div class="text-start mb-2"><span class="badge bg-secondary p-2 text-wrap text-start" style="max-width: 90%; line-height: 1.5;">${marked.parse(data.reply)}</span></div>`;
        chatHistory.scrollTop = chatHistory.scrollHeight;
    } catch (e) {
        chatHistory.innerHTML += `<div class="text-danger small">Error connecting to AI.</div>`;
    }
});

// --- 3. De-obfuscate Feature ---
document.getElementById("deobfuscateBtn").addEventListener("click", async () => {
    const code = document.getElementById("codeInput").value;
    if (!code.trim()) return alert("No code to de-obfuscate.");

    try {
        const res = await fetch("http://127.0.0.1:8001/deobfuscate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ code })
        });
        const data = await res.json();
        alert(`De-obfuscation Results:\n\n${data.results.join('\n')}`);
    } catch (e) {
        alert("De-obfuscation failed.");
    }
});

// --- 4. VirusTotal Feature ---
document.getElementById("vtBtn").addEventListener("click", async () => {
    // Note: This hashes the TEXT content. 
    // For a real binary, we'd ideally pass the file hash, but for this demo, 
    // hashing the extracted strings is a reasonable fallback or we rely on the logic below.
    const code = document.getElementById("codeInput").value;
    if (!code.trim()) return alert("No content to scan.");

    // Generate SHA-256 of the content
    const msgBuffer = new TextEncoder().encode(code);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    try {
        alert(`Checking VirusTotal (Hash: ${hashHex.substring(0, 10)}...)...`);
        const res = await fetch("http://127.0.0.1:8001/virustotal", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ hash: hashHex })
        });
        const data = await res.json();
        
        if (data.error) {
            alert(`VirusTotal Error: ${data.error}`);
        } else if (data.malicious !== undefined) {
            alert(`VirusTotal Results:\n\n🔴 Malicious: ${data.malicious}\n🟢 Harmless: ${data.harmless}\n\nLink: ${data.permalink}`);
        } else {
            alert(`VirusTotal: ${data.status}`);
        }
    } catch (e) {
        alert("VT Check failed.");
    }
});

// --- 5. PDF Export Feature ---
document.getElementById("pdfBtn").addEventListener("click", async () => {
    if (!currentAnalysisData) return alert("Run analysis first.");

    try {
        const res = await fetch("http://127.0.0.1:8001/report/pdf", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(currentAnalysisData)
        });
        
        if (!res.ok) throw new Error("PDF generation failed");

        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = "Malware_Report.pdf";
        document.body.appendChild(a);
        a.click();
        a.remove();
    } catch (e) {
        alert("PDF Generation failed.");
    }
});

// --- Helpers ---
function toggleLoading(isLoading) {
    const spinner = document.getElementById("loadingSpinner");
    const results = document.getElementById("resultsSection");
    if (isLoading) {
        spinner.classList.remove("d-none");
        results.classList.add("d-none");
    } else {
        spinner.classList.add("d-none");
        results.classList.remove("d-none");
    }
}

function getRiskColor(score) {
    if (score >= 70) return "bg-danger";
    if (score >= 30) return "bg-warning text-dark";
    return "bg-success";
}

function renderBehaviors(behaviors) {
    const container = document.getElementById("behaviorsList");
    if (!behaviors || behaviors.length === 0) {
        container.innerHTML = '<span class="text-muted">No specific behaviors detected.</span>';
        return;
    }
    container.innerHTML = [...new Set(behaviors)].map(b => 
        `<span class="badge bg-secondary me-1 mb-1 border border-secondary p-2">${b}</span>`
    ).join('');
}

function renderAttackChart(behaviors) {
    const ctx = document.getElementById('attackChart').getContext('2d');
    const categories = ["Command Execution", "Network Exfiltration", "Persistence", "File Tampering", "Obfuscation", "Privilege Escalation", "Reverse Shells"];
    
    // Count occurrences of each category in the behaviors list
    // (Note: This assumes your behaviors strings contain these keywords, 
    // or you map them. For this demo, we do a simple keyword match)
    const dataCounts = categories.map(cat => {
        // Basic keyword matching for the chart
        const keywords = {
            "Command Execution": ["cmd", "exec", "system", "shell", "powershell"],
            "Network Exfiltration": ["http", "socket", "connect", "download", "upload"],
            "Persistence": ["registry", "startup", "schtasks", "service"],
            "File Tampering": ["write", "delete", "remove", "chmod", "encrypt"],
            "Obfuscation": ["base64", "hex", "encode", "decode", "pack"],
            "Privilege Escalation": ["admin", "root", "sudo", "uac"],
            "Reverse Shells": ["nc", "netcat", "reverse", "bind"]
        };
        
        let count = 0;
        const catKeywords = keywords[cat] || [];
        
        // Check if any behavior string contains any keyword for this category
        behaviors.forEach(b => {
            const lowerB = b.toLowerCase();
            if (catKeywords.some(k => lowerB.includes(k))) count++;
        });
        
        // Add specific check if the category name itself is in the behavior string
        behaviors.forEach(b => {
             if(b.toLowerCase().includes(cat.toLowerCase())) count++;
        });

        return Math.min(count, 5); // Cap at 5 for visual balance
    });

    if (attackChartInstance) attackChartInstance.destroy();

    attackChartInstance = new Chart(ctx, {
        type: 'radar',
        data: {
            labels: categories,
            datasets: [{
                label: 'Threat Intensity',
                data: dataCounts,
                backgroundColor: 'rgba(13, 202, 240, 0.2)',
                borderColor: '#0dcaf0',
                borderWidth: 2,
                pointBackgroundColor: '#fff',
                pointBorderColor: '#0dcaf0'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                r: {
                    angleLines: { color: '#444' },
                    grid: { color: '#333' },
                    pointLabels: { color: '#0dcaf0', font: { size: 11, family: 'Courier New' } },
                    ticks: { display: false, max: 5 }
                }
            },
            plugins: { legend: { display: false } }
        }
    });
}
// frontend/app.js

const chatInput = document.getElementById('chatInput');

// Auto-expand the input box as the user types
chatInput.addEventListener('input', function () {
    // Reset height to calculate correctly
    this.style.height = 'auto';
    // Set height based on scrollHeight (content size)
    this.style.height = (this.scrollHeight) + 'px';
});

// Optional: Allow 'Enter' to send, and 'Shift+Enter' for new line
chatInput.addEventListener('keydown', function (e) {
    if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        document.getElementById('sendChatBtn').click();
    }
});