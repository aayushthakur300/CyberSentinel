

// -->2nd version
// document.addEventListener("DOMContentLoaded", () => {
//     console.log("✅ CyberSentinel Frontend Initializing...");

//     // --- CONFIGURATION ---
//     const API_BASE = "http://127.0.0.1:8001";
//     const WS_BASE = "ws://127.0.0.1:8001";
//     let currentAnalysisData = null; 
//     let attackChartInstance = null;

//     // ============================================================
//     // 1. NEURAL LINK (WebSocket System Stats)
//     // ============================================================
//     try {
//         const ws = new WebSocket(`${WS_BASE}/ws/system`);

//         ws.onmessage = (event) => {
//             const data = JSON.parse(event.data);
//             safeSetText("cpuMetric", `CPU: ${data.cpu}%`);
//             safeSetText("ramMetric", `RAM: ${data.ram}%`);
//             const netVal = Math.round((data.net_recv) / 1024);
//             safeSetText("netMetric", `NET: ${netVal} KB/s`);

//             const dot = document.querySelector(".status-dot-live");
//             if(dot) dot.style.boxShadow = `0 0 ${data.cpu * 0.5}px #00ff41`;
//         };
//         ws.onerror = () => console.warn("WebSocket Disconnected (Ignore if backend is restarting)");
//     } catch (e) { console.warn("WebSocket Init Failed", e); }
//     // ============================================================
//     //  THREAT INTELLIGENCE TICKER (ROBUST VERSION)
//     // ============================================================
//     async function loadThreatTicker() {
//         console.groupCollapsed("☠️ [FRONTEND] Initializing Threat Feed...");
//         const marquee = document.getElementById("threatMarquee");

//         // 1. UI Validation
//         if (!marquee) {
//             console.warn("⚠️ [FRONTEND] Critical: Element #threatMarquee not found. Skipping ticker.");
//             console.groupEnd();
//             return;
//         }

//         try {
//             console.log("🚀 [FRONTEND] Fetching Global Threat Data...");

//             // 2. Fetch Request (Matches Backend: /analyze/threats)
//             const res = await fetch(`${API_BASE}/analyze/threats`);

//             console.log(`📡 [FRONTEND] Feed Status: ${res.status}`);

//             if (!res.ok) {
//                 throw new Error(`HTTP Error ${res.status}`);
//             }

//             // 3. Parse Data
//             const threats = await res.json();
//             console.log("📦 [FRONTEND] Feed Data:", threats);

//             // 4. Render Ticker
//             if (Array.isArray(threats) && threats.length > 0) {
//                 const tickerHTML = threats.map(t => {
//                     // Smart Fallback: Handles RSS 'title' or DB 'filename'
//                     const label = t.title || t.filename || "Unknown Anomaly";
//                     const verdict = t.verdict ? `(${t.verdict})` : "";

//                     // Dynamic Styling based on keywords
//                     let icon = "⚠️";
//                     let colorClass = "text-warning";

//                     if (label.toLowerCase().includes("ransom") || (t.risk_score && t.risk_score > 80)) {
//                         icon = "💀";
//                         colorClass = "text-danger";
//                     } else if (label.toLowerCase().includes("info") || (t.risk_score && t.risk_score < 40)) {
//                         icon = "ℹ️";
//                         colorClass = "text-info";
//                     }

//                     return `<span class="${colorClass} fw-bold mx-5" style="font-family: 'Courier New', monospace; letter-spacing: 1px;">
//                                 ${icon} [DETECTED] ${label} ${verdict}
//                             </span>`;
//                 }).join("");

//                 marquee.innerHTML = tickerHTML;
//                 console.log(`✅ [FRONTEND] Ticker updated with ${threats.length} entries.`);

//             } else {
//                 console.warn("⚠️ [FRONTEND] Threat feed returned empty array.");
//                 marquee.innerHTML = '<span class="text-success mx-4">✔ Global Threat Levels Nominal. No active alerts.</span>';
//             }

//         } catch (err) {
//             // 5. Error Handling (Silent UI Fallback)
//             console.error("❌ [FRONTEND] Threat Feed Failed:", err);
//             marquee.innerHTML = '<span class="text-secondary mx-4">⚠️ Threat Intelligence Feed Offline (Check Server Console)</span>';
//         } finally {
//             console.groupEnd();
//         }
//     }

//     // 🔥 Auto-Start the Ticker
//     loadThreatTicker();

//     // Optional: Auto-Refresh every 60 seconds
//     setInterval(loadThreatTicker, 60000);

//     // ============================================================
//     // 2. UNIVERSAL CLICK LISTENER (FIXES "UNCLICKABLE" BUTTONS)
//     // ============================================================
//     document.body.addEventListener("click", async (e) => {
//         // match: The element clicked, OR its parent (for icons <i> inside buttons)
//         const target = e.target.closest("#exportPdfBtn, #export-btn, #pdfBtn, #vtScanBtn, #vtBtn, #virustotal-btn, #deobfuscateBtn, #deobfuscate-btn, #analyzeBtn, #sendChatBtn");

//         if (!target) return; // Clicked something irrelevant

//         const id = target.id;
//         console.log(`🖱️ CLICK DETECTED ON ID: ${id}`);

//         // --- A. PDF EXPORT ---
//         if (id === "exportPdfBtn" || id === "export-btn" || id === "pdfBtn") {
//             if (!currentAnalysisData) return alert("No analysis data available. Run a scan first!");

//             // 🔥 SILENT KILLER DETECTION: Check Console for Metadata
//             console.group("🔍 PDF Generation - Silent Killer Check");
//             console.log("Full Payload:", currentAnalysisData);

//             const hasMetadata = currentAnalysisData && currentAnalysisData.metadata;
//             const hasHash = hasMetadata && (currentAnalysisData.metadata.sha256 || currentAnalysisData.metadata.md5);

//             if (!hasMetadata) {
//                 console.error("❌ CRITICAL: 'metadata' object is MISSING in response!");
//             } else if (!hasHash) {
//                 console.error("⚠️ WARNING: Metadata exists, but 'sha256' or 'md5' hash is MISSING!", currentAnalysisData.metadata);
//             } else {
//                 console.log("✅ Metadata Check Passed. Hash available:", currentAnalysisData.metadata.sha256);
//             }
//             console.groupEnd();

//             toggleLoading(true);
//             try {
//                 const res = await fetch(`${API_BASE}/analyze/report/pdf`, {
//                     method: "POST",
//                     headers: { "Content-Type": "application/json" },
//                     body: JSON.stringify(currentAnalysisData)
//                 });

//                 if (!res.ok) {
//                     const errText = await res.text();
//                     console.error("Server Response:", errText);
//                     throw new Error(`PDF Generation Failed: ${res.status} ${res.statusText}`);
//                 }

//                 const blob = await res.blob();
//                 const url = window.URL.createObjectURL(blob);
//                 const a = document.createElement("a");
//                 a.href = url;
//                 a.download = `CyberSentinel_Report_${Date.now()}.pdf`;
//                 document.body.appendChild(a);
//                 a.click();
//                 window.URL.revokeObjectURL(url);
//                 document.body.removeChild(a);

//             } catch (err) {
//                 console.error("❌ PDF Export Error:", err);
//                 alert("PDF Error: " + err.message + "\n(Check Console for Silent Killer details)");
//             } finally {
//                 toggleLoading(false);
//             }
//         }
//         // --- B. VIRUSTOTAL SCAN (ROBUST VERSION) ---
//             if (["vtScanBtn", "vtBtn", "virustotal-btn"].includes(id)) {
//                 // 🔥 DEBUGGING THE SILENT KILLER
//             console.log("🔍 Checking Metadata:", currentAnalysisData);
//                 // 1. Validation
//                 if (!currentAnalysisData?.metadata?.sha256) {
//                     console.warn("⚠️ [FRONTEND] No Hash available in metadata.");
//                     alert("No file hash available. Run a Binary or Image analysis first to generate a hash.");
//                     return;
//                 }

//                 const hash = currentAnalysisData.metadata.sha256;
//                 console.log(`🚀 [FRONTEND] Starting VirusTotal Scan for: ${hash}`);
//                 toggleLoading(true);

//                 try {
//                     // 2. Send Request (Matches Backend: /analyze/virustotal)
//                     const res = await fetch(`${API_BASE}/analyze/virustotal`, {
//                         method: "POST",
//                         headers: { "Content-Type": "application/json" },
//                         body: JSON.stringify({ hash: hash })
//                     });

//                     console.log(`📡 [FRONTEND] HTTP Status: ${res.status}`);

//                     if (!res.ok) {
//                         throw new Error(`HTTP Error! Status: ${res.status}`);
//                     }

//                     const data = await res.json();
//                     console.log("📦 [FRONTEND] VT Data Received:", data);

//                     // 3. Handle Response Logic
//                     // We check data.success (added in our python update) OR data.found
//                     if (data.success && data.found) {
//                         const mal = data.malicious || 0;
//                         const safe = data.harmless || 0;

//                         console.log(`✅ [FRONTEND] VT Success: ${mal} malicious detections.`);

//                         const msg = `VirusTotal Results:\n\n🔴 Malicious: ${mal}\n🟢 Harmless: ${safe}\n\nClick OK to open full report.`;
//                         if(confirm(msg)) {
//                             window.open(data.link || `https://www.virustotal.com/gui/file/${hash}`, '_blank');
//                         }

//                     } else if (data.success && !data.found) {
//                         console.warn("⚠️ [FRONTEND] Hash not found in VT.");
//                         alert("⚠️ Not Found: This file hash is not in the VirusTotal database (It might be a unique or new file).");

//                     } else {
//                         // Handle API errors (Quota, Key missing, etc)
//                         console.error("❌ [FRONTEND] VT API Error:", data.error);
//                         alert(`VirusTotal API Error:\n${data.error || "Unknown error occurred."}`);
//                     }

//                 } catch (err) {
//                     // 4. Critical Errors
//                     console.error("❌ [FRONTEND] CRITICAL VT ERROR:", err);
//                     alert("VirusTotal Connection Failed!\nCheck Console (F12) for details.\n\n" + err.message);
//                 } finally {
//                     toggleLoading(false);
//                 }
//             }
//        // --- C. DEOBFUSCATOR (FINAL ENHANCED VERSION) ---
//         if (["deobfuscateBtn", "deobfuscate-btn"].includes(id)) {
//             const codeInput = document.getElementById("codeInput");
//             if (!codeInput || !codeInput.value.trim()) return alert("Paste obfuscated code into the editor first.");

//             console.log("🚀 [FRONTEND] Sending request to Deobfuscator...");
//             toggleLoading(true);

//             try {
//                 // 1. Send Request
//                 const res = await fetch(`${API_BASE}/deobfuscate`, { 
//                     method: "POST",
//                     headers: { "Content-Type": "application/json" },
//                     body: JSON.stringify({ code: codeInput.value })
//                 });

//                 console.log(`📡 [FRONTEND] HTTP Status: ${res.status}`);

//                 if (!res.ok) {
//                     throw new Error(`HTTP Error! Status: ${res.status}`);
//                 }

//                 // 2. Parse JSON
//                 const data = await res.json();
//                 console.log("📦 [FRONTEND] Data Received:", data);

//                 // 3. CHECK RESULT
//                 // Flexible check for boolean true or string "true"
//                 const isSuccess = data.pattern_found === true || String(data.pattern_found).toLowerCase() === "true";

//                 if (isSuccess) {
//                     // Update Editor
//                     const resultText = data.results || "";
//                     codeInput.value = resultText;

//                     // Create a preview for the alert (max 100 chars)
//                     // We try to find the comment /* ... */ to show the user what was found
//                     let preview = "Check the editor for full changes.";
//                     const commentMatch = resultText.match(/\/\*.*?\*\//);
//                     if (commentMatch) {
//                         preview = "\nFound: " + commentMatch[0];
//                     } else {
//                         preview = "\nPreview: " + resultText.substring(0, 150) + "...";
//                     }

//                     console.log("✅ [FRONTEND] Success! Updating UI.");
//                     alert(`✅ SUCCESS: Hidden patterns decoded!\n${preview}`);

//                 } else {
//                     console.warn("⚠️ [FRONTEND] Backend analyzed code but returned 'pattern_found: false'.");
//                     alert("⚠️ NO RESULT: The backend analyzed the code but found no known obfuscation patterns.");
//                 }

//             } catch (err) {
//                 // 4. CATCH SILENT ERRORS
//                 console.error("❌ [FRONTEND] CRITICAL ERROR:", err);
//                 alert("Deobfuscator Error! Check Console (F12) for details.\n\n" + err.message);
//             } finally {
//                 toggleLoading(false);
//             }
//         }
//         // --- D. MAIN ANALYZE BUTTON ---
//         if (id === "analyzeBtn") {
//             handleMainAnalysis();
//         }

//         // --- E. CHAT SEND ---
//         if (id === "sendChatBtn") {
//             handleChat();
//         }
//     });

//     function updateDashboard(data) {
//         console.log("🔥 Updating Dashboard:", data);

//         // 🔥 CRITICAL FIX: Update the LOCAL variable used by click listeners
//         currentAnalysisData = data;
//         // 1. Update Global State (Crucial for VirusTotal)
//         window.currentAnalysisData = data; 
//         // 2. Risk Score
//         const scoreDisplay = document.getElementById("riskScoreDisplay");
//         if(scoreDisplay) {
//             scoreDisplay.textContent = data.risk_score;
//             scoreDisplay.className = `display-4 fw-bold ${getRiskColorText(data.risk_score)}`;
//         }

//         const typeLabel = document.getElementById("malwareTypeLabel");
//         if(typeLabel) {
//             typeLabel.textContent = data.malware_type;
//             typeLabel.className = `badge fs-6 ${getRiskColorBg(data.risk_score)}`;
//         }

//         // 4. AI Report & "Silent Killer" Prevention
//         const aiOutput = document.getElementById("aiExplanation");
//         if(aiOutput) {
//             aiOutput.classList.add("text-light");

//             let rawText = data.explanation || "No AI report available.";

//             // 🕵️ SILENT KILLER IDENTIFICATION & FIX
//             // If we have binary metadata (SHA256) but the user is on the main screen,
//             // they might miss the extracted strings hidden in the 'Source Code' tab.
//             // We append a preview here to kill that silence.
//             if (data.metadata && data.metadata.sha256 && data.code) {
//                 console.log("🕵️ Silent Killer Check: Appending Binary Preview to Report.");

//                 const preview = data.code.substring(0, 600); // First 600 chars
//                 const binaryInfo = `
//                 ### Analysis Artifacts
//                 **SHA256:** \`${data.metadata.sha256}\`
//                 **MD5:** \`${data.metadata.md5 || 'N/A'}\`

//                 **Extracted Strings (Preview):**
//                 \`\`\`text
//                 ${preview}...
//                 \`\`\`
//                 *(Full strings available in 'Source Code' tab)*
//                 `;
//                 // Append this technical info to the AI explanation
//                 rawText += "\n" + binaryInfo;
//             }

//             // Render Markdown
//             aiOutput.innerHTML = (typeof marked !== 'undefined') ? marked.parse(rawText) : rawText;
//         }

//         // 5. Charts & Behaviors
//         // Check if function exists before calling to prevent crashes
//         if (typeof renderAttackChart === "function") renderAttackChart(data.behaviors || []);
//         if (typeof renderBehaviors === "function") renderBehaviors(data.behaviors || []);

//         // 6. Update Radar Chart (If it exists)
//         if (window.riskChart && data.risk_matrix) {
//              window.riskChart.data.datasets[0].data = Object.values(data.risk_matrix);
//              window.riskChart.update();
//         }

//         // 7. Show Results Section
//         const resSection = document.getElementById("resultsSection");
//         const emptyState = document.getElementById("emptyState");
//         if(resSection) resSection.classList.remove("d-none");
//         if(emptyState) emptyState.classList.add("d-none");
//     }
//     // ============================================================
//     // 4. MAIN ANALYSIS FUNCTION
//     // ============================================================
//     async function handleMainAnalysis() {
//         const binaryTab = document.getElementById("binary-tab");
//         const isBinaryTab = binaryTab && binaryTab.classList.contains("active");

//         let url = `${API_BASE}/analyze`;
//         let bodyData;
//         let headers = {};

//         // 1. Prepare Data
//         if (isBinaryTab) {
//             url = `${API_BASE}/analyze/binary`;
//             const fileInput = document.getElementById("fileInput");
//             if (!fileInput || !fileInput.files[0]) {
//                 alert("Select a binary file first.");
//                 return;
//             }
//             const formData = new FormData();
//             formData.append("file", fileInput.files[0]);
//             bodyData = formData;
//         } else {
//             const codeInput = document.getElementById("codeInput");
//             if (!codeInput || !codeInput.value.trim()) {
//                 alert("Paste source code first.");
//                 return;
//             }
//             headers = { "Content-Type": "application/json" };
//             bodyData = JSON.stringify({ code: codeInput.value });
//         }

//         // 2. Send Request
//         toggleLoading(true);
//         try {
//             const res = await fetch(url, { method: "POST", headers, body: bodyData });
//             if(!res.ok) throw new Error("Analysis Failed");

//             const data = await res.json();

//             // 🔥 FORCE UPDATE GLOBAL DATA
//             if (!window.currentAnalysisData) window.currentAnalysisData = {};
//             window.currentAnalysisData = data;

//             // 3. Update Dashboard UI
//             updateDashboard(data);

//             // 4. Handle The Report
//             if (isBinaryTab) {
//                 const codeBox = document.getElementById("codeInput");

//                 // 🕵️ DEBUG: SILENT KILLER CHECK 🕵️
//                 console.log("🕵️ SILENT KILLER CHECK:", {
//                     "Is CodeBox Found?": !!codeBox,
//                     "Data.Code Length": data.code ? data.code.length : "UNDEFINED (This is the killer)",
//                     "Data.Code Preview": data.code ? data.code.substring(0, 50) : "N/A"
//                 });

//                 if(codeBox) {
//                     if (data.code) {
//                         codeBox.value = data.code;
//                         console.log("✅ Report successfully injected into hidden code box.");
//                     } else {
//                         console.error("❌ SILENT KILLER FOUND: Backend returned empty 'code' field!");
//                         alert("Error: Backend finished analysis but sent an empty report.");
//                     }
//                 } else {
//                     console.error("❌ SILENT KILLER FOUND: HTML Element 'codeInput' is missing!");
//                 }

//                 console.log("✅ Report generated. Hash:", data.metadata?.sha256);
//                 alert("Analysis Complete!\n\n1. Risk Score Updated.\n2. VirusTotal Button is Ready.\n3. Full Report is waiting in the 'Source Code' tab.");
//             }

//         } catch (e) {
//             console.error("❌ Analysis Error:", e);
//             alert(e.message);
//         } finally {
//             toggleLoading(false);
//         }
//     }
//     // ============================================================
//     // 5. GLOBAL FUNCTIONS (Window Scope for HTML onclick="")
//     // ============================================================

//     // --- STEGANOGRAPHY ---
//     window.runStego = async function() {
//         console.log("🖱️ Run Stego Clicked");
//         const fileInput = document.getElementById("stegoInput");
//         if(!fileInput || !fileInput.files[0]) return alert("Upload an image first.");

//         const formData = new FormData();
//         formData.append("file", fileInput.files[0]);

//         toggleLoading(true);
//         try {
//             const res = await fetch(`${API_BASE}/analyze/stego`, { method: "POST", body: formData });
//             const data = await res.json();

//             const output = document.getElementById("stegoResults");
//             if(output) {
//                 output.classList.remove("d-none");
//                 let html = `<strong>Hidden Data Found:</strong> ${data.has_hidden_data ? '<span class="text-danger fw-bold">YES</span>' : '<span class="text-success">NO</span>'}<br>`;

//                 if(data.has_hidden_data && data.behaviors) {
//                     const secretMsg = data.behaviors.find(b => 
//                         b.toLowerCase().includes("decoded") || 
//                         b.toLowerCase().includes("hidden content") ||
//                         b.toLowerCase().includes("secret")
//                     );

//                     if(secretMsg) {
//                         const cleanMsg = secretMsg.replace(/CRITICAL:|Hidden content decoded ->/gi, "").trim();
//                         html += `<div class="mt-2 p-2 bg-dark border border-warning text-warning font-monospace text-wrap" style="word-break: break-all;">
//                                     <i class="fas fa-key me-2"></i><strong>DECODED:</strong> ${cleanMsg}
//                                  </div>`;
//                     }
//                 }
//                 output.innerHTML = html;
//             }
//             updateDashboard(data);
//         } catch(e) {
//             alert("Stego Failed: " + e.message);
//         } finally {
//             toggleLoading(false);
//         }
//     };

//     // --- NETWORK PCAP ---
//     window.runPcap = async function() {
//         console.log("🖱️ Run PCAP Clicked");
//         const fileInput = document.getElementById("pcapInput");
//         if(!fileInput || !fileInput.files[0]) return alert("Upload a .pcap file first.");

//         const formData = new FormData();
//         formData.append("file", fileInput.files[0]);

//         toggleLoading(true);
//         try {
//             const res = await fetch(`${API_BASE}/analyze/pcap`, { method: "POST", body: formData });
//             const data = await res.json();

//             const output = document.getElementById("pcapResults");
//             if(output) {
//                 output.classList.remove("d-none");
//                 let html = `<div class="mb-2"><strong>Packets:</strong> ${data.packet_count}</div>`;
//                 html += data.risk_score > 50 
//                     ? `<div class="text-danger fw-bold">⚠️ Threats Found</div>` 
//                     : `<div class="text-success">✔ Clean</div>`;
//                 output.innerHTML = html;
//             }
//             updateDashboard(data);
//         } catch(e) {
//             alert("PCAP Failed: " + e.message);
//         } finally {
//             toggleLoading(false);
//         }
//     };

//     // --- CHAT HANDLER (ROBUST VERSION) ---
//     async function handleChat() {
//         console.group("💬 [FRONTEND] Chat Interaction Started");

//         const input = document.getElementById("chatInput");
//         const chatBody = document.getElementById("chatBody");
//         const codeInput = document.getElementById("codeInput");

//         // 1. UI Validation
//         if (!chatBody) {
//             console.error("❌ [FRONTEND] Critical: Element #chatBody not found in HTML.");
//             alert("UI Error: Chat window missing.");
//             console.groupEnd();
//             return;
//         }

//         const question = input.value.trim();
//         if(!question) {
//             console.warn("⚠️ [FRONTEND] Empty input ignored.");
//             console.groupEnd();
//             return;
//         }

//         console.log(`User Question: "${question}"`);

//         // 2. Append USER Message (Immediate UI Feedback)
//         const userDiv = document.createElement("div");
//         userDiv.className = "text-end mb-2";
//         userDiv.innerHTML = `<span class="badge bg-primary p-2 text-wrap text-start" style="max-width: 85%; font-size: 0.9rem;">${question}</span>`;
//         chatBody.appendChild(userDiv);
//         chatBody.scrollTop = chatBody.scrollHeight; // Auto-scroll

//         input.value = ""; // Clear Input

//         try {
//             // 3. Prepare Payload
//             const payload = { 
//                 code: codeInput ? codeInput.value : "", 
//                 question: question 
//             };

//             console.log("🚀 [FRONTEND] Sending Chat Request...");

//             // 4. Send Request (Matches Backend: /analyze/chat)
//             const res = await fetch(`${API_BASE}/analyze/chat`, {
//                 method: "POST",
//                 headers: { "Content-Type": "application/json" },
//                 body: JSON.stringify(payload)
//             });

//             console.log(`📡 [FRONTEND] HTTP Status: ${res.status}`);

//             if(!res.ok) {
//                 // Try to read error text from server
//                 const errText = await res.text();
//                 throw new Error(`Server Error ${res.status}: ${errText}`);
//             }

//             const data = await res.json();
//             console.log("📦 [FRONTEND] AI Reply Received:", data);

//             // 5. Render AI Reply
//             const replyText = data.reply || "⚠️ AI returned an empty response.";

//             // Check for Markdown library 'marked'
//             let formattedText = replyText;
//             if (typeof marked !== 'undefined') {
//                 formattedText = marked.parse(replyText);
//             } else {
//                 console.warn("⚠️ [FRONTEND] 'marked' library missing. Using plain text.");
//             }

//             const aiDiv = document.createElement("div");
//             aiDiv.className = "text-start mb-2";
//             // Uses 'bg-dark' and 'border' to distinguish from user
//             aiDiv.innerHTML = `<span class="badge bg-dark border border-secondary p-2 text-wrap text-start w-100" style="white-space: pre-wrap; font-size: 0.9rem;">${formattedText}</span>`;

//             chatBody.appendChild(aiDiv);
//             chatBody.scrollTop = chatBody.scrollHeight; // Auto-scroll

//         } catch(e) { 
//             // 6. Error Handling in Chat Bubble
//             console.error("❌ [FRONTEND] Chat Failed:", e);
//             const errDiv = document.createElement("div");
//             errDiv.className = "text-center mb-2";
//             errDiv.innerHTML = `<span class="badge bg-danger p-2">Error: ${e.message}</span>`;
//             chatBody.appendChild(errDiv);
//         } finally {
//             console.groupEnd();
//         }
//     }

//     // ============================================================
//     // 6. UTILITIES
//     // ============================================================
//     function toggleLoading(isLoading) {
//         const overlay = document.getElementById("loadingOverlay");
//         const main = document.getElementById("mainContainer");
//         if(overlay) overlay.style.display = isLoading ? "flex" : "none";
//         if(main) isLoading ? main.classList.add("blur-content") : main.classList.remove("blur-content");
//     }

//     function safeSetText(id, text) {
//         const el = document.getElementById(id);
//         if(el) el.textContent = text;
//     }

//     function getRiskColorText(score) {
//         if (score >= 80) return "text-danger";
//         if (score >= 40) return "text-warning";
//         return "text-success";
//     }

//     function getRiskColorBg(score) {
//         if (score >= 80) return "bg-danger";
//         if (score >= 40) return "bg-warning text-dark";
//         return "bg-success";
//     }

//     function renderBehaviors(behaviors) {
//         const container = document.getElementById("behaviorsList");
//         if(!container) return;

//         if (!behaviors || behaviors.length === 0) {
//             container.innerHTML = '<span class="text-muted">No specific threats detected.</span>';
//             return;
//         }

//         container.innerHTML = [...new Set(behaviors)].map(b => {
//             if(b.includes("DECODED") || b.includes("Hidden content")) return ''; 
//             const isCrit = b.includes("CRITICAL") || b.includes("ALERT") || b.includes("Metasploit");
//             return `<span class="badge ${isCrit ? 'bg-danger' : 'bg-dark border border-secondary'} p-2 m-1">${b}</span>`;
//         }).join('');
//     }

// function renderAttackChart(behaviors) {
//         const ctx = document.getElementById('attackChart');
//         if (!ctx) return;

//         // 1. Get Data from Global State (Ensures sync with Backend)
//         // Default to zeros if no matrix exists
//         let chartData = [0, 0, 0, 0, 0, 0, 0, 0];

//         if (window.currentAnalysisData && window.currentAnalysisData.risk_matrix) {
//             const m = window.currentAnalysisData.risk_matrix;
//             // 🔥 CRITICAL: Map Keys exactly as defined in risk_engine.py
//             chartData = [
//                 m["Exfil"] || 0,
//                 m["C2"] || 0,
//                 m["Obfuscation"] || 0,
//                 m["Spyware"] || 0,
//                 m["Crypto"] || 0,
//                 m["Persistence"] || 0,
//                 m["PrivEsc"] || 0,
//                 m["Recon"] || 0
//             ];
//         }

//         // 2. Destroy Old Chart
//         if (attackChartInstance) attackChartInstance.destroy();

//         // 3. Render New 8-Axis Radar
//         attackChartInstance = new Chart(ctx.getContext('2d'), {
//             type: 'radar',
//             data: {
//                 // Must match the order of chartData above!
//                 labels: ["Exfiltration", "C2", "Obfuscation", "Spyware", "Crypto", "Persistence", "PrivEsc", "Recon"],
//                 datasets: [{
//                     label: 'Threat Intensity',
//                     data: chartData,
//                     backgroundColor: 'rgba(220, 53, 69, 0.2)',
//                     borderColor: '#dc3545',
//                     borderWidth: 2,
//                     pointBackgroundColor: '#dc3545',
//                     pointBorderColor: '#fff'
//                 }]
//             },
//             options: {
//                 scales: {
//                     r: {
//                         angleLines: { color: '#495057' },
//                         grid: { color: '#495057' },
//                         pointLabels: { color: '#adb5bd', font: { size: 11, family: 'Courier New' } },
//                         suggestedMin: 0,
//                         suggestedMax: 100,
//                         ticks: { display: false, maxTicksLimit: 5 }
//                     }
//                 },
//                 plugins: {
//                     legend: { display: false }
//                 }
//             }
//         });
//     }
// console.log("✅ Frontend Ready!");
// });

document.addEventListener("DOMContentLoaded", () => {
    console.log("✅ CyberSentinel Frontend Initializing...");

    // --- CONFIGURATION ---
    // const API_BASE = "http://127.0.0.1:8001";
    // const WS_BASE = "ws://127.0.0.1:8001";
    // --- CONFIGURATION ---
    // Automatically detect if running locally or on Render
    const isLocal = window.location.hostname === "127.0.0.1" || window.location.hostname === "localhost";

    const API_BASE = isLocal ? "http://127.0.0.1:8001" : window.location.origin;
    const WS_PROTOCOL = window.location.protocol === "https:" ? "wss:" : "ws:";
    const WS_BASE = isLocal ? "ws://127.0.0.1:8001" : `${WS_PROTOCOL}//${window.location.host}`;
    let currentAnalysisData = null;
    let attackChartInstance = null;

    // ============================================================
    // 1. NEURAL LINK (WebSocket System Stats)
    // ============================================================
    try {
        const ws = new WebSocket(`${WS_BASE}/ws/system`);

        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            safeSetText("cpuMetric", `CPU: ${data.cpu}%`);
            safeSetText("ramMetric", `RAM: ${data.ram}%`);
            const netVal = Math.round((data.net_recv) / 1024);
            safeSetText("netMetric", `NET: ${netVal} KB/s`);

            const dot = document.querySelector(".status-dot-live");
            if (dot) dot.style.boxShadow = `0 0 ${data.cpu * 0.5}px #00ff41`;
        };
        ws.onerror = () => console.warn("WebSocket Disconnected (Ignore if backend is restarting)");
    } catch (e) { console.warn("WebSocket Init Failed", e); }

    // ============================================================
    //  THREAT INTELLIGENCE TICKER (ROBUST VERSION)
    // ============================================================
    async function loadThreatTicker() {
        console.groupCollapsed("☠️ [FRONTEND] Initializing Threat Feed...");
        const marquee = document.getElementById("threatMarquee");

        // 1. UI Validation
        if (!marquee) {
            console.warn("⚠️ [FRONTEND] Critical: Element #threatMarquee not found. Skipping ticker.");
            console.groupEnd();
            return;
        }

        try {
            console.log("🚀 [FRONTEND] Fetching Global Threat Data...");

            // 2. Fetch Request
            const res = await fetch(`${API_BASE}/analyze/threats`);
            console.log(`📡 [FRONTEND] Feed Status: ${res.status}`);

            if (!res.ok) throw new Error(`HTTP Error ${res.status}`);

            // 3. Parse Data
            const threats = await res.json();
            console.log("📦 [FRONTEND] Feed Data:", threats);

            // 4. Render Ticker
            if (Array.isArray(threats) && threats.length > 0) {
                const tickerHTML = threats.map(t => {
                    const label = t.title || t.filename || "Unknown Anomaly";
                    const verdict = t.verdict ? `(${t.verdict})` : "";

                    let icon = "⚠️";
                    let colorClass = "text-warning";

                    if (label.toLowerCase().includes("ransom") || (t.risk_score && t.risk_score > 80)) {
                        icon = "💀";
                        colorClass = "text-danger";
                    } else if (label.toLowerCase().includes("info") || (t.risk_score && t.risk_score < 40)) {
                        icon = "ℹ️";
                        colorClass = "text-info";
                    }

                    return `<span class="${colorClass} fw-bold mx-5" style="font-family: 'Courier New', monospace; letter-spacing: 1px;">
                                ${icon} [DETECTED] ${label} ${verdict}
                            </span>`;
                }).join("");

                marquee.innerHTML = tickerHTML;
                console.log(`✅ [FRONTEND] Ticker updated with ${threats.length} entries.`);

            } else {
                console.warn("⚠️ [FRONTEND] Threat feed returned empty array.");
                marquee.innerHTML = '<span class="text-success mx-4">✔ Global Threat Levels Nominal. No active alerts.</span>';
            }

        } catch (err) {
            console.error("❌ [FRONTEND] Threat Feed Failed:", err);
            marquee.innerHTML = '<span class="text-secondary mx-4">⚠️ Threat Intelligence Feed Offline (Check Server Console)</span>';
        } finally {
            console.groupEnd();
        }
    }

    // 🔥 Auto-Start the Ticker
    loadThreatTicker();
    setInterval(loadThreatTicker, 60000);

    // ============================================================
    // 2. UNIVERSAL CLICK LISTENER
    // ============================================================
    document.body.addEventListener("click", async (e) => {
        const target = e.target.closest("#exportPdfBtn, #export-btn, #pdfBtn, #vtScanBtn, #vtBtn, #virustotal-btn, #deobfuscateBtn, #deobfuscate-btn, #analyzeBtn, #sendChatBtn");
        if (!target) return;

        const id = target.id;
        console.log(`🖱️ CLICK DETECTED ON ID: ${id}`);

        // --- A. PDF EXPORT ---
        if (id === "exportPdfBtn" || id === "export-btn" || id === "pdfBtn") {
            if (!currentAnalysisData) return alert("No analysis data available. Run a scan first!");

            console.group("🔍 PDF Generation - Silent Killer Check");
            const hasMetadata = currentAnalysisData && currentAnalysisData.metadata;
            const hasHash = hasMetadata && (currentAnalysisData.metadata.sha256 || currentAnalysisData.metadata.md5);

            if (!hasMetadata) console.error("❌ CRITICAL: 'metadata' object is MISSING in response!");
            else if (!hasHash) console.error("⚠️ WARNING: Metadata exists, but 'sha256' or 'md5' hash is MISSING!");
            else console.log("✅ Metadata Check Passed.");
            console.groupEnd();

            toggleLoading(true);
            try {
                const res = await fetch(`${API_BASE}/analyze/report/pdf`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(currentAnalysisData)
                });

                if (!res.ok) throw new Error(`PDF Generation Failed: ${res.status}`);

                const blob = await res.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement("a");
                a.href = url;
                a.download = `CyberSentinel_Report_${Date.now()}.pdf`;
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
                document.body.removeChild(a);
            } catch (err) {
                alert("PDF Error: " + err.message);
            } finally {
                toggleLoading(false);
            }
        }

        // --- B. VIRUSTOTAL SCAN ---
        if (["vtScanBtn", "vtBtn", "virustotal-btn"].includes(id)) {
            if (!currentAnalysisData?.metadata?.sha256) {
                alert("No file hash available. Run a Binary/Image analysis first.");
                return;
            }

            const hash = currentAnalysisData.metadata.sha256;
            toggleLoading(true);

            try {
                const res = await fetch(`${API_BASE}/analyze/virustotal`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ hash: hash })
                });

                if (!res.ok) throw new Error(`HTTP Error! Status: ${res.status}`);

                const data = await res.json();

                if (data.success && data.found) {
                    const msg = `VirusTotal Results:\n\n🔴 Malicious: ${data.malicious}\n🟢 Harmless: ${data.harmless}\n\nClick OK to open full report.`;
                    if (confirm(msg)) window.open(data.link, '_blank');
                } else if (data.success && !data.found) {
                    alert("⚠️ Not Found: This hash is not in VirusTotal database.");
                } else {
                    alert(`VirusTotal Error: ${data.error}`);
                }
            } catch (err) {
                alert("VirusTotal Failed: " + err.message);
            } finally {
                toggleLoading(false);
            }
        }

        // --- C. DEOBFUSCATOR ---
        if (["deobfuscateBtn", "deobfuscate-btn"].includes(id)) {
            const codeInput = document.getElementById("codeInput");
            if (!codeInput || !codeInput.value.trim()) return alert("Paste obfuscated code first.");

            toggleLoading(true);
            try {
                const res = await fetch(`${API_BASE}/deobfuscate`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ code: codeInput.value })
                });

                if (!res.ok) throw new Error(`HTTP Error! Status: ${res.status}`);

                const data = await res.json();
                const isSuccess = data.pattern_found === true || String(data.pattern_found).toLowerCase() === "true";

                if (isSuccess) {
                    codeInput.value = data.results || "";
                    alert(`✅ SUCCESS: Hidden patterns decoded!\nPreview: ${data.results.substring(0, 100)}...`);
                } else {
                    alert("⚠️ NO RESULT: No known obfuscation patterns found.");
                }
            } catch (err) {
                alert("Deobfuscator Error: " + err.message);
            } finally {
                toggleLoading(false);
            }
        }

        // --- D. MAIN ANALYZE ---
        if (id === "analyzeBtn") handleMainAnalysis();

        // --- E. CHAT SEND ---
        if (id === "sendChatBtn") handleChat();
    });

    // ============================================================
    // 3. DASHBOARD UPDATER
    // ============================================================
    function updateDashboard(data) {
        console.log("🔥 Updating Dashboard:", data);

        // 1. Update Global State
        currentAnalysisData = data;
        window.currentAnalysisData = data;

        // 2. Risk Score
        const scoreDisplay = document.getElementById("riskScoreDisplay");
        if (scoreDisplay) {
            scoreDisplay.textContent = data.risk_score;
            scoreDisplay.className = `display-4 fw-bold ${getRiskColorText(data.risk_score)}`;
        }

        // 3. Malware Type
        const typeLabel = document.getElementById("malwareTypeLabel");
        if (typeLabel) {
            typeLabel.textContent = data.malware_type;
            typeLabel.className = `badge fs-6 ${getRiskColorBg(data.risk_score)}`;
        }

        // 4. AI Report
        const aiOutput = document.getElementById("aiExplanation");
        if (aiOutput) {
            aiOutput.classList.add("text-light");
            let rawText = data.explanation || "No AI report available.";

            // Silent Killer Fix: Append Binary Artifacts
            if (data.metadata && data.metadata.sha256 && data.code) {
                const preview = data.code.substring(0, 600);
                const binaryInfo = `
                ### Analysis Artifacts
                **SHA256:** \`${data.metadata.sha256}\`
                **MD5:** \`${data.metadata.md5 || 'N/A'}\`

                **Extracted Strings (Preview):**
                \`\`\`text
                ${preview}...
                \`\`\`
                *(Full strings available in 'Source Code' tab)*
                `;
                rawText += "\n" + binaryInfo;
            }
            aiOutput.innerHTML = (typeof marked !== 'undefined') ? marked.parse(rawText) : rawText;
        }

        // 5. Render Charts & Lists
        // We pass the risk matrix directly to the chart logic, behaviors to the list
        renderAttackChart(data.risk_matrix);
        renderBehaviors(data.behaviors || []);

        // 6. Show Results
        const resSection = document.getElementById("resultsSection");
        const emptyState = document.getElementById("emptyState");
        if (resSection) resSection.classList.remove("d-none");
        if (emptyState) emptyState.classList.add("d-none");
    }

    // ============================================================
    // 4. MAIN ANALYSIS HANDLER
    // ============================================================
    async function handleMainAnalysis() {
        const binaryTab = document.getElementById("binary-tab");
        const isBinaryTab = binaryTab && binaryTab.classList.contains("active");

        let url = `${API_BASE}/analyze`;
        let bodyData;
        let headers = {};

        if (isBinaryTab) {
            url = `${API_BASE}/analyze/binary`;
            const fileInput = document.getElementById("fileInput");
            if (!fileInput || !fileInput.files[0]) return alert("Select a binary file first.");

            const formData = new FormData();
            formData.append("file", fileInput.files[0]);
            bodyData = formData;
        } else {
            const codeInput = document.getElementById("codeInput");
            if (!codeInput || !codeInput.value.trim()) return alert("Paste source code first.");

            headers = { "Content-Type": "application/json" };
            bodyData = JSON.stringify({ code: codeInput.value });
        }

        toggleLoading(true);
        try {
            const res = await fetch(url, { method: "POST", headers, body: bodyData });
            if (!res.ok) throw new Error("Analysis Failed");

            const data = await res.json();
            updateDashboard(data);

            if (isBinaryTab) {
                const codeBox = document.getElementById("codeInput");
                if (codeBox && data.code) codeBox.value = data.code;
                alert("Analysis Complete! Risk Score Updated.");
            }

        } catch (e) {
            console.error("❌ Analysis Error:", e);
            alert(e.message);
        } finally {
            toggleLoading(false);
        }
    }

    // ============================================================
    // 5. GLOBAL FUNCTIONS (HTML Accessible)
    // ============================================================
    window.runStego = async function () {
        const fileInput = document.getElementById("stegoInput");
        if (!fileInput || !fileInput.files[0]) return alert("Upload an image first.");

        const formData = new FormData();
        formData.append("file", fileInput.files[0]);

        toggleLoading(true);
        try {
            const res = await fetch(`${API_BASE}/analyze/stego`, { method: "POST", body: formData });
            const data = await res.json();

            const output = document.getElementById("stegoResults");
            if (output) {
                output.classList.remove("d-none");
                let html = `<strong>Hidden Data:</strong> ${data.has_hidden_data ? '<span class="text-danger">YES</span>' : '<span class="text-success">NO</span>'}<br>`;

                if (data.has_hidden_data && data.behaviors) {
                    const secretMsg = data.behaviors.find(b => b.toLowerCase().includes("decoded") || b.toLowerCase().includes("hidden"));
                    if (secretMsg) html += `<div class="mt-2 p-2 bg-dark text-warning">${secretMsg}</div>`;
                }
                output.innerHTML = html;
            }
            updateDashboard(data);
        } catch (e) { alert("Stego Failed: " + e.message); } finally { toggleLoading(false); }
    };

    window.runPcap = async function () {
        const fileInput = document.getElementById("pcapInput");
        if (!fileInput || !fileInput.files[0]) return alert("Upload a .pcap file first.");

        const formData = new FormData();
        formData.append("file", fileInput.files[0]);

        toggleLoading(true);
        try {
            const res = await fetch(`${API_BASE}/analyze/pcap`, { method: "POST", body: formData });
            const data = await res.json();

            const output = document.getElementById("pcapResults");
            if (output) {
                output.classList.remove("d-none");
                output.innerHTML = `<div class="mb-2"><strong>Packets:</strong> ${data.packet_count}</div>` +
                    (data.risk_score > 50 ? `<div class="text-danger fw-bold">⚠️ Threats Found</div>` : `<div class="text-success">✔ Clean</div>`);
            }
            updateDashboard(data);
        } catch (e) { alert("PCAP Failed: " + e.message); } finally { toggleLoading(false); }
    };

    async function handleChat() {
        const input = document.getElementById("chatInput");
        const chatBody = document.getElementById("chatBody");
        const codeInput = document.getElementById("codeInput");

        if (!chatBody || !input.value.trim()) return;

        const question = input.value.trim();
        chatBody.innerHTML += `<div class="text-end mb-2"><span class="badge bg-primary p-2">${question}</span></div>`;
        input.value = "";

        try {
            const res = await fetch(`${API_BASE}/analyze/chat`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ code: codeInput ? codeInput.value : "", question: question })
            });

            if (!res.ok) throw new Error("Server Error");
            const data = await res.json();

            const formattedText = (typeof marked !== 'undefined') ? marked.parse(data.reply) : data.reply;
            chatBody.innerHTML += `<div class="text-start mb-2"><span class="badge bg-dark border border-secondary p-2 w-100 text-start" style="white-space: pre-wrap;">${formattedText}</span></div>`;
            chatBody.scrollTop = chatBody.scrollHeight;

        } catch (e) {
            chatBody.innerHTML += `<div class="text-center mb-2"><span class="badge bg-danger p-2">Error: ${e.message}</span></div>`;
        }
    }

    // ============================================================
    // 6. UTILITIES
    // ============================================================
    function toggleLoading(isLoading) {
        const overlay = document.getElementById("loadingOverlay");
        const main = document.getElementById("mainContainer");
        if (overlay) overlay.style.display = isLoading ? "flex" : "none";
        if (main) isLoading ? main.classList.add("blur-content") : main.classList.remove("blur-content");
    }

    function safeSetText(id, text) {
        const el = document.getElementById(id);
        if (el) el.textContent = text;
    }

    function getRiskColorText(score) {
        if (score >= 80) return "text-danger";
        if (score >= 40) return "text-warning";
        return "text-success";
    }

    function getRiskColorBg(score) {
        if (score >= 80) return "bg-danger";
        if (score >= 40) return "bg-warning text-dark";
        return "bg-success";
    }

    function renderBehaviors(behaviors) {
        const container = document.getElementById("behaviorsList");
        if (!container) return;

        if (!behaviors || behaviors.length === 0) {
            container.innerHTML = '<span class="text-muted">No specific threats detected.</span>';
            return;
        }

        container.innerHTML = [...new Set(behaviors)].map(b => {
            if (b.includes("DECODED") || b.includes("Hidden content")) return '';
            const isCrit = b.includes("CRITICAL") || b.includes("ALERT") || b.includes("Metasploit");
            return `<span class="badge ${isCrit ? 'bg-danger' : 'bg-dark border border-secondary'} p-2 m-1">${b}</span>`;
        }).join('');
    }

    // 🔥 FIXED: Now accepts the 'risk_matrix' object directly
    function renderAttackChart(riskMatrix) {
        const ctx = document.getElementById('attackChart');
        if (!ctx) return;

        // Default to zeros if no matrix exists
        let chartData = [0, 0, 0, 0, 0, 0, 0, 0];

        if (riskMatrix) {
            // 🔥 CRITICAL: Map Keys exactly as defined in risk_engine.py
            chartData = [
                riskMatrix["Exfiltration"] || 0,
                riskMatrix["C2"] || 0,
                riskMatrix["Obfuscation"] || 0,
                riskMatrix["Spyware"] || 0,
                riskMatrix["Crypto"] || 0,
                riskMatrix["Persistence"] || 0,
                riskMatrix["PrivEsc"] || 0,
                riskMatrix["Recon"] || 0
            ];
        }

        if (attackChartInstance) attackChartInstance.destroy();

        attackChartInstance = new Chart(ctx.getContext('2d'), {
            type: 'radar',
            data: {
                labels: ["Exfiltration", "C2", "Obfuscation", "Spyware", "Crypto", "Persistence", "PrivEsc", "Recon"],
                datasets: [{
                    label: 'Threat Intensity',
                    data: chartData,
                    backgroundColor: 'rgba(220, 53, 69, 0.2)',
                    borderColor: '#dc3545',
                    borderWidth: 2,
                    pointBackgroundColor: '#dc3545',
                    pointBorderColor: '#fff'
                }]
            },
            options: {
                scales: {
                    r: {
                        angleLines: { color: '#495057' },
                        grid: { color: '#495057' },
                        pointLabels: { color: '#adb5bd', font: { size: 11, family: 'Courier New' } },
                        suggestedMin: 0,
                        suggestedMax: 100,
                        ticks: { display: false, maxTicksLimit: 5 }
                    }
                },
                plugins: { legend: { display: false } }
            }
        });
    }

    console.log("✅ Frontend Ready!");
});