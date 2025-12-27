from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
import io

def generate_pdf_report(data):
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    y = height - 50  # Start position

    # --- Header ---
    c.setFillColor(colors.darkblue)
    c.setFont("Helvetica-Bold", 20)
    c.drawString(50, y, "CyberSentinel - Malware Analysis Report")
    y -= 10
    c.setStrokeColor(colors.gray)
    c.line(50, y, width - 50, y)
    y -= 40

    # --- Executive Summary ---
    c.setFillColor(colors.black)
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, f"Malware Type: {data.get('malware_type', 'Unknown')}")
    c.drawString(350, y, f"Risk Score: {data.get('risk_score', 0)}/100")
    y -= 40

    # --- Detected Behaviors ---
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Detected Behaviors:")
    c.setFont("Helvetica", 10)
    
    behaviors = data.get('behaviors', [])
    unique_behaviors = list(set(behaviors))
    
    if not unique_behaviors:
        y -= 20
        c.drawString(70, y, "- No suspicious behaviors detected.")
    else:
        for b in unique_behaviors:
            y -= 20
            c.drawString(70, y, f"- {b}")
            # Check page break
            if y < 100:
                c.showPage()
                y = height - 50
    y -= 40

    # --- AI Analyst Summary ---
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "AI Analyst Insights:")
    y -= 20
    c.setFont("Helvetica", 10)
    
    # Text wrapping for AI explanation
    text = data.get('explanation', 'No analysis provided.')
    text = text.replace('**', '').replace('##', '') # Basic markdown cleaning
    
    for line in text.split('\n'):
        # Simple char wrap (approx 90 chars per line)
        while len(line) > 90:
            chunk = line[:90]
            line = line[90:]
            c.drawString(50, y, chunk)
            y -= 15
        c.drawString(50, y, line)
        y -= 15
        
        if y < 80:
            c.showPage()
            y = height - 50

    # --- 🔥 NEW: Analyzed Code Snippet ---
    y -= 30
    if y < 100: # Ensure header has space
        c.showPage()
        y = height - 50

    c.setFillColor(colors.darkred)
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Analyzed Source Code (Evidence):")
    y -= 20
    
    # Switch to Monospaced Font for Code
    c.setFont("Courier", 8) 
    c.setFillColor(colors.black)

    code_content = data.get('code', '')
    if not code_content:
        c.drawString(50, y, "[No code content available]")
    else:
        code_lines = code_content.split('\n')
        for line in code_lines:
            # Wrap long code lines
            while len(line) > 100:
                chunk = line[:100]
                line = line[100:]
                c.drawString(50, y, chunk)
                y -= 10
            c.drawString(50, y, line)
            y -= 10

            # Page break for long code
            if y < 50:
                c.showPage()
                y = height - 50
                c.setFont("Courier", 8) # Reset font on new page

    c.save()
    buffer.seek(0)
    return buffer.getvalue()