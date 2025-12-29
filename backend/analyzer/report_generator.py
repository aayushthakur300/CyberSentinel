import io
import math
import datetime
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors

# =========================================================================
# HELPER: DRAW PAGE BORDER & FOOTER
# =========================================================================
def draw_page_template(c, width, height):
    """Draws the standard CyberSentinel border and footer on every page."""
    # 1. Border
    c.setStrokeColor(colors.darkblue)
    c.setLineWidth(2)
    c.rect(15, 15, width-30, height-30)
    
    # 2. Footer Timestamp
    c.setFillColor(colors.gray)
    c.setFont("Helvetica", 9)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.drawRightString(width - 25, 25, f"CyberSentinel Analysis | Generated: {timestamp}")
    c.setLineWidth(1) # Reset line width

# =========================================================================
# MAIN PDF GENERATION LOGIC
# =========================================================================
def generate_pdf_report(data):
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    
    # --- STYLING CONSTANTS ---
    MARGIN = 50
    CONTENT_WIDTH = width - (2 * MARGIN)
    BOTTOM_LIMIT = 60  # 🔥 SAFETY MARGIN: Stop drawing if Y is below this
    
    # ==========================================
    # PAGE 1: EXECUTIVE SUMMARY
    # ==========================================
    draw_page_template(c, width, height)
    
    # Header
    y = height - 60
    c.setFillColor(colors.darkblue)
    c.setFont("Helvetica-Bold", 24)
    c.drawString(40, y, "CyberSentinel Security Report")
    
    y -= 20
    c.setStrokeColor(colors.gray)
    c.line(40, y, width - 40, y)
    y -= 50
    
    # Risk Score Badge (Big & Visual)
    score = data.get('risk_score', 0)
    
    # Dynamic Color Selection
    score_color = colors.green
    risk_text = "LOW RISK"
    if score >= 50: 
        score_color = colors.orange
        risk_text = "HIGH RISK"
    if score >= 80: 
        score_color = colors.red
        risk_text = "CRITICAL"
    
    # Draw Score Circle
    c.setStrokeColor(score_color)
    c.setLineWidth(4)
    c.circle(100, y, 40)
    
    c.setFillColor(score_color)
    c.setFont("Helvetica-Bold", 22)
    c.drawCentredString(100, y - 8, str(score))
    
    c.setFont("Helvetica-Bold", 12)
    c.drawCentredString(100, y - 60, risk_text)
    
    # Verdict & Hash Info
    c.setFillColor(colors.black)
    c.setFont("Helvetica-Bold", 14)
    c.drawString(180, y + 10, f"Verdict: {data.get('malware_type', 'Unknown')}")
    
    c.setFont("Helvetica", 10)
    c.setFillColor(colors.gray)
    file_hash = data.get('metadata', {}).get('sha256', 'N/A')
    c.drawString(180, y - 10, f"SHA256: {file_hash[:40]}...")
    
    y -= 80
    
    # Detected Behaviors Section
    c.setFillColor(colors.darkblue)
    c.setFont("Helvetica-Bold", 14)
    c.drawString(40, y, "Detected Behaviors & Tactics:")
    y -= 25
    
    c.setFillColor(colors.black)
    c.setFont("Helvetica", 10)
    
    behaviors = list(set(data.get('behaviors', [])))
    if not behaviors:
        c.drawString(60, y, "- No suspicious behaviors detected.")
        y -= 15
    else:
        # Limit to fit on first page
        for b in behaviors[:10]: 
            # Color code specific threats in the list
            if "CRITICAL" in b: c.setFillColor(colors.red)
            elif "High" in b: c.setFillColor(colors.orange)
            else: c.setFillColor(colors.black)
            
            c.drawString(60, y, f"• {b}")
            y -= 15
    
    y -= 25
    
    # --- AI ANALYST INSIGHTS (SMART FORMATTING) ---
    c.setFillColor(colors.darkblue)
    c.setFont("Helvetica-Bold", 14)
    c.drawString(40, y, "AI Analyst Insights:")
    y -= 25
    
    explanation = data.get('explanation', "No detailed analysis provided.")
    
    # Smart Text Rendering Loop
    text_y = y
    
    for line in explanation.split('\n'):
        line = line.strip()
        if not line:
            text_y -= 8 # Small gap for empty lines
            continue
            
        # 1. Detect Styles
        is_header = False
        is_bullet = False
        
        # Header Detection
        if line.startswith('#') or (line.startswith('**') and line.endswith('**')):
            c.setFont("Helvetica-Bold", 11)
            c.setFillColor(colors.darkblue)
            line = line.replace('#', '').replace('**', '').strip()
            is_header = True
            text_y -= 5 # Extra spacing before header
        # Bullet Detection
        elif line.startswith('* ') or line.startswith('- '):
            c.setFont("Helvetica", 10)
            c.setFillColor(colors.black)
            line = "• " + line[2:].replace('**', '') 
            is_bullet = True
        # Normal Text
        else:
            c.setFont("Helvetica", 10)
            c.setFillColor(colors.black)
            line = line.replace('**', '') 

        # 2. Text Wrapping & Printing
        words = line.split()
        current_line = ""
        indent = 15 if is_bullet else 0
        
        for word in words:
            # Measure width
            if c.stringWidth(current_line + " " + word) < (CONTENT_WIDTH - indent):
                current_line += " " + word
            else:
                # 🔥 FIX: Check space BEFORE drawing wrapped line
                if text_y < BOTTOM_LIMIT:
                    c.showPage()
                    draw_page_template(c, width, height)
                    text_y = height - 60
                    # Restore font after page break
                    if is_header: c.setFont("Helvetica-Bold", 11)
                    else: c.setFont("Helvetica", 10)
                    c.setFillColor(colors.darkblue if is_header else colors.black)

                # Draw current line and wrap
                c.drawString(MARGIN + indent, text_y, current_line.strip())
                text_y -= 14 # Line height
                current_line = word
        
        # 🔥 FIX: Check space BEFORE drawing the last part of the line
        if text_y < BOTTOM_LIMIT:
            c.showPage()
            draw_page_template(c, width, height)
            text_y = height - 60
            if is_header: c.setFont("Helvetica-Bold", 11)
            else: c.setFont("Helvetica", 10)
            c.setFillColor(colors.darkblue if is_header else colors.black)

        # Draw the last part of the line
        c.drawString(MARGIN + indent, text_y, current_line.strip())
        text_y -= 14
        
    c.showPage() # End Page 1

    # ==========================================
    # PAGE 2+: SOURCE CODE EVIDENCE
    # ==========================================
    draw_page_template(c, width, height)
    
    y = height - 60
    c.setFillColor(colors.darkred)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(40, y, "Forensic Evidence: Source Code")
    y -= 30
    
    c.setFont("Courier", 9)
    c.setFillColor(colors.black)
    
    code = data.get('code', "No source code available.")
    lines = code.split('\n')
    
    line_height = 11
    
    for line in lines:
        # Wrap long code lines
        while len(line) > 95:
            chunk = line[:95]
            line = line[95:]
            
            # 🔥 FIX: Check space BEFORE drawing
            if y < BOTTOM_LIMIT:
                c.showPage()
                draw_page_template(c, width, height)
                y = height - 60
                c.setFont("Courier", 9)
                c.setFillColor(colors.black)

            c.drawString(40, y, chunk)
            y -= line_height
            
        # 🔥 FIX: Check space BEFORE drawing remainder
        if y < BOTTOM_LIMIT:
            c.showPage()
            draw_page_template(c, width, height)
            y = height - 60
            c.setFont("Courier", 9)
            c.setFillColor(colors.black)

        c.drawString(40, y, line)
        y -= line_height

    c.showPage()
    
    # ==========================================
    # LAST PAGE: FULL RADAR SYSTEM VISUALIZATION
    # ==========================================
    draw_page_template(c, width, height)
    
    # Chart Title
    c.setFillColor(colors.darkblue)
    c.setFont("Helvetica-Bold", 20)
    c.drawCentredString(width/2, height - 80, "8-Axis Threat Vector Analysis")
    
    # Radar Chart Settings
    cx, cy = width / 2, height / 2  # Center of page
    radar_radius = 220              # Large size
    
    # Get Data from Backend
    matrix = data.get('risk_matrix', {})
    keys = ["Exfiltration", "C2", "Obfuscation", "Spyware", "Crypto", "Persistence", "PrivEsc", "Recon"]
    values = [matrix.get(k, 0) for k in keys]
    
    # 1. Draw Background Grid (Spider Web)
    c.setLineWidth(1)
    c.setStrokeColor(colors.lightgrey)
    angle_step = 2 * math.pi / 8
    
    # Draw 5 concentric rings
    for i in range(1, 6): 
        r = radar_radius * (i / 5)
        p = c.beginPath()
        start_x = cx + r * math.cos(math.pi/2) 
        start_y = cy + r * math.sin(math.pi/2)
        p.moveTo(start_x, start_y)
        
        for j in range(1, 9): 
            angle = (math.pi/2) - (j * angle_step)
            px = cx + r * math.cos(angle)
            py = cy + r * math.sin(angle)
            p.lineTo(px, py)
        p.close()
        c.drawPath(p, stroke=1, fill=0)
        
    # 2. Draw Axes & Labels
    c.setFont("Helvetica-Bold", 12)
    c.setFillColor(colors.black)
    c.setStrokeColor(colors.grey)
    
    for j, label in enumerate(keys):
        angle = (math.pi/2) - (j * angle_step)
        
        # Axis Line
        end_x = cx + radar_radius * math.cos(angle)
        end_y = cy + radar_radius * math.sin(angle)
        c.line(cx, cy, end_x, end_y)
        
        # Label Positioning
        lbl_dist = radar_radius + 35
        lbl_x = cx + lbl_dist * math.cos(angle)
        lbl_y = cy + lbl_dist * math.sin(angle)
        
        c.drawCentredString(lbl_x, lbl_y, label)

    # 3. Draw Data Polygon (The Threat Shape)
    c.setStrokeColor(colors.red)
    c.setLineWidth(3)
    
    p = c.beginPath()
    # First point
    val_norm = values[0] / 100.0
    start_x = cx + (radar_radius * val_norm) * math.cos(math.pi/2)
    start_y = cy + (radar_radius * val_norm) * math.sin(math.pi/2)
    p.moveTo(start_x, start_y)
    
    dots = [(start_x, start_y)]
    
    for j in range(1, 8):
        val_norm = values[j] / 100.0
        angle = (math.pi/2) - (j * angle_step)
        px = cx + (radar_radius * val_norm) * math.cos(angle)
        py = cy + (radar_radius * val_norm) * math.sin(angle)
        p.lineTo(px, py)
        dots.append((px, py))
        
    p.close()
    c.drawPath(p, stroke=1, fill=0)
    
    # 4. Draw Data Points
    c.setFillColor(colors.red)
    for dot in dots:
        c.circle(dot[0], dot[1], 4, fill=1, stroke=0)

    # Caption
    c.setFillColor(colors.gray)
    c.setFont("Helvetica", 10)
    c.drawCentredString(width/2, 50, "Visual Representation of Threat Intensity by Category")

    c.showPage()
    c.save()
    
    buffer.seek(0)
    return buffer.getvalue()