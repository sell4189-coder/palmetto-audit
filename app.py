from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

def generate_identity_report(filename, domain, breach_data):
    # 1. Setup Document Setup with 0.5-inch margins (Letter width is 612, printable area is 540)
    doc = SimpleDocTemplate(
        filename, 
        pagesize=letter,
        leftMargin=36, 
        rightMargin=36, 
        topMargin=36, 
        bottomMargin=36
    )
    story = []
    
    # 2. Setup Typography Styles
    styles = getSampleStyleSheet()
    
    # Custom text styles to handle cell wrapping cleanly
    style_header_cell = ParagraphStyle(
        'HeaderCell',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10,
        textColor=colors.whitesmoke
    )
    
    style_body_cell = ParagraphStyle(
        'BodyCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        textColor=colors.HexColor("#cbd5e1"), # Light text corresponding to your slate UI
        leading=12
    )

    # ... Include your document Header / Title logic here ...
    # Example:
    # story.append(Paragraph("Employee Identity Leak Exposure Analysis", styles['Title']))
    # story.append(Spacer(1, 15))

    # 3. Build Table Structure with Clean Headers
    # Replacing truncated text strings with concise titles
    table_data = [
        [
            Paragraph("Target Email", style_header_cell),
            Paragraph("Breached Platform", style_header_cell),
            Paragraph("Risk Level", style_header_cell),
            Paragraph("Remediation Action", style_header_cell)
        ]
    ]
    
    # 4. Populate Dynamic Rows and Wrap Content
    for item in breach_data:
        # Expected keys matching your data collection structures
        email = item.get('email', 'N/A')
        platform = item.get('platform', 'N/A')
        risk = item.get('risk', 'Standard Profile')
        instruction = item.get('instruction', 'Audit usage patterns.')
        
        table_data.append([
            Paragraph(email, style_body_cell),
            Paragraph(platform, style_body_cell),
            Paragraph(risk, style_body_cell),
            Paragraph(instruction, style_body_cell)
        ])
        
    # 5. Enforce Strict Column Width Matching
    # Combined width matches the 540px printable canvas space perfectly
    column_widths = [140, 100, 90, 210]
    
    report_table = Table(table_data, colWidths=column_widths, repeatRows=1)
    
    # 6. Apply Professional Table Styling
    report_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0f172a")), # Dark slate background for header
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor("#1e293b"), colors.HexColor("#334155")]), # Alternate slate rows
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#475569")), # Subtle borders
    ]))
    
    story.append(report_table)
    
    # 7. Compile Layout Architecture
    doc.build(story)
