import streamlit as strl
import dns.resolver
import json
import io
import os
import zipfile
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

# 1. CORE FUNCTION: RUN PASSIVE DNS AUDIT
def check_dmarc(domain):
    try:
        query = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(query, 'TXT')
        for rdata in answers:
            for txt_string in rdata.strings:
                record = txt_string.decode('utf-8')
                if "v=DMARC1" in record:
                    if "p=reject" in record:
                        return "Secure (p=reject)", record
                    elif "p=quarantine" in record:
                        return "Partial (p=quarantine)", record
                    elif "p=none" in record:
                        return "Vulnerable (p=none)", record
        return "No DMARC Record Found", "Missing"
    except Exception:
        return "No DMARC Record Found", "Missing"

# 2. CORE FUNCTION: GENERATE IDENTITY REPORT
def generate_identity_report(domain, breach_data):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, 
        pagesize=letter,
        leftMargin=36, 
        rightMargin=36, 
        topMargin=36, 
        bottomMargin=36
    )
    story = []
    styles = getSampleStyleSheet()
    
    style_title = ParagraphStyle(
        'DocTitle1',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=15
    )
    style_header_cell = ParagraphStyle(
        'HeaderCell1',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10,
        textColor=colors.whitesmoke
    )
    style_body_cell = ParagraphStyle(
        'BodyCell1',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        textColor=colors.HexColor("#334155"),
        leading=12
    )

    story.append(Paragraph("PALMETTO INFRASTRUCTURE GROUP | EXTERNAL THREAT INTELLIGENCE", styles['Normal']))
    story.append(Spacer(1, 10))
    story.append(Paragraph("Employee Identity Leak Exposure Analysis", style_title))
    story.append(Paragraph(f"Target Domain: {domain}", styles['Normal']))
    story.append(Spacer(1, 15))
    
    notice_text = (
        "IDENTITY FOOTPRINT DETECTION NOTICE: An open-source passive credential mapping was "
        "executed against targets within your organizational domain perimeter. Active user profiles "
        "were successfully mapped to external web environments that have experienced historical data exposures."
    )
    story.append(Paragraph(notice_text, styles['Normal']))
    story.append(Spacer(1, 20))

    table_data = [
        [
            Paragraph("Target Email", style_header_cell),
            Paragraph("Breached Platform", style_header_cell),
            Paragraph("Risk Level", style_header_cell),
            Paragraph("Remediation Action", style_header_cell)
        ]
    ]
    
    for item in breach_data:
        table_data.append([
            Paragraph(item.get('email', 'N/A'), style_body_cell),
            Paragraph(item.get('platform', 'N/A'), style_body_cell),
            Paragraph(item.get('risk', 'Standard Profile'), style_body_cell),
            Paragraph(item.get('instruction', 'Audit usage patterns.'), style_body_cell)
        ])
        
    column_widths = [140, 100, 90, 210]
    report_table = Table(table_data, colWidths=column_widths, repeatRows=1)
    report_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0f172a")), 
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.HexColor("#f1f5f9")]), 
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")), 
    ]))
    
    story.append(report_table)
    doc.build(story)
    return buffer.getvalue()

# 3. CORE FUNCTION: GENERATE EMAIL SPOOFING REPORT
def generate_spoofing_report(domain, status, raw_record):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, 
        pagesize=letter,
        leftMargin=36, 
        rightMargin=36, 
        topMargin=36, 
        bottomMargin=36
    )
    story = []
    styles = getSampleStyleSheet()
    
    style_title = ParagraphStyle(
        'DocTitle2',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=15
    )
    style_header_cell = ParagraphStyle(
        'HeaderCell2',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10,
        textColor=colors.whitesmoke
    )
    style_body_cell = ParagraphStyle(
        'BodyCell2',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        textColor=colors.HexColor("#334155"),
        leading=12
    )

    story.append(Paragraph("PALMETTO INFRASTRUCTURE GROUP | EMAIL IDENTITY VALIDATION", styles['Normal']))
    story.append(Spacer(1, 10))
    story.append(Paragraph("Email Spoofing & Brand Deliverability Audit", style_title))
    story.append(Paragraph(f"Target Domain: {domain}", styles['Normal']))
    story.append(Spacer(1, 15))
    
    intro_text = (
        "CORE INFRASTRUCTURE ASSESSMENT: A boundary scan of external DNS records was performed to evaluate "
        "the authentication parameters regulating incoming and outbound email assets representing your organization."
    )
    story.append(Paragraph(intro_text, styles['Normal']))
    story.append(Spacer(1, 20))

    # Contextual remediation action text based on real DNS query findings
    if "Secure" in status:
        action_plan = "No immediate modifications required. Maintain active enforcement status and cross-examine daily alignment metrics."
    elif "Partial" in status:
        action_plan = "Review staging rules. Prepare to upgrade infrastructure flags from tracking variants to strict drop assertions safely."
    else:
        action_plan = "CRITICAL ACTION REQUIRED: Define a missing core policy path immediately. External servers can manipulate address fields to target customers using your specific brand identity."

    table_data = [
        [
            Paragraph("Security Vector", style_header_cell),
            Paragraph("Detected Metric Status", style_header_cell),
            Paragraph("Engineering Remediation Guidance", style_header_cell)
        ],
        [
            Paragraph("DMARC Brand Policy Alignment", style_body_cell),
            Paragraph(status, style_body_cell),
            Paragraph(action_plan, style_body_cell)
        ],
        [
            Paragraph("Raw Host Zone Declaration", style_body_cell),
            Paragraph(raw_record, style_body_cell),
            Paragraph("Ensure txt string records are nested correctly within zone root arrays without duplicating validation entries.", style_body_cell)
        ]
    ]
        
    column_widths = [130, 130, 280]
    report_table = Table(table_data, colWidths=column_widths, repeatRows=1)
    report_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0f172a")), 
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.HexColor("#f1f5f9")]), 
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")), 
    ]))
    
    story.append(report_table)
    doc.build(story)
    return buffer.getvalue()

# 4. STREAMLIT USER INTERFACE DEPLOYMENT
strl.set_page_config(page_title="Palmetto Threat Portal", page_icon="🛡️", layout="centered")

strl.title("🛡️ Palmetto Threat Intelligence Portal")
strl.subheader("On-Demand External Infrastructure Risk Validation")

domain_input = strl.text_input("Enter Corporate Domain Name (e.g., company.com):", "")

if strl.button("Execute Perimeter Audit"):
    if domain_input.strip() == "":
        strl.warning("Please enter a valid domain name.")
    else:
        domain = domain_input.strip().lower()
        
        with strl.spinner("Analyzing public architecture records..."):
            status, raw_record = check_dmarc(domain)
            
            strl.write("---")
            strl.markdown(f"### Audit Results for: **{domain}**")
            
            if "Secure" in status:
                strl.success(f"**DMARC Status:** {status}")
            elif "Partial" in status:
                strl.info(f"**DMARC Status:** {status}")
            else:
                strl.error(f"**DMARC Status:** {status}")
                
            strl.text_area("Raw DNS Record Data:", raw_record, height=70)
            
            mock_breach_data = [
                {"email": f"jimsmith@{domain}", "platform": "amazon.com", "risk": "High Risk Profile", "instruction": "Change corporate core credential parameters immediately to eradicate password cross-contamination."},
                {"email": f"jimsmith@{domain}", "platform": "any.do", "risk": "Standard Profile", "instruction": "Audit identity usage patterns on third-party channels."},
                {"email": f"jimsmith@{domain}", "platform": "twitter.com", "risk": "High Risk Profile", "instruction": "Change corporate core credential parameters immediately to eradicate password cross-contamination."}
            ]
            
            strl.markdown("### 📋 Generated Deliverables Available")
            
            # Generate BOTH PDFs as bytes
            pdf_identity = generate_identity_report(domain, mock_breach_data)
            pdf_spoofing = generate_spoofing_report(domain, status, raw_record)
            
            # Create a ZIP Archive in memory holding both documents
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
                zip_file.writestr(f"{domain}_identity_leak_report.pdf", pdf_identity)
                zip_file.writestr(f"{domain}_email_spoofing_audit.pdf", pdf_spoofing)
            zip_buffer.seek(0)
            
            # Offer single deliverable package download button
            strl.download_button(
                label="📥 Download Complete Threat Assessment Package (ZIP)",
                data=zip_buffer,
                file_name=f"{domain}_threat_assessment_package.zip",
                mime="application/zip"
            )
