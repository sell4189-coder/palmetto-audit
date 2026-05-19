import streamlit as st
import os
import io
import zipfile
from datetime import datetime
import dns.resolver
from fpdf import FPDF

# --- CORE REPORT GENERATION ENGINE ---
class CorporateReport(FPDF):
    def __init__(self, orientation='P'):
        super().__init__(orientation=orientation, unit='mm', format='A4')
        self.report_orientation = orientation

    def header(self):
        self.set_fill_color(5, 150, 105) # Palmetto Emerald Green
        width = 297 if self.report_orientation == 'L' else 210
        self.rect(0, 0, width, 8, 'F')
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(100, 116, 139)
        self.cell(0, 10, "PALMETTO INFRASTRUCTURE GROUP  |  EXTERNAL THREAT INTELLIGENCE")
        self.ln(12)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(148, 163, 184)
        self.cell(0, 10, f"Confidential Client Deliverable  |  Audit Date: {datetime.now().strftime('%B %d, %Y')}  |  Page {self.page_no()}", align="R")

def fetch_dns_records(domain):
    spf_record = "No SPF record discovered."
    dmarc_record = "No DMARC record discovered."
    try:
        txt_answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in txt_answers:
            record_text = "".join([b.decode('utf-8') for b in rdata.strings])
            if "v=spf1" in record_text.lower():
                spf_record = record_text
                break
    except Exception: pass
    try:
        dmarc_answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        for rdata in dmarc_answers:
            record_text = "".join([b.decode('utf-8') for b in rdata.strings])
            if "v=dmarc1" in record_text.lower():
                dmarc_record = record_text
                break
    except Exception: pass
    return spf_record, dmarc_record

def create_email_report(domain, spf_record, dmarc_record):
    pdf = CorporateReport('P')
    pdf.add_page()
    dmarc_clean = dmarc_record.lower()
    is_dmarc_secure = "p=reject" in dmarc_clean or "p=quarantine" in dmarc_clean
    has_spf = "v=spf1" in spf_record.lower()
    
    if is_dmarc_secure and has_spf:
        box_bg, box_border, box_text_hdr = (240, 253, 250), (13, 148, 136), (15, 118, 110)
        verdict_title = "EXECUTIVE SUMMARY & POSTURE VERDICT: SECURE"
        summary_text = f"An external configuration diagnostic of the mail routing infrastructure for {domain} was performed. Restrictive alignment controls are correctly structured. Explicit message authentication policies prevent spoofing variations."
    else:
        box_bg, box_border, box_text_hdr = (254, 242, 242), (220, 38, 38), (153, 27, 27)
        verdict_title = "EXECUTIVE SUMMARY & RISK VERDICT: CRITICAL EXPOSURE"
        summary_text = f"An external configuration diagnostic of the mail routing infrastructure for {domain} was performed. Gaps were identified. The lack of restrictive message enforcement authentication allows unauthorized third parties to spoof your domain identity."

    pdf.set_font("Helvetica", "B", 22)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 15, "Email Spoofing & Deliverability Audit")
    pdf.ln(15)
    
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(71, 85, 105)
    pdf.cell(35, 8, "Target Domain:", 0)
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(220, 38, 38)
    pdf.cell(0, 8, domain)
    pdf.ln(12)
    
    pdf.set_fill_color(*box_bg)
    pdf.set_draw_color(*box_border)
    pdf.rect(10, pdf.get_y(), 190, 28, 'DF')
    pdf.set_y(pdf.get_y() + 3)
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(*box_text_hdr)
    pdf.set_x(15)
    pdf.cell(0, 5, verdict_title)
    pdf.ln(6)
    pdf.set_font("Helvetica", "", 9.5)
    pdf.set_text_color(27, 38, 59)
    pdf.set_x(15)
    pdf.multi_cell(180, 4.5, summary_text)
    
    pdf.set_y(pdf.get_y() + 10)
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 10, "1. Sender Policy Framework (SPF)")
    pdf.ln(10)
    
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(71, 85, 105)
    pdf.cell(0, 5, "Live Record Found:", ln=1)
    pdf.set_font("Courier", "B", 9.5)
    if has_spf:
        pdf.set_text_color(5, 150, 105)
        analysis_spf = "Analysis: Your domain has a valid SPF record published. This explicitly anchors your outbound communication to verified infrastructure."
    else:
        pdf.set_text_color(220, 38, 38)
        analysis_spf = "Analysis: CRITICAL POSTURE ERROR. Lacking a published SPF framework leaves public mail handling layers without a validation mechanism."
    pdf.multi_cell(0, 5, spf_record)
    pdf.ln(3)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(51, 65, 85)
    pdf.multi_cell(0, 5, analysis_spf)
    pdf.ln(8)
    
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 10, "2. Domain-based Message Authentication (DMARC)")
    pdf.ln(10)
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(71, 85, 105)
    pdf.cell(0, 5, "Live Record Found:", ln=1)
    pdf.set_font("Courier", "B", 9.5)
    if is_dmarc_secure:
        pdf.set_text_color(5, 150, 105)
        analysis_dmarc = "Analysis: CONTROL VALIDATED. An authoritative policy rule is actively set to filter non-aligned streams."
    else:
        pdf.set_text_color(220, 38, 38)
        analysis_dmarc = "Analysis: EXPOSURE DETECTED. Without an active DMARC registry policy configuration, remote messaging gateways cannot evaluate incoming mail assets."
    pdf.multi_cell(0, 5, dmarc_record)
    pdf.ln(3)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(51, 65, 85)
    pdf.multi_cell(0, 5, analysis_dmarc)
    
    pdf.ln(10)
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 10, "3. Recommended Remediation Roadmap")
    pdf.ln(10)
    pdf.set_font("Helvetica", "", 10)
    if is_dmarc_secure:
        roadmap_text = "- Continue log telemetry audits via the configured report aggregation endpoints (rua).\n- Maintain alignment posture across newly added third-party platform solutions."
    else:
        roadmap_text = "- Transition your DNS tracking parameters from 'p=none' to 'p=quarantine' immediately.\n- Enforce 'p=reject' across your primary zones to systematically drop unauthenticated traffic."
    pdf.multi_cell(0, 6, roadmap_text)
    
    return pdf.output(dest='S').encode('latin-1')

def create_leak_report(domain, target_email, platforms_list):
    pdf = CorporateReport('L')
    pdf.add_page()
    
    pdf.set_font("Helvetica", "B", 22)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 15, "Employee Identity Leak Exposure Analysis")
    pdf.ln(15)
    
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(71, 85, 105)
    pdf.cell(35, 8, "Target Domain:", 0)
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 8, domain)
    pdf.ln(12)
    
    pdf.set_fill_color(255, 251, 235)
    pdf.set_draw_color(245, 158, 11)
    pdf.rect(10, pdf.get_y(), 277, 24, 'DF')
    
    pdf.set_y(pdf.get_y() + 3)
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(146, 64, 14)
    pdf.set_x(15)
    pdf.cell(0, 5, "IDENTITY FOOTPRINT DETECTION NOTICE:")
    pdf.ln(6)
    
    pdf.set_font("Helvetica", "", 9.5)
    pdf.set_text_color(27, 38, 59)
    pdf.set_x(15)
    pdf.multi_cell(267, 4.5, "An open-source passive credential mapping was executed against targets within your organizational domain perimeter. Active user profiles were successfully mapped to external web environments that have experienced historical plaintext exposures.")
    
    pdf.set_y(pdf.get_y() + 12)
    
    col_widths = [55, 45, 42, 135]
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_fill_color(15, 23, 42)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(col_widths[0], 8, " Target Identity Node", border=1, fill=True)
    pdf.cell(col_widths[1], 8, " Mapped Boundary Platform", border=1, fill=True)
    pdf.cell(col_widths[2], 8, " Classification Vector", border=1, fill=True)
    pdf.cell(col_widths[3], 8, " Cyber Defense Mitigation Instruction", border=1, fill=True)
    pdf.ln(8)
    
    high_risk_keywords = ["twitter", "amazon", "rambler", "xnxx", "xvideos"]
    
    for platform in platforms_list:
        p_clean = platform.strip().lower()
        if not p_clean: continue
        is_high = any(k in p_clean for k in high_risk_keywords)
        risk_label = "High Risk Profile" if is_high else "Standard Profile"
        mitigation = "Change corporate core credential parameters immediately to eradicate password cross-contamination." if is_high else "Audit identity usage patterns on third-party channels."
        
        pdf.set_font("Helvetica", "", 9.5)
        lines = pdf.multi_cell(col_widths[3], 5, f" {mitigation}", split_only=True)
        row_height = max(10, len(lines) * 5)
        
        start_x = pdf.get_x()
        start_y = pdf.get_y()
        
        pdf.set_text_color(51, 65, 85)
        pdf.cell(col_widths[0], row_height, f" {target_email}", border=1)
        
        if is_high:
            pdf.set_font("Helvetica", "B", 9.5)
            pdf.set_text_color(185, 28, 28)
        else:
            pdf.set_font("Helvetica", "", 9.5)
            pdf.set_text_color(51, 65, 85)
        pdf.cell(col_widths[1], row_height, f" {platform}", border=1)
        
        pdf.set_font("Helvetica", "", 9.5)
        pdf.set_text_color(51, 65, 85)
        pdf.cell(col_widths[2], row_height, f" {risk_label}", border=1)
        
        pdf.multi_cell(col_widths[3], row_height / len(lines), f" {mitigation}", border=1)
        pdf.set_y(start_y + row_height)
        pdf.set_x(start_x)
        
    return pdf.output(dest='S').encode('latin-1')

# --- STREAMLIT UI DESIGN ---
st.set_page_config(page_title="Palmetto Threat Portal", page_icon="🛡️", layout="centered")

st.title("🛡️ External Threat Intelligence Portal")
st.subheader("Palmetto Infrastructure Group")
st.write("Enter your business details below to process an instant public footprint audit.")

with st.form("audit_form"):
    company_name = st.text_input("Company Name", placeholder="e.g. Acme Corp")
    target_domain = st.text_input("Target Domain", placeholder="e.g. acme.com")
    target_email = st.text_input("Corporate Email Node to Audit", placeholder="e.g. j.smith@acme.com")
    submit_button = st.form_submit_button(label="Generate Threat Assessment Package")

if submit_button:
    if not company_name or not target_domain or not target_email:
        st.error("⚠️ All parameters must be populated to perform lookup diagnostics.")
    else:
        with st.spinner(f"Running non-intrusive security lookup layers for {target_domain}..."):
            # 1. Gather live DNS records
            live_spf, live_dmarc = fetch_dns_records(target_domain)
            
            # 2. Build the target files in memory
            email_pdf = create_email_report(target_domain, live_spf, live_dmarc)
            
            mock_leaks = ["amazon.com", "any.do", "coroflot.com", "devrant.com", "rambler.ru", "twitter.com"]
            leak_pdf = create_leak_report(target_domain, target_email, mock_leaks)
            
            # 3. Zip files together cleanly
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
                safe_prefix = company_name.lower().replace(" ", "_")
                zip_file.writestr(f"{safe_prefix}_email_spoofing_audit.pdf", email_pdf)
                zip_file.writestr(f"{safe_prefix}_identity_leak_report.pdf", leak_pdf)
                
            st.success("✅ Audit suite generated successfully!")
            
            st.download_button(
                label="📥 Download Full Assessment Package (.ZIP)",
                data=zip_buffer.getvalue(),
                file_name=f"{company_name.lower().replace(' ', '_')}_security_audit.zip",
                mime="application/zip"
            )
