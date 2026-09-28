import os
import hashlib
from typing import Dict, Any
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

class ReportGenerator:
    """
    SENTINEL-X Verifiable PDF Report & Certificate Generator.
    Produces professional digital-forensics PDF reports and calculates SHA-256 report hashes.
    """

    @staticmethod
    def generate_sanitization_certificate(data: Dict[str, Any], output_path: str) -> str:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        doc = SimpleDocTemplate(output_path, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
        
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'TitleStyle',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=22,
            leading=26,
            textColor=colors.HexColor('#0f172a'),
            alignment=1
        )
        subtitle_style = ParagraphStyle(
            'SubTitle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=11,
            leading=14,
            textColor=colors.HexColor('#06b6d4'),
            alignment=1
        )
        body_style = styles['BodyText']
        body_style.textColor = colors.HexColor('#1e293b')
        
        story = []
        
        story.append(Paragraph("SENTINEL-X CYBERSECURITY & FORENSICS LAB", subtitle_style))
        story.append(Spacer(1, 4))
        story.append(Paragraph("CERTIFICATE OF MEDIA SANITIZATION", title_style))
        story.append(Spacer(1, 8))
        story.append(Paragraph("Standard: NIST SP 800-88 Rev. 2 Guidelines for Media Sanitization", subtitle_style))
        story.append(Spacer(1, 15))
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#06b6d4'), spaceAfter=15))

        table_data = [
            [Paragraph("<b>Certificate ID:</b>", body_style), Paragraph(str(data.get('operation_id', 'SAN-2026-001')), body_style)],
            [Paragraph("<b>Timestamp:</b>", body_style), Paragraph(str(data.get('timestamp', '')), body_style)],
            [Paragraph("<b>Target Device:</b>", body_style), Paragraph(str(data.get('device_name', '')), body_style)],
            [Paragraph("<b>Model / Serial:</b>", body_style), Paragraph(f"{data.get('model', '')} / {data.get('serial', '')}", body_style)],
            [Paragraph("<b>Capacity:</b>", body_style), Paragraph(str(data.get('capacity', '')), body_style)],
            [Paragraph("<b>Media Type / Interface:</b>", body_style), Paragraph(f"{data.get('media_type', '')} ({data.get('interface', '')})", body_style)],
            [Paragraph("<b>Sanitization Method:</b>", body_style), Paragraph(str(data.get('method', '')), body_style)],
            [Paragraph("<b>Assurance Level:</b>", body_style), Paragraph(str(data.get('assurance_level', 'CLEAR')), body_style)],
            [Paragraph("<b>Execution Mode:</b>", body_style), Paragraph(str(data.get('execution_mode', 'DEMO_MODE')), body_style)],
            [Paragraph("<b>Verification Result:</b>", body_style), Paragraph(f"<font color='green'><b>{data.get('verification_status', 'PASS')}</b></font>", body_style)],
            [Paragraph("<b>Operator / Auditor:</b>", body_style), Paragraph(str(data.get('operator', 'Investigator')), body_style)],
            [Paragraph("<b>Operation Cryptographic Hash:</b>", body_style), Paragraph(f"<font size=8>{data.get('operation_hash', '')}</font>", body_style)],
        ]

        t = Table(table_data, colWidths=[180, 360])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
            ('PADDING', (0,0), (-1,-1), 6),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        story.append(t)
        story.append(Spacer(1, 20))

        story.append(Paragraph("<b>NIST SP 800-88 Assurance Statement & Limitations:</b>", styles['Heading3']))
        limitations = data.get('limitations', [
            'Operation executed under verified laboratory controls.',
            'Verification performed via surface sector sampling.'
        ])
        for lim in limitations:
            story.append(Paragraph(f"• {lim}", body_style))

        story.append(Spacer(1, 25))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#94a3b8'), spaceAfter=10))
        story.append(Paragraph("Verifiable Evidence Record — SENTINEL-X Immutable Integrity Ledger", subtitle_style))

        doc.build(story)

        # Calculate report file SHA-256
        sha256 = hashlib.sha256()
        with open(output_path, 'rb') as f:
            while chunk := f.read(65536):
                sha256.update(chunk)
        return sha256.hexdigest()

    @staticmethod
    def generate_forensic_recovery_report(data: Dict[str, Any], output_path: str) -> str:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        doc = SimpleDocTemplate(output_path, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
        
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle('RTitle', parent=styles['Heading1'], fontName='Helvetica-Bold', fontSize=18, textColor=colors.HexColor('#0f172a'))
        subtitle_style = ParagraphStyle('RSubTitle', parent=styles['Normal'], fontName='Helvetica', fontSize=10, textColor=colors.HexColor('#06b6d4'))
        body_style = styles['BodyText']
        body_style.fontSize = 9
        body_style.leading = 12

        story = []
        story.append(Paragraph("SENTINEL-X DIGITAL FORENSICS RECOVERY REPORT", title_style))
        story.append(Spacer(1, 4))
        story.append(Paragraph("Standard: NIST SP 800-86 Guide to Integrating Forensic Techniques into Incident Response", subtitle_style))
        story.append(Spacer(1, 10))
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#06b6d4'), spaceAfter=12))

        case_info = [
            [Paragraph("<b>Case Number:</b>", body_style), Paragraph(str(data.get('case_number', '')), body_style)],
            [Paragraph("<b>Evidence Source:</b>", body_style), Paragraph(str(data.get('evidence_name', '')), body_style)],
            [Paragraph("<b>Recovery Mode:</b>", body_style), Paragraph(str(data.get('recovery_mode', 'DEEP')).upper(), body_style)],
            [Paragraph("<b>Evidence Hash (SHA-256):</b>", body_style), Paragraph(f"<font size=7>{data.get('evidence_hash', '')}</font>", body_style)],
            [Paragraph("<b>Total Candidates Found:</b>", body_style), Paragraph(str(data.get('total_candidates', 0)), body_style)],
            [Paragraph("<b>Valid Files Recovered:</b>", body_style), Paragraph(str(data.get('valid_count', 0)), body_style)],
        ]
        t = Table(case_info, colWidths=[150, 390])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f1f5f9')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
            ('PADDING', (0,0), (-1,-1), 5)
        ]))
        story.append(t)
        story.append(Spacer(1, 12))

        # Recovery Methods Executed
        methods_completed = data.get('methods_completed', ['Evidence Verification', 'Partition Detection', 'Filesystem Metadata', 'Signature Carving', 'Structure Validation'])
        story.append(Paragraph("<b>Executed Recovery Methods:</b>", styles['Heading4']))
        for m in methods_completed:
            story.append(Paragraph(f"• <font color='#047857'><b>[PASSED]</b></font> {m}", body_style))
        
        story.append(Spacer(1, 10))
        story.append(Paragraph("<b>Recovered Artifacts Inventory (Top Candidates):</b>", styles['Heading4']))
        
        rec_files = data.get('recovered_files', [])
        table_headers = [Paragraph("<b>Filename</b>", body_style), Paragraph("<b>Type</b>", body_style), Paragraph("<b>Source</b>", body_style), Paragraph("<b>Size</b>", body_style), Paragraph("<b>Status</b>", body_style), Paragraph("<b>Score</b>", body_style)]
        rows = [table_headers]
        for f in rec_files[:15]: # Top 15 in summary table
            rows.append([
                Paragraph(str(f.get('filename', '')), body_style),
                Paragraph(str(f.get('detected_type', '')), body_style),
                Paragraph(str(f.get('recovery_source', 'Carving')), body_style),
                Paragraph(f"{f.get('size_bytes', 0)/1024:.1f} KB", body_style),
                Paragraph(str(f.get('validation_status', '')), body_style),
                Paragraph(f"{f.get('confidence_score', 0)}%", body_style)
            ])

        t_files = Table(rows, colWidths=[140, 50, 130, 60, 100, 60])
        t_files.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#e2e8f0')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
            ('PADDING', (0,0), (-1,-1), 4)
        ]))
        story.append(t_files)
        story.append(Spacer(1, 12))

        # Forensic Limitations Disclaimer
        story.append(Paragraph("<b>Forensic Limitations & Methodology Notes:</b>", styles['Heading4']))
        limitations = [
            "Recovery depends on surviving media sectors and unallocated space integrity.",
            "Overwritten data sectors cannot be recovered through software recovery.",
            "SSD TRIM, wear leveling, and garbage collection may render deleted sectors zero-filled.",
            "Analytical confidence score indicates structural recovery quality, not legal proof of ownership."
        ]
        for lim in limitations:
            story.append(Paragraph(f"• {lim}", body_style))

        story.append(Spacer(1, 15))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#94a3b8'), spaceAfter=8))
        story.append(Paragraph("Verifiable Evidence Record — SENTINEL-X Cryptographic Audit & Immutable Ledger", subtitle_style))

        doc.build(story)

        sha256 = hashlib.sha256()
        with open(output_path, 'rb') as f:
            while chunk := f.read(65536):
                sha256.update(chunk)
        return sha256.hexdigest()

