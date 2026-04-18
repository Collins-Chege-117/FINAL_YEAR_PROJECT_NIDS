import io
from datetime import datetime, timedelta
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from database.db_config import SessionLocal
from database.models import Alert

def generate_threat_report():
   
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    elements = []
    styles = getSampleStyleSheet()

    
    title = Paragraph("<b>NIDS Shield: 24-Hour Threat Report</b>", styles['Title'])
    elements.append(title)
    elements.append(Spacer(1, 12))
    
    timestamp = Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal'])
    elements.append(timestamp)
    elements.append(Spacer(1, 24))

    
    db = SessionLocal()
    time_threshold = datetime.now() - timedelta(hours=24)
    
    
    alerts = db.query(Alert).filter(
        Alert.timestamp >= time_threshold,
        Alert.severity == 'HIGH'
    ).all()
    
    db.close()

    
    data = [["Timestamp", "Source IP", "Threat Type", "Severity"]]
    for alert in alerts:
        data.append([
            alert.timestamp.strftime('%H:%M:%S'),
            alert.source_ip,
            alert.threat_type,
            alert.severity
        ])

    
    if len(data) > 1:
        t = Table(data, colWidths=[100, 120, 200, 80])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        elements.append(t)
    else:
        elements.append(Paragraph("No threats detected in the last 24 hours.", styles['Normal']))

    
    doc.build(elements)
    buffer.seek(0)
    return buffer
