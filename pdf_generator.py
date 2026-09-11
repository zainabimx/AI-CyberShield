from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.enums import TA_CENTER
from reportlab.pdfbase import pdfmetrics
import tempfile


def create_incident_pdf(report_text):
    """
    Creates a professional PDF from the incident report.
    Returns the temporary PDF path.
    """

    styles = getSampleStyleSheet()

    title_style = styles["Heading1"]
    title_style.alignment = TA_CENTER

    heading_style = styles["Heading2"]

    body_style = styles["BodyText"]

    temp = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")

    doc = SimpleDocTemplate(temp.name)

    story = []

    story.append(Paragraph("AI CYBERSHIELD", title_style))
    story.append(Paragraph("Security Incident Report", heading_style))

    story.append(Paragraph("<br/><br/>", body_style))

    # Convert Markdown-like report into PDF paragraphs
    for line in report_text.split("\n"):

        line = line.strip()

        if not line:
            story.append(Paragraph("<br/>", body_style))
            continue

        if line.startswith("#"):
            story.append(
                Paragraph(
                    line.replace("#", "").strip(),
                    heading_style
                )
            )

        else:
            story.append(
                Paragraph(
                    line.replace("|", " "),
                    body_style
                )
            )

    doc.build(story)

    return temp.name