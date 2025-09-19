from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import cm
from reportlab.lib.utils import ImageReader
from datetime import datetime
import io, os

CERT_TITLE = "Certificado de Conclusão"

def build_certificate_pdf(user_name: str, course_title: str, score_pct: float) -> bytes:
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)
    w, h = A4
    c.setTitle(CERT_TITLE)

    # draw company logo if available
    logo_path = os.path.join(os.path.dirname(__file__), "static", "logo.png")
    if os.path.exists(logo_path):
        try:
            c.drawImage(ImageReader(logo_path), (w-8*cm)/2, h-5*cm, width=8*cm, height=3*cm, mask='auto')
        except Exception:
            pass

    c.setFont("Helvetica-Bold", 24)
    c.drawCentredString(w/2, h-4*cm, CERT_TITLE)
    c.setFont("Helvetica", 12)
    text = (
        f"Certificamos que {user_name} concluiu o curso {course_title} "
        f"com aproveitamento de {score_pct:.0f}% em {datetime.utcnow().strftime('%d/%m/%Y')}"
    )
    c.drawString(3*cm, h-6*cm, text)
    c.line(3*cm, 4*cm, w-3*cm, 4*cm)
    c.drawCentredString(w/2, 3.5*cm, "Assinatura Digital: emitido (OTP)")
    c.showPage()
    c.save()
    pdf = buffer.getvalue()
    buffer.close()
    return pdf
