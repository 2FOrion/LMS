from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import Enum
import enum, hashlib

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="aluno")
    cpf = db.Column(db.String(14), unique=True)
    employee_id = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, pw): self.password_hash = generate_password_hash(pw)
    def check_password(self, pw): return check_password_hash(self.password_hash, pw)

class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    code = db.Column(db.String(64), unique=True, nullable=False)
    summary = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Lesson(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    course_id = db.Column(db.Integer, db.ForeignKey("course.id"), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    content_md = db.Column(db.Text, default="")
    order_index = db.Column(db.Integer, default=0)
    video_url = db.Column(db.String(500))
    attachment_url = db.Column(db.String(500))
    course = db.relationship("Course", backref=db.backref("lessons", lazy=True, order_by="Lesson.order_index"))

class Enrollment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey("course.id"), nullable=False)
    enrolled_at = db.Column(db.DateTime, default=datetime.utcnow)
    progress_pct = db.Column(db.Float, default=0.0)
    user = db.relationship("User", backref=db.backref("enrollments", lazy=True))
    course = db.relationship("Course", backref=db.backref("enrollments", lazy=True))

class QuizQuestion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    course_id = db.Column(db.Integer, db.ForeignKey("course.id"), nullable=False)
    question = db.Column(db.Text, nullable=False)
    options_json = db.Column(db.Text, nullable=False)  # JSON list
    correct_index = db.Column(db.Integer, nullable=False)
    course = db.relationship("Course", backref=db.backref("questions", lazy=True))

class QuizSubmission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey("course.id"), nullable=False)
    score_pct = db.Column(db.Float, nullable=False)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_name = db.Column(db.String(160))
    user_cpf = db.Column(db.String(20))

class Certificate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey("course.id"), nullable=False)
    issued_at = db.Column(db.DateTime)
    pdf_path = db.Column(db.String(255))  # path to generated PDF
    signature = db.Column(db.String(255), default="PENDENTE")

class OtpToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey("course.id"))
    code = db.Column(db.String(6), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    @staticmethod
    def new(db_session, user_id: int, course_id: int | None = None, ttl_minutes: int = 10):
        import random
        code = f"{random.randint(0, 999999):06d}"
        tok = OtpToken(user_id=user_id, course_id=course_id,
                       code=code, expires_at=datetime.utcnow()+timedelta(minutes=ttl_minutes))
        db_session.add(tok); db_session.commit(); return tok

class DocumentTemplate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(160), nullable=False)
    slug = db.Column(db.String(80), unique=True, nullable=False)
    content_md = db.Column(db.Text, nullable=False)

class DocumentEnvelope(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    template_id = db.Column(db.Integer, db.ForeignKey("document_template.id"), nullable=False)
    status = db.Column(db.String(20), default="PENDENTE")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship("User")
    template = db.relationship("DocumentTemplate")

class SignedDocument(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    envelope_id = db.Column(db.Integer, db.ForeignKey("document_envelope.id"), nullable=False)
    file_path = db.Column(db.String(255), nullable=False)
    sha256 = db.Column(db.String(64), nullable=False)
    signed_at = db.Column(db.DateTime, default=datetime.utcnow)
    signer_name = db.Column(db.String(160))
    signer_cpf = db.Column(db.String(20))
    method = db.Column(db.String(30), default="OTP")
    ip = db.Column(db.String(64))
    user_agent = db.Column(db.String(255))
    envelope = db.relationship("DocumentEnvelope")

class HiringStage(enum.Enum):
    CADASTRO = "Cadastro"
    DOCUMENTOS = "Documentos"
    TREINAMENTOS = "Treinamentos NR"
    CONTRATO = "Contrato"
    INTEGRACAO = "Integração"

class HiringPipeline(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    stage = db.Column(Enum(HiringStage), default=HiringStage.CADASTRO)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship("User")

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()
