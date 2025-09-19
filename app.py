import os, json, csv
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, request, flash, abort, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from dotenv import load_dotenv

from models import db, User, Course, Lesson, Enrollment, QuizQuestion, QuizSubmission, Certificate, OtpToken, DocumentTemplate, DocumentEnvelope, SignedDocument, HiringPipeline, HiringStage, sha256_file
from mailer import send_mail
from certs import build_certificate_pdf

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "troque-isto")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///local.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

login_manager = LoginManager(app)
login_manager.login_view = "login"

db.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.before_request
def ensure_db():
    with app.app_context():
        db.create_all()

def is_admin():
    return current_user.is_authenticated and current_user.role == "admin"

# --------- Público/Auth ---------
@app.get("/")
def index():
    courses = Course.query.order_by(Course.created_at.desc()).limit(6).all()
    my_progress = None
    if current_user.is_authenticated:
        my_progress = db.session.query(Enrollment.course_id, Enrollment.progress_pct).filter(Enrollment.user_id==current_user.id).all()
    return render_template("index.html", courses=courses, my_progress=my_progress)

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name","").strip()
        email = request.form.get("email","").lower().strip()
        password = request.form.get("password","")
        cpf = request.form.get("cpf","")
        if User.query.filter_by(email=email).first():
            flash("E-mail já cadastrado.", "warning"); return redirect(url_for("register"))
        u = User(name=name, email=email, cpf=cpf); u.set_password(password)
        db.session.add(u); db.session.commit()
        flash("Conta criada! Faça login.", "success")
        return redirect(url_for("login"))
    return render_template("auth_register.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email","").lower().strip(); password = request.form.get("password","")
        u = User.query.filter_by(email=email).first()
        if u and u.check_password(password):
            login_user(u); flash("Bem-vindo(a)!", "success"); return redirect(url_for("dashboard"))
        flash("Credenciais inválidas.", "danger")
    return render_template("auth_login.html")

@app.get("/logout")
@login_required
def logout():
    logout_user(); flash("Sessão encerrada.", "info"); return redirect(url_for("index"))

# --------- Aluno ---------
@app.get("/dashboard")
@login_required
def dashboard():
    my_enrolls = Enrollment.query.filter_by(user_id=current_user.id).all()
    my_courses = [e.course for e in my_enrolls]
    subs = QuizSubmission.query.filter_by(user_id=current_user.id).order_by(QuizSubmission.submitted_at.desc()).all()
    return render_template("dashboard.html", courses=my_courses, subs=subs)

@app.get("/courses")
@login_required
def course_list():
    return render_template("course_list.html", courses=Course.query.order_by(Course.title).all())

@app.get("/course/<int:course_id>")
@login_required
def course_detail(course_id):
    c = db.session.get(Course, course_id) or abort(404)
    enrolled = Enrollment.query.filter_by(user_id=current_user.id, course_id=c.id).first()
    return render_template("course_detail.html", c=c, enrolled=bool(enrolled))

@app.post("/course/<int:course_id>/enroll")
@login_required
def enroll(course_id):
    c = db.session.get(Course, course_id) or abort(404)
    already = Enrollment.query.filter_by(user_id=current_user.id, course_id=c.id).first()
    if not already:
        db.session.add(Enrollment(user_id=current_user.id, course_id=c.id))
        db.session.commit()
        send_mail(current_user.email, f"Inscrição em {c.title}", f"Você se inscreveu no curso <b>{c.title}</b>.")
    return redirect(url_for("course_detail", course_id=c.id))

@app.get("/lesson/<int:lesson_id>")
@login_required
def lesson_view(lesson_id):
    l = db.session.get(Lesson, lesson_id) or abort(404)
    lessons = Lesson.query.filter_by(course_id=l.course_id).count()
    if lessons:
        enr = Enrollment.query.filter_by(user_id=current_user.id, course_id=l.course_id).first()
        if enr:
            idx = l.order_index + 1
            enr.progress_pct = max(enr.progress_pct, (idx/lessons)*100)
            db.session.commit()
    return render_template("lesson.html", l=l)

@app.route("/course/<int:course_id>/quiz", methods=["GET","POST"])
@login_required
def course_quiz(course_id):
    c = db.session.get(Course, course_id) or abort(404)
    qs = QuizQuestion.query.filter_by(course_id=c.id).all()
    if request.method == "POST":
        correct = 0
        for q in qs:
            ans = request.form.get(f"q_{q.id}")
            if ans is not None and int(ans) == q.correct_index:
                correct += 1
        score = int((correct/len(qs))*100) if qs else 0
        sub = QuizSubmission(user_id=current_user.id, course_id=c.id, score_pct=score,
                             user_name=current_user.name, user_cpf=current_user.cpf or "")
        db.session.add(sub)
        if score >= 70:
            db.session.add(Certificate(user_id=current_user.id, course_id=c.id))
        db.session.commit()
        flash(f"Prova enviada! Nota: {score}%", "success")
        return redirect(url_for("dashboard"))
    return render_template("quiz.html", c=c, qs=qs)

# --------- Certificado (OTP + PDF) ---------
@app.post("/certificate/<int:course_id>/request-signature")
@login_required
def request_signature(course_id):
    c = db.session.get(Course, course_id) or abort(404)
    cert = Certificate.query.filter_by(user_id=current_user.id, course_id=c.id).first()
    if not cert:
        flash("Aprovação necessária antes do certificado.", "warning")
        return redirect(url_for("course_detail", course_id=c.id))
    tok = OtpToken.new(db.session, current_user.id, c.id, ttl_minutes=10)
    send_mail(current_user.email, f"Código de assinatura — {c.title}", f"Seu código: <b>{tok.code}</b> (10 min)")
    flash("Código enviado por e-mail.", "info")
    return redirect(url_for("course_detail", course_id=c.id))

@app.post("/certificate/<int:course_id>/sign")
@login_required
def sign_certificate(course_id):
    c = db.session.get(Course, course_id) or abort(404)
    code = request.form.get("code","").strip()
    tok = OtpToken.query.filter_by(user_id=current_user.id, course_id=c.id, code=code).order_by(OtpToken.id.desc()).first()
    if not tok or tok.expires_at < datetime.utcnow():
        flash("Código inválido/expirado.", "danger")
        return redirect(url_for("course_detail", course_id=c.id))
    cert = Certificate.query.filter_by(user_id=current_user.id, course_id=c.id).first() or abort(404)
    pdf_bytes = build_certificate_pdf(current_user.name, c.title, 100.0)
    pdf_path = f"cert_{current_user.id}_{c.id}.pdf"
    with open(pdf_path, "wb") as f: f.write(pdf_bytes)
    cert.pdf_path = pdf_path
    cert.signature = f"OTP:{code}"
    cert.issued_at = datetime.utcnow()
    db.session.commit()
    flash("Certificado assinado e emitido!", "success")
    return send_file(pdf_path, mimetype="application/pdf", as_attachment=True, download_name=os.path.basename(pdf_path))

# --------- Sala de Assinatura (Documentos) ---------
@app.get("/docs")
@login_required
def my_docs():
    envs = DocumentEnvelope.query.filter_by(user_id=current_user.id).order_by(DocumentEnvelope.created_at.desc()).all()
    return render_template("docs_list.html", envelopes=envs)

@app.get("/docs/<int:env_id>")
@login_required
def docs_view(env_id):
    envp = db.session.get(DocumentEnvelope, env_id) or abort(404)
    if envp.user_id != current_user.id and not is_admin(): abort(403)
    return render_template("docs_sign.html", env=envp)

@app.post("/docs/<int:env_id>/request-code")
@login_required
def docs_request_code(env_id):
    envp = db.session.get(DocumentEnvelope, env_id) or abort(404)
    if envp.user_id != current_user.id: abort(403)
    tok = OtpToken.new(db.session, current_user.id, None, ttl_minutes=10)
    send_mail(current_user.email, "Código para assinatura", f"Seu código: <b>{tok.code}</b> (10 min)")
    flash("Código enviado por e-mail.", "info")
    return redirect(url_for("docs_view", env_id=envp.id))

@app.post("/docs/<int:env_id>/sign")
@login_required
def docs_sign(env_id):
    envp = db.session.get(DocumentEnvelope, env_id) or abort(404)
    if envp.user_id != current_user.id: abort(403)
    code = request.form.get("code","").strip()
    tok = OtpToken.query.filter_by(user_id=current_user.id, code=code).order_by(OtpToken.id.desc()).first()
    if not tok or tok.expires_at < datetime.utcnow():
        flash("Código inválido/expirado.", "danger")
        return redirect(url_for("docs_view", env_id=envp.id))
    # gerar PDF simples reaproveitando builder do certificado
    pdf_bytes = build_certificate_pdf(current_user.name, envp.template.name, 100.0)
    out_path = f"signed_{envp.id}_{current_user.id}.pdf"
    with open(out_path, "wb") as f: f.write(pdf_bytes)
    doc = SignedDocument(envelope_id=envp.id, file_path=out_path,
                         sha256=sha256_file(out_path), signer_name=current_user.name,
                         signer_cpf=current_user.cpf or "", method="OTP")
    envp.status = "ASSINADO"
    db.session.add(doc); db.session.commit()
    flash("Documento assinado e salvo!", "success")
    return redirect(url_for("my_docs"))

@app.get("/docs/download/<int:doc_id>")
@login_required
def docs_download(doc_id):
    doc = db.session.get(SignedDocument, doc_id) or abort(404)
    envp = db.session.get(DocumentEnvelope, doc.envelope_id) or abort(404)
    if envp.user_id != current_user.id and not is_admin(): abort(403)
    return send_file(doc.file_path, mimetype="application/pdf", as_attachment=True,
                     download_name=os.path.basename(doc.file_path))

# --------- Admin: Templates/Envelopes & Hiring ---------
@app.get("/admin/docs/templates")
@login_required
def admin_doc_templates():
    if not is_admin(): abort(403)
    ts = DocumentTemplate.query.order_by(DocumentTemplate.name).all()
    return render_template("admin/doc_templates.html", templates=ts)

@app.route("/admin/docs/templates/new", methods=["GET","POST"])
@login_required
def admin_doc_templates_new():
    if not is_admin(): abort(403)
    if request.method == "POST":
        name = request.form.get("name")
        slug = request.form.get("slug")
        content_md = request.form.get("content_md")
        db.session.add(DocumentTemplate(name=name, slug=slug, content_md=content_md))
        db.session.commit()
        flash("Template criado!", "success")
        return redirect(url_for("admin_doc_templates"))
    return render_template("admin/doc_template_edit.html", t=None)

@app.post("/admin/docs/envelope")
@login_required
def admin_create_envelope():
    if not is_admin(): abort(403)
    user_id = int(request.form.get("user_id"))
    template_id = int(request.form.get("template_id"))
    envp = DocumentEnvelope(user_id=user_id, template_id=template_id, status="PENDENTE")
    db.session.add(envp); db.session.commit()
    flash("Envelope criado!", "success")
    return redirect(url_for("admin_doc_templates"))

@app.get("/admin/hiring")
@login_required
def admin_hiring():
    if not is_admin(): abort(403)
    pipes = HiringPipeline.query.order_by(HiringPipeline.updated_at.desc()).all()
    return render_template("admin/hiring.html", pipes=pipes, stages=[s.value for s in HiringStage])

@app.post("/admin/hiring/<int:pipe_id>/stage")
@login_required
def admin_hiring_set_stage(pipe_id):
    if not is_admin(): abort(403)
    p = db.session.get(HiringPipeline, pipe_id) or abort(404)
    stage_val = request.form.get("stage")
    p.stage = HiringStage(stage_val)
    p.updated_at = datetime.utcnow()
    db.session.commit()
    flash("Etapa atualizada!", "success")
    return redirect(url_for("admin_hiring"))

@app.get("/hiring/me")
@login_required
def hiring_me():
    p = HiringPipeline.query.filter_by(user_id=current_user.id).first()
    if not p:
        p = HiringPipeline(user_id=current_user.id)
        db.session.add(p); db.session.commit()
    return render_template("hiring_me.html", pipe=p)

# --------- Seed ---------
@app.get("/seed")
def seed():
    if User.query.filter_by(email="admin@local").first() is None:
        admin = User(name="Admin", email="admin@local", role="admin")
        admin.set_password("admin123"); db.session.add(admin)
        c = Course(title="NR-10 (Demo)", code="NR10", summary="Segurança em Eletricidade")
        db.session.add(c); db.session.flush()
        db.session.add(Lesson(course_id=c.id, title="Introdução", order_index=0,
                              content_md="# NR-10\nConteúdo.", video_url="https://www.youtube.com/embed/dQw4w9WgXcQ"))
        db.session.add(QuizQuestion(course_id=c.id, question="NR-10 trata de quê?",
                        options_json=json.dumps(["Eletricidade","Altura","Espaços Confinados","Máquinas"]), correct_index=0))
        db.session.add(DocumentTemplate(name="Contrato Padrão", slug="contrato-padrao",
                        content_md="Contrato entre {{nome}} (CPF {{cpf}}) em {{data}}."))
        db.session.commit()
    return "ok"

if __name__ == "__main__":
    app.run(debug=True)
