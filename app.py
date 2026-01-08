import os
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin

from config import Config

ALLOWED_EXTENSIONS = {"pdf", "doc", "docx", "ppt", "pptx", "zip", "rar", "png", "jpg", "jpeg", "txt"}

app = Flask(__name__)
app.config.from_object(Config)

os.makedirs(os.path.join(app.root_path, "instance"), exist_ok=True)
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

# -------------------- Models --------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="student")  # admin / student

    def set_password(self, pw: str):
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw: str) -> bool:
        return check_password_hash(self.password_hash, pw)

class Field(db.Model):  # مثال: Python / Web / AI
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)

class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    field_id = db.Column(db.Integer, db.ForeignKey("field.id"), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, default="")

    field = db.relationship("Field", backref=db.backref("courses", lazy=True))

class Lesson(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    course_id = db.Column(db.Integer, db.ForeignKey("course.id"), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    content_html = db.Column(db.Text, nullable=False)  # نخزن HTML جاهز (سهل كبداية)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    course = db.relationship("Course", backref=db.backref("lessons", lazy=True, order_by="Lesson.id"))

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    course_id = db.Column(db.Integer, db.ForeignKey("course.id"), nullable=False)
    display_name = db.Column(db.String(200), nullable=False)
    filename = db.Column(db.String(300), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

    course = db.relationship("Course", backref=db.backref("docs", lazy=True, order_by="Document.id.desc()"))

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# -------------------- Helpers --------------------
def is_admin():
    return current_user.is_authenticated and current_user.role == "admin"

def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def admin_required():
    if not is_admin():
        abort(403)

# -------------------- Public Routes --------------------
@app.route("/")
def home():
    fields = Field.query.order_by(Field.name.asc()).all()
    return render_template("home.html", fields=fields)

@app.route("/course/<int:course_id>")
def course_page(course_id):
    course = db.session.get(Course, course_id)
    if not course:
        abort(404)
    return render_template("course.html", course=course)

@app.route("/lesson/<int:lesson_id>")
def lesson_page(lesson_id):
    lesson = db.session.get(Lesson, lesson_id)
    if not lesson:
        abort(404)
    return render_template("lesson.html", lesson=lesson)

@app.route("/uploads/<path:filename>")
def download_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename, as_attachment=True)

# -------------------- Auth --------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        user = User.query.filter_by(username=username).first()
        if not user or not user.check_password(password):
            flash("بيانات الدخول غير صحيحة", "error")
            return redirect(url_for("login"))

        login_user(user)
        return redirect(url_for("admin_dashboard") if is_admin() else url_for("home"))

    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))

# -------------------- Admin Routes --------------------
@app.route("/admin")
@login_required
def admin_dashboard():
    admin_required()
    return render_template(
        "admin_dashboard.html",
        fields=Field.query.count(),
        courses=Course.query.count(),
        lessons=Lesson.query.count(),
        docs=Document.query.count(),
    )

@app.route("/admin/fields", methods=["GET", "POST"])
@login_required
def admin_fields():
    admin_required()
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        if name:
            exists = Field.query.filter_by(name=name).first()
            if exists:
                flash("هذا الحقل موجود مسبقًا", "error")
            else:
                db.session.add(Field(name=name))
                db.session.commit()
                flash("تم إضافة الحقل ✅", "success")
        return redirect(url_for("admin_fields"))

    fields = Field.query.order_by(Field.name.asc()).all()
    return render_template("admin_fields.html", fields=fields)

@app.route("/admin/courses", methods=["GET", "POST"])
@login_required
def admin_courses():
    admin_required()
    fields = Field.query.order_by(Field.name.asc()).all()

    if request.method == "POST":
        field_id = int(request.form.get("field_id"))
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()

        if title:
            db.session.add(Course(field_id=field_id, title=title, description=description))
            db.session.commit()
            flash("تم إضافة الكورس ✅", "success")
        return redirect(url_for("admin_courses"))

    courses = Course.query.order_by(Course.id.desc()).all()
    return render_template("admin_courses.html", fields=fields, courses=courses)

@app.route("/admin/lessons", methods=["GET", "POST"])
@login_required
def admin_lessons():
    admin_required()
    courses = Course.query.order_by(Course.id.desc()).all()

    if request.method == "POST":
        course_id = int(request.form.get("course_id"))
        title = request.form.get("title", "").strip()
        content_html = request.form.get("content_html", "").strip()

        if title and content_html:
            db.session.add(Lesson(course_id=course_id, title=title, content_html=content_html))
            db.session.commit()
            flash("تم إضافة الدرس ✅", "success")
        else:
            flash("لازم عنوان + محتوى", "error")

        return redirect(url_for("admin_lessons"))

    lessons = Lesson.query.order_by(Lesson.id.desc()).limit(50).all()
    return render_template("admin_lessons.html", courses=courses, lessons=lessons)

@app.route("/admin/docs", methods=["GET", "POST"])
@login_required
def admin_docs():
    admin_required()
    courses = Course.query.order_by(Course.id.desc()).all()

    if request.method == "POST":
        course_id = int(request.form.get("course_id"))
        display_name = request.form.get("display_name", "").strip()
        f = request.files.get("file")

        if not f or f.filename == "":
            flash("اختر ملف", "error")
            return redirect(url_for("admin_docs"))

        if not allowed_file(f.filename):
            flash("نوع الملف غير مسموح", "error")
            return redirect(url_for("admin_docs"))

        safe = secure_filename(f.filename)
        # نخزن داخل uploads مع مسار واضح
        course = db.session.get(Course, course_id)
        rel_dir = os.path.join(course.field.name, course.title).replace("\\", "/")
        save_dir = os.path.join(app.config["UPLOAD_FOLDER"], rel_dir)
        os.makedirs(save_dir, exist_ok=True)

        save_path = os.path.join(save_dir, safe)
        f.save(save_path)

        rel_path = os.path.join(rel_dir, safe).replace("\\", "/")
        db.session.add(Document(course_id=course_id, display_name=display_name or safe, filename=rel_path))
        db.session.commit()

        flash("تم رفع الملف ✅", "success")
        return redirect(url_for("admin_docs"))

    docs = Document.query.order_by(Document.id.desc()).limit(50).all()
    return render_template("admin_docs.html", courses=courses, docs=docs)

# -------------------- Init DB + Create Admin --------------------
@app.cli.command("initdb")
def initdb():
    """flask initdb"""
    db.create_all()
    # أنشئ أدمن افتراضي
    if not User.query.filter_by(username="admin").first():
        u = User(username="admin", role="admin")
        u.set_password("admin12345")
        db.session.add(u)
        db.session.commit()
        print("✅ Created admin: admin / admin12345")
    else:
        print("ℹ️ Admin already exists")

if __name__ == "__main__":
    app.run(debug=True)
