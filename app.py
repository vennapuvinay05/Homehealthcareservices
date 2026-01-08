from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_cors import CORS
import mysql.connector
import bcrypt
from datetime import datetime, timedelta

app = Flask(
    __name__,
    template_folder="templates",
    static_folder="static"
)

app.secret_key = "secretkey123"
CORS(app)

# -------- DATABASE CONNECTION --------
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="root",
    database="tvvha_healthcare"
)

# ================= PAGES =================

@app.route("/")
def index():
    return redirect(url_for("home"))

@app.route("/home")
def home():
    return render_template("home.html")

@app.route("/services")
def services():
    return render_template("services.html")

@app.route("/login")
def login_page():
    return render_template("loginfrom.html")

@app.route("/register-page")
def register_page():
    return render_template("register.html")

# ================= BOOKINGS PAGE (ONLY OWN BOOKINGS) =================
@app.route("/bookings")
def bookings_page():
    if "user" not in session:
        return redirect(url_for("login_page"))

    username = session["user"]

    cursor = db.cursor(dictionary=True)
    cursor.execute("""
        SELECT * FROM bookings
        WHERE username=%s
        ORDER BY id DESC
    """, (username,))
    bookings = cursor.fetchall()
    cursor.close()

    return render_template("bookings.html", bookings=bookings)

@app.route("/doctor-bookings")
def doctor_bookings_page():
    return render_template("doctor-bookings.html")

@app.route("/admin")
def admin_panel():
    return render_template("admin.html")

@app.route("/admin-dashboard")
def admin_dashboard_page():
    return render_template("admin-dashboard.html")

# ----- service pages -----
@app.route("/general")
def general():
    return render_template("general.html")

@app.route("/physiotherapy")
def physiotherapy():
    return render_template("physiotherapy.html")

@app.route("/nursing")
def nursing():
    return render_template("nursing.html")

@app.route("/lab")
def lab():
    return render_template("lab.html")

@app.route("/fullbody")
def fullbody():
    return render_template("fullbody.html")

@app.route("/elder")
def elder():
    return render_template("elder.html")

@app.route("/child")
def child():
    return render_template("child.html")

@app.route("/diabetic")
def diabetic():
    return render_template("diabetic.html")

@app.route("/pregnent")
def pregnent():
    return render_template("pregnent.html")

# ================= REGISTER =================
@app.route("/register", methods=["POST"])
def register():
    data = request.form

    username = data.get("username")
    password = data.get("password")
    role = data.get("role")
    phone = data.get("phone")
    address = data.get("address")
    specialization = data.get("specialization")

    if not username or not password or not role:
        return jsonify({"error": "Missing fields"}), 400

    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT id FROM users WHERE username=%s", (username,))
    if cursor.fetchone():
        return jsonify({"error": "Username already exists"}), 400

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    cursor.execute("""
        INSERT INTO users (username, password, role, phone, address, specialization)
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (username, hashed, role, phone, address, specialization))

    db.commit()
    cursor.close()

    return jsonify({"message": "Registered successfully"}), 201

# ================= LOGIN =================
@app.route("/login-user", methods=["POST"])
def login_user():
    data = request.form

    username = data.get("username")
    password = data.get("password")

    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
    user = cursor.fetchone()

    if not user:
        return jsonify({"error": "User not registered!"}), 404

    if not bcrypt.checkpw(password.encode(), user["password"].encode()):
        return jsonify({"error": "Wrong password"}), 401

    session["user"] = user["username"]
    session["role"] = user["role"]

    cursor.close()

    return jsonify({"message": "Login successful", "role": user["role"]}), 200

# ================= BOOK SERVICE =================
@app.route("/book-service", methods=["POST"])
def book_service():
    if "user" not in session:
        return jsonify({"error": "Login required"}), 401

    data = request.get_json() or request.form

    cursor = db.cursor()
    cursor.execute("""
        INSERT INTO bookings (name, phone, service, date, doctor, username)
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (
        data.get("name"),
        data.get("phone"),
        data.get("service"),
        data.get("date"),
        data.get("doctor"),
        session["user"]
    ))

    db.commit()
    cursor.close()

    return jsonify({"message": "Booking submitted"}), 201

# ================= ADMIN BOOKINGS =================
@app.route("/api/admin/bookings")
def get_all_bookings():
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM bookings ORDER BY id DESC")
    data = cursor.fetchall()
    cursor.close()
    return jsonify(data)

# ================= DOCTOR BOOKINGS =================
@app.route("/api/doctor/bookings/<doctor>")
def get_doctor_bookings(doctor):
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM bookings WHERE doctor=%s", (doctor,))
    data = cursor.fetchall()
    cursor.close()
    return jsonify(data)

# ================= DOCTOR ACCEPT BOOKING =================
@app.route("/api/doctor/accept/<int:booking_id>", methods=["POST"])
def accept_booking(booking_id):
    cursor = db.cursor()
    cursor.execute("""
        UPDATE bookings
        SET status='Accepted',
            notification='Doctor has accepted your appointment'
        WHERE id=%s
    """, (booking_id,))
    db.commit()
    cursor.close()
    return jsonify({"message": "Booking accepted"})

# ================= CLIENT APPOINTMENT POLLING API =================
@app.route("/api/client/appointments")
def client_appointments():
    if "user" not in session:
        return jsonify([])

    cursor = db.cursor(dictionary=True)
    cursor.execute("""
        SELECT service, status, notification
        FROM bookings
        WHERE username=%s
        ORDER BY id DESC
    """, (session["user"],))

    data = cursor.fetchall()
    cursor.close()
    return jsonify(data)

# ================= APPOINTMENT STATUS PAGE =================
@app.route("/appointment-status")
def appointment_status():
    if "user" not in session:
        return redirect(url_for("login_page"))

    cursor = db.cursor(dictionary=True)
    cursor.execute(
        "SELECT * FROM bookings WHERE username=%s ORDER BY id DESC",
        (session["user"],)
    )
    bookings = cursor.fetchall()
    cursor.close()

    return render_template(
        "appointment-status.html",
        bookings=bookings,
        username=session["user"]
    )

# ================= LOGOUT =================
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

# ---------- CREATE DEFAULT ADMIN ----------
cursor = db.cursor(dictionary=True)
cursor.execute("SELECT * FROM users WHERE role='admin'")
admin = cursor.fetchone()

if not admin:
    password = bcrypt.hashpw("admin123".encode(), bcrypt.gensalt()).decode()
    cursor.execute("""
        INSERT INTO users (username, password, role)
        VALUES (%s, %s, %s)
    """, ("admin", password, "admin"))
    db.commit()

cursor.close()

# ================= DELETE BOOKING (UPDATED) =================
@app.route("/delete-booking/<int:booking_id>", methods=["POST"])
def delete_booking(booking_id):
    if "user" not in session:
        return jsonify({"error": "Login required"}), 401

    cursor = db.cursor(dictionary=True)
    cursor.execute(
        "SELECT * FROM bookings WHERE id=%s AND username=%s",
        (booking_id, session["user"])
    )
    booking = cursor.fetchone()

    if not booking:
        cursor.close()
        return jsonify({"error": "Booking not found"}), 404

    # ✅ ACCEPTED STATUS CHECK REMOVED
    # ✅ TIME LIMIT CHECK REMOVED

    cursor.execute(
        "DELETE FROM bookings WHERE id=%s AND username=%s",
        (booking_id, session["user"])
    )

    db.commit()
    cursor.close()

    return jsonify({"message": "Booking removed successfully"})

# ================= RUN APP =================
if __name__ == "__main__":
    app.run(debug=True)
