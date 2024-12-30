from flask import Flask, render_template, redirect, request, session, url_for, flash, Response
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import re
import cv2
from roboflow import Roboflow
import numpy as np
from sort import Sort
import sqlite3

def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///dataUsuarios.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.secret_key = 'tu_secreto_super_seguro'

    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    
    return app

# Inicialización de extensiones
db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.login_message = "Por favor, inicia sesión para acceder a esta página."

# Modelo de usuario
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email_address = db.Column(db.String(50), nullable=False)
    dni = db.Column(db.String(8), nullable=False)
    phone = db.Column(db.String(9), nullable=False)
    address = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

app = create_app()

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        last_name = request.form['last_name']
        email_address = request.form['email_address']
        dni = request.form['dni']
        phone = request.form['phone']
        address = request.form['address']
        username = request.form['username']
        password = request.form['password']

        if not re.fullmatch(r'\d{8}', dni):
            flash("El DNI debe tener exactamente 8 dígitos.", "danger")
        elif not re.fullmatch(r'9\d{8}', phone):
            flash("El número de teléfono debe comenzar con 9 y tener 9 dígitos.", "danger")
        elif not re.fullmatch(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$', password):
            flash("La contraseña debe cumplir los requisitos de seguridad.", "danger")
        elif not re.fullmatch(r'^[a-zA-Z0-9._%+-]+@(gmail\.com|hotmail\.com|outlook\.com)$', email_address):
            flash("El correo debe ser válido y pertenecer a Gmail o Hotmail/Outlook.", "danger")
        else:
            existing_user = User.query.filter(
                (User.username == username) |
                (User.dni == dni) |
                (User.email_address == email_address) |
                (User.phone == phone)
            ).first()

            if existing_user:
                flash("El usuario ya existe con alguno de esos datos.", "danger")
            else:
                hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
                new_user = User(
                    name=name, last_name=last_name, email_address=email_address,
                    dni=dni, phone=phone, address=address,
                    username=username, password=hashed_password
                )
                db.session.add(new_user)
                db.session.commit()
                flash("Usuario registrado exitosamente.", "success")
                return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash("Inicio de sesión exitoso.", "success")
            return redirect(url_for('index'))
        else:
            flash("Credenciales inválidas.", "danger")

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Cerraste sesión exitosamente.", "success")
    return redirect(url_for('login'))

# Configuración para detección y rastreo
class_names = {0: "Limon", 1: "Limon Malo", 2: "Mandarina", 3: "Mandarina Mala", 4: "Mango", 5: "Mango Malo",
               6: "Palta", 7: "Palta Mala"}
colors = {0: (0, 255, 0), 1: (0, 0, 255), 2: (0, 165, 255), 3: (0, 0, 255), 4: (0, 255, 255), 5: (0, 0, 255),
          6: (34, 139, 34), 7: (0, 0, 255)}
tracker = Sort()
rf = Roboflow(api_key="Vd2I88rNGk6HVseIwsiE")
project = rf.workspace().project("frutasestados")
modelo = project.version(2).model

@app.route('/Detector_Camara')
def Detector_Camara():
    def generar_video():
        cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)
        cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)  # Ancho del video
        cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)  # Alto del video
        cap.set(cv2.CAP_PROP_FPS, 30)  # Establecer FPS

        db = sqlite3.connect("deteccion_frutas.db")
        cursor = db.cursor()

        while True:
            ret, frame = cap.read()
            if not ret:
                break

            frame_resized = cv2.resize(frame, (416, 416))  # Redimensionar para mejorar el rendimiento
            results = modelo.predict(frame_resized).json()
            predictions = results.get('predictions', [])

            detections = []
            class_mapping = {}
            for i, pred in enumerate(predictions):
                try:
                    x, y, width, height = pred['x'], pred['y'], pred['width'], pred['height']
                    x1, y1, x2, y2 = x - width / 2, y - height / 2, x + width / 2, y + height / 2
                    conf = pred['confidence']
                    cls_name = pred['class']
                    cls = next((k for k, v in class_names.items() if v == cls_name), None)

                    if cls is not None:
                        detections.append([x1, y1, x2, y2, conf])
                        class_mapping[i] = cls
                except KeyError as e:
                    print(f"Error procesando la predicción: {e}")
                    continue

            if detections:
                detections = np.array(detections)
                tracked_objects = tracker.update(detections)

                for track in tracked_objects:
                    x1, y1, x2, y2, track_id = map(int, track[:5])
                    closest_detection_idx = np.argmin(
                        [np.linalg.norm([(x1 + x2) / 2 - (det[0] + det[2]) / 2,
                                         (y1 + y2) / 2 - (det[1] + det[3]) / 2])
                         for det in detections]
                    )

                    cls = class_mapping.get(closest_detection_idx, None)
                    if cls is not None and cls in class_names:
                        conf = detections[closest_detection_idx, 4]
                        bbox_center = [(x1 + x2) / 2, (y1 + y2) / 2]

                        cursor.execute(
                            "INSERT INTO detecciones (clase, confianza, bbox_x, bbox_y, fecha) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)",
                            (cls, float(conf), float(bbox_center[0]), float(bbox_center[1]))
                        )
                        db.commit()

                        color = colors.get(cls, (255, 255, 255))
                        label = f'{class_names[cls]} {conf:.2f}'
                        cv2.rectangle(frame, (x1, y1), (x2, y2), color, 2)
                        cv2.putText(frame, label, (x1, y1 - 10), cv2.FONT_HERSHEY_SIMPLEX, 0.5, color, 2)

            _, buffer = cv2.imencode('.jpg', frame)
            frame_bytes = buffer.tobytes()
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')

        cap.release()
        db.close()

    return Response(generar_video(), mimetype='multipart/x-mixed-replace; boundary=frame')

@app.route('/reporte')
@login_required
def reporte():
    # Obtener los parámetros de filtro y paginación
    fecha_inicio = request.args.get('fecha_inicio', '')
    fecha_fin = request.args.get('fecha_fin', '')
    pagina = int(request.args.get('pagina', 1))
    registros_por_pagina = 15

    # Diccionario para traducir las clases


    # Conectar a la base de datos
    db = sqlite3.connect("deteccion_frutas.db")
    cursor = db.cursor()

    # Construir la consulta con filtros de fecha
    query = "SELECT clase, confianza, bbox_x, bbox_y, fecha FROM detecciones WHERE 1=1"
    parametros = []
    if fecha_inicio:
        query += " AND fecha >= ?"
        parametros.append(fecha_inicio)
    if fecha_fin:
        query += " AND fecha <= ?"
        parametros.append(fecha_fin)

    # Obtener el total de registros para calcular las páginas
    cursor.execute("SELECT COUNT(*) FROM detecciones WHERE 1=1" + 
                   (" AND fecha >= ?" if fecha_inicio else "") +
                   (" AND fecha <= ?" if fecha_fin else ""), parametros)
    total_registros = cursor.fetchone()[0]

    # Agregar paginación
    query += " ORDER BY fecha DESC LIMIT ? OFFSET ?"
    parametros.extend([registros_por_pagina, (pagina - 1) * registros_por_pagina])

    cursor.execute(query, parametros)
    detecciones = cursor.fetchall()
    db.close()

    # Traducir las clases
    detecciones = [
        (class_names[det[0]], det[1], det[2], det[3], det[4]) for det in detecciones
    ]

    # Calcular total de páginas
    total_paginas = (total_registros + registros_por_pagina - 1) // registros_por_pagina

    # Pasar las detecciones y la información de paginación a la plantilla
    return render_template(
        'reporte.html',
        detecciones=detecciones,
        fecha_inicio=fecha_inicio,
        fecha_fin=fecha_fin,
        pagina=pagina,
        total_paginas=total_paginas,
        total_registros=total_registros
    )

if __name__ == '__main__':
    app.run(debug=True)
