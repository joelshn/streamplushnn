from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, render_template_string
from datetime import datetime, timedelta
from database import connect_db, get_next_id
from decimal import Decimal
from functools import wraps
from flask import session
import random
import requests
import string
import smtplib
from email.mime.text import MIMEText
from time import sleep
from io import BytesIO
from PIL import Image, ImageDraw, ImageFont, ImageOps
from threading import Thread
import imaplib
import email
from email.header import decode_header
from imapclient import IMAPClient
import chardet

app = Flask(__name__)
app.secret_key = '29122020'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)


# Configuración de Gmail
IMAP_SERVER = "imap.gmail.com"
IMAP_PORT = 993
GMAIL_USER = "streamplus504hn@gmail.com"  # Reemplaza con tu correo
GMAIL_PASSWORD = "jzqj pyhr anxg gelj"  # Contraseña generada de Google

#---------------------------------------------------------------------------------------------------------
def fetch_last_email():
    """Obtiene el último correo recibido con un filtro de asuntos específicos."""
    try:
        # Lista de asuntos permitidos
        allowed_subjects = [
            "¿Vas a actualizar tu Hogar de Disney+?",
            "Netflix: Tu código de inicio de sesión",
            "Tu código de acceso único para Disney+"
        ]

        # Conexión al servidor IMAP
        mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
        mail.login(GMAIL_USER, GMAIL_PASSWORD)
        mail.select("inbox")

        # Buscar todos los correos
        status, messages = mail.search(None, "ALL")
        if status != "OK" or not messages[0]:
            return None

        # Iterar desde el más reciente
        for email_id in messages[0].split():
            status, msg_data = mail.fetch(email_id, "(RFC822)")
            if status != "OK":
                continue

            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg = email.message_from_bytes(response_part[1])

                    # Decodificar el asunto
                    subject = decode_header(msg["Subject"])[0][0]
                    subject = subject.decode() if isinstance(subject, bytes) else subject

                    # Comprobar si el asunto está permitido
                    if subject not in allowed_subjects:
                        continue

                    # Decodificar remitente
                    sender = decode_header(msg["From"])[0][0]
                    sender = sender.decode() if isinstance(sender, bytes) else sender

                    # Extraer la fecha
                    date = msg["Date"]

                    # Extraer el cuerpo del correo
                    body = ""
                    if msg.is_multipart():
                        html_body = None
                        plain_body = None
                        for part in msg.walk():
                            content_type = part.get_content_type()
                            content_disposition = str(part.get("Content-Disposition"))

                            # Si es HTML, lo guardamos como prioridad
                            if content_type == "text/html" and "attachment" not in content_disposition:
                                payload = part.get_payload(decode=True)
                                if payload:
                                    encoding = chardet.detect(payload)['encoding']
                                    html_body = payload.decode(encoding or 'utf-8', errors="ignore")

                            # Si es texto plano, lo guardamos como alternativa
                            elif content_type == "text/plain" and "attachment" not in content_disposition:
                                payload = part.get_payload(decode=True)
                                if payload:
                                    encoding = chardet.detect(payload)['encoding']
                                    plain_body = payload.decode(encoding or 'utf-8', errors="ignore")

                        # Usar HTML si está disponible, de lo contrario usar texto plano
                        body = html_body if html_body else plain_body
                    else:
                        payload = msg.get_payload(decode=True)
                        if payload:
                            encoding = chardet.detect(payload)['encoding']
                            body = payload.decode(encoding or 'utf-8', errors="ignore")

                    # Cerrar la conexión y devolver el último correo que coincide
                    mail.logout()
                    return {
                        "subject": subject,
                        "sender": sender,
                        "date": date,
                        "body": body
                    }

        # Cerrar la conexión si no hay coincidencias
        mail.logout()
        return None
    except Exception as e:
        print(f"Error: {e}")
        return None

def client_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'client_id' not in session:
            flash("Ingresa tu ID y numero de telefono para continuar.", "danger")
            return redirect(url_for('codigos'))
        return f(*args, **kwargs)
    return decorated_function

@app.route("/codigosdc")
@client_required
def codigosdc():
    """Página principal para mostrar el último correo."""
    email_data = fetch_last_email()
    session.pop('client_id', None)
    # HTML dinámico incrustado
    html_template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Inbox - Streamplus</title>
    </head>
    <body>
        <h1>Bandeja de Entrada</h1>
        <button onclick="window.location.href='/codigos'" style="padding: 10px 20px; background-color: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer;">
         Volver
         </button>

        {% if email_data %}
        <div class="email-container">
            <div class="email-header">
                <p><strong>Remitente:</strong> {{ email_data.sender }}</p>
                <p><strong>Asunto:</strong> {{ email_data.subject }}</p>
                <p><strong>Fecha:</strong> {{ email_data.date }}</p>
            </div>
           
                {{ email_data.body | safe }}
            </div>
        </div>
        {% else %}
        <p>No se encontró ningún correo.</p>
        {% endif %}
    </body>
    </html>
    """
    return render_template_string(html_template, email_data=email_data)
#---------------------------------------------------------------------------------------------------------



@app.route('/codigos', methods=['GET', 'POST'])
def codigos():
    if request.method == 'POST':
        cliente_id = request.form['id']
        numero_telefono = request.form['telefono']

        # Verificar datos en la base de datos
        db = connect_db()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM clientes WHERE id = %s AND numero = %s AND activacion > 0", (cliente_id, numero_telefono))
        cliente = cursor.fetchone()

        if cliente:
            session['client_id'] = cliente_id
            # Restar 1 en la columna activacion
            cursor.execute("UPDATE clientes SET activacion = activacion - 1 WHERE id = %s", (cliente_id,))
            db.commit()
            return redirect(url_for('codigosdc'))
        else:
            db.close()
            flash("ID o número de teléfono incorrectos, o no tienes activaciones disponibles.", "danger")
            return redirect(url_for('codigos'))

    return render_template('codigos.html')






# Redirigir HTTP a HTTPS
@app.before_request
def redirect_to_https():
    if not request.is_secure:
        return redirect(request.url.replace("http://", "https://"), code=301)

PORCENTAJE_REFERIDO = 0.5

def send_verification_email(email, code):
    msg = MIMEText(f'Tu código de verificación para confirmar tu correo electronico en StreamPlus es: {code}')
    msg['Subject'] = 'Código de Verificación StreamPlus'
    msg['From'] = 'streamplus504hn@gmail.com'
    msg['To'] = email

    with smtplib.SMTP('smtp.gmail.com', 587) as server:
        server.starttls()
        server.login('streamplus504hn@gmail.com', 'jzqj pyhr anxg gelj')
        server.sendmail(msg['From'], [msg['To']], msg.as_string())

# Función para enviar un correo para cambio de contraseña
@app.route('/send_password_reset', methods=['GET', 'POST'])
def send_password_reset_email():
    email= session['correo']
    code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    session['code'] = code
    msg = MIMEText("""
<!DOCTYPE html>
<html>
<body>
    <h3>¡Hola!</h3>
    <p>Recibimos una solicitud para cambiar la contraseña de tu cuenta en StreamPlus.</p>
    <p><strong>Tu código de verificación es:</strong> <span style="font-size: 20px; color: #007BFF;">{code}</span></p>
    <p>Si no solicitaste este cambio, puedes ignorar este correo.</p>
    <hr>
    <p style="font-size: 12px; color: gray;">Este correo es una notificación automática de StreamPlus.</p>
</body>
</html>
""".format(code=code), 'html')

    msg['Subject'] = '"Actualización en tu cuenta de StreamPlus---Código para actualizar tu contraseña'
    msg['From'] = 'streamplus504hn@gmail.com'
    msg['To'] = email

    msg['X-Priority'] = '3'
    msg['X-MSMail-Priority'] = '1'
    msg['X-Mailer'] = 'StreamPlus Notification'



    with smtplib.SMTP('smtp.gmail.com', 587) as server:
        try:
            server.starttls()  # Inicia conexión segura
            server.login('streamplus504hn@gmail.com', 'jzqj pyhr anxg gelj')  # Credenciales del correo
            server.sendmail(msg['From'], [msg['To']], msg.as_string()) # enviar correo
            flash("Se ha enviado un código de verificación a tu correo electrónico.", "success")
            return redirect(url_for('verify_password_reset'))
        except Exception as e:
            print(f"Error al enviar el correo: {e}")
            flash("No se pudo enviar el correo. Por favor, inténtalo más tarde.", "danger")
            return redirect(url_for('settings'))

        

# Ruta para verificar el código ingresado por el usuario
@app.route('/verify_password_reset', methods=['GET', 'POST'])
def verify_password_reset():
    if request.method == 'POST':
        entered_code = request.form['verification_code']

        if entered_code != session.get('code'):
            flash("El código de verificación no coincide.", "danger")
            return redirect(url_for('verify_password_reset'))

        flash("Código verificado. Ahora puedes cambiar tu contraseña.", "success")
        return redirect(url_for('change_password'))

    return render_template('verify_password_reset.html')

# Ruta para cambiar la contraseña
@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash("Las contraseñas no coinciden.", "danger")
            return redirect(url_for('change_password'))

        # Aquí deberías actualizar la contraseña en la base de datos
        # Ejemplo simulado
        flash("Tu contraseña ha sido cambiada exitosamente.", "success")
        return redirect(url_for('settings'))

    return render_template('change_password.html')

# Ruta para la página de ajustes
@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'username' not in session:
        return redirect(url_for('login'))  # Redirige al login si no hay sesión activa

    db = connect_db()
    cursor = db.cursor(dictionary=True)
    username = session['username']

    # Obtener los datos del usuario
    cursor.execute("SELECT nombre_usuario, numero_telefono, correo_electronico, codigo_referido, saldo FROM usuarios WHERE nombre_usuario = %s", (username,))
    user_data = cursor.fetchone()
    db.close()

    return render_template('settings.html', user_data=user_data)

def check_credentials(username, password):
    db = connect_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, rol, verificado, correo_electronico, nombre_usuario, codigo_referido FROM usuarios WHERE (nombre_usuario = %s OR correo_electronico = %s) AND contraseña = %s", (username, username, password))
    user = cursor.fetchone()
    db.close()
    if user:
        session['user_id'] = user[0]
        session['username'] = user[4]
        session['referido'] = user[5]
        session['correo'] = user[3]
        session['rol'] = user[1]
        session.permanent = True
        session['verificado'] = user[2]
        if 'verificado' in session ==0:
            session.pop('username', None)
        return True
    return False


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session and 'verificado' in session ==0:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session or session.get('rol') != 'admin':
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session and 'verificado' in session== True:
        return redirect(url_for('streamplus'))
    
    if request.method == 'POST':
        username = request.form['identificador']  # Puede ser nombre de usuario o correo electrónico
        password = request.form['password']

        db = connect_db()
        cursor = db.cursor()
        cursor.execute("""
            SELECT id, contraseña, verificado 
            FROM usuarios 
            WHERE correo_electronico = %s OR nombre_usuario = %s
        """, (username, username))
        usuario = cursor.fetchone()
        db.close()

        if usuario and check_credentials(username, password):
            if usuario[2]==1:  # Verificar si el usuario ha confirmado el correo electrónico
                session['user_id'] = usuario[0]
    
                return redirect(url_for('streamplus'))
            else:
                flash('Por favor, verifica tu correo electrónico antes de iniciar sesión.', 'warning')
                return redirect(url_for('verify_email'))
        else:
            flash('Correo electrónico/nombre de usuario o contraseña incorrectos.', 'danger')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('verificado', None)
    session.pop('correo', None)
    session.pop('user_id', None)
    return redirect(url_for('login'))

# Ruta de Registro
@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'username' in session and 'verificado' in session== True:
        return redirect(url_for('streamplus'))
    if request.method == 'POST':
        nombre_usuario = request.form['nombre_usuario']
        contraseña = request.form['password']
        numero_telefono = request.form['numero_telefono']
        correo_electronico = request.form['correo_electronico']
        codigo_referido = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
        rol = 'usuario'

        # Generar y enviar el código de verificación
        codigo_verificacion = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        send_verification_email(correo_electronico, codigo_verificacion)

        db = connect_db()
        cursor = db.cursor()
        cursor.execute("INSERT INTO usuarios (nombre_usuario, contraseña, numero_telefono, correo_electronico, codigo_referido, rol, codigo_verificacion, verificado) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                       (nombre_usuario, contraseña, numero_telefono, correo_electronico, codigo_referido, rol, codigo_verificacion, False))
        db.commit()
        db.close()

        session['correo'] = correo_electronico
        flash('Se ha enviado un código de verificación a tu correo electrónico', 'info')
        return redirect(url_for('verify_email'))

    return render_template('register.html')

@app.route('/verify_email', methods=['GET', 'POST'])
def verify_email():
    if 'verificado' in session == True:
        return redirect(url_for('streamplus'))
    if 'correo' not in session:
        return redirect(url_for('register'))

    if request.method == 'POST':
        codigo_verificacion = request.form['codigo_verificacion']
        correo_electronico = session['correo']

        db = connect_db()
        cursor = db.cursor()
        cursor.execute("SELECT codigo_verificacion FROM usuarios WHERE correo_electronico = %s", (correo_electronico,))
        codigo_correcto = cursor.fetchone()

        if codigo_correcto and codigo_correcto[0] == codigo_verificacion:
            cursor.execute("UPDATE usuarios SET verificado = %s WHERE correo_electronico = %s", (True, correo_electronico))
            db.commit()
            db.close()
            session.pop('correo', None)
            flash('Verificación exitosa. Ahora puedes iniciar sesión.', 'success')
            return redirect(url_for('login'))
        else:
            db.close()
            flash('Código de verificación incorrecto. Inténtalo de nuevo.', 'danger')

    return render_template('verify_email.html')

#Ruta de Usuarios
@app.route('/streamplus')
@login_required
def streamplus():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if session.get('rol') == "admin":
        return redirect(url_for('admin'))

    db = connect_db()
    cursor = db.cursor()

    # Obtener el saldo actual del usuario
    user_id = session['user_id']
    cursor.execute("SELECT saldo, verificado FROM usuarios WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    saldo_actual = user[0]
    correoest = user[1]
    if correoest == 0:
        return redirect(url_for('verify_email'))

    db.close()
    return render_template('streamplus.html', saldo_actual=saldo_actual)

@app.route("/")
def index():
    products = [
        {
            "name": "Netflix",
            "image_url": "https://i.ytimg.com/vi/ZMak63mHq5Y/maxresdefault.jpg",
            "plans": [
                {"duration": 1, "price": 100},
                {"duration": 2, "price": 200},
                {"duration": 3, "price": 300},
            ],
        },
        {
            "name": "Disney+",
            "image_url": "https://lumiere-a.akamaihd.net/v1/images/disney_logo_march_2024_050fef2e.png",
            "plans": [
                {"duration": 1, "price": 100},
                {"duration": 2, "price": 200},
                {"duration": 3, "price": 300},
            ],
        },
        # Agrega más productos aquí
    ]
    return render_template("index.html", products=products)

# Ruta estado de cuentas
@app.route("/estado")
def estado():
    conn = connect_db()
    cursor = conn.cursor(dictionary=True)

    # Consulta a la tabla cuentas
    cursor.execute("""
        SELECT id, tipocuenta, correoc, perfiles, fechac, fechav 
        FROM cuentas
    """)
    cuentas = cursor.fetchall()

    data = []
    current_date = datetime.now().date()

    for cuenta in cuentas:
        # Verificar usuarios activos según fechas
        if cuenta['fechac'] <= current_date <= cuenta['fechav']:
            # Consulta a la tabla ventas para relacionar los datos
            cursor.execute("""
                SELECT id, cliente, tipocuenta, cuenta_disponible, fechaini, fechaexp 
                FROM ventas 
                WHERE cuenta_disponible = %s AND %s BETWEEN fechaini AND fechaexp
            """, (cuenta['id'], current_date))
            ventas = cursor.fetchall()

            # Verificar perfiles disponibles
            perfiles_ocupados = len(ventas)
            perfiles_disponibles = cuenta['perfiles']
            if perfiles_disponibles < 0:
                perfiles_disponibles = 0


            data.append({
                "cuenta": cuenta,
                "ventas": ventas,
                "perfiles_disponibles": perfiles_disponibles
            })

    cursor.close()
    conn.close()
    return render_template("estado.html", data=data)


# Ruta para ver los usuarios registrados
@app.route('/usuarios', endpoint='mostrar_usuarios')
def mostrar_usuarios():
    db = connect_db()
    cursor = db.cursor()

    # Consulta para obtener todos los usuarios
    cursor.execute("SELECT id, nombre_usuario, numero_telefono, correo_electronico, codigo_referido, rol, saldo, verificado FROM usuarios")
    usuarios = cursor.fetchall()

    # Cerrar la conexión
    db.close()
    
    return render_template('usuarios.html', usuarios=usuarios)

@app.route('/netflix')
def netflix():
    return render_template('netflix.html')

@app.route('/metodos_pago')
def metodos_pago():
    return render_template('metodos_pago.html')

@app.route('/tasas_de_pago')
def tasas_de_pago():
    return render_template('tasasdepago.html')

@app.route('/max')
def max():
    return render_template('max.html')

@app.route('/disney')
def disney():
    return render_template('disney.html')

@app.route('/spotify')
def spotify():
    return render_template('spotify.html')

@app.route('/youtube')
def youtube():
    return render_template('youtube.html')

@app.route('/primevideo')
def primevideo():
    return render_template('primevideo.html')

@app.route('/paramount')
def paramount():
    return render_template('paramount.html')

@app.route('/crunchyroll')
def crunchyroll():
    return render_template('crunchyroll.html')


# Ruta principal Admin
@app.route('/admin')
@admin_required
def admin():
    db = connect_db()
    cursor = db.cursor()

    # Obtener notificaciones de renovaciones pendientes y cuentas expiradas
    today = datetime.now().date()

    # Notificaciones de clientes que deben renovar
    cursor.execute("SELECT v.id, c.nombre FROM ventas v JOIN clientes c ON v.cliente = c.id WHERE v.fechaexp <= %s AND (v.estado IS NULL OR v.estado = '')", (today,))
    clientes_a_renovar = cursor.fetchall()

    # Notificaciones de pedidos
    cursor.execute("SELECT id FROM pedidos")
    pedidos = cursor.fetchall()

    # Notificaciones de solicitud de retiros
    cursor.execute("SELECT * FROM retiros WHERE estado = %s", ('pendiente',))
    retiros = cursor.fetchall()

    # Notificaciones de cuentas expiradas
    cursor.execute("SELECT id, correoc FROM cuentas WHERE fechav <= %s", (today,))
    cuentas_expiradas = cursor.fetchall()

    # Crear lista de notificaciones
    notificaciones = []
    for cliente in clientes_a_renovar:
        link = url_for('ver_renovaciones')
        notificaciones.append({'mensaje': f"Cliente {cliente[1]} (ID: {cliente[0]}) debe renovar", 'link': link})
    for cuenta in cuentas_expiradas:
        link = url_for('ver_cuentas')
        notificaciones.append({'mensaje': f"Renovación de cuenta ID: {cuenta[0]} pendiente", 'link': link})
    for pedido in pedidos:
        link = url_for('ver_pedidos')
        notificaciones.append({'mensaje': f"Nuevo Pedido ID: {pedido[0]}", 'link': link})
    for retiro in retiros:
        link = url_for('ver_retiros')  # Necesitarás crear esta ruta si no existe
        notificaciones.append({'mensaje': f"Solicitud de retiro ID: {retiro[0]}", 'link': link})

    db.close()
    return render_template('admin.html', notificaciones=notificaciones)


# Ruta para ver cuentas
@app.route('/ver_cuentas', methods=['GET', 'POST'])
@admin_required
def ver_cuentas():
    db = connect_db()
    cursor = db.cursor()
    if request.method == 'POST':
        search_query = request.form['search']
        cursor.execute("SELECT * FROM cuentas WHERE correoc LIKE %s OR tipocuenta LIKE %s", 
                       ('%' + search_query + '%', '%' + search_query + '%'))
    else:
        cursor.execute("SELECT * FROM cuentas")
    cuentas = cursor.fetchall()
    db.close()
    return render_template('ver_cuentas.html', cuentas=cuentas)

# Ruta para ver clientes
@app.route('/ver_clientes', methods=['GET', 'POST'])
@admin_required
def ver_clientes():
    db = connect_db()
    cursor = db.cursor()
    if request.method == 'POST':
        search_query = request.form['search']
        cursor.execute("SELECT * FROM clientes WHERE nombre LIKE %s OR numero LIKE %s", 
                       ('%' + search_query + '%', '%' + search_query + '%'))
    else:
        cursor.execute("SELECT * FROM clientes")
    clientes = cursor.fetchall()
    db.close()
    return render_template('ver_clientes.html', clientes=clientes)

# Ruta para ver ventas
@app.route('/ver_ventas', methods=['GET', 'POST'])
@admin_required
def ver_ventas():
    db = connect_db()
    cursor = db.cursor()
    if request.method == 'POST':
        search_query = request.form['search']
        cursor.execute("SELECT * FROM ventas WHERE cliente LIKE %s OR tipocuenta LIKE %s", 
                       ('%' + search_query + '%', '%' + search_query + '%'))
    else:
        cursor.execute("SELECT * FROM ventas")
    ventas = cursor.fetchall()
    db.close()
    return render_template('ver_ventas.html', ventas=ventas)


# Ruta para agregar cuenta
@app.route('/agregar_cuenta', methods=['GET', 'POST'])
@admin_required
def agregar_cuenta():
    if request.method == 'POST':
        tipo_cuenta = request.form['tipo_cuenta']
        correoc = request.form['correoc']
        password = request.form['password']
        fechac = request.form['fechac']
        fechav = request.form['fechav']
        perfiles = request.form['perfiles']
        inversion = request.form['inversion']

        db = connect_db()
        cursor = db.cursor()
        cursor.execute("INSERT INTO cuentas (tipocuenta, correoc, password, fechac, fechav, perfiles, inversion) VALUES (%s, %s, %s, %s, %s, %s, %s)", 
                       (tipo_cuenta, correoc, password, fechac, fechav, perfiles, inversion))
        db.commit()
        db.close()
        flash('Cuenta agregada exitosamente', 'success')
        return redirect(url_for('agregar_cuenta'))

    return render_template('agregar_cuenta.html', next_id=get_next_id('cuentas'))

# Ruta para agregar cliente
@app.route('/agregar_cliente', methods=['GET', 'POST'])
@login_required
def agregar_cliente():
    if request.method == 'POST':
        nombre = request.form['nombre']
        numero = request.form['numero']
        referido = session.get('referido')

        db = connect_db()
        cursor = db.cursor()
        cursor.execute("INSERT INTO clientes (nombre, numero, referido) VALUES (%s, %s, %s)", (nombre, numero, referido))
        db.commit()
        db.close()
        flash('Cliente agregado exitosamente', 'success')
        return redirect(url_for('agregar_cliente'))

    return render_template('agregar_cliente.html', next_id=get_next_id('clientes'))

# Obtener la inversión según el correo de la cuenta seleccionada
def get_inversion(cuenta_diponible,tipo_cuenta):
    db = connect_db()
    cursor = db.cursor()
    cursor.execute("SELECT inversion FROM cuentas WHERE id = %s and tipocuenta = %s", (cuenta_diponible,tipo_cuenta))
    inversion = cursor.fetchone()[0]  # Asegurarse de obtener un Decimal
    db.close()
    return float(inversion)  # Convertir a float antes de retornar 

# Función para restar un perfil de perfiles en cuentas
def restar_perfil(correo_cuenta):
    db = connect_db()
    cursor = db.cursor()
    cursor.execute("UPDATE cuentas SET perfiles = perfiles - 1 WHERE id = %s", (correo_cuenta,))
    db.commit()
    db.close()

# Ruta para agregar venta
@app.route('/agregar_venta', methods=['GET', 'POST'])
@admin_required
def agregar_venta():
    if request.method == 'POST':
        cliente = request.form['cliente']
        tipo_cuenta = request.form['tipo_cuenta']
        cuenta_disponible = request.form['cuenta_disponible']
        fechaini = datetime.strptime(request.form['fechaini'], '%Y-%m-%d')
        dias = int(request.form['dias'])
        fechaexp = fechaini + timedelta(days=dias)
        monto = float(request.form['monto'])
        inversion = get_inversion(cuenta_disponible,tipo_cuenta)
        gananciaref = "0.00"
        referido = request.form['referido']

        if dias == '60':
                inversion *= 2
                ganancia = monto - inversion
        elif dias == '90':
                inversion *= 3
                ganancia = monto - inversion

        if referido != '' and referido == 'STREAMPLUS':
            ganancia = monto - inversion
        else :
            gananciaref = float(monto - inversion) * PORCENTAJE_REFERIDO

        db = connect_db()
        cursor = db.cursor()
        cursor.execute("INSERT INTO ventas (cliente, tipocuenta, cuenta_disponible, fechaini, dias, fechaexp, monto, inversion, referido, gananciaref) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", 
                       (cliente, tipo_cuenta, cuenta_disponible, fechaini, dias, fechaexp, monto, inversion, referido, gananciaref))
        db.commit()
        # Restar un perfil de perfiles en cuentas
        restar_perfil(cuenta_disponible)
        db.close()
        
        # Redirigir con el parámetro para descargar factura
        return redirect(url_for('agregar_venta'))

    # Obtener datos necesarios para el formulario
    clientes = obtener_clientes()
    tipos_cuenta = ["netflix", "disneyplus", "max", "spotify", "youtube", "primevideo"]
    cuentas_disponibles = obtener_cuentas_disponibles()

    return render_template('agregar_venta.html', next_id=get_next_id('ventas'), clientes=clientes, tipos_cuenta=tipos_cuenta, cuentas_disponibles=cuentas_disponibles)

@app.route('/get_cuentas_disponibles/<tipo_cuenta>')
def get_cuentas_disponibles(tipo_cuenta):
    cuentas_disponibles = obtener_cuentas_disponibles_por_tipo(tipo_cuenta)
    return jsonify(cuentas_disponibles)

# Función para obtener clientes desde la base de datos
def obtener_clientes():
    db = connect_db()
    cursor = db.cursor()
    referido = session.get('referido')
    cursor.execute("SELECT id, nombre, numero FROM clientes WHERE referido = %s", (referido,))
    clientes = cursor.fetchall()
    db.close()
    return clientes

# Función para obtener cuentas disponibles desde la base de datos
def obtener_cuentas_disponibles():
    db = connect_db()
    cursor = db.cursor()
    cursor.execute("SELECT id,perfiles FROM cuentas WHERE perfiles BETWEEN 1 AND 8")
    cuentas_disponibles = cursor.fetchall()
    db.close()
    return cuentas_disponibles

def obtener_cuentas_disponibles_por_tipo(tipo_cuenta):
    db = connect_db()
    cursor = db.cursor()
    cursor.execute("SELECT correoc,id,perfiles FROM cuentas WHERE tipocuenta = %s AND perfiles BETWEEN 1 AND 8", (tipo_cuenta,))
    cuentas_disponibles = cursor.fetchall()
    db.close()
    return [cuenta for cuenta in cuentas_disponibles] 

@app.route('/get_inversion')
def get_inversion_route():
    db = connect_db()
    cursor = db.cursor()
    correo = request.args.get('correo')
    cursor.execute("SELECT inversion FROM cuentas WHERE correoc = %s", (correo,))
    inversion = cursor.fetchall()
    db.close()
    return {'inversion': inversion}


# Ruta para ver ingresos
@app.route('/ver_ingresos')
@admin_required
def ver_ingresos():
    db = connect_db()
    cursor = db.cursor()

    # Ingresos mensuales
    current_month = datetime.now().month
    cursor.execute("SELECT SUM(ganancia) FROM ventas WHERE MONTH(fechaini) = %s", (current_month,))
    ingresos_mensuales = cursor.fetchone()[0] or 0

    # Ingresos anuales
    current_year = datetime.now().year
    cursor.execute("SELECT SUM(ganancia) FROM ventas")
    ingresos_anuales = cursor.fetchone()[0] or 0

     # Ingresos por referidos mensuales y anuales
    cursor.execute("SELECT referido, SUM(gananciaref) as ganancia_mensual FROM ventas WHERE referido IS NOT NULL AND referido != '' AND MONTH(fechaini) = %s GROUP BY referido", (current_month,))
    referidos_mensuales = cursor.fetchall()

    cursor.execute("SELECT referido, SUM(gananciaref) as ganancia_anual FROM ventas WHERE referido IS NOT NULL AND referido != '' AND YEAR(fechaini) = %s GROUP BY referido", (current_year,))
    referidos_anuales = cursor.fetchall()

    # Ventas mensuales y anuales de STREAMPLUS
    cursor.execute("SELECT SUM(ganancia) FROM ventas WHERE referido = 'STREAMPLUS' AND MONTH(fechaini) = %s", (current_month,))
    ventas_streamplus_mensual = cursor.fetchone()[0] or 0

    cursor.execute("SELECT SUM(ganancia) FROM ventas WHERE referido = 'STREAMPLUS' AND YEAR(fechaini) = %s", (current_year,))
    ventas_streamplus_anual = cursor.fetchone()[0] or 0

    db.close()

    return render_template('ver_ingresos.html', 
                           ingresos_mensuales=ingresos_mensuales, 
                           ingresos_anuales=ingresos_anuales,
                           referidos_mensuales=referidos_mensuales, 
                           referidos_anuales=referidos_anuales,
                           ventas_streamplus_mensual=ventas_streamplus_mensual,
                           ventas_streamplus_anual=ventas_streamplus_anual)


#Ruta Agregar Pedido
@app.route('/agregar_pedido', methods=['GET', 'POST'])
@login_required
def agregar_pedido():
    if request.method == 'POST':
        cliente = request.form['cliente']
        tipo_cuenta = request.form['tipo_cuenta']
        cuenta_disponible = request.form['cuenta_disponible']
        fechaini = datetime.strptime(request.form['fechaini'], '%Y-%m-%d')
        dias = int(request.form['dias'])
        fechaexp = fechaini + timedelta(days=dias)
        monto = float(request.form['monto'])
        inversion = get_inversion(cuenta_disponible,tipo_cuenta)
        user_id = session['user_id']
        # obtener referido
        db = connect_db()
        cursor = db.cursor()
        cursor.execute("SELECT codigo_referido FROM usuarios WHERE id = %s", (user_id,))
        referido = cursor.fetchone()[0]

        gananciaref = "0.00"

        if dias == 60:
                inversion *= 2
                ganancia = monto - inversion
        elif dias == 90:
                inversion *= 3
                ganancia = monto - inversion
        gananciaref = (monto - inversion) * PORCENTAJE_REFERIDO

        db = connect_db()
        cursor = db.cursor()
        cursor.execute("INSERT INTO pedidos (cliente, tipocuenta, cuenta_disponible, fechaini, dias, fechaexp, monto, inversion, referido, gananciaref) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", 
                       (cliente, tipo_cuenta, cuenta_disponible, fechaini, dias, fechaexp, monto, inversion, referido, gananciaref))
        db.commit()
        db.close()

        flash('Pedido agregado exitosamente', 'success')
        return redirect(url_for('agregar_pedido'))

    # Obtener datos necesarios para el formulario
    clientes = obtener_clientes()
    tipos_cuenta = ["netflix", "disneyplus", "max", "spotify", "youtube", "primevideo"]
    cuentas_disponibles = obtener_cuentas_disponibles()

    next_id = get_next_id('ventas')

    return render_template('agregar_pedido.html', next_id=next_id, clientes=clientes, tipos_cuenta=tipos_cuenta, cuentas_disponibles=cuentas_disponibles)


@app.route('/ver_ventas_usuario')
@login_required
def ver_ventas_usuario():
    db = connect_db()
    cursor = db.cursor()

    # Obtener el codigo ref de usuario
    username = session['username']
    cursor.execute("SELECT codigo_referido FROM usuarios WHERE nombre_usuario = %s", (username,))
    referido = cursor.fetchone()[0]  

    # Consulta para obtener las ventas del usuario específicado
    cursor.execute("SELECT * FROM ventas WHERE referido = %s", (referido,))
    ventas = cursor.fetchall()

    db.close()
    return render_template('ver_ventas_usuario.html', ventas=ventas)


#Ruta ver ingresos del usuario
@app.route('/ver_ingresos_usuario')
@login_required
def ver_ingresos_usuario():
    db = connect_db()
    cursor = db.cursor()

    current_month = datetime.now().month
    current_year = datetime.now().year

    #Obtener el codigo ref de usuario
    username = session['username']
    cursor.execute("SELECT codigo_referido FROM usuarios WHERE nombre_usuario = %s", (username,))
    referido = cursor.fetchone()[0] 

    cursor.execute("SELECT SUM(gananciaref) FROM ventas WHERE referido = %s AND MONTH(fechaini) = %s", (referido, current_month))
    ingresos_mensuales = cursor.fetchone()[0] or 0

    cursor.execute("SELECT SUM(gananciaref) FROM ventas WHERE referido = %s", (referido,))
    ingresos_anuales = cursor.fetchone()[0] or 0

    db.close()
    return render_template('ver_ingresos_usuario.html', ingresos_mensuales=ingresos_mensuales, ingresos_anuales=ingresos_anuales)


# Ruta para ver clientes que deben renovar
@app.route('/ver_renovaciones')
@admin_required
def ver_renovaciones():
    db = connect_db()
    cursor = db.cursor()
    today = datetime.now().date()
    cursor.execute("SELECT v.id, v.cliente, v.tipocuenta, v.cuenta_disponible, v.fechaini, v.fechaexp, c.nombre, c.numero "
                   "FROM ventas v JOIN clientes c ON v.cliente = c.id WHERE v.fechaexp <= %s AND (v.estado IS NULL OR v.estado = '')", (today,))
    renovaciones = cursor.fetchall()
    db.close()
    return render_template('ver_renovaciones.html', renovaciones=renovaciones)

#Ruta ver y confirmar pedidos
@app.route('/ver_pedidos', methods=['GET', 'POST'])
@admin_required
def ver_pedidos():
    db = connect_db()
    cursor = db.cursor()

    if request.method == 'POST':
        pedido_id = request.form['pedido_id']

        # Obtener detalles del pedido
        cursor.execute("SELECT * FROM pedidos WHERE id = %s", (pedido_id,))
        pedido = cursor.fetchone()
        cursor.execute("SELECT perfiles FROM cuentas WHERE tipocuenta = %s and correoc = %s", (pedido[2],pedido[3]))
        perfiles = cursor.fetchone()

        if perfiles and perfiles[0] == 0:
            flash('Ya no hay perfiles disponibles', 'danger')
            return redirect(url_for('ver_pedidos'))
        else:
            # Mover a tabla ventas
            cursor.execute(
            "INSERT INTO ventas (cliente, tipocuenta, cuenta_disponible, fechaini, dias, fechaexp, monto, inversion, referido, gananciaref) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (pedido[1], pedido[2], pedido[3], pedido[4], pedido[5], pedido[6], pedido[7], pedido[8], pedido[9], pedido[10])
            )
            # Sumar gananciaref al saldo del usuario referido
            if pedido[8]:  # Verificar si hay un usuario referido
             referido_id = pedido[9]
             gananciaref = pedido[10]

            # Obtener el saldo actual del usuario referido
            cursor.execute("SELECT saldo FROM usuarios WHERE codigo_referido = %s", (referido_id,))
            referido = cursor.fetchone()

            if referido:
                nuevo_saldo = referido[0] + gananciaref

                # Actualizar el saldo del usuario referido
                cursor.execute("UPDATE usuarios SET saldo = %s WHERE codigo_referido = %s", (nuevo_saldo, referido_id))

            # Borrar de la tabla pedidos
            cursor.execute("DELETE FROM pedidos WHERE id = %s", (pedido_id,))
            db.commit()

            # Restar un perfil de perfiles en cuentas
            restar_perfil(pedido[2])

            db.close()

            flash('Pedido confirmado exitosamente', 'success')
            return redirect(url_for('ver_pedidos'))
            

    else:
        # Mostrar pedidos pendientes
        cursor.execute("SELECT * FROM pedidos")
        pedidos = cursor.fetchall()
        db.close()
        return render_template('ver_pedidos.html', pedidos=pedidos)



# Ruta para renovar una venta
@app.route('/renovar_venta/<int:venta_id>', methods=['POST'])
@admin_required
def renovar_venta(venta_id):
    dias = int(request.form['dias'])
    fechaini = datetime.now().date()
    fechaexp = fechaini + timedelta(days=dias)

    db = connect_db()
    cursor = db.cursor()
    cursor.execute("SELECT cliente, tipocuenta, cuenta_disponible, monto, inversion, referido, gananciaref FROM ventas WHERE id = %s", (venta_id,))
    venta = cursor.fetchone()

    cursor.execute("INSERT INTO ventas (cliente, tipocuenta, cuenta_disponible, fechaini, dias, fechaexp, monto, inversion, referido, gananciaref) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", 
                   (venta[0], venta[1], venta[2], fechaini, dias, fechaexp, venta[3], venta[4], venta[5], venta[6]))
    
    # Sumar ganancia al saldo del usuario
    if venta[5]:
        referido_id = venta[5]
        gananciaref = float(venta[6])

        # Obtener el saldo actual del usuario
        cursor.execute("SELECT saldo FROM usuarios WHERE codigo_referido = %s", (referido_id,))
        referido = cursor.fetchone()

        if referido:
            nuevo_saldo = referido[0] + gananciaref

            # Actualizar el saldo del usuario
            cursor.execute("UPDATE usuarios SET saldo = %s WHERE codigo_referido = %s", (nuevo_saldo, referido_id))

    cursor.execute("UPDATE ventas SET estado = 'renovado' WHERE id = %s", (venta_id,))
    db.commit()
    db.close()

    flash('Venta renovada exitosamente', 'success')
    return redirect(url_for('ver_renovaciones'))

# Ruta para marcar como no renovado
@app.route('/no_renovo/<int:venta_id>', methods=['POST'])
@admin_required
def no_renovo(venta_id):
    db = connect_db()
    cursor = db.cursor()

    cursor.execute("SELECT cuenta_disponible FROM ventas WHERE id = %s", (venta_id,))
    cuenta_disponible = cursor.fetchone()[0]

    cursor.execute("UPDATE cuentas SET perfiles = perfiles + 1 WHERE id = %s", (cuenta_disponible,))
    cursor.execute("UPDATE ventas SET estado = 'inactivo' WHERE id = %s", (venta_id,))
    db.commit()
    db.close()
    return redirect(url_for('ver_renovaciones'))

# Ruta para editar cuenta
@app.route('/editar_cuenta/<int:cuenta_id>', methods=['GET', 'POST'])
@admin_required
def editar_cuenta(cuenta_id):
    db = connect_db()
    cursor = db.cursor()
    if request.method == 'POST':
        tipo_cuenta = request.form['tipo_cuenta']
        correoc = request.form['correoc']
        password = request.form['password']
        fechac = request.form['fechac']
        fechav = request.form['fechav']
        perfiles = request.form['perfiles']
        inversion = request.form['inversion']

        cursor.execute("UPDATE cuentas SET tipocuenta=%s, correoc=%s, password=%s, fechac=%s, fechav=%s, perfiles=%s, inversion=%s WHERE id=%s", 
                       (tipo_cuenta, correoc, password, fechac, fechav, perfiles, inversion, cuenta_id))
        db.commit()
        db.close()
        flash('Cuenta actualizada exitosamente', 'success')
        return redirect(url_for('ver_cuentas'))

    cursor.execute("SELECT id, tipocuenta, correoc, password, fechac, fechav, perfiles, inversion FROM cuentas WHERE id=%s", (cuenta_id,))
    cuenta = cursor.fetchone()
    db.close()
    return render_template('editar_cuenta.html', cuenta=cuenta)


@app.route('/retirar', methods=['GET'])
@login_required
def retirar():
    db = connect_db()
    cursor = db.cursor()
    user_id = session['username']

    cursor.execute("SELECT saldo FROM usuarios WHERE nombre_usuario = %s", (user_id,))
    saldo = cursor.fetchall()[0]
    
    # Recuperar el historial de retiros
    cursor.execute("SELECT id, usuario, cantidad, metpago, infopago, fecha, estado FROM retiros WHERE usuario = %s", (user_id,))
    retiros = cursor.fetchall()

    db.close()
    return render_template('retirar.html', retiros=retiros,saldo=saldo)



#Ruta para Retirar
@app.route('/retirar_dinero', methods=['POST'])
@login_required
def retirar_dinero():
    user_id = session['username']
    cantidad = float(request.form['cantidad'])
    metpago = request.form['metpago']
    infopago = ''

    if metpago == 'transferencia':
        banco = request.form['banco']
        cuenta = request.form['cuenta']
        infopago = f'Banco: {banco}, Cuenta: {cuenta}'
    elif metpago == 'tigo_money':
        telefono = request.form['telefono']
        infopago = f'Teléfono: {telefono}'
    elif metpago == 'paypal':
        paypal_email = request.form['paypal_email']
        infopago = f'Correo PayPal: {paypal_email}'

    db = connect_db()
    cursor = db.cursor()

    # Obtener el saldo actual del usuario
    cursor.execute("SELECT saldo FROM usuarios WHERE nombre_usuario = %s", (user_id,))
    saldo_actual = cursor.fetchone()[0]

    if cantidad > saldo_actual:
        flash('Saldo insuficiente para retirar esa cantidad.', 'danger')
        db.close()
        return redirect(url_for('retirar'))

    # Calcular el nuevo saldo del usuario
    nuevo_saldo = saldo_actual - cantidad

    # Insertar en la tabla de retiros
    cursor.execute("INSERT INTO retiros (usuario, cantidad, metpago, infopago, saldo_actual, estado) VALUES (%s, %s, %s, %s, %s, 'pendiente')",
                   (user_id, cantidad, metpago, infopago, nuevo_saldo))

    # Actualizar el saldo del usuario
    cursor.execute("UPDATE usuarios SET saldo = %s WHERE nombre_usuario = %s", (nuevo_saldo, user_id))

    db.commit()
    db.close()

    return redirect(url_for('retirar'))

# Ruta para ver retiros pendientes y confirmar retiro
@app.route('/ver_retiros', methods=['GET', 'POST'])
@admin_required
def ver_retiros():
    db = connect_db()
    cursor = db.cursor()

    if request.method == 'POST':
        retiro_id = request.form['retiro_id']

        # Actualizar estado del retiro a pagado
        cursor.execute("UPDATE retiros SET estado = 'pagado' WHERE id = %s", (retiro_id,))
        db.commit()
        return redirect(url_for('ver_retiros'))

    # Obtener retiros pendientes
    cursor.execute("SELECT * FROM retiros WHERE estado = 'pendiente'")
    retiros = cursor.fetchall()
    db.close()
    return render_template('ver_retiros.html', retiros=retiros)

@app.route('/pedido', methods=['GET', 'POST'])
def pedido():
    if request.method == 'POST':
        nombre = request.form['nombre']
        numero = request.form['numero']
        tipo_cuenta = request.form['tipo_cuenta']
        cuenta_disponible = request.form['cuenta_disponible']
        fechaini = datetime.strptime(request.form['fechaini'], '%Y-%m-%d')
        dias = int(request.form['dias'])
        fechaexp = fechaini + timedelta(days=dias)
        monto = float(request.form['monto'])

        db = connect_db()
        cursor = db.cursor()

        # Insertar cliente
        cursor.execute("INSERT INTO clientes (nombre, numero) VALUES (%s, %s)", (nombre, numero))
        cliente_id = cursor.lastrowid
        cliente = str(cliente_id) + "-" + nombre

        # Calcular ganancia e inversión
        inversion = get_inversion(cuenta_disponible, tipo_cuenta)
        referido = request.form['referido']

        gananciaref = 0.00
        if dias == 60:
            inversion *= 2
        elif dias == 90:
            inversion *= 3

        ganancia = monto - inversion
        gananciaref = ganancia * PORCENTAJE_REFERIDO

        # Insertar pedido
        cursor.execute("""
            INSERT INTO pedidos (cliente, tipocuenta, cuenta_disponible, fechaini, dias, fechaexp, monto, inversion, referido, gananciaref)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (cliente, tipo_cuenta, cuenta_disponible, fechaini, dias, fechaexp, monto, inversion, referido, gananciaref))

        pedido_id = cursor.lastrowid
        db.commit()
        db.close()

        # Enviar mensaje de WhatsApp
        mensaje = f"Mi ID del pedido: {pedido_id}"
        enviar_whatsapp('+50497302756', mensaje)
        flash('Pedido agregado exitosamente', 'success')

    # Obtener datos necesarios para el formulario
    tipos_cuenta = ["netflix", "disneyplus", "max", "spotify", "youtube", "primevideo"]
    next_id = get_next_id('pedidos')

    return render_template('pedido.html', next_id=next_id, tipos_cuenta=tipos_cuenta)

def enviar_whatsapp(numero, mensaje):
    url = f'https://api.whatsapp.com/send?phone={numero}&text={mensaje}'
    return requests.get(url)

# Función para obtener los datos de la venta desde la base de datos
def obtener_venta_por_id(venta_id):
    db = connect_db()
    cursor = db.cursor()

    # Consulta para obtener los datos de la venta
    cursor.execute("""
        SELECT id, cliente, tipocuenta, cuenta_disponible, fechaini, dias, fechaexp, monto, referido
        FROM ventas
        WHERE id = %s
    """, (venta_id,))

    venta = cursor.fetchone()

    db.close()

    if venta:
        return {
            'id': venta[0],
            'cliente': venta[1],
            'tipocuenta': venta[2],
            'cuenta_disponible': venta[3],
            'fechaini': venta[4],
            'dias': venta[5],
            'fechaexp': venta[6],
            'monto': venta[7],
            'referido': venta[8]
        }
    return None

# Ruta para generar la factura y convertirla en PNG
@app.route('/factura/<int:venta_id>', methods=['GET'])
def generar_factura(venta_id):
    venta = obtener_venta_por_id(venta_id)

    if venta is None:
        return "Venta no encontrada", 404

    # Crear una imagen en blanco con Pillow, tamaño ajustado para mayor contenido
    img = Image.new('RGB', (1000, 1500), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)

    # Cargar el logotipo desde la URL proporcionada
    logo_url = "https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEieGkUeZGUtcHFXvXvldzZrOPIXRhEQfH_OdthzY8ypt5-Vt7IAnlTmpSNGg9WZpf3fjfuNMveyAm5NSdvU2ipa1ggFN4ePPXr7GjtP8ZwtaP3VUBgp0ld-InUodUAXwV3CjBx5XLWW4gcosuKhjz2co0Z-2yiJVg7gi5nIELP6jha0O-kJ2LU9hN0ksiI/s1600/s.png"
    logo_response = requests.get(logo_url)
    logo = Image.open(BytesIO(logo_response.content))
    logo = ImageOps.contain(logo, (250, 250))  # Ajustar el tamaño del logo
    img.paste(logo, (50, 50))

    # Cargar la fuente
    font_path = "arial.ttf"  # Asegúrate de tener la fuente o especifica la ruta correcta
    font_largebold = ImageFont.truetype("arialbd.ttf", 60)
    font_medium = ImageFont.truetype(font_path, 40)
    font_small = ImageFont.truetype(font_path, 35)
    font_smallc = ImageFont.truetype(font_path, 30)
    font_small2 = ImageFont.truetype(font_path, 40)
    font_bold = ImageFont.truetype("arialbd.ttf", 40)  # Fuente en negrita

    # Dibujar los datos de la empresa
    draw.text((350, 50), "StreamPlus", font=font_largebold, fill=(0, 0, 0))
    draw.text((350, 150), "Honduras, C.A", font=font_bold, fill=(0, 0, 0))
    draw.text((350, 200), "Teléfono: 9730-2756", font=font_bold, fill=(0, 0, 0))
    draw.text((350, 250), "Email: streamplushn@gmail.com", font=font_bold, fill=(0, 0, 0))

    # Dibujar los datos de la factura
    draw.text((50, 350), f"Factura ID: {venta['id']}", font=font_bold, fill=(0, 0, 0))
    draw.text((50, 425), "Fecha de Emisión:", font=font_bold, fill=(0, 0, 0))
    draw.text((450, 425), f"{datetime.now().strftime('%Y-%m-%d')}", font=font_small2, fill=(0, 0, 0))
    # Dibujar los datos del cliente
    draw.text((50, 500), "Cliente:", font=font_bold, fill=(0, 0, 0))
    draw.text((450, 500), f"{venta['cliente']}", font=font_small2, fill=(0, 0, 0))

    # Detalles de la venta
    draw.text((50, 650), "Detalles de la Compra", font=font_largebold, fill=(0, 0, 0))
    draw.text((50, 750), "Tipo de Cuenta:", font=font_bold, fill=(0, 0, 0))
    draw.text((450, 757), venta['tipocuenta'], font=font_small, fill=(0, 0, 0))
    draw.text((50, 815), "ID Cuenta:", font=font_bold, fill=(0, 0, 0))
    draw.text((450, 822), venta['cuenta_disponible'], font=font_smallc, fill=(0, 0, 0))
    draw.text((50, 880), "Fecha de Inicio:", font=font_bold, fill=(0, 0, 0))
    draw.text((450, 887), f"{venta['fechaini']}", font=font_small, fill=(0, 0, 0))
    draw.text((50, 945), "Días:", font=font_bold, fill=(0, 0, 0))
    draw.text((450, 952), str(venta['dias']), font=font_small, fill=(0, 0, 0))
    draw.text((50, 1010), "Vence:", font=font_bold, fill=(0, 0, 0))
    draw.text((450, 1017), f"{venta['fechaexp']}", font=font_small, fill=(0, 0, 0))
    draw.text((50, 1075), "Monto:", font=font_bold, fill=(0, 0, 0))
    draw.text((450, 1082), f"{venta['monto']} L", font=font_small, fill=(0, 0, 0))
    draw.text((50, 1140), "Referido:", font=font_bold, fill=(0, 0, 0))
    draw.text((450, 1147), venta['referido'], font=font_small, fill=(0, 0, 0))

    # Guardar la imagen en un objeto BytesIO
    img_io = BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)

    return send_file(img_io, mimetype='image/png', as_attachment=True, download_name=f'factura_{venta_id}.png')


def run_http():
    app.run(host="0.0.0.0", port=80)  # HTTP (sin cifrado)

def run_https():
    ssl_context = ("C:\\streamplushn.com\\certificate.crt", "C:\\streamplushn.com\\private.key")
    app.run(host="0.0.0.0", port=443, ssl_context=ssl_context)  # HTTPS (cifrado)

if __name__ == "__main__":
    Thread(target=run_http).start()  # Inicia HTTP
    Thread(target=run_https).start()  # Inicia HTTPS