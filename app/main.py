from flask import Flask, render_template_string
import imaplib
import email
from email.header import decode_header

# Configuración de Gmail
IMAP_SERVER = "imap.gmail.com"
IMAP_PORT = 993
GMAIL_USER = "streamplus504hn@gmail.com"  # Reemplaza con tu correo
GMAIL_PASSWORD = "jzqj pyhr anxg gelj"  # Reemplaza con la contraseña generada

app = Flask(__name__)

def fetch_latest_email():
    try:
        # Conexión al servidor IMAP de Gmail
        mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
        mail.login(GMAIL_USER, GMAIL_PASSWORD)
        
        # Seleccionar la bandeja de entrada
        mail.select("inbox")
        
        # Buscar todos los correos en la bandeja de entrada
        status, messages = mail.search(None, "ALL")
        if status != "OK":
            return None
        
        # Obtener el ID del correo más reciente
        message_ids = messages[0].split()
        latest_email_id = message_ids[-1]
        
        # Recuperar el correo más reciente
        status, msg_data = mail.fetch(latest_email_id, "(RFC822)")
        if status != "OK":
            return None
        
        # Procesar el contenido del correo
        for response_part in msg_data:
            if isinstance(response_part, tuple):
                msg = email.message_from_bytes(response_part[1])
                
                # Obtener el asunto del correo
                subject = decode_header(msg["Subject"])[0][0]
                if isinstance(subject, bytes):
                    subject = subject.decode()
                
                # Extraer el cuerpo del mensaje
                email_body = {"from": msg["From"], "subject": subject, "content": ""}
                if msg.is_multipart():
                    for part in msg.walk():
                        content_type = part.get_content_type()
                        if content_type == "text/html" or content_type == "text/html":
                            email_body["content"] = part.get_payload(decode=True).decode()
                            return email_body
                else:
                    email_body["content"] = msg.get_payload(decode=True).decode()
                    return email_body
        mail.logout()
    except Exception as e:
        print(f"Error: {str(e)}")
        return None

@app.route("/")
def show_email():
    email_data = fetch_latest_email()
    if not email_data:
        return "<h1>No se pudo obtener el correo más reciente.</h1>"

    # Renderizar el correo en HTML
    html_template = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Correo</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            .email-header {{ margin-bottom: 20px; }}
            .email-body {{ border: 1px solid #ddd; padding: 10px; }}
        </style>
    </head>
    <body>
        <div class="email-header">
            <h1>Correo Más Reciente</h1>
            <p><strong>De:</strong> {email_data['from']}</p>
            <p><strong>Asunto:</strong> {email_data['subject']}</p>
        </div>
        <div class="email-body">
            {email_data['content']}
        </div>
    </body>
    </html>
    """
    return render_template_string(html_template)

if __name__ == "__main__":
    app.run(debug=True,host='0.0.0.0', port=8080)
