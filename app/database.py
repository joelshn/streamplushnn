import mysql.connector

# Función para conectar a la base de datos
def connect_db():
    return mysql.connector.connect(
        host="db4free.net",
        user="allanh",
        password="hernandez2210",
        database="registro504"
    )

# Obtener la siguiente ID autoincremental de una tabla
def get_next_id(table_name):
    db = connect_db()
    cursor = db.cursor()
    cursor.execute(f"SELECT MAX(id) FROM {table_name}")
    result = cursor.fetchone()
    db.close()
    return (result[0] or 0) + 1
