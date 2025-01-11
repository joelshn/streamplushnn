import mysql.connector
from datetime import datetime

# Función para conectar a la base de datos
def connect_db():
    return mysql.connector.connect(
        host="db4free.net",
        user="allanh",
        password="hernandez2210",
        database="registro504"
    )

# Función para calcular las ganancias de las tablas `ventas` y `recargas` de los últimos 2 meses
def calculate_last_two_months_combined(referido):
    try:
        # Conectar a la base de datos
        connection = connect_db()
        cursor = connection.cursor()

        # Obtener el mes actual y el mes anterior
        now = datetime.now()
        current_month = now.month
        previous_month = (current_month - 1) if current_month > 1 else 12
        current_year = now.year
        previous_year = current_year if current_month > 1 else current_year - 1

        # Consulta para las ganancias de la tabla `ventas`
        query_ventas = """
        SELECT SUM(ganancia) 
        FROM ventas 
        WHERE referido = %s AND 
              ((MONTH(fechaini) = %s AND YEAR(fechaini) = %s) OR 
               (MONTH(fechaini) = %s AND YEAR(fechaini) = %s))
        """
        cursor.execute(query_ventas, (referido, current_month, current_year, previous_month, previous_year))
        ventas_gains = cursor.fetchone()[0] or 0

        # Consulta para las ganancias de la tabla `recargas`
        query_recargas = """
        SELECT SUM(ganancia) 
        FROM recargas 
        WHERE (MONTH(fecha) = %s AND YEAR(fecha) = %s) OR 
              (MONTH(fecha) = %s AND YEAR(fecha) = %s)
        """
        cursor.execute(query_recargas, (current_month, current_year, previous_month, previous_year))
        recargas_gains = cursor.fetchone()[0] or 0

        # Sumar las ganancias
        total_gains = ventas_gains + recargas_gains
        print(f"Ganancias totales de los últimos 2 meses para {referido}: {total_gains}")

        return total_gains
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return 0
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

# Ejecutar la función
if __name__ == "__main__":
    referido = 'DVOSM2Y50K'  # Cambiar según sea necesario
    calculate_last_two_months_combined(referido)
