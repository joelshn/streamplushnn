import flet as ft

# Función para interpretar el pseudocódigo
def interpretar_pseudocodigo(pseudocodigo):
    """
    Intérprete extendido para comandos comunes de PSeInt.
    """
    try:
        lineas = pseudocodigo.strip().split("\n")
        variables = {}
        salida = []

        def eval_condicional(condicion):
            """Evalúa una condición lógica en base a las variables."""
            try:
                return eval(condicion, {}, variables)
            except Exception as e:
                raise ValueError(f"Error en la condición: {condicion}, {e}")

        i = 0
        while i < len(lineas):
            linea = lineas[i].strip().lower()

            if linea.startswith("leer"):
                var = linea.split("leer")[1].strip()
                variables[var] = 10  # Entrada simulada para pruebas
                salida.append(f"Variable '{var}' leída con valor 10.")

            elif linea.startswith("escribir"):
                expresion = linea.split("escribir")[1].strip()
                if expresion in variables:
                    salida.append(f"{variables[expresion]}")
                else:
                    salida.append(expresion)

            elif "=" in linea:
                var, valor = linea.split("=")
                var = var.strip()
                valor = valor.strip()
                variables[var] = eval(valor, {}, variables)
                salida.append(f"{var} = {variables[var]}")

            elif linea.startswith("si"):
                condicion = linea.split("si")[1].split("entonces")[0].strip()
                if eval_condicional(condicion):
                    salida.append(f"Condición '{condicion}' verdadera.")
                else:
                    salida.append(f"Condición '{condicion}' falsa.")
                    while not lineas[i].strip().lower().startswith("fin si"):
                        i += 1

            elif linea.startswith("mientras"):
                condicion = linea.split("mientras")[1].strip()
                if not eval_condicional(condicion):
                    while not lineas[i].strip().lower().startswith("fin mientras"):
                        i += 1

            elif linea.startswith("repetir"):
                repetir_inicio = i + 1
                while not lineas[i].strip().lower().startswith("hasta que"):
                    i += 1
                condicion = lineas[i].split("hasta que")[1].strip()
                while not eval_condicional(condicion):
                    for j in range(repetir_inicio, i):
                        interpretar_pseudocodigo(lineas[j])

            elif linea.startswith("para"):
                parts = linea.split()
                var = parts[1]
                inicio = eval(parts[3], {}, variables)
                fin = eval(parts[5], {}, variables)
                paso = eval(parts[7], {}, variables) if len(parts) > 7 else 1
                for val in range(inicio, fin + 1, paso):
                    variables[var] = val
                    salida.append(f"Iteración {var} = {val}")

            elif linea.startswith("fin"):
                salida.append(f"Fin de bloque detectado: {linea}")
            
            else:
                salida.append(f"Comando no reconocido: {linea}")

            i += 1

        return "\n".join(salida)
    except Exception as e:
        return f"Error al interpretar: {e}"


# Función principal de la app
def main(page: ft.Page):
    page.title = "PSeInt Executor - Allan Hernández"
    page.scroll = "adaptive"

    # Título de la app
    title = ft.Text("Ejecutar Pseudocódigos - PSeInt", size=32, weight="bold", color="blue")

    # Campo de entrada para el pseudocódigo
    pseudocode_input = ft.TextField(
        label="Introduce tu pseudocódigo aquí:",
        multiline=True,
        expand=True,
        min_lines=10,
        max_lines=15,
    )

    # Área de salida
    output_title = ft.Text("Salida:", size=20, weight="bold")
    output_text = ft.Text(value="", color="green", size=18)

    # Función para ejecutar el pseudocódigo
    def ejecutar_pseudocodigo(event):
        pseudocodigo = pseudocode_input.value
        if not pseudocodigo.strip():
            output_text.value = "Por favor, introduce un pseudocódigo válido."
        else:
            resultado = interpretar_pseudocodigo(pseudocodigo)
            output_text.value = resultado
        page.update()

    # Botón para ejecutar el pseudocódigo
    execute_button = ft.ElevatedButton(
        "Ejecutar",
        icon=ft.icons.PLAY_ARROW,
        on_click=ejecutar_pseudocodigo,
        bgcolor="green",
        color="white",
    )

    # Layout
    page.add(
        title,
        pseudocode_input,
        execute_button,
        ft.Divider(),
        output_title,
        output_text,
    )

# Ejecuta la app
ft.app(target=main)
