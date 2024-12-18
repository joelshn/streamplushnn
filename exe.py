import os
from PyInstaller.__main__ import run

# Obtener la ruta completa al archivo
script_path = os.path.join(os.path.dirname(__file__), 'app', 'main.py')

# Especificar las rutas de las carpetas a incluir
app_folder = os.path.join(os.path.dirname(__file__), 'app')

# Ruta del ícono
icon_path = os.path.join(os.path.dirname(__file__), 's.ico')

# Verificar que la carpeta exista
if not os.path.exists(app_folder):
    print(f"La carpeta {app_folder} no existe.")
    exit(1)

# Imprimir las rutas para verificar
print("Rutas de las carpetas:")
print("app:", app_folder)
print("icono:", icon_path)

# Línea para crear el ejecutable utilizando PyInstaller
params = [
    '--onefile', 
    '--noconsole', 
    '--icon', icon_path,
    '--collect-all', 'sv_ttk', 
    '--add-data', f'{app_folder};app',  
    script_path
]

# Ejecutar PyInstaller
run(params)
