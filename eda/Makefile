# Analisis exploratorio de los conjuntos de datos del Trabajo Final.
#
# Regenera de punta a punta las salidas y las figuras del INFORME.md.
# Se ejecuta desde este directorio:   make -C eda
#
# El entorno virtual vive en eda/.venv y no se instala nada en el sistema.
# Los datos se esperan en ../datasets, segun datasets/LEEME.md.

PY       := .venv/bin/python
PIP      := .venv/bin/pip
SCRIPTS  := scripts
SALIDAS  := salidas
FIGURAS  := figuras

.PHONY: todo venv p1 p2 p3 p4 p5 limpiar limpiar-venv requirements

# `duplicados` va PRIMERO entre los de Westermo: produce la tabla de flujos
# con los contadores de volumen recontados sobre paquetes unicos, que es la
# que usan el 11, el 16 y el 17. Sin ella esos tres caen al CSV publicado,
# avisan por stderr, y sus cifras de volumen quedan infladas al doble.
duplicados: $(PY)
	$(PY) -I $(SCRIPTS)/22_westermo_duplicados.py

.PHONY: duplicados

todo: duplicados p1 p2 p3 p4 p5 icsflow verificaciones exploratorio guarda-tabla
	@echo ""
	@echo "Analisis completo. Salidas en $(SALIDAS)/ y figuras en $(FIGURAS)/."

# ---------------------------------------------------------------- entorno
venv: $(PY)

$(PY):
	python3 -m venv .venv
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt

requirements: $(PY)
	$(PIP) freeze > requirements.txt

# ------------------------------------------------------------- preguntas
# Pregunta 1: carga util DNP3 en QUT. Recorre ~4 GB de PCAP; es el paso lento.
p1: $(PY)
	$(PY) -I $(SCRIPTS)/01_qut_payload.py

# Pregunta 2: determinismo del trafico normal (Westermo y QUT).
p2: $(PY)
	$(PY) -I $(SCRIPTS)/05_determinismo.py

# Preguntas 3 y 4 sobre Westermo y sobre Morris, y 3/4/5 sobre HAI.
p3 p4: westermo morris hai

p5: hai

westermo: $(PY)
	$(PY) -I $(SCRIPTS)/02_westermo_etiquetas.py

morris: $(PY)
	$(PY) -I $(SCRIPTS)/03_morris.py

hai: $(PY)
	$(PY) -I $(SCRIPTS)/04_hai.py

# Seccion 4 de INFORME.md: ICS-Flow tiene escrituras Modbus con parametros?
# Requiere datasets/ics-flow/, que se baja de Kaggle.
icsflow: $(PY)
	$(PY) -I $(SCRIPTS)/06_icsflow_escrituras.py

.PHONY: westermo morris hai icsflow verificaciones guarda-tabla

# Verificaciones posteriores, que nacieron de auditar INFORME.md contra sus
# fuentes. Las tres primeras son rapidas: ninguna llega a tres segundos.
#
# Las dos ultimas responden la pregunta por las caracteristicas de cada
# conjunto y por si se puede armar uno integrado.
# 10 recorre los 2,6 GB de entrenamiento de HAI y tarda unos minutos; 11
# depende de las salidas de 04 y de 10, de modo que el orden importa. 19 lee
# la salida de 01 y no vuelve a abrir ningun PCAP.
verificaciones: $(PY)
	$(PY) -I $(SCRIPTS)/07_morris_fuga_presion.py
	$(PY) -I $(SCRIPTS)/08_qut_desglose_paquetes.py
	$(PY) -I $(SCRIPTS)/09_intervalos_pd.py
	$(PY) -I $(SCRIPTS)/10_inventario_caracteristicas.py
	$(PY) -I $(SCRIPTS)/11_integracion_esquemas.py
	$(PY) -I $(SCRIPTS)/12_westermo_modbus.py
	$(PY) -I $(SCRIPTS)/13_icsflow_determinismo.py
	$(PY) -I $(SCRIPTS)/14_schuster_pd_pfa.py
	$(PY) -I $(SCRIPTS)/19_qut_escrituras.py

# 15 no es una medicion sino una guarda: escribe la regla que convierte cada
# medicion en un simbolo, la aplica a los insumos y compara celda por celda
# contra la tabla de criterios de comparabilidad del documento del proyecto
# que la lleva, terminando con codigo distinto de cero cuando las dos se
# separan. Entra en `todo` justamente por eso: si alguien cambia un simbolo de
# esa tabla sin cambiar la medicion que lo sostiene, la regeneracion completa
# falla. Ese documento no se publica junto con el analisis, de modo que donde
# la guarda no esta el objetivo lo dice y sigue adelante.
guarda-tabla: $(PY)
	@if [ -f $(SCRIPTS)/15_regla_calificacion.py ]; then \
	  $(PY) -I $(SCRIPTS)/15_regla_calificacion.py; \
	else \
	  echo "guarda-tabla: la guarda no esta en este arbol; se omite."; \
	fi

# Estudio exploratorio de los conjuntos (eda/EXPLORATORIO.md). Escribe sus
# propios derivados en eda/derivados/.
exploratorio: $(PY)
	$(PY) -I $(SCRIPTS)/16_exploratorio_flujos.py
	$(PY) -I $(SCRIPTS)/17_discriminante_estructura.py
	$(PY) -I $(SCRIPTS)/18_exploratorio_resto.py

.PHONY: exploratorio

# Las dos solas, para rehacer el inventario sin correr todo lo anterior.
inventario: $(PY)
	$(PY) -I $(SCRIPTS)/10_inventario_caracteristicas.py
	$(PY) -I $(SCRIPTS)/11_integracion_esquemas.py

.PHONY: inventario

# --------------------------------------------------------------- limpieza
limpiar:
	rm -rf $(SALIDAS) $(FIGURAS) derivados

limpiar-venv:
	rm -rf .venv
