# Análisis exploratorio de los conjuntos de datos — brief de trabajo

## Qué es este proyecto

Trabajo Final de la Carrera de Especialización en Inteligencia Artificial (FIUBA). El
objetivo es un detector de anomalías de
tráfico para redes LAN determinísticas o industriales, entrenado de forma **no
supervisada** sobre tráfico normal y evaluado con inyección controlada de anomalías. El
desempeño se expresa como probabilidad de detección (PD) frente a probabilidad de falsa
alarma (PFA).

El relevamiento del estado del arte ya está hecho. Esta tarea es el análisis
exploratorio: la **tarea 3 del plan de trabajo** y el **requerimiento 2.8**, que exige
caracterizar el comportamiento normal del tráfico documentando las distribuciones de las
características, su periodicidad y su poder discriminante.

## Leer antes de empezar

En este orden, y no hace falta más:

1. `datasets/LEEME.md` — qué conjunto hay, dónde, en qué formato, y los detalles de
   formato que ya se detectaron (separadores distintos en HAI, etiquetas en archivo
   aparte en 23.05).
2. `datasets/morris-turnipseed/PROCEDENCIA.md` — de dónde salió ese conjunto y por qué
   hay dos versiones, una de ellas con fuga documentada.
3. La tabla de criterios de comparabilidad D1–D7 y la selección de conjuntos que dejó
   el relevamiento del estado del arte del proyecto. **Es lo que este análisis tiene
   que validar o refutar.** Esos documentos no forman parte de este repositorio; lo que
   de ellos se contrasta queda transcrito en [`INFORME.md`](INFORME.md), al lado de la
   medición.

## Regla de trabajo del proyecto

**No afirmar nada que no se haya comprobado contra los datos.** Si un dato no se puede
verificar, decirlo en lugar de completarlo. Ya ocurrió en este proyecto que una
afirmación tomada de un paper resultó falsa contra la realidad de los archivos, y por eso
este análisis existe.

Si un hallazgo **contradice** la selección previa, eso es un resultado valioso: hay
que reportarlo de forma destacada, no suavizarlo.

## Tres restricciones que no son negociables

### 1. Todo en un entorno virtual

Nada se instala en el sistema. Crear `eda/.venv` y trabajar siempre desde ahí:

```bash
cd <raíz del repositorio>/eda
python3 -m venv .venv
./.venv/bin/pip install --upgrade pip
./.venv/bin/pip install <paquetes>
./.venv/bin/pip freeze > requirements.txt
```

Python del sistema es 3.9.6: verificar compatibilidad al elegir versiones.

**Para leer PCAP usar `scapy` o `dpkt`, no `pyshark`.** `pyshark` es un envoltorio de
`tshark`, que es un binario del sistema y no se puede instalar en un venv. `scapy` y
`dpkt` son Python puro y leen PCAP sin dependencias externas.

### 2. No tocar el conjunto de prueba

El protocolo de evaluación que el proyecto adoptó (requerimiento 3.6 del plan, y
criterios P3 y P4 de la revisión del estado del arte) exige partición estricta en tres conjuntos
disjuntos —entrenar, calibrar umbral, medir— y que ninguna decisión se tome mirando el
de prueba.

**Un análisis exploratorio que explore el conjunto de prueba contamina el protocolo antes
de empezar**, y es el defecto que este proyecto le critica a buena parte de la
literatura.

**Las particiones ya están definidas. No hay que decidirlas: hay que respetarlas.**

#### Westermo

La captura dura 5442 s. Se comprobó que **los eventos están repartidos de forma
uniforme a lo largo de toda ella** —entre 57 % y 75 % de flujos anómalos en cada tramo
del 10 %, con el primer evento a los 46 s— de modo que **no existe un tramo inicial de
tráfico normal limpio**. La partición es por tiempo, usando la columna `startOffset`:

| Partición | Tramo | Uso |
|---|---|---|
| Entrenamiento | 0 – 3265 s (60 %) | Exploración y ajuste del modelo |
| Calibración | 3265 – 4354 s (20 %) | Umbral. **No explorar en este análisis** |
| Prueba | 4354 – 5442 s (20 %) | **No abrir** |

Del tramo de entrenamiento, usar **solo los flujos etiquetados como normales**. Eso es
legítimo y es lo que hacen los trabajos relevados: las etiquetas se usan para
*seleccionar* el tráfico normal de entrenamiento, no para entrenar.

**Etiquetado de referencia: `NST`, no `IT`.** Está medido sobre
`data/reduced/flows/output_bottom.csv`:

| Estrategia | Normal | Anómalo |
|---|---:|---:|
| `IT_B_Label` | 36,4 % | 63,6 % |
| `NST_B_Label` | 82,4 % | 17,6 % |

Con `IT` el tráfico normal es minoría, porque esa estrategia marca *todo* el tráfico
mientras el ataque está activo y los 96 eventos cubren casi toda la captura. Eso rompe la
premisa del enfoque no supervisado. `NST` marca solo el tráfico que involucra al
atacante y deja un «normal» utilizable. Reportar `IT` en paralelo como cota pesimista,
pero construir sobre `NST`.

Conviene además señalar un hallazgo ya detectado, que corresponde a la pregunta 3: el
reparto medido (82,4 / 14,9 / 2,5 por ciento) **no coincide exactamente** con el que
publica el paper y que la revisión del estado del arte cita (75 / 18,5 / 6,5). Puede deberse a que el paper
describa el conjunto completo —tres puntos de captura, variante extendida— y no este
archivo. Hay que verificarlo sobre los seis CSV y reportar la diferencia.

#### QUT DNP3

**No hace falta definir ningún corte: el conjunto ya trae la partición.** Todas las
carpetas de escenario (`Attacks`, `Control`, `Flooding`, `Injection`, `MITM`,
`Masqurading`, `Replay`) contienen subcarpetas `training/` y `testing/`.

Usar **únicamente `training/`**. No abrir `testing/`.

#### HAI

Usar únicamente los archivos `train*.csv`. No abrir los `test*.csv` ni los
`label-test*.csv`.

Para la pregunta 5, la deriva *dentro* de una versión se mide entre los `train`
sucesivos, que son tramos temporales consecutivos.

#### Morris / Turnipseed

El atributo `time` es un timestamp Unix monótono creciente, de 1418682163 a 1418957854:
275.691 s, unas 76,6 horas. Ordenar por esa columna y cortar 60 / 20 / 20:

| Partición | Tramo | Uso |
|---|---|---|
| Entrenamiento | primeros 165.415 s | Exploración |
| Calibración | siguientes 55.138 s | Umbral. No explorar |
| Prueba | últimos 55.138 s | **No abrir** |

#### La única excepción

Contar etiquetas del conjunto de prueba para responder la pregunta 4 —¿hay suficientes
muestras por tipo?— porque eso es dimensionamiento del experimento y no una decisión de
modelado. Hacerlo de forma explícita y acotada: **solo conteos**, sin mirar
distribuciones de características.

### 3. El código tiene que ser reproducible por un tercero

El proyecto ya está bajo control de versiones (`git`), y el director puede pedir que se
le comparta el código. De modo que:

- **Todo el análisis en scripts**, no en comandos sueltos ni en un notebook con estado.
  Si se usa un notebook, que sea ejecutable de principio a fin sin intervención.
- **Cada script declara qué pregunta responde** en un comentario de cabecera, y es
  ejecutable solo, desde la raíz del repositorio.
- **Rutas relativas**, nunca absolutas: los datos están en `datasets/`, que no se
  versiona pero se reconstruye con `datasets/LEEME.md`.
- **Semilla fija** en todo lo que tenga aleatoriedad, y declarada.
- **`requirements.txt` con versiones fijadas**, generado con `pip freeze`.
- **Un script o `Makefile` que corra todo el análisis de punta a punta** y regenere las
  figuras y las tablas de `INFORME.md`. Si una cifra no sale de correr el código,
  hay que decirlo.
- Los datos no se modifican nunca en su lugar: si hace falta un derivado, se escribe en
  `eda/derivados/` y ese directorio se agrega al `.gitignore`.

## Las cinco preguntas

Cada figura o tabla de `INFORME.md` tiene que responder una de estas. Si no responde ninguna,
no entra. **No hacer un barrido de histogramas de todas las variables**: se ve prolijo y
no decide nada.

### Pregunta 1 — ¿Los PCAP de QUT tienen carga útil DNP3 interpretable? (crítica)

Es la que puede invalidar la selección de conjuntos. Hacerla primero.

La selección previa propone **QUT DNP3 como conjunto de trabajo** para las características
semánticas, con el argumento de que conserva la carga útil del protocolo. Eso se infirió
de que Schuster y König lo usan para análisis de payload, **pero nunca se abrió un PCAP
para comprobarlo.**

Verificar, sobre una muestra de PCAP de cada carpeta (`Attacks`, `Control`, `Flooding`,
`Injection`, `MITM`, `Masqurading`, `Replay`):

- Si hay capa DNP3 reconocible y en qué puerto (DNP3 usa habitualmente TCP 20000).
- Si los **códigos de función** son extraíbles e interpretables.
- Si se pueden recuperar los parámetros de los comandos, no solo las cabeceras.
- Si la separación `master.pcap` / `slave.pcap` se corresponde efectivamente con comando
  y respuesta (hay 28 pares).
- Si los pares de comando y respuesta se pueden emparejar, y con qué información
  (secuencia, marca de tiempo).

**Si la respuesta es que no hay carga útil interpretable, detener el análisis y
reportarlo de inmediato**: cambia la selección de conjuntos y hay que rehacer esa
parte de la revisión del estado del arte.

### Pregunta 2 — ¿El tráfico normal es determinístico? (crítica)

Es la premisa de todo el enfoque no supervisado y el criterio **D2** de comparabilidad, que
dice textualmente que el determinismo «debe medirse sobre los datos y no asumirse por la
descripción del conjunto». **Nunca se midió.**

Sobre el tráfico normal de Westermo y de QUT:

- Periodicidad: distribución de intervalos entre paquetes, autocorrelación de la tasa de
  paquetes por ventana, presencia de ciclos.
- Entropía de direcciones IP de origen y destino, y de puertos.
- Cantidad de interlocutores distintos y estabilidad del conjunto de pares que
  conversan.
- Estabilidad del tamaño de paquete y de la tasa a lo largo del tiempo.

La conclusión que interesa: **¿la envolvente del «normal» es estrecha como supone el
plan, o es más ancha de lo esperado?** Si es ancha, el enfoque no supervisado rinde peor
de lo previsto y conviene saberlo ahora.

### Pregunta 3 — ¿Lo que afirma la documentación está efectivamente en los datos?

Verificar contra los archivos estas afirmaciones concretas:

**Westermo** (de Strandberg et al. 2023):
- Reparto aproximado 75 % tráfico normal, 18,5 % malas configuraciones y SSH malicioso,
  6,5 % ataques.
- Seis tipos de evento: SSH legítimo, SSH malicioso, IP mal configurada, IP duplicada,
  escaneo de puertos, intermediario.
- 96 eventos en total, en 16 tandas aleatorizadas.
- Las cuatro columnas de etiqueta (`IT_B_Label`, `IT_M_Label`, `NST_B_Label`,
  `NST_M_Label`) corresponden a dos estrategias de etiquetado en versión binaria y
  multiclase. **Cuantificar en qué se diferencian**: la estrategia IT marca todo el
  tráfico durante el ataque, la NST solo el que involucra al atacante. La elección cambia
  el problema y conviene saber cuánto.

**Morris / Turnipseed**: 274.628 filas, 214.580 normales, 7 categorías de ataque con
conteos 7753 / 13.035 / 7900 / 20.412 / 4898 / 2176 / 3874. Y el atributo
`command response` con 137.013 comandos y 137.615 respuestas. (Estos valores ya se
verificaron una vez; confirmarlos sirve de control del propio análisis.)

**HAI**: formato por versión según `datasets/LEEME.md`, y qué anomalías están etiquetadas
en cada una.

### Pregunta 4 — ¿Alcanzan las muestras para medir PD por tipo de anomalía?

Decide si el compromiso de línea base que el proyecto se propone es viable:
comprometer **un punto de operación por familia de anomalía** en lugar de un
valor agregado, y para eso hace falta poder estimar PD por tipo con precisión razonable.

Para cada conjunto y cada tipo de anomalía: cuántas instancias y, más importante,
**cuántos eventos distintos**. Un tipo con 20.000 instancias pero 3 eventos no permite
estimar PD por evento con sentido.

Señalar explícitamente los tipos para los que **no** alcanza.

### Pregunta 5 — ¿Hay deriva medible en HAI?

La revisión del estado del arte declara como vacío que no se encontraron estudios
de deriva sobre estos
conjuntos. Esta pregunta empieza a llenarlo con medición propia.

Dos niveles, y conviene no confundirlos:

- **Dentro de una versión**: comparar las distribuciones entre los archivos de
  entrenamiento sucesivos (`train1`, `train2`, …), que son tramos temporales
  consecutivos. Esa sí es deriva temporal.
- **Entre versiones** (20.07 → 21.03 → 22.04 → 23.05): acá hay cambios de testbed
  documentados entre versiones, de modo que las diferencias **no son deriva temporal**
  sino cambio de sistema. Reportarlo como tal y no mezclarlo con lo anterior.

## Qué entregar

En `eda/`:

- `INFORME.md` — los hallazgos, organizados por las cinco preguntas, cada uno con el
  número que lo sustenta. Breve y conclusivo: qué se midió, qué dio, qué implica para el
  proyecto. Si algo contradice la selección previa, en sección destacada al
  principio.
- `scripts/` — el código, ejecutable de nuevo sobre los mismos datos.
- `figuras/` — solo las que responden una de las cinco preguntas.
- `requirements.txt` — del venv, con versiones fijadas.
- `Makefile` o script equivalente que regenere todo el análisis desde cero.
- Al principio de `INFORME.md`, **qué partición se usó y qué tramo se exploró**, para
  quede explícito ante cualquier lector que el conjunto de prueba no se abrió.

## Qué no hacer

- No instalar nada fuera de `eda/.venv`.
- No explorar conjuntos de prueba más allá del conteo de etiquetas de la pregunta 4.
- No usar rutas absolutas ni dejar análisis que solo corra en esta máquina.
- No barrer histogramas de todas las variables.
- No modificar los documentos del relevamiento del estado del arte: reportar los
  hallazgos y dejar que la decisión de actualizarlos se tome aparte.
- No entrenar modelos. Esto es exploración y validación de datos, no modelado.
