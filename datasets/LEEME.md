# Conjuntos de datos

Descargados el 24 de octubre de 2026. Este directorio no se versiona: ver `.gitignore`.

| Directorio | Rol | En disco | Listo para usar |
|---|---|---:|---|
| `westermo/` | Ancla: anomalías de red y errores de configuración | 885 MB | **Sí**, descomprimido y verificado |
| `morris-turnipseed/` | Validación por tipo de anomalía contextual | 27 MB | **Sí**, ARFF directo |
| `qut-dnp3/` | Conjunto de trabajo para características semánticas | 16 GB | **Sí**, 3.051 PCAP extraídos |
| `hai/` | Eje temporal y deriva | 3,4 GB | **Sí**, las cinco versiones |

Total en disco: 20 GB. Los 303 archivos ZIP originales se probaron uno por uno antes de
extraer: ninguno corrupto.

### Detalle de formato que afecta al pipeline

Las versiones de HAI **no comparten formato entre sí**. Conviene no asumir ni el
separador ni dónde están las etiquetas:

| Versión | Separador | Columnas | Etiquetas |
|---|---|---:|---|
| `hai-20.07` | punto y coma (`;`) | 64 | 4 columnas: `attack`, `attack_P1`, `attack_P2`, `attack_P3` |
| `hai-21.03` | coma | 84 | 4 columnas, mismos nombres |
| `hai-22.04` | coma | 88 | 1 columna: `Attack` |
| `hai-23.05` | coma | 87 | **en archivo aparte** |
| `haiend-23.05` | coma | 226 | **en archivo aparte** |

**`hai-20.07/train2.csv` no es tráfico normal limpio**: el análisis exploratorio
encontró dos ataques etiquetados, 776 s en total. Hay que filtrarlos antes de usarlo como
entrenamiento, o excluir ese archivo.

En las dos versiones 23.05 las etiquetas vienen en `label-test1.csv` y
`label-test2.csv`, con dos columnas (`timestamp`, `label`) y 54.001 filas cada uno; hay
que unirlas por marca de tiempo con el CSV de proceso correspondiente. Los archivos de
etiquetas son idénticos entre `hai-23.05` y `haiend-23.05`.

## westermo — verificado

`git clone --depth 1 https://github.com/westermo/network-traffic-dataset.git`
Licencia CC BY 4.0.

Descomprimido: **6 PCAP y 6 CSV**, en dos variantes (`extended` y `reduced`) por cada
uno de los tres puntos de captura (`bottom`, `left`, `right`).

- Los PCAP tienen firma válida (`pcap capture file, microsecond ts, Ethernet`). El mayor
  es `extended/pcaps/bottom.pcap`, 415 MB.
- Los CSV de flujos tienen **64 columnas y 35.405 filas** (variante reducida, punto
  inferior), con las cuatro columnas de etiqueta del paper: `IT_B_Label`, `IT_M_Label`,
  `NST_B_Label`, `NST_M_Label` — las dos estrategias de etiquetado, en versión binaria y
  multiclase.

## qut-dnp3

`git clone --depth 1 https://github.com/qut-infosec/2017QUT_DNP3.git`

Los ataques vienen **separados en carpetas por tipo**: `Flooding`, `Injection`, `MITM`,
`Masqurading`, `Replay`, más `Attacks` y `Control`. Esa estructura da directamente el
desglose por tipo de anomalía que pide el requerimiento 3.5 del plan.

**Corrección del 24/10/2026.** Este archivo afirmaba que la separación entre comando y
respuesta estaba dada por los archivos `master.pcap` y `slave.pcap`. **Era una inferencia
a partir de los nombres, y es falsa**: el análisis exploratorio midió que los dos archivos
traen las dos direcciones del diálogo, con 51–56 % de peticiones en los 28 pares, y que en
`Control` ambos registran la misma conversación (la secuencia de pares *función, número de
secuencia* coincide en 20.000 de 20.000).

Lo que sí funciona, y es lo que sostiene la elección del conjunto: la separación se
recupera del **código de función DNP3** y el emparejamiento de comando con respuesta
funciona por **número de secuencia**, con el 100 % de las operaciones READ emparejadas y
una latencia mediana de 8,1 ms.

**Limitación medida:** el conjunto **no contiene comandos de control con parámetros**.
Sobre 2.318.278 cabeceras de objeto no hay ninguna g12v1 (CROB), g41 ni g40; las 207.798
operaciones WRITE escriben g80v1, es decir limpian el bit de reinicio. La familia de
anomalías de manipulación de parámetros de comando no se puede ejercitar sobre QUT.

**Contenido extraído y verificado**: 3.051 PCAP, 16 GB, con firma válida
(`pcap capture file, microsecond ts, Ethernet`). Reparto por carpeta:

| Carpeta | PCAP | Tamaño |
|---|---:|---:|
| `Injection` | 525 | 3,3 GB |
| `Replay` | 513 | 3,0 GB |
| `Masqurading` | 510 | 1,5 GB |
| `MITM` | 504 | 2,2 GB |
| `Flooding` | 498 | 1,6 GB |
| `Attacks` | 489 | 2,2 GB |
| `Control` | 12 | 812 MB |

Hay 28 pares `master.pcap` / `slave.pcap`. Sin licencia declarada en el repositorio.

## hai — parcial, por una limitación del servidor

`GIT_LFS_SKIP_SMUDGE=1 git clone --depth 1 https://github.com/icsdataset/hai.git`

| Versión | Archivos | Tamaño |
|---|---:|---:|
| `hai-20.07` | 4 CSV | 398 MB |
| `hai-21.03` | 8 CSV | 689 MB |
| `hai-22.04` | 10 CSV + 10 resúmenes | 730 MB |
| `hai-23.05` | 8 CSV (6 de proceso + 2 de etiquetas) | 657 MB |
| `haiend-23.05` | 8 CSV (6 de proceso + 2 de etiquetas) | 1,0 GB |

**Por qué faltan tres versiones.** Las versiones 22.04 y posteriores están almacenadas
con Git LFS, y el repositorio **excedió su cuota de LFS en GitHub**. El error exacto al
intentar bajarlas es: *"This repository exceeded its LFS budget. The account responsible
for the budget should increase it to restore access."* No es un problema del entorno
local: `git-lfs` está instalado e inicializado. No hay forma de bajarlas por git hasta
que los autores amplíen la cuota.

**Las dos versiones que sí están son las que importan para la línea base**: 20.07 es la
que presenta el paper de CSET'20 y 21.03 la del concurso HAICon 2020, que son las
fuentes de los valores de referencia en eTaPR del relevamiento.

**Resuelto el 24/10/2026 vía Kaggle.** Las cinco versiones están completas. Se bajaron
de `kaggle.com/datasets/icsdataset/hai-security-dataset` (licencia CC BY-SA 4.0) y se
verificaron **archivo por archivo contra el repositorio oficial**: los punteros Git LFS
del repositorio llevan el SHA-256 del archivo real, lo que permite comprobar la
procedencia sin necesidad de descargarlo de GitHub.

**Resultado: 42 de 42 archivos idénticos** — 26 CSV de 22.04, 23.05 y haiend-23.05
contra los punteros oficiales, 12 CSV de 20.07 y 21.03 contra los que ya teníamos del
repositorio, y 4 archivos de resumen. Ninguna diferencia. La copia de Kaggle es bit a
bit la misma que publica el equipo de HAI, así que no hay mezcla de procedencias.

Se eliminaron los `.csv.gz` de 20.07 y 21.03, redundantes con los CSV ya extraídos y
verificados.

**Verificación cruzada.** Antes de usar el clone oficial se probó el espejo de terceros
`xuhongzuo/HAI-dataset`: sus 12 archivos de 20.07 y 21.03 tienen SHA-256 **idéntico** a
los del repositorio oficial. El espejo es fiel, pero no aporta nada que el oficial no
tenga, así que se descartó. Tampoco incluye 22.04 con datos ni 23.05.

## morris-turnipseed

Recuperado del Internet Archive: el servidor original ya no sirve los archivos. La
procedencia completa, los atributos y qué versión usó cada trabajo citado están en
`morris-turnipseed/PROCEDENCIA.md`.

En resumen: `IanArffDataset.arff` es la **versión corregida** (Dataset 4, Turnipseed),
274.628 filas, con código de función Modbus, consigna, parámetros del lazo PID, modo de
sistema y un atributo explícito de comando/respuesta. El otro archivo del directorio es
el Dataset 3, que tiene fuga documentada, y está solo como referencia para distinguirlos.

## ics-flow

Bajado de Kaggle (`alirezadehlaghi/icssim`) el 24 de octubre de 2026. 1,9 GB:
`traffic.pcap` con 25.161.400 paquetes, `Dataset.csv` con los flujos etiquetados,
`snapshots_PLC1.csv` y `snapshots_PLC2.csv` con las variables de proceso, y dos
resúmenes del atacante.

**Licencia CC BY-NC-SA 4.0**, verificada en la página de Kaggle. Ningún archivo del
conjunto trae licencia propia. La cláusula *NC* prohíbe el uso comercial y la *SA*
obliga a licenciar los derivados en los mismos términos: tenerlo presente antes de que
entre en algo que se entregue fuera del ámbito académico.

### Estructura de las escrituras Modbus

Importa para construir características, y no es evidente al leer el PCAP:

- Las consignas viajan como **enteros de 32 bits repartidos en dos registros
  consecutivos**, el más significativo primero, con función 16 y cantidad 2. Leer cada
  registro por separado da valores sin sentido: el alto parece un flag de 0 o 1 y el
  bajo parece desbordar.
- El valor físico se obtiene **dividiendo el entero de 32 bits por 10.000**.
- La **dirección Modbus es el doble del índice de la variable** que declaran las
  cabeceras de los dos `snapshots_PLC*.csv`. Así: dirección 6 → `tank_level_min(3)`,
  dirección 8 → `tank_level_max(4)`, dirección 22 → `bottle_level_max(11)`.
- Son **tres consignas**, no seis registros. Verificado contra el registro de proceso:
  `tank_level_max` escrito recorre 5,5258 – 9,5714 y el snapshot da exactamente el
  mismo rango.

### Volumen

| | |
|---|---:|
| Paquetes | 25.161.400 |
| Segmentos Modbus (puerto 502) | 5.924.975 |
| Lecturas (función 3) | 5.923.360 |
| **Escrituras (función 16)** | **1.615** |
| Escrituras con valor extraído | **802** |
| De ellas, bajo intermediario | 143 |

La proporción es de 3.668 lecturas por escritura. Es poco volumen para estimar
probabilidad de detección por evento sobre la familia de parámetros de comando.

Reproducible con `make -C eda icsflow`.
