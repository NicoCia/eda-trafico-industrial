# Morris / Turnipseed — procedencia de estos archivos

Recuperados el 24 de octubre de 2026 del **Internet Archive**, porque el servidor
original (`ece.uah.edu/~thm0009/icsdatasets/`) ya no sirve los archivos: todos sus
enlaces devuelven 404 y por HTTPS no responde. La página índice sigue en línea en
https://sites.google.com/a/uah.edu/tommy-morris-uah/ics-data-sets pero sus enlaces
están muertos.

## `IanArffDataset.arff` — **el que hay que usar**

- **Origen**: captura del 1 de mayo de 2026
  `https://web.archive.org/web/20260501171709if_/http://www.ece.uah.edu/~thm0009/icsdatasets/IanArffDataset.arff`
- **Qué es**: Dataset 4 del sitio, "New Gas Pipeline", desarrollado por Ian Turnipseed.
  Es la **versión corregida**: la página lo describe como un conjunto nuevo "con más
  aleatoriedad", creado para resolver la fuga de información del Dataset 3.
- **Contenido verificado**: 274.628 filas, 20 atributos. 214.580 normales y 60.048
  ataques distribuidos en 7 categorías (7.753 / 13.035 / 7.900 / 20.412 / 4.898 /
  2.176 / 3.874).
- **Atributos semánticos** (cumple el criterio D3):
  `address`, `function` (código de función Modbus), `length`, `setpoint`, `gain`,
  `reset rate`, `deadband`, `cycle time`, `rate`, `system mode`, `control scheme`,
  `pump`, `solenoid`, `pressure measurement`, `crc rate`, **`command response`**
  (**1 = comando, 0 = respuesta**; 137.615 comandos y 137.013 respuestas), `time`.

  **Corrección del 24/10/2026.** Este archivo decía antes lo contrario (0 = comando).
  La polaridad correcta se verificó con tres evidencias independientes sobre el propio
  archivo, cada una con su criterio de conteo explícito:

  | Evidencia | Criterio | `cr=0` | `cr=1` |
  |---|---|---:|---:|
  | Códigos de excepción en `function` | valor ≥ 128 | **3.905** | 0 |
  | `setpoint` informado | valor distinto de cero | 0 | **63.963** |
  | `pressure measurement` informado | valor distinto de cero | **63.314** | 0 |

  Un código de excepción y una medición de presión solo pueden venir en una respuesta;
  una consigna, solo en un comando.

  Dos precisiones sobre los criterios, porque cambian los números:

  - El criterio de excepción es **`function` ≥ 128**, no una lista enumerada de los
    códigos canónicos de Modbus. El conjunto contiene 128, 132, 133, 136, 137, 138, 139,
    140, 141, 142 y 171; los dos que pesan son el 136 (2.521 filas) y el 171 (1.024).
    Una lista de los códigos canónicos omite 133 y 138 a 142, que son 240 filas, y da
    3.665 por defecto.
  - En `pressure measurement` hay 68.848 filas con valor numérico y `cr=0`, de las cuales
    63.314 tienen valor distinto de cero. Con `cr=1` hay 40 filas con valor numérico, y
    **las 40 traen un cero explícito**: ninguna informa una medición real.

  Los conteos totales del atributo que este archivo ya daba sí eran correctos.
  Etiquetas: `binary result`, `categorized result` (8 clases), `specific result`
  (36 clases).
- **Limitación**: es la versión con features ya extraídas. El archivo crudo
  (`IanRawDataset.txt`, con el hexadecimal de las tramas) **no está archivado**: no
  tiene ninguna captura en el Internet Archive. Por lo tanto este conjunto no permite
  ejercitar la extracción de características desde la carga útil, solo trabajar sobre
  las features ya calculadas.

## `gas_final_DATASET3_CON_FUGA.arff` — **no usar para entrenar**

- **Origen**: captura del 10 de marzo de 2019.
- **Qué es**: Dataset 3 del sitio (gasoducto), 97.019 filas y 27 atributos.
- **Por qué está acá**: solo como referencia, para poder distinguirlo del anterior. Es
  el conjunto sobre el que pesa la advertencia de los autores: contiene patrones no
  intencionales que permiten identificar ataques de forma irreal (algunos ataques se
  ejecutaron con la presión de gas en un valor y la operación normal en otro).

## Qué versión usó cada trabajo citado

Dato verificado por conteo directo sobre los dos archivos, y relevante porque cambia
cómo deben leerse sus métricas:

| Trabajo | Lo que reporta | Corresponde a |
|---|---|---|
| Shirazi et al. 2016 | 274.627 instancias, 20 features | **Dataset 4** (corregido) |
| Kim et al. 2021 | 274.628 registros, 214.580 normales, 60.048 ataques | **Dataset 4** (corregido) |

Es decir que **sus métricas no están afectadas** por la fuga del Dataset 3, que tiene
97.019 filas y 27 atributos.

## Cita

Morris, T., Thornton, Z., Turnipseed, I. *Industrial Control System Simulation and Data
Logging for Intrusion Detection System Research.* 7th Annual Southeastern Cyber Security
Summit, Huntsville, AL, 3–4 de junio de 2015.

Para el conjunto original: Morris y Gao 2014, DOI `10.1007/978-3-662-45355-1_5`.
