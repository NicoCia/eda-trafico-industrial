# Análisis exploratorio de cinco conjuntos de tráfico industrial

Este repositorio contiene el análisis exploratorio de cinco conjuntos de datos
públicos de tráfico de red industrial —**Westermo**, **QUT DNP3**,
**Morris / Turnipseed**, **HAI** e **ICS-Flow**—, hecho para elegir sobre qué
datos construir un detector de anomalías no supervisado. Es parte del Trabajo
Final de la Carrera de Especialización en Inteligencia Artificial de la
Facultad de Ingeniería de la Universidad de Buenos Aires.

Lo que hay acá son mediciones sobre los archivos. El punto de partida fue una
selección de conjuntos escrita a partir de la documentación publicada de cada
uno, antes de abrir ninguno. El análisis la contrastó contra los datos, y
seis de los ocho hallazgos principales contradicen lo que la documentación de
los conjuntos o su descripción corriente dan por sentado. Cada contradicción
está en [`INFORME.md`](eda/INFORME.md) con el número que la sostiene y el
script que lo calcula.

## Orden de lectura

1. **[`eda/EXPLORATORIO.md`](eda/EXPLORATORIO.md)** — qué contiene cada
   conjunto. Una sección por conjunto: variables y tipos, faltantes y su
   mecanismo, redundancia, poder discriminante, estructura temporal, balance de
   clases y datos sensibles. Se lee primero porque describe los datos sin
   discutir todavía qué hacer con ellos.
2. **[`eda/INFORME.md`](eda/INFORME.md)** — qué implican. Los ocho hallazgos
   que cambian cómo se usan estos conjuntos, las cinco preguntas que el
   análisis tenía que responder, el papel de ICS-Flow y si los cinco se pueden
   unir en un conjunto integrado.
3. **[`eda/INSTRUCCIONES.md`](eda/INSTRUCCIONES.md)** — el encargo original,
   con la partición temporal fijada de antemano y las restricciones de trabajo.
   Es opcional: sirve para saber qué se pidió y con qué reglas.

Los números de los dos primeros documentos salen de los scripts de
[`eda/scripts/`](eda/scripts); las salidas completas, con su detalle campo por
campo, quedan versionadas en [`eda/salidas/`](eda/salidas).

## Las dos reglas que dieron forma al análisis

**No se abrió ningún conjunto de prueba.** La partición temporal 60/20/20 se
fijó antes de medir y el análisis recorre solo el tramo de entrenamiento. La
única excepción declarada es el conteo de etiquetas del tramo de prueba, que
hacía falta para saber si alcanza la muestra: son conteos de las columnas de
etiqueta y nada más. La sección 2 de `INFORME.md` lo detalla archivo por
archivo.

**Nada se afirma sin haberlo medido.** Donde un dato no se pudo verificar, el
texto lo dice en lugar de completarlo, y `INFORME.md` enumera las cifras que
no salen de correr el código.

Y eso no alcanzó, lo que también se deja dicho. Tres auditorías
independientes recalcularon las cifras contra los archivos y encontraron
errores que la aritmética no muestra: una frase que responde una pregunta
distinta de la que mide la cifra de al lado —otra población, otro
denominador, otra ventana—. Están corregidos, y los documentos registran en
su lugar cuál era el error y qué lo reemplaza, porque esa historia es parte
del resultado.

## Los datos no están acá

Son alrededor de 22 GB, con 54 archivos por encima del límite de 100 MB por
archivo, y dos de los cinco conjuntos no declaran licencia, de modo que
redistribuirlos no estaría respaldado.
[`datasets/LEEME.md`](datasets/LEEME.md) tiene el comando de descarga de cada
uno, lo que ocupa, y los detalles de formato que hay que conocer antes de
leerlos —los separadores distintos entre versiones de HAI, las etiquetas en
archivo aparte, el empaquetado de 32 bits de ICS-Flow—. Para Morris hay además
una ficha de procedencia,
[`datasets/morris-turnipseed/PROCEDENCIA.md`](datasets/morris-turnipseed/PROCEDENCIA.md),
porque el servidor original ya no sirve los archivos y hay dos versiones del
conjunto, una de ellas con fuga documentada.

Una vez descargados, los conjuntos van en `datasets/`, con un subdirectorio por
conjunto, según los nombres que usa ese archivo.

## Cómo reproducir

Todo corre en un entorno virtual propio y no se instala nada en el sistema. Las
versiones están fijadas en `eda/requirements.txt`; el análisis se escribió con
Python 3.9.

```bash
make -C eda venv
```

```bash
make -C eda todo
```

`make todo` regenera las salidas y las figuras desde los datos. Dos pasos
son lentos: la pregunta 1 recorre 3,46 GB de PCAP y 31,1 millones de paquetes, y
la sección 4 recorre 1,8 GB y 25,2 millones; tardan alrededor de cinco y de
siete minutos. Hay objetivos sueltos para rehacer una parte sola —`p1`, `p2`,
`westermo`, `morris`, `hai`, `icsflow`, `verificaciones`, `exploratorio`—, y la
semilla está fijada en `eda/scripts/comun.py`.

Los lectores de DNP3 y de Modbus/TCP están escritos para este análisis, en
`eda/scripts/dnp3.py` y `eda/scripts/modbus.py`. Delimitan las tramas, les
quitan los CRC de enlace e interpretan los objetos y las escrituras; no hacen
falta herramientas externas de captura.

**Dos comprobaciones no corren acá, y las dos lo dicen en lugar de callarlo.**
El script 14 deriva la probabilidad de detección y de falsa alarma de un trabajo
publicado, a partir de las tablas que ese trabajo trae, y comprueba su propia
transcripción contra el texto extraído del PDF, que no se redistribuye. Sin ese
archivo el script corre igual y declara que la comprobación no se hizo. Y el
objetivo `guarda-tabla` compara la tabla de criterios de comparabilidad contra
el documento del proyecto que la publica, que tampoco forma parte de este
repositorio; donde no está, el objetivo lo informa y `make todo` sigue
adelante.

## Los conjuntos y sus licencias

Las licencias se verificaron una por una en su fuente, no en la ficha del
repositorio que las agrega.

| Conjunto | Autoría | Dónde | Licencia |
|---|---|---|---|
| Westermo | Westermo Network Technologies | `github.com/westermo/network-traffic-dataset` | CC BY 4.0 |
| HAI | publicado por la cuenta `icsdataset` | `github.com/icsdataset/hai`, Kaggle `icsdataset/hai-security-dataset` | CC BY-SA 4.0 |
| ICS-Flow | Alireza Dehlaghi | Kaggle `alirezadehlaghi/icssim` | CC BY-NC-SA 4.0 |
| QUT DNP3 (2017) | QUT InfoSec | `github.com/qut-infosec/2017QUT_DNP3` | **sin declarar** |
| Morris / Turnipseed | Tommy Morris e Ian Turnipseed, laboratorio SCADA de Mississippi State University | recuperado del Internet Archive | **sin declarar** |

Tres advertencias que conviene tener a la vista:

- **ICS-Flow prohíbe el uso comercial** (cláusula NC) y obliga a licenciar los
  derivados en los mismos términos.
- **HAI obliga a licenciar los derivados en los mismos términos** (cláusula
  SA).
- **Morris y QUT no conceden derechos de forma explícita.** Para un uso
  académico los dos sirven; para cualquier otro, la ausencia de licencia es más
  incómoda que una cláusula restrictiva, porque no dice qué se puede hacer.

## Licencia de lo propio

El código, las figuras y los documentos de este repositorio se publican bajo la
licencia **MIT**: ver [`LICENSE`](LICENSE).

Con una aclaración que no es una restricción añadida sino la de los conjuntos:
las salidas de `eda/salidas/`, las figuras y las tablas de los documentos
contienen mediciones derivadas de conjuntos con cláusula ShareAlike —HAI, bajo
CC BY-SA 4.0— y no comercial —ICS-Flow, bajo CC BY-NC-SA 4.0—. Quien reutilice
esas mediciones concretas conviene que revise los términos de origen; la
licencia MIT cubre lo que es trabajo propio de este repositorio.
