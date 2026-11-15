"""Lector de Modbus/TCP sobre dpkt, en Python puro y sin tshark.

Escrito con el mismo criterio que `dnp3.py`: reensamblado por flujo TCP, una
estructura por unidad de datos de aplicacion (ADU) y nada de adivinar los
campos que no se pueden derivar del propio formato.

Formato (MODBUS Messaging on TCP/IP Implementation Guide v1.0b):

    MBAP: transaccion(2) protocolo(2) longitud(2) unidad(1)
    PDU : funcion(1) datos(longitud-2)

`longitud` cuenta la unidad mas el PDU, de modo que la ADU completa mide
6 + longitud octetos. Un segmento TCP puede traer varias ADU, y una ADU puede
quedar partida entre dos segmentos: por eso hace falta el buffer por flujo.
"""

import struct

PUERTO = 502

LECTURA = {
    1: "Read Coils", 2: "Read Discrete Inputs", 3: "Read Holding Registers",
    4: "Read Input Registers", 7: "Read Exception Status",
    20: "Read File Record", 24: "Read FIFO Queue",
}

ESCRITURA = {
    5: "Write Single Coil", 6: "Write Single Register",
    15: "Write Multiple Coils", 16: "Write Multiple Registers",
    21: "Write File Record", 22: "Mask Write Register",
    23: "Read/Write Multiple Registers",
}

OTRAS = {8: "Diagnostics", 11: "Get Comm Event Counter",
         12: "Get Comm Event Log", 17: "Report Server ID",
         43: "Encapsulated Interface Transport"}


def nombre_funcion(fn):
    if fn & 0x80:
        base = fn & 0x7F
        return "EXCEPCION de %s" % (
            LECTURA.get(base) or ESCRITURA.get(base) or OTRAS.get(base) or base)
    return (LECTURA.get(fn) or ESCRITURA.get(fn) or OTRAS.get(fn)
            or "desconocida_%d" % fn)


class Adu(object):
    """Una unidad de datos de aplicacion Modbus/TCP ya delimitada."""

    __slots__ = ("ts", "src_ip", "dst_ip", "sport", "dport", "src_mac",
                 "dst_mac", "transaccion", "unidad", "funcion", "datos",
                 "es_peticion", "direccion", "cantidad", "valores",
                 "valor32", "excepcion")

    def __init__(self):
        self.direccion = None
        self.cantidad = None
        self.valores = []
        self.valor32 = None
        self.excepcion = None

    @property
    def es_escritura(self):
        return self.funcion in ESCRITURA

    @property
    def es_lectura(self):
        return self.funcion in LECTURA

    @property
    def nombre(self):
        return nombre_funcion(self.funcion)


def _interpretar_escritura(adu):
    """Extrae direccion, cantidad y valores de una peticion de escritura.

    Solo se interpreta la peticion: la respuesta de 5, 6, 15 y 16 es un eco de
    la cabecera y no agrega informacion.
    """
    d = adu.datos
    fn = adu.funcion
    if fn in (5, 6) and len(d) >= 4:
        adu.direccion, valor = struct.unpack(">HH", d[:4])
        adu.cantidad = 1
        adu.valores = [valor]
    elif fn in (15, 16) and len(d) >= 5:
        adu.direccion, adu.cantidad = struct.unpack(">HH", d[:4])
        n = d[4]
        cuerpo = d[5:5 + n]
        if fn == 16:
            adu.valores = [struct.unpack(">H", cuerpo[i:i + 2])[0]
                           for i in range(0, len(cuerpo) - 1, 2)]
            # ICSSIM escribe cada variable como un entero de 32 bits repartido
            # en dos registros consecutivos, el mas significativo primero.
            if adu.cantidad == 2 and len(cuerpo) == 4:
                adu.valor32 = struct.unpack(">I", cuerpo)[0]
        else:
            adu.valores = [(cuerpo[i // 8] >> (i % 8)) & 1
                           for i in range(adu.cantidad)
                           if i // 8 < len(cuerpo)]
    elif fn == 22 and len(d) >= 6:
        adu.direccion = struct.unpack(">H", d[:2])[0]
        adu.valores = list(struct.unpack(">HH", d[2:6]))
    elif fn == 23 and len(d) >= 10:
        adu.direccion = struct.unpack(">H", d[4:6])[0]
        adu.cantidad = struct.unpack(">H", d[6:8])[0]


def adus_del_buffer(buf):
    """Delimita las ADU completas de un buffer de flujo.

    Devuelve (lista de (transaccion, unidad, funcion, datos), resto). Si la
    cabecera no es plausible se avanza un octeto y se vuelve a probar, que es
    lo unico sensato cuando el flujo arranca a mitad de una ADU.
    """
    salida = []
    i = 0
    n = len(buf)
    while i + 8 <= n:
        trans, proto, longitud = struct.unpack(">HHH", buf[i:i + 6])
        # El identificador de protocolo vale 0 en Modbus/TCP, y la longitud
        # nunca pasa de 253 octetos de PDU mas la unidad.
        if proto != 0 or not (2 <= longitud <= 254):
            i += 1
            continue
        total = 6 + longitud
        if i + total > n:
            break
        unidad = buf[i + 6]
        funcion = buf[i + 7]
        salida.append((trans, unidad, funcion, buf[i + 8:i + total]))
        i += total
    return salida, buf[i:]


def leer_pcap(ruta, hasta=None, max_paquetes=None):
    """Itera las ADU Modbus de un PCAP.

    `hasta` corta la lectura en esa marca de tiempo absoluta, que es como se
    respeta la particion temporal sin recorrer el resto del archivo.
    Devuelve tuplas (adu, contadores); la ultima lleva adu = None.
    """
    import dpkt
    import socket

    flujos = {}
    c = {"paquetes": 0, "ip": 0, "tcp": 0, "no_tcp": {}, "con_carga": 0,
         "puerto_502": 0, "adus": 0, "primer_ts": None, "ultimo_ts": None}
    with open(ruta, "rb") as fh:
        try:
            pcap = dpkt.pcap.Reader(fh)
        except ValueError:
            yield None, c
            return
        for ts, buf in pcap:
            c["paquetes"] += 1
            if c["primer_ts"] is None:
                c["primer_ts"] = ts
            c["ultimo_ts"] = ts
            if hasta is not None and ts > hasta:
                break
            if max_paquetes and c["paquetes"] > max_paquetes:
                break
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except Exception:
                continue
            ip = eth.data
            if not isinstance(ip, dpkt.ip.IP):
                continue
            c["ip"] += 1
            tr = ip.data
            # El PCAP trae ICMP y UDP de los escaneos y del DDoS. Hay que
            # descartarlos ANTES de leer un puerto que no existe.
            if not isinstance(tr, dpkt.tcp.TCP):
                k = type(tr).__name__
                c["no_tcp"][k] = c["no_tcp"].get(k, 0) + 1
                continue
            c["tcp"] += 1
            if not tr.data:
                continue
            c["con_carga"] += 1
            if PUERTO not in (tr.sport, tr.dport):
                continue
            c["puerto_502"] += 1
            clave = (ip.src, ip.dst, tr.sport, tr.dport)
            previo = flujos.get(clave, b"")
            adus, resto = adus_del_buffer(previo + bytes(tr.data))
            flujos[clave] = resto if len(resto) < 65536 else b""
            if not adus:
                continue
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            smac = ":".join("%02x" % b for b in eth.src)
            dmac = ":".join("%02x" % b for b in eth.dst)
            for trans, unidad, funcion, datos in adus:
                a = Adu()
                a.ts, a.src_ip, a.dst_ip = ts, src, dst
                a.sport, a.dport = tr.sport, tr.dport
                a.src_mac, a.dst_mac = smac, dmac
                a.transaccion, a.unidad, a.funcion, a.datos = (
                    trans, unidad, funcion, datos)
                a.es_peticion = (tr.dport == PUERTO)
                if funcion & 0x80:
                    a.excepcion = datos[0] if datos else None
                elif a.es_peticion:
                    _interpretar_escritura(a)
                c["adus"] += 1
                yield a, c
    yield None, c
