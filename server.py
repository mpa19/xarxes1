#!/usr/bin/env python3

import sys
import time
import socket
import select
from struct import *
from multiprocessing import Process, Manager
from random import randint
from optparse import OptionParser
import os


# ------------- Variables globales -----------------#
DATOS_SERVER = [] #0- NomServer   1- MACserver  2- UDPport  3- TCPport
DATA = []
ADRECA = []
SOCK = []
# ---------------------- Fin variables globales ------------------ #

# ------- class Clients ---------- #
class Clients:
    """
    Estructura que tiene un cliente
    """
    def __init__(self, nom, ip, mac, num_ale, estat):
        self.nom = nom
        self.ip = ip
        self.mac = mac
        self.num_ale = num_ale
        self.estat = estat
# ---------------------- Fin class Clients ------------------ #

# ----------- Funcion setup ------------- #
def setup():
    """
    Configuramos los sockets UDP y TCP
    """

    global SOCK, OPTIONS, DATOS_SERVER, INPUTS

    #Socket UDP
    INPUTS = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    INPUTS.bind(("", int(DATOS_SERVER[2])))
    SOCK.append(INPUTS)

    if OPTIONS.debug:
        print(time.strftime('%X:'), "DEBUG =>  Socket UDP actiu")

    #Socket TCP
    INPUTS = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    INPUTS.bind(("", int(DATOS_SERVER[3])))
    INPUTS.listen(5)
    SOCK.append(INPUTS)

    if OPTIONS.debug:
        print(time.strftime('%X:'), "DEBUG =>  Socket TCP actiu")
# ---------------------- Fin setup ------------------ #

# ---------- Funcion leer_config --------- #
def leer_config():
    """
    Lee los ficheros correspondientes y los guarda en variables
    """
    global SOCK, OPTIONS, LISTA_CLIENTES, DATOS_SERVER

    #Leer archivo de equipos
    file = open(OPTIONS.equips)
    datos = file.readline()

    while True:
        if not datos or datos == "\n":
            break;
        DATOS_CLIENT = datos.split()
        LISTA_CLIENTES.append(Clients(DATOS_CLIENT[0], "        -", \
            DATOS_CLIENT[1], "     -", "DISCONNECTED"))
        datos = file.readline()
    file.close()

    if OPTIONS.debug:
        print(time.strftime('%X:'), "INFO  =>  Llegits", \
            len(LISTA_CLIENTES), "equips autoritzats en el sistema")

    #Leer archivo de config
    file = open(OPTIONS.servidor)
    datos = file.readline()

    while True:
        if not datos:
            break;
        datos_server = datos.split()
        DATOS_SERVER.append(datos_server[1])
        datos = file.readline()
    file.close()

    if OPTIONS.debug:
        print(time.strftime('%X:'), "DEBUG =>  Llegits paràmetres arxiu de configuració")
# ---------------------- Fin leer_config ------------------ #

# -------------- Funcion mirar_tipo_paquete ------- #
def mirar_tipo_paquete(tipus):
    if tipus == 0x02:
        return "REGISTER_NACK"
    elif tipus == 0x03:
        return "REGISTER_REJ"
    elif tipus == 0x12:
        return "ALIVE_NACK"
    elif tipus == 0x13:
        return "ALIVE_REJ"
    return ""
# -------------- Fin mirar_tipo_paquete ------- #

# ------ Funcion buscar_index_cliente --------- #
def buscar_index_cliente(index, donde):
    """
    Encuentra el index del cliente en la lista de los clientes autorizados
    """

    global CLIENTS_ALIVE, LISTA_CLIENTES, DATA
    for index_client in range(len(LISTA_CLIENTES)):
        if donde == 0:
            if LISTA_CLIENTES[index_client].nom == CLIENTS_ALIVE[index]:
                return int(index_client)

        else:
            nom = DATA[index][1].split(b'\0', 1)[0]

            if LISTA_CLIENTES[index_client].nom == nom.decode('utf-8'):
                return index_client

    return None
# ---------------------- Fin buscar_index_cliente ------------------ #

# --------- Funcion entrada_paquet  ------------ #
def entrada_paquet():
    """
    Espera la entrada de un paquete y crea otro proceso
    para gestionar dicho paquete
    """
    global DATA, ADRECA, SOCK, DATA, LISTA_CLIENTES, INPUTS

    i = 0
    while 1:
        infds, outfds, errfds = select.select(SOCK, [], [], 100000)

        if [SOCK[0]] == infds:
            data1, adreca1 = SOCK[0].recvfrom(78)
            DATA.append(data1)
            ADRECA.append(adreca1)
            process2 = Process(target=gestionar_paquet, args=(i,))

        elif [SOCK[1]] == infds:
            newsocket, adreca1 = SOCK[1].accept()
            data1 = newsocket.recv(178)
            DATA.append(data1)
            ADRECA.append(adreca1)
            DATA[i] = unpack('=B7s13s7s150s', DATA[i][:178])
            if DATA[i][0] == 32:
                process2 = Process(target=paquet_send, args=(i, newsocket))
            else:
                process2 = Process(target=paquet_get, args=(i, newsocket))

        process2.processes = False
        process2.start()

        i += 1
# ---------------------- Fin entrada_paquet ------------------ #

# ------- Funcion gestionar_paquet -------- #
def gestionar_paquet(index):
    """
    Mira el paquete que ha llegado y dependiendo del tipo
    hara el registro o el alive
    """

    global DATA, ADRECA, SOCK, DATA, LISTA_CLIENTES
    DATA[index] = unpack('=B7s13s7s50s', DATA[index][:78])

    if DATA[index][0] == 0:
        if OPTIONS.debug:
            print(time.strftime('%X:'), \
                "DEBUG =>  Rebut: bytes=78, comanda=REGISTER_REQ, nom=", \
                DATA[index][1].decode('utf-8'), \
                ", mac=", DATA[index][2].decode('utf-8'), ", alea=", \
                DATA[index][3].decode('utf-8'), \
                ",  dades=")
        correcto = comprobar_estado(0, index)

        if correcto is not None:
            registro(correcto, index)

    elif DATA[index][0] == 16:

        if OPTIONS.debug:
            print(time.strftime('%X:'), \
                "DEBUG =>  Rebut: bytes=78, comanda=ALIVE_INF, nom=", \
                DATA[index][1].decode('utf-8'), \
                ", mac=", DATA[index][2].decode('utf-8'), ", alea=", \
                DATA[index][3].decode('utf-8'), \
                ",  dades=")
        correcto = comprobar_estado(1, index)

        if correcto is not None:
            enviar_alive(correcto, index)
# ---------------------- Fin gestionar_paquet ------------------ #

# --------- Funcion comprobar_estado ----------#
def comprobar_estado(tipo, index):
    """ Mirar que tipo de paquete a entrado y en que estado deberia estar
        depende del estado y el paquete pasara a estar en otro estado o no """

    global LISTA_CLIENTES, DATA, CLIENTS_ALIVE, TIME_ALIVE

    index_client = buscar_index_cliente(index, 3)

    if index_client is not None:

        if tipo == 0:
            num_aleatori = DATA[index][3].split(b'\0', 1)[0]

            if LISTA_CLIENTES[index_client].estat == "DISCONNECTED" and \
                num_aleatori.decode('utf-8') == "000000":
                TIME_ALIVE.append(7)
                CLIENTS_ALIVE.append(LISTA_CLIENTES[index_client].nom)
                return index_client

            # Enviar paquete de suplantacion de identidad
            enviar_paquete_error(index, "Error en dades de l'equip", 0x02)
            return None

        elif tipo == 1:

            if LISTA_CLIENTES[index_client].estat == "REGISTERED":

                if comprobar_alive(index_client, index):
                    index_alive = CLIENTS_ALIVE.index(LISTA_CLIENTES[index_client].nom)
                    TIME_ALIVE[index_alive] = 10
                    cliente = LISTA_CLIENTES[index_client]
                    cliente.estat = "ALIVE"
                    LISTA_CLIENTES.pop(index_client)
                    LISTA_CLIENTES.insert(index_client, cliente)
                    print(time.strftime('%X:'), \
                        "MSG.  =>  Equip", cliente.nom, "passa a estat: ALIVE")
                    return index_client

                return None

            elif LISTA_CLIENTES[index_client].estat == "ALIVE":

                if comprobar_alive(index_client, index):
                    index_alive = CLIENTS_ALIVE.index(LISTA_CLIENTES[index_client].nom)
                    TIME_ALIVE[index_alive] = 10
                    return index_client
                return None

            # Enviar paquete de error "no registrado"
            enviar_paquete_error(index, "Equip no autoritzat en el sistema", 0x13)
            return None

    # Enviar paquete que no se encuentra registrado
    if DATA[index][0] == 16:
        enviar_paquete_error(index, "Equip no autoritzat en el sistema", 0x13)
    else:
        enviar_paquete_error(index, "Equip no autoritzat en el sistema", 0x03)
        return None
# ---------------------- Fin comprobar_estado ------------------ #

# -------- Funcion random_number -------------#
def random_number():
    """
    Crea un numero random que no este ya assignado a un cliente
    """
    global LISTA_CLIENTES
    num_invalido = False

    while 1:
        value = randint(100000, 999999)
        for index_client in range(len(LISTA_CLIENTES)):
            if LISTA_CLIENTES[index_client].num_ale == str(value):
                num_invalido = True

        if num_invalido is False:
            return str(value)
# ---------------------- Fin random_number ------------------ #

# --------- Funcion registro --------- #
def registro(index_client, index):
    """
    Cambia el estado del cliente a REGISTERED y envia
    el paquete REGISTER_ACK con la información del servidor y el puerto TCP
    """

    global ADRECA, DATOS_SERVER, SOCK, DATA, DATOS_CLIENT, LISTA_CLIENTES

    DATA[index] = list(DATA[index])
    DATA[index][0] = 0x01
    random = random_number()
    paq = pack('B7s13s7s50s', DATA[index][0], DATOS_SERVER[0].encode('utf-8'), \
        DATOS_SERVER[1].encode('utf-8'), random.encode('utf-8'), DATOS_SERVER[3].encode('utf-8'))

    cliente = LISTA_CLIENTES[index_client]
    cliente.estat = "REGISTERED"
    cliente.num_ale = random
    cliente.ip = ADRECA[index][0]
    LISTA_CLIENTES.pop(index_client)
    LISTA_CLIENTES.insert(index_client, cliente)
    print(time.strftime('%X:'), "MSG.  =>  Equip", cliente.nom, "passa a estat: REGISTERED")

    SOCK[0].sendto(paq, ADRECA[index])

    if OPTIONS.debug:
        print(time.strftime('%X:'), \
            "INFO  =>  Acceptat registre. Equip: nom=", cliente.nom, \
            ", ip=", cliente.ip, ", mac=", cliente.mac, \
            ",  alea=", cliente.num_ale)
        print(time.strftime('%X:'), \
            "DEBUG =>  Enviat: bytes=78, comanda=REGISTER_ACK, nom=", DATOS_SERVER[0], \
            ", mac=", DATOS_SERVER[1], ", alea=", LISTA_CLIENTES[index_client].num_ale, \
            ",  dades=", DATOS_SERVER[3])
# ---------------------- Fin registro ------------------ #

# --------- Funcion paquet_send --------- #
def paquet_send(index, newsocket):
    """
    Hacemos unpack del paquete SEND_FILE y llamamos a comprobar_send_get
    si nos devuelve un id significa que todo esta correcto
    entonces enviamos un SEND_ACK y vamos leyendo y escribiendo en el fichero
    """

    global DATA, DATOS_SERVER, LISTA_CLIENTES, SOCK

    if OPTIONS.debug:
        dades = DATA[index][4].split(b'\0', 1)[0]
        print(time.strftime('%X:'), \
            "DEBUG =>  Rebut: bytes=178, comanda=SEND_FILE, nom=", \
            DATA[index][1].decode('utf-8'), \
            ", mac=", DATA[index][2].decode('utf-8'), ", alea=", \
            DATA[index][3].decode('utf-8'), \
            ",  dades=", dades.decode('utf-8'))

    destinatari = comprobar_send_get(index, newsocket, 0)

    if destinatari > -1:
        file = open('./' + LISTA_CLIENTES[destinatari].nom + '.cfg', 'w')
        DATA[index] = list(DATA[index])
        DATA[index][0] = 0x21

        paq = pack('B7s13s7s150s', DATA[index][0], DATOS_SERVER[0].encode('utf-8'), \
            DATOS_SERVER[1].encode('utf-8'), LISTA_CLIENTES[destinatari].num_ale.encode('utf-8'), \
            (LISTA_CLIENTES[destinatari].nom+".cfg").encode('utf-8'))

        print(time.strftime('%X:'), \
            "INFO  =>  Acceptada petició enviament arxiu configuració. Equip: nom=", \
            LISTA_CLIENTES[destinatari].nom, \
            ", ip=", LISTA_CLIENTES[destinatari].ip, \
            ", mac=", LISTA_CLIENTES[destinatari].mac, \
            ",  alea=", LISTA_CLIENTES[destinatari].num_ale)

        if OPTIONS.debug:
            print(time.strftime('%X:'), \
                "DEBUG =>  Enviat: bytes=178, comanda=SEND_ACK, nom=", \
                DATOS_SERVER[0], \
                ", mac=", DATOS_SERVER[1], ", alea=", \
                LISTA_CLIENTES[destinatari].num_ale, \
                ",  dades=", LISTA_CLIENTES[destinatari].nom+".cfg")

        newsocket.sendall(paq)

        while True:
            infds = select.select([newsocket], [], [], 4)
            if infds[0]:
                dades = newsocket.recv(178)

                if not dades:
                    file.truncate()
                    break
                dades = unpack('=B7s13s7s150s', dades[:178])

                if dades[0] is not 0x25:
                    dades = dades[4].split(b'\0', 1)[0]

                    if OPTIONS.debug:
                        print(time.strftime('%X:'), \
                            "DEBUG =>  Rebut: bytes=178, comanda=SEND_DATA, nom=", dades[1], \
                            ", mac=", dades[2], ", alea=", dades[3], \
                            ",  dades=", dades.decode('utf-8'))
                    file.write(dades.decode('utf-8'))

                else:

                    print(time.strftime('%X:'), \
                        "MSG.  =>  Finalitzat enviament arxiu configuració. Equip: nom=", \
                        LISTA_CLIENTES[destinatari].nom, \
                        ", ip=", LISTA_CLIENTES[destinatari].ip, \
                        ", mac=", LISTA_CLIENTES[destinatari].mac, \
                        ",  alea=", LISTA_CLIENTES[destinatari].num_ale)
                    if OPTIONS.debug:
                        print(time.strftime('%X:'), \
                            "DEBUG =>  Rebut: bytes=178, comanda=SEND_END, nom=", \
                            dades[1].decode('utf-8'), ", mac=", \
                            dades[2].decode('utf-8'), ", alea=", dades[3].decode('utf-8'), \
                            ",  dades=")
            else:
                print(time.strftime('%X:'), \
                    "ALERT =>  No s'ha rebut informació per el canal TCP durant 4 segons")
                break
    newsocket.close()
    if OPTIONS.debug:
        print(time.strftime('%X:'), \
            "DEBUG =>  Finalitzat el procés que atenia a un client TCP")
    exit(0)
# ---------------------- Fin paqueteSend ------------------ #

# ---------------Funcion comprobar_send_get -------------- #
def comprobar_send_get(index, newsocket, tipo):
    """
    Miramos si hay algun problema con el paquete send llegado,
    si es asi enviamos los paquetes NACK or REJ,
    en caso contrario devolvemos la posicio del cliente
    """
    global DATA, LISTA_CLIENTES

    destinatari = buscar_index_cliente(index, 2)
    num_aleatori = DATA[index][3].split(b'\0', 1)[0]
    mac = DATA[index][2].split(b'\0', 1)[0]

    if destinatari is None or LISTA_CLIENTES[destinatari].mac != mac.decode('utf-8') or \
        LISTA_CLIENTES[destinatari].estat == "DISCONNECTED":
        DATA[index] = list(DATA[index])
        if tipo == 0:
            DATA[index][0] = 0x23
            tipo_paquete = "SEND_REJ"
        else:
            DATA[index][0] = 0x33
            tipo_paquete = "GET_REJ"
        DATA[index][4] = "Discrepacia en les dades principals de l'equip"

    elif tipo == 1 and os.path.isfile('./' + LISTA_CLIENTES[destinatari].nom + '.cfg') == False:
        DATA[index] = list(DATA[index])
        DATA[index][0] = 0x33
        tipo_paquete = "GET_REJ"
        DATA[index][4] = "Arxiu de configuració no trobat"

    else:
        if LISTA_CLIENTES[destinatari].num_ale == num_aleatori.decode('utf-8') and \
            ADRECA[index][0] == LISTA_CLIENTES[destinatari].ip:
            return destinatari

        DATA[index] = list(DATA[index])
        if tipo == 0:
            DATA[index][0] = 0x22
            tipo_paquete = "SEND_NACK"
        else:
            DATA[index][0] = 0x32
            tipo_paquete = "GET_NACK"
        DATA[index][4] = "Dades adicionals de l'equip incorrectes"

    DATA[index][1] = ""
    DATA[index][2] = "000000000000"
    DATA[index][3] = "000000"

    paq = pack('B7s13s7s150s', DATA[index][0], DATA[index][1].encode('utf-8'), \
        DATA[index][2].encode('utf-8'), DATA[index][3].encode('utf-8'), \
        DATA[index][4].encode('utf-8'))

    if OPTIONS.debug:
        print(time.strftime('%X:'), \
            "DEBUG =>  Enviat: bytes=178, comanda=", tipo_paquete, ", nom=", DATA[index][1], \
            ", mac=", DATA[index][2], ", alea=", DATA[index][3], ",  dades=", DATA[index][4])

    newsocket.sendall(paq)
    return -1
# ---------------------- Fin comprobar_send_get ------------------ #

# ---------------------- Funcion paquet_send --------------------- #
def paquet_get(index, newsocket):
    global DATA, DATOS_SERVER, LISTA_CLIENTES, SOCK

    if OPTIONS.debug:
        dades = DATA[index][4].split(b'\0', 1)[0]
        print(time.strftime('%X:'), \
            "DEBUG =>  Rebut: bytes=178, comanda=GET_FILE, nom=", \
            DATA[index][1].decode('utf-8'), \
            ", mac=", DATA[index][2].decode('utf-8'), ", alea=", \
            DATA[index][3].decode('utf-8'), \
            ",  dades=", dades.decode('utf-8'))

    destinatari = comprobar_send_get(index, newsocket, 1)

    if destinatari > -1:
        file = open('./' + LISTA_CLIENTES[destinatari].nom + '.cfg', 'r')
        DATA[index] = list(DATA[index])
        DATA[index][0] = 0x31

        paq = pack('B7s13s7s150s', DATA[index][0], DATOS_SERVER[0].encode('utf-8'), \
            DATOS_SERVER[1].encode('utf-8'), LISTA_CLIENTES[destinatari].num_ale.encode('utf-8'), \
            (LISTA_CLIENTES[destinatari].nom+".cfg").encode('utf-8'))

        print(time.strftime('%X:'), \
            "INFO  =>  Acceptada petició obtenció arxiu configuració. Equip: nom=", \
            LISTA_CLIENTES[destinatari].nom, \
            ", ip=", LISTA_CLIENTES[destinatari].ip, \
            ", mac=", LISTA_CLIENTES[destinatari].mac, \
            ",  alea=", LISTA_CLIENTES[destinatari].num_ale)

        if OPTIONS.debug:
            print(time.strftime('%X:'), \
                "DEBUG =>  Enviat: bytes=178, comanda=GET_ACK, nom=", \
                DATOS_SERVER[0], \
                ", mac=", DATOS_SERVER[1], ", alea=", \
                LISTA_CLIENTES[destinatari].num_ale, \
                ",  dades=", LISTA_CLIENTES[destinatari].nom+".cfg")
        newsocket.sendall(paq)

        DATA[index] = list(DATA[index])
        DATA[index][0] = 0x34
        datos = file.readline()

        while True:
            if not datos:
                DATA[index] = list(DATA[index])
                DATA[index][0] = 0x35
                paq = pack('B7s13s7s150s', DATA[index][0], DATOS_SERVER[0].encode('utf-8'), \
                    DATOS_SERVER[1].encode('utf-8'), LISTA_CLIENTES[destinatari].num_ale.encode('utf-8'), \
                    "".encode('utf-8'))

                if OPTIONS.debug:
                    print(time.strftime('%X:'), \
                        "DEBUG =>  Enviat: bytes=178, comanda=GET_END, nom=", \
                        DATOS_SERVER[0], \
                        ", mac=", DATOS_SERVER[1], ", alea=", \
                        LISTA_CLIENTES[destinatari].num_ale, \
                        ",  dades=")
                newsocket.sendall(paq)
                break;

            paq = pack('B7s13s7s150s', DATA[index][0], DATOS_SERVER[0].encode('utf-8'), \
                DATOS_SERVER[1].encode('utf-8'), LISTA_CLIENTES[destinatari].num_ale.encode('utf-8'), \
                datos.encode('utf-8'))
            if OPTIONS.debug:
                print(time.strftime('%X:'), \
                    "DEBUG =>  Enviat: bytes=178, comanda=GET_DATA, nom=", \
                    DATOS_SERVER[0], \
                    ", mac=", DATOS_SERVER[1], ", alea=", \
                    LISTA_CLIENTES[destinatari].num_ale, \
                    ",  dades=", datos)
            newsocket.sendall(paq)
            datos = file.readline()
        file.close()
        print(time.strftime('%X:'), \
            "MSG.  =>  Finalitzat obtenció arxiu configuració. Equip: nom=", \
            LISTA_CLIENTES[destinatari].nom, \
            ", ip=", LISTA_CLIENTES[destinatari].ip, \
            ", mac=", LISTA_CLIENTES[destinatari].mac, \
            ",  alea=", LISTA_CLIENTES[destinatari].num_ale)
    newsocket.close()

    if OPTIONS.debug:
        print(time.strftime('%X:'), \
            "DEBUG =>  Finalitzat el procés que atenia a un client TCP")
    exit(0)
# ---------------------- Fin paquet_send --------------------- #

# ------ Funcion comprobar_alive ---- #
def comprobar_alive(index_client, index):
    """
    Mirar la informacion del paquete ALIVE_INF
    si es correcta con la que hay guardada en caso contrario
    llama a la funcion enviar_paquete_error
    """

    global LISTA_CLIENTES, DATA, ADRECA

    nom = DATA[index][1].split(b'\0', 1)[0]
    mac = DATA[index][2].split(b'\0', 1)[0]
    num_aleatori = DATA[index][3].split(b'\0', 1)[0]

    if nom.decode('utf-8') == LISTA_CLIENTES[index_client].nom and \
        mac.decode('utf-8') == LISTA_CLIENTES[index_client].mac and \
        str(ADRECA[index][0]) == LISTA_CLIENTES[index_client].ip and \
        num_aleatori.decode('utf-8') == LISTA_CLIENTES[index_client].num_ale:
        return True

    #Enviar paquete de error "no coincide la informacion"
    enviar_paquete_error(index, "Error en dades de l'equip", 0x12)
    return False
# ---------------------- Fin comprobar_alive ------------------ #

# ------- Funcion enviar_paquete_error -------- #
def enviar_paquete_error(index, msg, tipus):
    """
    Enviar un paquete de error NACK o REJ, tanto de ALIVE como REGISTER
    """

    global SOCK, DATA, CLIENTS_ALIVE, LISTA_CLIENTES

    DATA[index] = list(DATA[index])
    DATA[index][0] = tipus
    DATA[index][1] = ""
    DATA[index][2] = "000000000000"
    DATA[index][3] = "000000"
    DATA[index][4] = msg

    paq = pack('B7s13s7s50s', DATA[index][0], DATA[index][1].encode('utf-8'), \
        DATA[index][2].encode('utf-8'), DATA[index][3].encode('utf-8'), \
        DATA[index][4].encode('utf-8'))

    SOCK[0].sendto(paq, ADRECA[index])

    if OPTIONS.debug:
        print(time.strftime('%X:'), \
            "DEBUG =>  Enviat: bytes=78, comanda=", mirar_tipo_paquete(tipus), \
            ", nom=", DATA[index][1], \
            ", mac=", DATA[index][2], ", alea=", DATA[index][3], \
            ",  dades=", DATA[index][4])
    exit(0)
# ---------------------- Fin enviar_paquete_error ------------------ #

# ----------- Funcion enviar_alive ------------- #
def enviar_alive(destinatari, index):
    """
    Enviar paquete ALIVE_ACK
    """

    global ADRECA, DATOS_SERVER, SOCK, DATA, DATOS_CLIENT, LISTA_CLIENTES

    DATA[index] = list(DATA[index])
    DATA[index][0] = 0x11
    paq = pack('B7s13s7s50s', DATA[index][0], DATOS_SERVER[0].encode('utf-8'), \
        DATOS_SERVER[1].encode('utf-8'), \
        LISTA_CLIENTES[destinatari].num_ale.encode('utf-8'), "".encode('utf-8'))

    SOCK[0].sendto(paq, ADRECA[index])

    if OPTIONS.debug:
        print(time.strftime('%X:'), \
            "INFO  =>  Acceptat ALIVE. Equip: nom=", LISTA_CLIENTES[destinatari].nom, \
            ", ip=", LISTA_CLIENTES[destinatari].ip, \
            ", mac=", LISTA_CLIENTES[destinatari].mac, \
            ",  alea=", LISTA_CLIENTES[destinatari].num_ale)
        print(time.strftime('%X:'), \
            "DEBUG =>  Enviat: bytes=178, comanda=ALIVE_ACK, nom=", \
            DATOS_SERVER[0], ", mac=", DATOS_SERVER[1],  \
            ", alea=", LISTA_CLIENTES[destinatari].num_ale, \
            ",  dades=")
    exit(0)
# ---------------------- Fin enviar_alive ------------------ #

# ---------- Funcion alives -------- #
def alives():
    """
    Controlador de los Alive, tanto los primeros como los demas
    """

    global CLIENTS_ALIVE, TIME_ALIVE, LISTA_CLIENTES
    if OPTIONS.debug:
        print(time.strftime('%X:'), "INFO  =>  Establert temporitzador per control alives")

    while 1:
        # Controlem tots els alive menys els primers
        for cont, val in enumerate(TIME_ALIVE):
            TIME_ALIVE[cont] -= 1
            if TIME_ALIVE[cont] == 0:
                index_client = buscar_index_cliente(cont, 0)
                cliente = LISTA_CLIENTES[index_client]
                cliente.ip = "        -"
                cliente.num_ale = "     -"
                cliente.estat = "DISCONNECTED"
                LISTA_CLIENTES.pop(index_client)
                LISTA_CLIENTES.insert(index_client, cliente)
                TIME_ALIVE.pop(cont)
                CLIENTS_ALIVE.pop(cont)

                print(time.strftime('%X:'), \
                    "MSG.  =>  Equip", cliente.nom, "passa a estat: DISCONNECTED")
        time.sleep(1)
# ---------------------- Fin alives ------------------ #

# --------------- Funcion controlar_comandas ---------------- #
def controlar_comandas():
    """
    Controla las comandas introducidas por teclado
    """

    while 1:
        name = input()
        if name == 'quit':
            P1.terminate()
            sys.exit(0)
        elif name == 'list':
            print("-NOM-- ------IP------- -----MAC---- -ALEA- ----ESTAT---")
            for index_client in range(len(LISTA_CLIENTES)):
                print(LISTA_CLIENTES[index_client].nom, "      ", \
                    LISTA_CLIENTES[index_client].ip, LISTA_CLIENTES[index_client].mac, \
                    LISTA_CLIENTES[index_client].num_ale, LISTA_CLIENTES[index_client].estat)
        else:
            print(time.strftime('%X:'), "MSG.  =>  Comanda incorrecta")
# --------------- Fin controlar_comandas ---------------- #

# -------- Funcion main ------------- #
if __name__ == '__main__':

    # Opciones de comanda
    PARSER = OptionParser()
    PARSER.add_option("-u", type="string", dest="equips", default="equips.dat")
    PARSER.add_option("-c", type="string", dest="servidor", default="server.cfg")
    PARSER.add_option("-d", action="store_true", dest="debug", default=False)
    (OPTIONS, ARGS) = PARSER.parse_args()

    if OPTIONS.debug:
        print(time.strftime('%X:'), "DEBUG =>  Llegits paràmetres línia de comandes")

    with Manager() as manager:
        CLIENTS_ALIVE = manager.list()
        TIME_ALIVE = manager.list()
        LISTA_CLIENTES = manager.list()

        leer_config()
        setup()

        # Proceso que controlara los paquetes Alives
        if OPTIONS.debug:
            print(time.strftime('%X:'), "DEBUG =>  Creat fill per gestionar alives")
        P = Process(target=alives, args=())
        P.daemon = True
        P.start()
        P.join(1)

        if OPTIONS.debug:
            print(time.strftime('%X:'), "DEBUG =>  Creat fill per gestionar els paquets")

        # Proceso que controlara lo que nos va llegando por el socket UDP
        P1 = Process(target=entrada_paquet)
        P1.processes = False
        P1.start()

        # Controlador de entrada de comandos por consola
        controlar_comandas()
