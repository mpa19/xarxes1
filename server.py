#!/usr/bin/env python 3

import sys, os, traceback, optparse
import time, datetime
import socket
from struct import *
import os
import signal
from multiprocessing import Process, Value, Array, Manager
from random import seed
from random import randint

__program__ = "server"
__version__ = '0.0.1'
__author__ = 'Marc Perez>'
__copyright__ = 'Copyright (c) 2019  Marc Perez '
__license__ = 'GPL3+'
__vcs_id__ = '$Id: server.py 554 2019-04-15 18:07:51Z mpa19 $'


class clients:
    def __init__(self,nom,ip,mac,numAl,estat):
        self.nom = nom
        self.ip = ip
        self.mac = mac
        self.numAl = numAl
        self.estat = estat


def setup():
    global sock, options, datosServer
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("",int(datosServer[2])))

#0- NomServer   1- MACserver  2- UDPport  3- TCPport
datosServer = []
data = []
adreca = []

def leerConfig():
    global sock, options, listaClientes, datosServer

    #Leer archivo de equipos
    f = open("equips.dat")
    datos = f.readline()

    while datos != "\n":
        datosClient = datos.split()
        listaClientes.append(clients(datosClient[0],"        -",datosClient[1],"     -","DISCONNECTED"))
        datos = f.readline()

    f.close()

    #Leer archivo de config
    f = open("server.cfg")
    datos = f.readline()

    while datos != "\n":
        datosS = datos.split()
        datosServer.append(datosS[1])
        datos = f.readline()

    f.close()


def randomNumber():
    global listaClientes
    numInvalido = False

    while(1):
        value = randint(100000,999999)
        for indexClient in range(len(listaClientes)):
            if listaClientes[indexClient].numAl == str(value):
                numInvalido = True
        if numInvalido == False:
            return str(value)

def registro(indexClient, index):
    global adreca, datosServer, sock, data, datosClient, listaClientes

    data[index] = list(data[index])
    data[index][0] = 0x01
    random = randomNumber()
    a = pack('B7s13s7s50s',data[index][0], datosServer[0].encode('utf-8'),datosServer[1].encode('utf-8'),random.encode('utf-8'),datosServer[3].encode('utf-8'))

    cliente = listaClientes[indexClient]
    cliente.estat = "REGISTERED"
    cliente.numAl = random
    cliente.ip = adreca[index][0]
    listaClientes.pop(indexClient)
    listaClientes.insert(indexClient, cliente)

    sock.sendto(a,adreca[index])

def entradaPaquet():
    global data, adreca, sock, data, listaClientes

    i = 0
    while(1):
        data1,adreca1 = sock.recvfrom(78)
        data.append(data1)
        adreca.append(adreca1)
        p2 = Process(target=gestionarPaquet, args=(i,))
        p2.daemon = True
        p2.start()
        p2.join(1)

        i += 1


def gestionarPaquet(index):
    global data, adreca, sock, data, listaClientes
    data[index] = unpack('=B7s13s7s50s',data[index][:78])
    if data[index][0] == 0:
        correcto = comprobarEstado(0, index)
        if correcto != None:
            registro(correcto, index)

    elif data[index][0] == 16:
        correcto = comprobarEstado(1, index)
        if correcto != None:
            enviarAlive(correcto, index)


def encontrarCliente(index):
    global data, listaClientes

    estado = data[index][1].split(b'\0',1)[0]

    for indexClient in range(len(listaClientes)):
        if listaClientes[indexClient].nom == estado.decode('utf-8'):
            return indexClient

    return None

def comprobarEstado(tipo, index):
    global listaClientes, data, clientsAlive, timeAlive

    indexClient = encontrarCliente(index)

    if indexClient != None:
        if tipo == 0:
            if listaClientes[indexClient].estat == "DISCONNECTED":
                return indexClient
            else:
                #Enviar paquete de suplantacion de identidad
                enviarPaqueteError(index, "Error en dades de l'equip", 0x02)
                return None
        else:
            print(listaClientes[indexClient].estat)
            print(listaClientes[indexClient].nom)

            if listaClientes[indexClient].estat == "REGISTERED":
                clientsAlive.append(listaClientes[indexClient].nom)
                timeAlive.append(6)
                if comprobarAlive(indexClient, index) == True:
                    cliente = listaClientes[indexClient]
                    cliente.estat = "ALIVE"
                    listaClientes.pop(indexClient)
                    listaClientes.insert(indexClient, cliente)
                    return indexClient
                else:
                    return None

            elif listaClientes[indexClient].estat == "ALIVE":
                if comprobarAlive(indexClient, index) == True:
                    indexAlive = clientsAlive.index(listaClientes[indexClient].nom)
                    timeAlive[indexAlive] = 6
                    return indexClient
                else:
                    return None
            else:
                #Enviar paquete de error "no registrado"
                enviarPaqueteError(index, "Equip no autoritzat en el sistema", 0x13)
                return None
    else:
        #Enviar paquete que no se encuentra registrado
        enviarPaqueteError(index, "Equip no autoritzat en el sistema", 0x03)
        return None

def comprobarAlive(indexClient, index):
    global listaClientes, data, adreca

    nom = data[index][1].split(b'\0',1)[0]
    mac = data[index][2].split(b'\0',1)[0]
    numAl = data[index][3].split(b'\0',1)[0]
    if nom.decode('utf-8') == listaClientes[indexClient].nom and \
        mac.decode('utf-8') == listaClientes[indexClient].mac and \
        str(adreca[index][0]) == listaClientes[indexClient].ip and \
        numAl.decode('utf-8') == listaClientes[indexClient].numAl:
        return True
    else:
        #Enviar paquete de error "no coincide la informacion"
        enviarPaqueteError(index, "Error en dades de l'equip", 0x12)
        return False

def enviarPaqueteError(index, msg, tipus):
    global sock, data

    data[index] = list(data[index])
    data[index][0] = tipus
    data[index][1] = ""
    data[index][2] = "000000000000"
    data[index][4] = msg

    a = pack('B7s13s7s50s',data[index][0], data[index][1].encode('utf-8'),data[index][2].encode('utf-8'),data[index][3],data[index][4].encode('utf-8'))
    sock.sendto(a,adreca[index])

def enviarAlive(destinatari, index):
    global adreca, datosServer, sock, data, datosClient, listaClientes

    print("ENVIAR ALIVE")
    data[index] = list(data[index])
    data[index][0] = 0x11

    a = pack('B7s13s7s50s',data[index][0], datosServer[0].encode('utf-8'),datosServer[1].encode('utf-8'),listaClientes[destinatari].numAl.encode('utf-8'),"".encode('utf-8'))

    sock.sendto(a,adreca[index])


def alives():
    global clientsAlive, timeAlive
    while 1:
        for x, val in enumerate(timeAlive):
            timeAlive[x] -= 1
            if timeAlive[x] == 0:
                for indexClient in range(len(listaClientes)):
                    if listaClientes[indexClient].nom == clientsAlive[x]:
                        cliente = listaClientes[indexClient]
                        cliente.ip = "        -"
                        cliente.numAl = "     -"
                        cliente.estat = "DISCONNECTED"
                        listaClientes.pop(indexClient)
                        listaClientes.insert(indexClient, cliente)
                timeAlive.pop(x)
                clientsAlive.pop(x)
                listaClientes
        time.sleep(1)


if __name__ == '__main__':
#    try:
 #       start_time = time.time()
 #       parser = optparse.OptionParser(formatter=optparse.TitledHelpFormatter(), usage=globals()["__doc__"],version=__version__)
  #      parser.add_option ('-v', '--verbose', action='store_true', default=False, help='verbose output')
   #     parser.add_option ('-p', '--port', action='store', type='int', default=2019, help='Listening port, default 1234')
    #    (options, args) = parser.parse_args()
     #   if len(args) > 0: parser.error ('bad args, use --help for help')

        #if options.verbose: print time.asctime()


        with Manager() as manager:
            clientsAlive = manager.list()
            timeAlive = manager.list()
            listaClientes = manager.list()

            leerConfig()
            setup()

            p = Process(target=alives, args=())
            p.daemon = True
            p.start()
            p.join(1)
            print("Controladors de ALIVE activat")


            #crear otro daemon para controlar la entrada recvfrom
            p1 = Process(target=entradaPaquet)
            p1.processes = False
            p1.start()

            print("HOLA")

            while 1:
                name = input()
                if name == 'quit':
                    p1.terminate()
                    sys.exit(0)
                elif name == 'list':
                    print("-NOM-- ------IP------- -----MAC---- -ALEA- ----ESTAT---")
                    for indexClient in range(len(listaClientes)):
                        print(listaClientes[indexClient].nom,"      ", listaClientes[indexClient].ip, listaClientes[indexClient].mac, listaClientes[indexClient].numAl, listaClientes[indexClient].estat)
                else:
                    print("MSG.  =>  Comanda incorrecta")





#        now_time = time.time()
 #       if options.verbose: print time.asctime()
  #      if options.verbose: print 'TOTAL TIME:', (now_time - start_time), "(seconds)"
   #     if options.verbose: print '          :', datetime.timedelta(seconds=(now_time - start_time))
    #except KeyboardInterrupt, e: # Ctrl-C
     #   raise e
    #except SystemExit, e: # sys.exit()
     #   raise e
   # except Exception, e:
    #    print 'ERROR, UNEXPECTED EXCEPTION'
     # print str(e)
      #  traceback.print_exc()
       # os._exit(1)
