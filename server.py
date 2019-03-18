#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim: set fileencoding=utf-8 :

"""
SYNOPSIS

    echoudp-server.py [-h,--help] [--version] [-p,--port <port>, default=1234]

DESCRIPTION

    Creates a ECHO/UDP server, resending all received data back to sender.
    Default port 1234


EXAMPLES

    echoudp-server.py  --port 4321

AUTHOR

    Carles Mateu <carlesm@carlesm.com>

LICENSE

    This script is published under the Gnu Public License GPL3+

VERSION

    0.0.1
"""

import sys, os, traceback, optparse
import time, datetime
import socket
from struct import *
import os
import signal
from multiprocessing import Process, Value, Array, Manager


__program__ = "echoudp-server"
__version__ = '0.0.1'
__author__ = 'Carles Mateu <carlesm@carlesm.com>'
__copyright__ = 'Copyright (c) 2012  Carles Mateu '
__license__ = 'GPL3+'
__vcs_id__ = '$Id: echoudp-server.py 554 2012-05-06 08:07:51Z carlesm $'


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

listaClientes = []

#0- NomServer   1- MACserver  2- UDPport  3- TCPport
datosServer = []

def leerConfig():
    global sock, options, listaClientes, datosServer

    #Leer archivo de equipos
    f = open("equips.dat")
    datos = f.readline()

    while datos != "\n":
        datosClient = datos.split()
        listaClientes.append(clients(datosClient[0],"",datosClient[1],"","DISCONNECTED"))
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


def registro(indexClient, index):
    global adreca, datosServer, sock, paquete, datosClient, listaClientes

    paquete[index] = list(paquete[index])
    paquete[index][0] = 0x01

    listaClientes[indexClient].numAl = "715642"
    a = pack('B7s13s7s50s',paquete[index][0], datosServer[0].encode('utf-8'),datosServer[1].encode('utf-8'),listaClientes[indexClient].numAl.encode('utf-8'),datosServer[3].encode('utf-8'))

    listaClientes[indexClient].estat = "REGISTERED"

    sock.sendto(a,adreca[index])


data = []
adreca = []
paquete = []
def entradaPaquet():
    global data, adreca, sock, paquete, listaClientes

    i = 0
    while(1):
        print("ESTADOOO",listaClientes[0].nom)
        print("ESTADOOO",listaClientes[0].estat)

        print("ESTADOOO",listaClientes[1].nom)
        print("ESTADOOO",listaClientes[1].estat)

        print("ESTADOOO",listaClientes[2].nom)
        print("ESTADOOO",listaClientes[2].estat)


        data1,adreca1 = sock.recvfrom(78)
        data.append(data1)
        adreca.append(adreca1)
        paquete = data
        print("HOLAAA")
        p2 = Process(target=gestionarPaquet, args=(i,))
        p2.daemon = True
        p2.start()
        p2.join(2)
        #gestionarPaquet(i)
        i += 1



def gestionarPaquet(index):
    global data, adreca, sock, paquete, listaClientes
    print("a")
    paquete[index] = unpack('=B7s13s7s50s',data[index][:78])
    print("DATA: ",paquete[index][0])
    if paquete[index][0] == 0:
        print("Registro")
        correcto = comprobarEstado(0, index)
        if correcto != None:
            registro(correcto, index)
            print("ESTADO:",listaClientes[0].estat)
    elif paquete[index][0] == 16:
        print("PAQUET ALIVE")
        print("ESTADO:",listaClientes[0].estat)

        correcto = comprobarEstado(1, index)
        if correcto != None:
            print("ENVIAR ALIVE")
            print("ESTADO:",listaClientes[0].estat)

            enviarAlive(correcto, index)


def encontrarCliente(index):
    global paquete, listaClientes

    estado = paquete[index][1].split(b'\0',1)[0]

    for indexClient in range(len(listaClientes)):
        if listaClientes[indexClient].nom == estado.decode('utf-8'):
            return indexClient

    return None

def comprobarEstado(tipo, index):
    global listaClientes, paquete, clientsAlive, timeAlive

    indexClient = encontrarCliente(index)

    if indexClient != None:
        if tipo == 0:
            print("TIPO")
            if listaClientes[indexClient].estat == "DISCONNECTED":
                print("DEVOLVER")
                return indexClient
            else:
                return None
        else:
            print(listaClientes[indexClient].estat)
            print(listaClientes[indexClient].nom)
            print("INDEX FINAL", indexClient)


            if listaClientes[indexClient].estat == "REGISTERED":
                clientsAlive.append(listaClientes[indexClient].nom)
                timeAlive.append(6)
                return indexClient
            elif listaClientes[indexClient].estat == "ALIVE":
                indexAlive = clientsAlive.index(listaClientes[indexClient].nom)
                timeAlive[indexAlive] = 6
                return indexClient
            else:
                return None
    else:
        return None


def enviarAlive(destinatari, index):
    global adreca, datosServer, sock, paquete, datosClient, listaClientes

    paquete[index] = list(paquete[index])
    paquete[index][0] = 0x11

    a = pack('B7s13s7s50s',paquete[index][0], datosServer[0].encode('utf-8'),datosServer[1].encode('utf-8'),listaClientes[destinatari].numAl.encode('utf-8'),"".encode('utf-8'))

    sock.sendto(a,adreca[index])


def alives(clientsAlive, timeAlive):
    while 1:
        for x, val in enumerate(timeAlive):
            timeAlive[x] -= 1
            if timeAlive[x] == 0:
                timeAlive.pop(x)
                clientsAlive.pop(x)
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
        leerConfig()
        setup()

        with Manager() as manager:
            clientsAlive = manager.list()
            timeAlive = manager.list()


            p = Process(target=alives, args=(clientsAlive, timeAlive))
            p.daemon = True
            p.start()
            p.join(1)
            print("Controladors de ALIVE activat")


            #crear otro daemon para controlar la entrada recvfrom
            #p1 = Process(target=entradaPaquet)
            #p1.daemon = True
            #p1.processes = False
            #p1.start()
            #p1.join(1)

            entradaPaquet()


            #clientsAlive.append("Mario")
            #timeAlive.append(10)

            while 1:
                name = input()
                if name == 'quit':
                    sys.exit(0)
                elif name == 'list':
                    print(clientsAlive[0])






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
