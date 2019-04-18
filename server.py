#!/usr/bin/env python 3

import sys, os, traceback, optparse
import time, datetime
import socket, select
from struct import *
import os
import signal
from multiprocessing import Process, Value, Array, Manager
from random import seed
from random import randint
from optparse import OptionParser
import re


class clients:
    def __init__(self,nom,ip,mac,numAl,estat):
        self.nom = nom
        self.ip = ip
        self.mac = mac
        self.numAl = numAl
        self.estat = estat


def setup():
    global sock, options, datosServer, inputs
    #Socket UDP
    inputs = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    inputs.bind(("",int(datosServer[2])))
    sock.append(inputs)

    #Socket TCP
    inputs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    inputs.bind(("",int(datosServer[3])))
    inputs.listen(5)
    sock.append(inputs)

#0- NomServer   1- MACserver  2- UDPport  3- TCPport
datosServer = []
data = []
adreca = []
sock = []


def leerConfig():
    global sock, options, listaClientes, datosServer

    #Leer archivo de equipos
    f = open(options.equips)
    datos = f.readline()

    while datos != "\n":
        datosClient = datos.split()
        listaClientes.append(clients(datosClient[0],"        -",datosClient[1],"     -","DISCONNECTED"))
        datos = f.readline()
    f.close()

    #Leer archivo de config
    f = open(options.servidor)
    datos = f.readline()

    while datos != "\n":
        datosS = datos.split()
        datosServer.append(datosS[1])
        datos = f.readline()
    f.close()

#Crea un numero random que no este ya assignado a un cliente
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

#Cambia el estado del cliente a REGISTERED y envia el paquete REGISTER_ACK
#con la información del servidor y el puerto
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

    sock[0].sendto(a,adreca[index])

#Espera la entrada de un paquete y crea un hijo en segundo plano para gestionarlo
def entradaPaquet():
    global data, adreca, sock, data, listaClientes, inputs

    i = 0
    while(1):
        infds, outfds, errfds = select.select(sock, [], [], 100000)
        if [sock[0]] == infds:
            data1,adreca1 = sock[0].recvfrom(78)
            data.append(data1)
            adreca.append(adreca1)
            p2 = Process(target=gestionarPaquet, args=(i,))
        elif [sock[1]] == infds:
            newsocket,adreca1 = sock[1].accept()
            data1 = newsocket.recv(178)
            data.append(data1)
            adreca.append(adreca1)
            p2 = Process(target=paquetSend, args=(i,newsocket))

        p2.processes = False
        p2.start()

        i += 1

#Mira el paquete que ha llegado y dependiendo del tipo sabe si es ALIVE o REGISTER
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


#Mirar que tipo de paquete a entrado y en que estado deberia estar
def comprobarEstado(tipo, index):
    global listaClientes, data, clientsAlive, timeAlive, timePrimerAlive, clientsRegistered

    indexClient = buscarIndexCliente(index, 3)

    if indexClient != None:
        if tipo == 0:
            numAle = data[index][3].split(b'\0',1)[0]
            if listaClientes[indexClient].estat == "DISCONNECTED" and \
                numAle.decode('utf-8') == "000000":
                timePrimerAlive.append(7)
                clientsRegistered.append(listaClientes[indexClient].nom)
                return indexClient
            else:
                #Enviar paquete de suplantacion de identidad
                enviarPaqueteError(index, "Error en dades de l'equip", 0x02)
                return None
        elif tipo == 1:
            if listaClientes[indexClient].estat == "REGISTERED":

                if comprobarAlive(indexClient, index) == True:
                    indexPrimerAlive = clientsRegistered.index(listaClientes[indexClient].nom)
                    timePrimerAlive.pop(indexPrimerAlive)
                    clientsRegistered.pop(indexPrimerAlive)
                    clientsAlive.append(listaClientes[indexClient].nom)
                    timeAlive.append(10)
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
                    timeAlive[indexAlive] = 10
                    return indexClient
                else:
                    return None
            else:
                #Enviar paquete de error "no registrado"
                enviarPaqueteError(index, "Equip no autoritzat en el sistema", 0x13)
                return None
    else:
        #Enviar paquete que no se encuentra registrado
        if data[index][0] == 16:
            enviarPaqueteError(index, "Equip no autoritzat en el sistema", 0x13)
        else:
            enviarPaqueteError(index, "Equip no autoritzat en el sistema", 0x03)
        return None


def paquetSend(index, newsocket):
    global data, datosServer, listaClientes, sock

    data[index] = unpack('=B7s13s7s150s',data[index][:178])
    destinatari = comprobarSend(index, newsocket)
    if destinatari != False:
        f = open('./'+listaClientes[destinatari].nom+'.cfg', 'w')
        data[index] = list(data[index])
        data[index][0] = 0x21

        a = pack('B7s13s7s150s',data[index][0], datosServer[0].encode('utf-8'),datosServer[1].encode('utf-8'),listaClientes[destinatari].numAl.encode('utf-8'),(listaClientes[destinatari].nom+".cfg").encode('utf-8'))
        newsocket.sendall(a)
        while True:
            dades = newsocket.recv(178)
            if not dades:
                f.truncate()
                break
            dades = unpack('=B7s13s7s150s',dades[:178])
            dades = dades[4].split(b'\0',1)[0]
            print(dades.decode('utf-8'))
            f.write(dades.decode('utf-8'))
    newsocket.close()
    exit(0)

def comprobarSend(index, newsocket):
    global data, listaClientes

    destinatari = buscarIndexCliente(index, 2)
    numAl = data[index][3].split(b'\0',1)[0]
    MAC = data[index][2].split(b'\0',1)[0]
    if destinatari == None or listaClientes[destinatari].mac != MAC.decode('utf-8') or \
        listaClientes[destinatari].estat == "DISCONNECTED":
        data[index][0] = 0x23
        data[index][4] = "Discrepacia en les dades principals de l'equip"

    else:
        if listaClientes[destinatari].numAl == numAl.decode('utf-8') or \
            adreca[index][0] == listaClientes[destinatari].ip:
            return destinatari

        else:
            data[index] = list(data[index])
            data[index][0] = 0x22
            data[index][4] = "Dades adicionals de l'equip incorrectes"

    data[index][1] = ""
    data[index][2] = "000000000000"
    data[index][3] = "000000"
    a = pack('B7s13s7s150s',data[index][0], data[index][1].encode('utf-8'),data[index][2].encode('utf-8'),data[index][3].encode('utf-8'),data[index][4].encode('utf-8'))
    newsocket.sendall(a)
    return False

#Mirar la informacion del paquete si es correcta con la que hay guardada
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

#Enviar un paquete de error NACK o REJ, tanto de ALIVE como REGISTER
def enviarPaqueteError(index, msg, tipus):
    global sock, data
    print("ENVIAR ERROR")
    data[index] = list(data[index])
    data[index][0] = tipus
    data[index][1] = ""
    data[index][2] = "000000000000"
    data[index][3] = "000000"
    data[index][4] = msg

    a = pack('B7s13s7s50s',data[index][0], data[index][1].encode('utf-8'),data[index][2].encode('utf-8'),data[index][3].encode('utf-8'),data[index][4].encode('utf-8'))
    sock[0].sendto(a,adreca[index])
    exit(0)

#Enviar paquete ALIVE_ACK
def enviarAlive(destinatari, index):
    global adreca, datosServer, sock, data, datosClient, listaClientes

    data[index] = list(data[index])
    data[index][0] = 0x11

    a = pack('B7s13s7s50s',data[index][0], datosServer[0].encode('utf-8'),datosServer[1].encode('utf-8'),listaClientes[destinatari].numAl.encode('utf-8'),"".encode('utf-8'))

    sock[0].sendto(a,adreca[index])
    exit(0)

#Encuentra el index del cliente en la lista de los clientes autorizados
def buscarIndexCliente(index, donde):
    global clientsAlive, clientsRegistered, listaClientes, data
    for indexClient in range(len(listaClientes)):
        if donde == 0:
            if listaClientes[indexClient].nom == clientsAlive[index]:
                return int(indexClient)
        elif donde == 1:
            if listaClientes[indexClient].nom == clientsRegistered[index]:
                return int(indexClient)
        else:
            nom = data[index][1].split(b'\0',1)[0]
            if listaClientes[indexClient].nom == nom.decode('utf-8'):
                return indexClient
    return None

#Controlador de los Alive, tanto los primeros como los demas
def alives():
    global clientsAlive, timeAlive, listaClientes, timePrimerAlive, clientsRegistered

    while 1:
        for x, val in enumerate(timeAlive):
            timeAlive[x] -= 1
            if timeAlive[x] == 0:
                indexClient = buscarIndexCliente(x, 0)
                cliente = listaClientes[indexClient]
                cliente.ip = "        -"
                cliente.numAl = "     -"
                cliente.estat = "DISCONNECTED"
                listaClientes.pop(indexClient)
                listaClientes.insert(indexClient, cliente)
                timeAlive.pop(x)
                clientsAlive.pop(x)

        for x, val in enumerate(timePrimerAlive):
            timePrimerAlive[x] -= 1
            if timePrimerAlive[x] == 0:
                indexClient = buscarIndexCliente(x, 1)
                cliente = listaClientes[indexClient]
                cliente.ip = "        -"
                cliente.numAl = "     -"
                cliente.estat = "DISCONNECTED"
                listaClientes.pop(indexClient)
                listaClientes.insert(indexClient, cliente)
                timePrimerAlive.pop(x)
                clientsRegistered.pop(x)
            print("AAAA", timePrimerAlive)

        time.sleep(1)


if __name__ == '__main__':

        #Opciones de comanda
        parser = OptionParser()
        parser.add_option("-u", type="string", dest="equips", default="equips.dat")
        parser.add_option("-c", type="string", dest="servidor", default="server.cfg")
        parser.add_option("-d", action="store_true", dest="debug", default=False)
        (options, args) = parser.parse_args()

        with Manager() as manager:
            clientsAlive = manager.list()
            timeAlive = manager.list()
            listaClientes = manager.list()
            clientsRegistered = manager.list()
            timePrimerAlive = manager.list()

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
