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
    global sock, options
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("",options.port))

listaClientes = []
def mainloop():
    global sock, options, listaClientes


    f = open("equips.dat")
    datos = f.readline()

    while datos != "\n":
        datosClient = datos.split()
        print >>sys.stderr, "Datagrama de DATO: ",datosClient[0]
        listaClientes.append(clients(datosClient[0],"",datosClient[1],"","DISCONNECTED"))
        datos = f.readline()


    print >>sys.stderr, "Datagrama de CLIENTS: ",listaClientes[0].nom
    print >>sys.stderr, "Datagrama de CLIENTS: ",listaClientes[1].nom
    print >>sys.stderr, "Datagrama de NUM CLIENTS: ",len(listaClientes)



    data,adreca = sock.recvfrom(78)
    magic = unpack('B7s13s7s50s',data[:78])
    print >>sys.stderr, "Datagrama de DATA: ",data
    print >>sys.stderr, "Datagrama de MAGIC: ",magic

    magic = list(magic)
    magic[0] = 0x01
    magic[1] = "NMS-01"
    magic[2] = "43D3F4D80005"
    magic[3] = "714906"
    magic[4] = "9102"

    a = pack('B7s13s7s50s',magic[0], magic[1],magic[2],magic[3],magic[4])
    print >>sys.stderr, "Datagrama de ENVIAR: ",a
    sock.sendto(a,adreca)


def main():
    global options, args, listaClientes
    setup()
    mainloop()
    print >>sys.stderr, "AADatagrama de NUM CLIENTS: ",len(listaClientes)


if __name__ == '__main__':
    try:
        start_time = time.time()
        parser = optparse.OptionParser(formatter=optparse.TitledHelpFormatter(), usage=globals()["__doc__"],version=__version__)
        parser.add_option ('-v', '--verbose', action='store_true', default=False, help='verbose output')
        parser.add_option ('-p', '--port', action='store', type='int', default=2019, help='Listening port, default 1234')
        (options, args) = parser.parse_args()
        if len(args) > 0: parser.error ('bad args, use --help for help')

        if options.verbose: print time.asctime()

        main()

        now_time = time.time()
        if options.verbose: print time.asctime()
        if options.verbose: print 'TOTAL TIME:', (now_time - start_time), "(seconds)"
        if options.verbose: print '          :', datetime.timedelta(seconds=(now_time - start_time))
        sys.exit(0)
    except KeyboardInterrupt, e: # Ctrl-C
        raise e
    except SystemExit, e: # sys.exit()
        raise e
    except Exception, e:
        print 'ERROR, UNEXPECTED EXCEPTION'
        print str(e)
        traceback.print_exc()
        os._exit(1)
