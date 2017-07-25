#! /usr/bin/env python2.7
"""
Script que decide si envia un TCP SYN/ACK o un TCP RST en base al calculo de un numero de IP ID correcto en el header IP.
El numero se calcula en base a un secreto (psk) y un valor que cambie en el tiempo (timestamp), esto es para que el valor de IP ID que se envie
sea distinto a cada rato.

Se toma cada 10 segundos un nuevo valor de timestamp (timestamp / 10).

Futuros cambios:
    - Agregar cambio de IP ID con cada RST enviado distinguido por IP de origen.
    - Agregar autenticacion con tokens OTP, validamos segundo factor.
    - Agregar proteccion de DoS Spoofeado, una maquina que haga un spoof de una IP y envie TCP SYN al server nos deja sin acceso al server.
    - Centralizar tokens OTP con un sistema central de tokens (linOTP)
Ver la manera de detectar que nos estan haciendo un DoS y poner la IP de origen en una blacklist temporal, alertar.
"""
#scapy, modulo de Python para ver y modificar paquetes
from scapy.all import *
#netfilter, modulo de Python para mirar paquetes que caen en una queue de iptables, decide si dropearlos o aceptarlos
from netfilterqueue import NetfilterQueue
#time para el timestamp, hashlib para MD5, iptc para agregar dinamicamente reglas de iptables
import time
import hashlib
import iptc

LOG_FILE = '/var/log/covert_server.log'
logging.basicConfig(filename=LOG_FILE,level=logging.INFO,format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%d/%m/%Y %H:%M:%S')

def generateID(psk,ts=False):
    logging.debug('generateID()')
    if ts:
        timestamp = str(int(time.time())/10)
        psk = psk + timestamp
    h = hashlib.md5()
    h.update(psk)
    hash = h.hexdigest()
    split_hash = list()
    check_num = 0
    i = 0
    while(i < len(hash)):
        split_hash.append(hash[i:i+4])
        i = i + 4
    for a in split_hash:
        check_num = check_num ^ int(a,16)
    logging.debug('IP ID: ' + str(check_num))
    return check_num

#Funcion del server, se inicia una vez por packete recibido
def server(packet):
    """
    Esta funcion se ejecuta cuando se recibio un TCP SYN en el iptables.
    La funcion chequea el cambio IP ID contra un numero generado con el secreto psk y el timestamp.
    """
    logging.debug('server()')
    pkt = IP(packet.get_payload())
    if pkt.id == generateID('secreto',True):
        #El campo es igual al numero generado, acepto el paquete. El paquete pasa al ruteo de kernel y lo recibe la aplicacion
        logging.info('Paquete aceptado: ' + str(pkt.src) + ':' + str(pkt.sport) + ' -> ' + str(pkt.dst) + ':' + str(pkt.dport) + ' / IP ID: ' + str(pkt.id))
        packet.accept()
    else:
        #El numero no coincide, dropeo el paquete y genero un TCP RST
        logging.warning('Paquete reseteado: ' + str(pkt.src) + ':' + str(pkt.sport) + ' -> ' + str(pkt.dst) + ':' + str(pkt.dport) + ' / IP ID recibido: ' + str(pkt.id$
        #Dropeo el paquete
        packet.drop()
        #Genero con scapy un paquete TCP RST
        i = IP()
        t = TCP()
        i.dst = pkt.src
        i.src = pkt.dst
        i.proto = pkt.proto
        t.sport = pkt.dport
        t.dport = pkt.sport
        t.seq = pkt.ack
        t.ack = pkt.seq + 1
        t.flags = 'RA'
        t.window = 0
        #Envio el paquete
        send(i/t)
        logging.warning('TCP RST enviado')

#Comienzo del script
logging.info('Script init')
try:
    #Agrego la regla de iptables que me va a mandar las conexiones que va a manejar mi funcion server()
    rule = iptc.Rule()
    rule.protocol = 'tcp'
    match = iptc.Match(rule, "state")
    match.state = "NEW"
    rule.add_match(match)
    match = iptc.Match(rule, "tcp")
    match.dport = '80'
    rule.add_match(match)
    rule.target = iptc.Target(rule, "NFQUEUE")
    rule.target.set_parameter('queue-num','1')
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    chain.insert_rule(rule)
except Exception as e:
    logging.error('Error al agregar el reruteo por iptables: ' + str(e))
    raise
else:
    logging.info('Reruteo por iptables agregado')
    logging.info('any -> any tcp/80')

#Creo un netfilterqueue para atrapar los paquetes en iptables
nfqueue = NetfilterQueue()
#Vinculo el netfilterqueue con la entrada de iptables con NFQUEUE, tiene el valor 1, ese valor se configuro antes en queue-num
#Vinculo tambien la funcion a la cual llamo cuando un paquete llego a esa cadena
nfqueue.bind(1, server)

try:
    logging.info('Ejecutando el listener asincronico...')
    #Ejecuto asinconicamente el nfqueue
    nfqueue.run()
except KeyboardInterrupt:
    logging.info('KeyboardInterrupt!')
    pass
finally:
    #Borro la regla del iptables, termina mi script
    try:
        chain.delete_rule(rule)
    except Exception as e:
        logging.warning('Error al remover la regla de iptables, es necesario removerla de forma manual: ' + str(e))
    else:
        logging.info('Reruteo por iptables borrado.')
    finally:
        logging.info('Script End')
