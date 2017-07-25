from scapy.all import *
from netfilterqueue import NetfilterQueue
import time
import hashlib
import iptc

LOG_FILE = '/var/log/covert_client.log'
logging.basicConfig(filename=LOG_FILE,level=logging.DEBUG,format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%d/%m/%Y %H:%M:%S')

def generateID(psk,ts=False):
        logging.debug('generateID()')
        if ts:
                timestamp = str(int(time.time())/10)
                psk = psk + str(timestamp)
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

def cliente(packet):
        logging.debug('cliente()')
        pkt = IP(packet.get_payload())
        pkt.id = generateID('secreto',ts=True)
        del pkt[IP].chksum
        packet.set_payload(str(pkt))
        packet.accept()
        logging.info('Paquete modificado: ' + str(pkt.src) + ':' + str(pkt.sport) + ' -> ' + str(pkt.dst) + ':' + str(pkt.dport) + ' / IP ID: ' + str(pkt.id))

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
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "OUTPUT")
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
nfqueue.bind(1, cliente)

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