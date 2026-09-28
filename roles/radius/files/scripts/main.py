#!/user/bin python3
#encoding=utf8

import sys
import re
from ApiLea5 import ApiLea5
import datetime
import dateutil.parser
import configparser

config = configparser.ConfigParser()
config.read('../config.ini')

now = datetime.datetime.now()

switch = sys.argv[1]
mac = sys.argv[2]
port = sys.argv[3]
mac = re.sub(r'(..)\B', r'\1:', mac)
api = ApiLea5(config['API LEA5']['ApiEndpoint'],config['API LEA5']['ApiKey'])

machine = api.fetchMachineByMac(mac)

internet_expiration = dateutil.parser.isoparse(machine.internet_expiration)
vlan = 14
if now.timestamp() < internet_expiration.timestamp():
    vlan = 12
print('Tunnel-type=VLAN,')
print('Tunnel-Medium-Type= IEEE-802,')
print('Tunnel-Private-Group-ID="{vlan}"'.format(vlan=vlan))

