import sys
import re
import configparser
from ApiLea5.apilea5.apilea5 import ApiLea5
config = configparser.ConfigParser()
config.read('/etc/freeradius/3.0/config.ini')


switch = sys.argv[1]
mac = sys.argv[2]
port = sys.argv[3]
mac = re.sub(r'(..)\B', r'\1:', mac)
api = ApiLea5(config['API LEA5']['ApiEndpoint'],config['API LEA5']['ApiKey'])

machine = api.fetch_machine_by_mac(mac)

vlan = 14
if machine.internet_expiration:
    vlan = 12
print('Tunnel-type=VLAN,')
print('Tunnel-Medium-Type= IEEE-802,')
print('Tunnel-Private-Group-ID="{vlan}"'.format(vlan=vlan))