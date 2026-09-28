import radiusd
import logging
import configparser
from ApiLea5 import ApiLea5

class RadiusHandler(logging.Handler):
    """Logs handler for FreeRADIUS"""

    def emit(self, record):
        if record.levelno >= logging.WARN:
            rad_sig = radiusd.L_ERR
        elif record.levelno >= logging.INFO:
            rad_sig = radiusd.L_INFO
        else:
            rad_sig = radiusd.L_DBG
        radiusd.radlog(rad_sig, str(record.msg))

logger = logging.getLogger("auth.py")
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s - %(name)s: [%(levelname)s] %(message)s")
handler = RadiusHandler()
handler.setFormatter(formatter)
logger.addHandler(handler)


def radius_event(fun):
    """
    Decorator for freeradius fonction with radius.
    This function take a unique argument which is a list of tuples (key, value)
    and return a tuple of 3 values which are:
     * return code (see radiusd.RLM_MODULE_* )
     * a tuple of 2 elements for response value (access ok , etc)
     * a tuple of 2 elements for internal value to update (password for example)

    Here, we convert the list of tuples into a dictionnary.
    """

    def new_f(auth_data):
        """ The function transforming the tuples as dict """
        if isinstance(auth_data, dict):
            data = auth_data
        else:
            data = dict()
            for (key, value) in auth_data or []:
                # Beware: les valeurs scalaires sont entre guillemets
                # Ex: Calling-Station-Id: "une_adresse_mac"
                data[key] = value.replace('"', "")
        try:
            # TODO s'assurer ici que les tuples renvoy  s sont bien des
            # (str,str) : rlm_python ne dig  re PAS les unicodes
            return fun(data)
        except Exception as err:
            exc_type, exc_instance, exc_traceback = sys.exc_info()
            formatted_traceback = "".join(traceback.format_tb(exc_traceback))
            logger.error("Failed %r on data %r" % (err, auth_data))
            logger.error("Function %r, Traceback : %r" %
                         (fun, formatted_traceback))
            return radiusd.RLM_MODULE_FAIL

    return new_f


@radius_event
def instantiate(p):
    """ Instantiate api connection """
    logger.info("Instantiation")

    config = configparser.ConfigParser()
    config.read('config.ini')
  
    api_hostname = config['API LEA5']['ApiEndpoint']
    api_key = config['API LEA5']['ApiKey']

    global api_client
    api_client = ApiLea5(api_hostname,api_key)

@radius_event
def authorize(data):
    """
    Check user authorizations to connect to wifi
    """
    username = data.get("User-Name", "")
    user = api_client.fetchUserByUsername(username)

    if not user:
        logger.info(f"User {username} does not exist")
        return radiusd.RLM_MODULE_REJECT
    
    if not user.internet_expiration:
        logger.info(f"User {username} internet subscription is expired")
        return radiusd.RLM_MODULE_REJECT

    password = user.ntlm_password.upper()

    if not password:
        logger.info(f"ERROR: User {username} NTLM password does not exist")
        return radiusd.RLM_MODULE_PROJECT

    logger.info(f"Connection authorized for user {username}")
    return(
        radiusd.RLM_MODULE_UPDATED,
        (),
        ((str("NT-Password"), str(password)),),
    )

@radius_event
def post_auth(data):
    """
    Register user's machine mac adress in Lea5
    """
    mac = data.get('Calling-Station-Id')
    username = data.get("User-Name", "")
    user = api_client.fetchUserByUsername(username)
    response = api_client.createMachine(user,mac)
    logger.info(f"Post-Auth: Connecting machine {mac}")
    return radiusd.RLM_MODULE_OK
