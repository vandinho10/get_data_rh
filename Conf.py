import os


# CONSTANTS
BASE_DIR = os.path.dirname(__file__)
TIME_EXPIRE = 15
os.chdir(BASE_DIR)

# Files CONF
SERVERS = f"{BASE_DIR}/conf/servers.json"
USERS = f"{BASE_DIR}/conf/users.json"
FILES_USERS = f"{BASE_DIR}/conf/files.json"
PERIODS = f"{BASE_DIR}/conf/periods.json"
