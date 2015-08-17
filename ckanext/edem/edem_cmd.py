from ckan.lib.cli import CkanCommand
import sys
import logging
log = logging.getLogger('ckanext')
log.setLevel(logging.DEBUG)
from model import lock_db

class EdemCmd(CkanCommand):
    """Init required vocabs
        Usage:
        edem-cmd <cmd>
        - deletes created db table
    """
    
    summary = __doc__.split('\n')[0]
    usage = __doc__
    #max_args = 3
    #min_args = 0
    
    def __init__(self, name):
        super(EdemCmd, self).__init__(name)
    def command(self):
        self._load_config()
              
        if len(self.args) == 0:
            self.parser.print_usage()
            sys.exit(1)
        cmd = self.args[0]
        if cmd == 'uninstall':
            log.info('Starting db uninstall')
            if lock_db.lock_table.exists():
                log.info("droping ckanext_edem_lock table")
                lock_db.lock_table.drop()
                log.info("table ckanext_edem_lock dropped")
            else:
                log.info("table ckanext_edem_lock doesnt exist")