import os
import sys
import logging
import csv

from ckan.lib.cli import CkanCommand
from model import lock_db, api_access_db, resource_ds_table_db

log = logging.getLogger('ckanext')
log.setLevel(logging.DEBUG)

def get_filename(resource_id, storage_path):
    directory = os.path.join(storage_path, 'resources', resource_id[0:3], resource_id[3:6])
    try:
        os.makedirs(directory)
    except OSError, e:
        ## errno 17 is file already exists
        if e.errno != 17:
            raise
    filepath = os.path.join(directory, resource_id[6:])
    return filepath
        
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
        
        import ckan.plugins.toolkit as toolkit
        import ckan.model as model
        import ckan.logic as logic
        import ckan.lib.base as base
        from pylons import config
        
        def _retrieve_resource_records(resource_id, limit, offset):
                context = {
                    'model': model,
                    'session': model.Session,
                    'ignore_auth' : True
                }
                data_dict = {
                    'resource_id': resource_id,
                    'limit': limit,
                    'offset': offset
                }
                action = toolkit.get_action('datastore_search')
                return action(context, data_dict)

        def resource2file(resource_id):
            log.info('resource %s to file', resource_id)
            context = {'model' : model, 'Session' : model.Session, 'ignore_auth' : True}
            data_dict = {'resource_id' : resource_id}
            storage_path = config.get('ckan.storage_path', None)
            filename = get_filename(resource_id, storage_path)
            tmpfilename = filename + '~'
            limit = 100
            offset = 0
            with open(tmpfilename, 'wb') as csvfile:
                spamwriter = csv.writer(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                while True:
                    try:
                        result = _retrieve_resource_records(resource_id, limit, offset)
                    except toolkit.ObjectNotFound:
                        log.warning('no records in datastore for resource %s', resource_id)
                        break
                    log.info('iteration: offset %d, records %d, limit %d', offset, len(result['records']), limit)
                    if not offset:
                        header = [x['id'] for x in result['fields']]
                        spamwriter.writerow(header)
                    count = result['records']
                    if not count:
                        break
                    for record in result['records']:
                        spamwriter.writerow([unicode(record[column]).encode("utf-8") for column in header])
                    offset+=limit
            os.rename(tmpfilename, filename)
        
        if len(self.args) == 0:
            self.parser.print_usage()
            sys.exit(1)

        cmd = self.args[0]
        if cmd == 'uninstall':
            def _db_lock_uninstall():
                if lock_db.lock_table.exists():
                    log.info("droping ckanext_edem_lock table")
                    lock_db.lock_table.drop()
                    log.info("table ckanext_edem_lock dropped")
                else:
                    log.info("table doesnt exist")

            def _db_api_access_uninstall():
                if api_access_db.abort_api_table.exists():
                    log.info("droping ckanext_edem_abort_api table")
                    api_access_db.abort_api_table.drop()
                    log.info("table ckanext_edem_abort_api dropped")
                else:
                    log.info("table doesnt exist")
            
            def _db_resource_table_uninstall():
                if resource_ds_table_db.resource_table.exists():
                    log.info("droping ckanext_edem_resource_table table")
                    resource_ds_table_db.resource_table.drop()
                    log.info("table ckanext_edem_resource_table dropped")
                else:
                    log.info("table doesnt exist")

            if len(self.args) == 2:
                db_name = self.args[1]
            else:
                db_name = None
            
            if db_name == 'resource_table':
                _db_resource_table_uninstall()
            elif db_name == 'lock':
                _db_lock_uninstall()
            elif db_name == 'api_access':
                _db_api_access_uninstall()
            elif db_name == 'all':
                _db_resource_table_uninstall()
                _db_lock_uninstall()
                _db_api_access_uninstall()
            else:
                log.warning('invalid argument of command uninstall')
        
        if cmd == 'init_resource_table':
            def _retrieve_package_list(limit, offset):
                context = {
                    'model': model,
                    'session': model.Session,
                    'ignore_auth' : True
                }
                data_dict = {
                    'limit': limit,
                    'offset': offset
                }
                action = toolkit.get_action('current_package_list_with_resources')
                return action(context, data_dict)
            
            url_type = 'datastore'
            limit = 100
            offset = 0
            while True:
                package_list = _retrieve_package_list(limit, offset)
                if not package_list:
                    break
                for package in package_list:
                    log.info('executing package %s with %d resources', package.get('name'), len(package.get('resources', [])))
                    for resource in package.get('resources', []):
                        if resource['url_type'] == url_type:
                            context = {'ignore_auth' : True}
                            data_dict = {'resource_id' : resource['id']}
                            toolkit.get_action('resource_table_status_update')(context, data_dict)
                offset+=limit

        if cmd == 'resource2file':
            if len(self.args) == 2:
                resource_id = self.args[1]
                resource2file(resource_id)
                context = {'ignore_auth' : True}
                data_dict = {'resource_id' : resource_id, 'to_file_success' : True}
                toolkit.get_action('resource_table_status_update')(context, data_dict)
            else:
                #convert all DS resource tables to CSV modified lately
                threshold = int(config.get('ckanext.edem.threshold',1))
                context = {'ignore_auth' : True}
                data_dict = {'threshold' : threshold}
                resources = toolkit.get_action('resource_datastore_lately_modified')(context, data_dict)
                if resources:
                    for item in resources:
                        try:
                            #check datastore records for resource
                            _retrieve_resource_records(item, 1, 0)
                            resource2file(item)
                            context = {'ignore_auth' : True}
                            data_dict = {'resource_id' : item, 'to_file_success' : True}
                            toolkit.get_action('resource_table_status_update')(context, data_dict)
                        except toolkit.ObjectNotFound:
                            log.warning('no records in datastore for resource %s', item)
                else:
                    log.info('no recent updates in datastore')
                    
                