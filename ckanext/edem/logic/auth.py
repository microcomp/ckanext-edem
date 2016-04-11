import ckan.logic as logic
import ckan.plugins.toolkit as toolkit

@logic.auth_sysadmins_check
def resource_table_status_update(context, data_dict):
    msg = toolkit._('Cannot update resource table status.')
    return {'success': False, 'msg': msg}