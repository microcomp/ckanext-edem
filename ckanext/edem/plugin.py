import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
import ckan.model as model
import ckan.new_authz as new_authz
import ckan.logic as logic
import ckan.logic.auth as logic_auth
import ckan.lib.navl.dictization_functions as df
import ckan.lib.dictization.model_dictize as model_dictize
import logging
import logic.actions as custom_action
import logic.auth as custom_auth
from ckan.logic.auth import (get_package_object, get_group_object,
                            get_resource_object, get_related_object)
from pylons import config
from pylons import session

from ckanext.edem.model.lock_db import DatasetLock, lock_table, is_locked, lock_dataset, authorized_dataset_update
from ckanext.edem.model.api_access_db import user_make_api_call

log = logging.getLogger(__name__)
#from ckan.common import _
_ = toolkit._

class Roles(object):
    MOD_R_PO = 'MOD-R-PO'
    MOD_R_DATA = 'MOD-R-DATA'
    MOD_R_ADM = 'MOD-R-ADM'
    MOD_R_ONTO = 'MOD-R-ONTO'
    MOD_R_TRANSA = 'MOD-R-TRANSA'
    MOD_R_MODER = 'MOD-R-MODER'
    MOD_R_APP = 'MOD-R-APP'
    MOD_R_PO_API = 'MOD-R-PO-API'
    
    

def roles(context, data_dict):
    return Roles

@logic.side_effect_free
def organization_list_for_user(context, data_dict):
    '''Return the organizations that the user has a given permission for.
    By default this returns the list of organizations that the currently
    authorized user can edit, i.e. the list of organizations that the user is an
    admin of.
    Specifically it returns the list of organizations that the currently
    authorized user has a given permission (for example: "edit_group") against.
    When a user becomes a member of an organization in CKAN they're given a
    "capacity" (sometimes called a "role"), for example "member", "editor" or
    "admin".
    Each of these roles has certain permissions associated with it. For example
    the admin role has the "admin" permission (which means they have permission
    to do anything). The editor role has permissions like "create_dataset",
    "update_dataset" and "delete_dataset". The member role has the "read"
    permission.
    This function returns the list of organizations that the authorized user has
    a given permission for. For example the list of organizations that the user
    is an admin of, or the list of organizations that the user can create
    datasets in.
    :param permission: the permission the user has against the
    returned organizations, for example ``"read"`` or ``"create_dataset"``
    (optional, default: ``"edit_group"``)
    :type permission: string
    :returns: list of organizations that the user has the given permission for
    :rtype: list of dicts
    '''
    model = context['model']
    user = context['user']
    logic.check_access('organization_list_for_user', context, data_dict)
    sysadmin = new_authz.is_sysadmin(user)
    orgs_q = model.Session.query(model.Group) \
    .filter(model.Group.is_organization == True) \
    .filter(model.Group.state == 'active')
    user_roles = user_custom_roles(context, data_dict)
    if not sysadmin and not Roles.MOD_R_DATA in user_roles:
        # for non-Sysadmins check they have the required permission
        permission = data_dict.get('permission', 'edit_group')
        roles = new_authz.get_roles_with_permission(permission)
        if not roles:
            return []
        user_id = new_authz.get_user_id_for_username(user, allow_none=True)
        if not user_id:
            return []
        q = model.Session.query(model.Member) \
        .filter(model.Member.table_name == 'user') \
        .filter(model.Member.capacity.in_(roles)) \
        .filter(model.Member.table_id == user_id) \
        .filter(model.Member.state == 'active')
        group_ids = []
        for row in q.all():
            group_ids.append(row.group_id)
        if not group_ids:
            return []
        orgs_q = orgs_q.filter(model.Group.id.in_(group_ids))
    orgs_list = model_dictize.group_list_dictize(orgs_q.all(), context)
    return orgs_list

def user_custom_roles(context, data_dict=None):
    try:
        return session.get('ckanext-cas-roles', [])
    except TypeError:
        return []
        

def user_has_role(user_id, role_name):
    try:
        roles = session.get('ckanext-cas-roles', [])
        if role_name in roles:
            return True
        return False
    except TypeError:
        return False

@logic.auth_allow_anonymous_access        
def resource_show(context, data_dict):
    model = context['model']
    user = context.get('user')
    log.info('user resource show: %s', user)  
    resource = get_resource_object(context, data_dict)
        
    # check authentication against package
    query = model.Session.query(model.Package)\
        .join(model.ResourceGroup)\
        .join(model.Resource)\
        .filter(model.ResourceGroup.id == resource.resource_group_id)
    pkg = query.first()
    if not pkg:
        raise logic.NotFound(_('No package found for this resource, cannot check auth.'))
    for_edit = context.get('for_edit', None)
    log.info('resource show for edit: %s', for_edit)
    locked = context.get('operation_locked', None)
    if for_edit and not locked:
        lock_dataset(pkg.id, user)
        context['operation_locked'] = True
    
    user_roles = user_custom_roles(context, data_dict)
    if Roles.MOD_R_DATA in user_roles:
        return {'success': True}
    
    pkg_dict = {'id': pkg.id}
    authorized = package_show(context, pkg_dict).get('success')

    if not authorized:
        return {'success': False, 'msg': _('User %s not authorized to read resource %s') % (user, resource.id)}
    else:
        #check resource status, if private just org members may see it
        if not toolkit.get_action('is_resource_public')(context, resource.extras):
            authorized_read = package_update(context, pkg_dict).get('success')
            if not authorized_read:
                return {'success': False, 'msg': _('User %s not authorized to read resource %s') % (user, resource.id)}
        return {'success': True}

@logic.auth_allow_anonymous_access
def package_show(context, data_dict):
    def _package_show(context, data_dict):
        user = context.get('user')
        package = get_package_object(context, data_dict)
        user_roles = user_custom_roles(context, data_dict)
        if Roles.MOD_R_DATA in user_roles:
            return {'success': True}
        # draft state indicates package is still in the creation process
        # so we need to check we have creation rights.
        if package.state.startswith('draft'):
            auth = new_authz.is_authorized('package_update',
                                           context, data_dict)
            authorized = auth.get('success')
        elif package.owner_org is None and package.state == 'active':
            return {'success': True}
        else:
            # anyone can see a public package
            if not package.private and package.state == 'active':
                return {'success': True}
            authorized = new_authz.has_user_permission_for_group_or_org(
                package.owner_org, user, 'read')
        if not authorized:
            return {'success': False, 'msg': _('User %s not authorized to read package %s') % (user, package.id)}
        else:
            return {'success': True}

    result = _package_show(context, data_dict)
    for_edit = context.get('for_edit', None)
    if result['success']:
        locked = context.get('operation_locked', None)
        if for_edit and not locked:
            user = context.get('user')
            package = get_package_object(context, data_dict)
            lock_dataset(package.id, user)
            context['operation_locked'] = True
    return result


@logic.auth_allow_anonymous_access
def package_create(context, data_dict=None):
    user = context['user']
    user_roles = user_custom_roles(context, data_dict)
    if Roles.MOD_R_DATA in user_roles:
        return {'success': True}
    
    if new_authz.auth_is_anon_user(context):
        check1 = all(new_authz.check_config_permission(p) for p in (
            'anon_create_dataset',
            'create_dataset_if_not_in_organization',
            'create_unowned_dataset',
            ))
    else:
        check1 = all(new_authz.check_config_permission(p) for p in (
            'create_dataset_if_not_in_organization',
            'create_unowned_dataset',
            )) or new_authz.has_user_permission_for_some_org(
            user, 'create_dataset')

    if not check1:
        return {'success': False, 'msg': _('User %s not authorized to create packages') % user}

    check2 = _check_group_auth(context,data_dict)
    if not check2:
        return {'success': False, 'msg': _('User %s not authorized to edit these groups') % user}

    # If an organization is given are we able to add a dataset to it?
    data_dict = data_dict or {}
    org_id = data_dict.get('owner_org')
    if org_id and not new_authz.has_user_permission_for_group_or_org(
            org_id, user, 'create_dataset'):
        return {'success': False, 'msg': _('User %s not authorized to add dataset to this organization') % user}
    return {'success': True}

@logic.auth_allow_anonymous_access
def package_update(context, data_dict):
    def _package_update(context, data_dict):
        user = context.get('user')
        package = logic_auth.get_package_object(context, data_dict)
        user_roles = user_custom_roles(context, data_dict)
        if Roles.MOD_R_DATA in user_roles:
            return {'success': True}
        if package.owner_org:
            # if there is an owner org then we must have update_dataset
            # permission for that organization
            check1 = new_authz.has_user_permission_for_group_or_org(
                package.owner_org, user, 'update_dataset'
            )
        else:
            # If dataset is not owned then we can edit if config permissions allow
            if new_authz.auth_is_anon_user(context):
                check1 = all(new_authz.check_config_permission(p) for p in (
                    'anon_create_dataset',
                    'create_dataset_if_not_in_organization',
                    'create_unowned_dataset',
                    ))
            else:
                check1 = all(new_authz.check_config_permission(p) for p in (
                    'create_dataset_if_not_in_organization',
                    'create_unowned_dataset',
                    )) or new_authz.has_user_permission_for_some_org(
                    user, 'create_dataset')
        if not check1:
            return {'success': False,
                    'msg': _('User %s not authorized to edit package %s') %
                            (str(user), package.id)}
        else:
            check2 = _check_group_auth(context, data_dict)
            if not check2:
                return {'success': False,
                        'msg': _('User %s not authorized to edit these groups') %
                                (str(user))}
    
        return {'success': True}
    
    result = _package_update(context, data_dict)
    for_edit = context.get('for_edit', None)
    if result['success']:
        locked = context.get('operation_locked', None)
        if for_edit and not locked:
            user = context.get('user')
            package = get_package_object(context, data_dict)
            lock_dataset(package.id, user)
            context['operation_locked'] = True
    return result

def _check_group_auth(context, data_dict):
    '''Has this user got update permission for all of the given groups?
    If there is a package in the context then ignore that package's groups.
    (owner_org is checked elsewhere.)
    :returns: False if not allowed to update one (or more) of the given groups.
              True otherwise. i.e. True is the default. A blank data_dict
              mentions no groups, so it returns True.

    '''
    # FIXME This code is shared amoung other logic.auth files and should be
    # somewhere better
    if not data_dict:
        return True

    model = context['model']
    user = context['user']
    pkg = context.get("package")

    api_version = context.get('api_version') or '1'

    group_blobs = data_dict.get('groups', [])
    groups = set()
    for group_blob in group_blobs:
        # group_blob might be a dict or a group_ref
        if isinstance(group_blob, dict):
            if api_version == '1':
                id = group_blob.get('name')
            else:
                id = group_blob.get('id')
            if not id:
                continue
        else:
            id = group_blob
        grp = model.Group.get(id)
        if grp is None:
            raise logic.NotFound(_('Group was not found.'))
        groups.add(grp)

    if pkg:
        pkg_groups = pkg.get_groups()

        groups = groups - set(pkg_groups)

    for group in groups:
        if not new_authz.has_user_permission_for_group_or_org(group.id, user, 'update'):
            return False

    return True

def _no_permissions(context, msg):
    user = context['user']
    return {'success': False, 'msg': msg.format(user=user)}

@logic.auth_allow_anonymous_access
def auth_organization_create(context, data_dict=None):
    msg = toolkit._('Organization can not be created.')
    return _no_permissions(context, msg)


def auth_organization_update(context, data_dict):
    group = logic_auth.get_group_object(context, data_dict)
    user = context['user']
    if is_data_curator(context, data_dict)['success']:
        return {'success': True}
    authorized = new_authz.has_user_permission_for_group_or_org(
        group.id, user, 'update')
    if not authorized:
        return {'success': False,
                'msg': _('User %s not authorized to edit organization %s') %
                        (user, group.id)}
    else:
        return {'success': True}

@logic.auth_allow_anonymous_access
def auth_group_create(context, data_dict=None):
    msg = toolkit._('Group can not be created.')
    return _no_permissions(context, msg)


@logic.auth_allow_anonymous_access
def auth_app_create(context, data_dict=None):
    # Get the user name of the logged-in user.
    user_name = context['user']
    # We have the logged-in user's user name, get their user id.
    convert_user_name_or_id_to_id = toolkit.get_converter('convert_user_name_or_id_to_id')
    try:
        convert_user_name_or_id_to_id(user_name, context)
    except df.Invalid:
        return {'success': False,
                'msg': _('Only authenticated users are allowed to create applications')}
    return {'success': True}

@logic.auth_allow_anonymous_access
def auth_app_edit(context, data_dict=None):
    user = context['user']
    convert_user_name_or_id_to_id = toolkit.get_converter('convert_user_name_or_id_to_id')
    try:
        user_id = convert_user_name_or_id_to_id(user, context)
    except df.Invalid:
        return {'success': False,
                'msg': _('Only application owner and application administrators are allowed to edit applications')}
    try:
        if data_dict['owner_id']==user_id or user_has_role(user_id, Roles.MOD_R_APP):
            return {'success': True}
    except TypeError as e:
        log.exception(e)
        if user_has_role(user_id, Roles.MOD_R_APP):
            return {'success': True}
    
    return {'success': False,
                'msg': _('Only application owner and application administrators are allowed to edit applications')}

@logic.auth_allow_anonymous_access
def auth_app_edit_all(context, data_dict=None):
    user = context['user']
    convert_user_name_or_id_to_id = toolkit.get_converter('convert_user_name_or_id_to_id')
    try:
        user_id = convert_user_name_or_id_to_id(user, context)
    except df.Invalid:
        return {'success': False,
                'msg': _('Only application owner and application administrators are allowed to edit applications')}
    if user_has_role(user_id, Roles.MOD_R_APP):
        return {'success': True}
    
    return {'success': False,
                'msg': _('Only application owner and application administrators are allowed to edit applications')}

@logic.auth_allow_anonymous_access
def auth_storage_usage(context, data_dict=None):
    user_roles = user_custom_roles(context, data_dict)
    if Roles.MOD_R_DATA in user_roles:
        return {'success': True}
    return {'success': False, 'msg': _('Only data curator is authorized to manage storage usage.')}

@logic.auth_allow_anonymous_access
def auth_comments_administration(context, data_dict=None):
    user_roles = user_custom_roles(context, data_dict)
    if Roles.MOD_R_MODER in user_roles:
        return {'success': True}
    return {'success': False, 'msg': _('Only moderator is authorized to manage comments and blogs.')}

@logic.auth_allow_anonymous_access
def auth_tags_administration(context, data_dict=None):
    user_roles = user_custom_roles(context, data_dict)
    if Roles.MOD_R_DATA in user_roles:
        return {'success': True}
    return {'success': False, 'msg': _('Only data curator is authorized to manage tags of datasets.')}

@logic.auth_allow_anonymous_access
def auth_add_dataset_rating(context, data_dict=None):
    user_roles = user_custom_roles(context, data_dict)
    if Roles.MOD_R_DATA in user_roles:
        return {'success': True}
    return {'success': False, 'msg': _('Only data curator is authorized to edit rating of datasets.')}

@logic.auth_allow_anonymous_access
def auth_uv_usage(context, data_dict=None):
    user_roles = user_custom_roles(context, data_dict)
    if Roles.MOD_R_TRANSA in user_roles or package_create(context, data_dict)['success']:
        return {'success': True}
    return {'success': False, 'msg': _('You do not have permission to use Unified Views.')}

@logic.auth_allow_anonymous_access
def auth_sla_management(context, data_dict=None):
    user_roles = user_custom_roles(context, data_dict)
    if Roles.MOD_R_DATA in user_roles:
        return {'success': True}
    return {'success': False, 'msg': _('Only data curator is authorized to manage SLA.')}

@logic.auth_allow_anonymous_access
def is_data_curator(context, data_dict=None):
    user_roles = user_custom_roles(context, data_dict)
    if Roles.MOD_R_DATA in user_roles:
        return {'success': True}
    return {'success': False, 'msg': _('Current user does not have role data curator.')}

def package_delete(context, data_dict):
    # Defer auhtorization for package_delete to package_update, as deletions
    # are essentially changing the state field
    return package_update(context, data_dict)

def resource_delete(context, data_dict):
    model = context['model']
    user = context.get('user')
    resource = get_resource_object(context, data_dict)

    # check authentication against package
    query = model.Session.query(model.Package)\
        .join(model.ResourceGroup)\
        .join(model.Resource)\
        .filter(model.ResourceGroup.id == resource.resource_group_id)
    pkg = query.first()
    if not pkg:
        raise logic.NotFound(_('No package found for this resource, cannot check auth.'))

    pkg_dict = {'id': pkg.id}
    authorized = package_delete(context, pkg_dict).get('success')

    if not authorized:
        return {'success': False, 'msg': _('User %s not authorized to delete resource %s') % (user, resource.id)}
    else:
        return {'success': True}

@logic.auth_allow_anonymous_access
def package_unlock(context, data_dict):
    log.info('auth package_unlock')
    return package_update(context, data_dict)

def user_update_url():
    return config.get('ckan.profile_update_url', None)

def package_is_locked(package_id):
    return is_locked(package_id)

def can_make_api_call(user_id):
    return user_make_api_call(user_id)


def _wrapper_allow_disable_api(role_name):
    @logic.auth_allow_anonymous_access
    def allow_disable_api(context, data_dict=None):
        user_roles = user_custom_roles(context, data_dict)
        log.info('user roles: %s', user_roles)
        log.info('role name: %s', role_name)
        if role_name in user_roles:
            return {'success': True}
        return {'success': False, 'msg': _('Current user does not have role data curator.')}
    return allow_disable_api
        
class EdemCustomPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer, inherit=False)
    plugins.implements(plugins.IAuthFunctions)
    plugins.implements(plugins.IActions)
    plugins.implements(plugins.ITemplateHelpers)
    plugins.implements(plugins.IConfigurable)
    plugins.implements(plugins.IRoutes, inherit=True)
    
    def before_map(self, map):
        map.connect('api_abort', '/api_access/abort', action='abort', controller='ckanext.edem.controllers.api_access:ApiAccessController')
        map.connect('api_allow', '/api_access/allow', action='allow', controller='ckanext.edem.controllers.api_access:ApiAccessController')
        return map
    
    def configure(self, config):
        self.ckan_url = config.get('ckan.site_url', None)
        self.role_allow_disable_api = config.get('ckanext.edem.user_role_allow_disable_api', None)
    
    def update_config(self, config):
        toolkit.add_template_directory(config, 'templates')
    
    def get_helpers(self):
        return {'get_user_update_url' : user_update_url,
                'package_is_locked' : package_is_locked,
                'user_allowed_api_call' : can_make_api_call}
    
    def get_actions(self):
        return {'organization_list_for_user' : organization_list_for_user,
                'user_custom_roles' : user_custom_roles,
                'enum_roles' : roles,
                'package_create' : custom_action.package_create,
                'package_update' : custom_action.package_update,
                'resource_create' : custom_action.resource_create,
                'resource_update' : custom_action.resource_update,
                'probe' : custom_action.probe,
                'package_unlock' : custom_action.package_unlock,
                'user_make_api_call' : custom_action.user_make_api_call,
                'resource_table_status_update' : custom_action.resource_table_status_update,
                'resource_datastore_lately_modified' : custom_action.resource_datastore_lately_modified}
    
    def get_auth_functions(self):
        return {'group_create' : auth_group_create,
                'organization_create' : auth_organization_create,
                'organization_update' : auth_organization_update,
                'package_create' : package_create,
                'package_update' : package_update,
                'package_delete' : package_delete,
                'package_show' : package_show,
                'resource_show' : resource_show,
                'resource_delete' : resource_delete,
                'app_create' : auth_app_create,
                'app_edit' : auth_app_edit,
                'app_editall' : auth_app_edit_all,
                'storage_usage' : auth_storage_usage,
                'commets_admin' : auth_comments_administration,
                'tags_admin' : auth_tags_administration,
                'add_dataset_rating' : auth_add_dataset_rating,
                'uv_usage' : auth_uv_usage,
                'sla_management' : auth_sla_management,
                'is_data_curator' : is_data_curator,
                'package_unlock' : package_unlock,
                'allow_disable_api' : _wrapper_allow_disable_api(self.role_allow_disable_api),
                'resource_table_status_update' : custom_auth.resource_table_status_update
                }
            
