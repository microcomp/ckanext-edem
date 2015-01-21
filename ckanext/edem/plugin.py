import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
import ckan.model as model
import ckan.new_authz as new_authz
import ckan.logic as logic
import ckan.logic.auth as logic_auth
import ckan.lib.navl.dictization_functions as df
import ckan.lib.dictization.model_dictize as model_dictize
#from ckan.common import _
_ = toolkit._

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
    if not sysadmin and not 'datovy-kurator' in user_roles:
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



def create_group_if_not_exists(data_dict):
        group_name = data_dict['name']
        group = model.Group.get(group_name)
        
        context = {'ignore_auth': True}
        site_user = toolkit.get_action('get_site_user')(context, {})
        c = toolkit.c

        if not group:
            context = {'user': site_user['name']}
            group = toolkit.get_action('group_create')(context, data_dict)
            group = model.Group.get(group_name)
        
        return group

def add_user_to_group(group_id, user_id):
    data_dict = {
        'id': group_id,
        'type': 'user',
    }
    context = {'ignore_auth': True}
    members = toolkit.get_action('member_list')(context, data_dict)
    members = [member[0] for member in members]
    if user_id not in members:
        # add membership
        member_dict = {
            'id': group_id,
            'object': user_id,
            'object_type': 'user',
            'capacity': 'member',
        }
        member_create_context = {
            'ignore_auth': True,
        }
        toolkit.get_action('member_create')(member_create_context, member_dict)

def user_custom_roles(context, data_dict=None):

    # Get the user name of the logged-in user.
    user_name = context['user']
    convert_user_name_or_id_to_id = toolkit.get_converter('convert_user_name_or_id_to_id')
    try:
        user_id = convert_user_name_or_id_to_id(user_name, context)
    except df.Invalid:
        return []
    possible_roles = ['moderator','app-admin','datovy-kurator']
    current_roles = []
    # Get a list of the members of the 'curators' group.
    for role in possible_roles:
        if user_has_role(user_id, role):
            current_roles.append(role)
    return current_roles

def user_has_role(user_id, role_name):
    members = toolkit.get_action('member_list')(data_dict={'id': role_name, 'object_type': 'user'})
    member_ids = [member_tuple[0] for member_tuple in members]
    if user_id in member_ids:
        return True
    return False
    
    
@logic.auth_allow_anonymous_access
def package_create(context, data_dict=None):
    user = context['user']
    user_roles = user_custom_roles(context, data_dict)
    if 'datovy-kurator' in user_roles:
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
    user = context.get('user')
    user_roles = user_custom_roles(context, data_dict)
    if 'datovy-kurator' in user_roles:
        return {'success': True}
    package = logic_auth.get_package_object(context, data_dict)

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


def auth_group_create(context, data_dict=None):

    # Get the user name of the logged-in user.
    user_name = context['user']

    # Get a list of the members of the 'curators' group.
    members = toolkit.get_action('member_list')(
        data_dict={'id': 'spravcovia', 'object_type': 'user'})

    # 'members' is a list of (user_id, object_type, capacity) tuples, we're
    # only interested in the user_ids.
    member_ids = [member_tuple[0] for member_tuple in members]

    # We have the logged-in user's user name, get their user id.
    convert_user_name_or_id_to_id = toolkit.get_converter(
        'convert_user_name_or_id_to_id')
    user_id = convert_user_name_or_id_to_id(user_name, context)

    # Finally, we can test whether the user is a member of the curators group.
    if user_id in member_ids:
        return {'success': True}
    else:
        return {'success': False,
                'msg': 'Only spravcovia are allowed to create groups'}
        
def auth_organization_create(context, data_dict=None):

    # Get the user name of the logged-in user.
    user_name = context['user']

    # Get a list of the members of the 'curators' group.
    members = toolkit.get_action('member_list')(
        data_dict={'id': 'spravcovia', 'object_type': 'user'})

    # 'members' is a list of (user_id, object_type, capacity) tuples, we're
    # only interested in the user_ids.
    member_ids = [member_tuple[0] for member_tuple in members]

    # We have the logged-in user's user name, get their user id.
    convert_user_name_or_id_to_id = toolkit.get_converter(
        'convert_user_name_or_id_to_id')
    user_id = convert_user_name_or_id_to_id(user_name, context)

    # Finally, we can test whether the user is a member of the curators group.
    if user_id in member_ids:
        return {'success': True}
    else:
        return {'success': False,
                'msg': 'Only spravcovia are allowed to create organization'}

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
    if data_dict['owner_id']==user_id or user_has_role(user_id, 'app-admin'):
        return {'success': True}
    
    return {'success': False,
                'msg': _('Only application owner and application administrators are allowed to edit applications')}


class EdemCustomPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IAuthFunctions)
    plugins.implements(plugins.IActions)
    
    def get_actions(self):
        return {'organization_list_for_user' : organization_list_for_user,
                'user_custom_roles' : user_custom_roles}
    
    def get_auth_functions(self):
        return {'group_create' : auth_group_create,
                'organization_create' : auth_organization_create,
                'package_create' : package_create,
                'package_update' : package_update,
                'app_create' : auth_app_create,
                'app_edit' : auth_app_edit
                }
            