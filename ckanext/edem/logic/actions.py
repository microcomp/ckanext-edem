import logging
import datetime
from pylons import session
from pylons import config
import sqlalchemy as sa
import ckan.lib.plugins as lib_plugins
import ckan.logic as logic
import ckan.lib.navl.dictization_functions
import ckan.lib.dictization.model_save as model_save
import ckan.plugins as plugins
import ckan.lib.uploader as uploader
import ckan.lib.dictization.model_dictize as model_dictize
import ckan.model as model
from ckan.common import _

from ckanext.edem.model.lock_db import unlock_dataset

_validate = ckan.lib.navl.dictization_functions.validate
_check_access = logic.check_access
ValidationError = logic.ValidationError
_get_action = logic.get_action
NotFound = logic.NotFound
_get_or_bust = logic.get_or_bust

log = logging.getLogger(__name__)

def audit_helper(input_data_dict, op_output_dict, event):
    revision_id = op_output_dict.get('revision_id', None)
    actor_id = input_data_dict.get('actor_id', None)
    if not actor_id:
        actor_id = session.get('ckanext-cas-actorid', None)
    if revision_id and actor_id:
        log.info('audit revision call: revision_id %s, actor_id %s', revision_id, actor_id)
        _get_action('audit_revision')(data_dict={'user_id' : actor_id, 'revision_id' : revision_id})
    
    audit_dict = {}
    result = model.Session.query(model.Revision).get(revision_id)
    log.info("result: %s", result)
    if result:
        audit_dict['subject'] = model.User.get(result.author).id
        log.info('subject: %s',audit_dict['subject'])
        if actor_id:
            audit_dict['authorized_user'] = actor_id
        else:
            audit_dict['authorized_user'] = model.User.get(result.author).id
        audit_dict['event_name'] = event
        audit_dict['debug_level'] = 1
        audit_dict['error_code'] = 0
        query = model.Session.query(model.PackageRevision)
        query = query.filter(model.PackageRevision.revision_id==revision_id)
        res = query.all()
        if res:
            audit_dict['object_reference'] = 'PackageID://' + res[0].continuity_id
        if not res:
            query = model.Session.query(model.ResourceRevision)
            query = query.filter(model.ResourceRevision.revision_id==revision_id)
            res = query.all()
            if res:
                audit_dict['object_reference'] = 'ResourceID://' + res[0].continuity_id
        log.info('dict for auditlog send: %s', audit_dict)
        _get_action('auditlog_send')(data_dict=audit_dict)

def package_unlock(context, data_dict):
    log.info('package_unlock')
    _check_access('package_unlock', context, data_dict)
    name_or_id = data_dict.get("id") or data_dict['name']
    log.info('package update: %s', data_dict)
    pkg = model.Package.get(name_or_id)
    if pkg is None:
        raise NotFound(_('Package was not found.'))
    subject_id = data_dict.get('subject_id', None)
    actor_id = data_dict.get('actor_id', None)
    user_obj = context['auth_user_obj']
    if not subject_id:
        subject_id = user_obj.id
    unlock_dataset(pkg.id, subject_id, actor_id)
    
    
def package_create(context, data_dict):
    '''Create a new dataset (package).

    You must be authorized to create new datasets. If you specify any groups
    for the new dataset, you must also be authorized to edit these groups.

    Plugins may change the parameters of this function depending on the value
    of the ``type`` parameter, see the ``IDatasetForm`` plugin interface.

    :param name: the name of the new dataset, must be between 2 and 100
        characters long and contain only lowercase alphanumeric characters,
        ``-`` and ``_``, e.g. ``'warandpeace'``
    :type name: string
    :param title: the title of the dataset (optional, default: same as
        ``name``)
    :type title: string
    :param author: the name of the dataset's author (optional)
    :type author: string
    :param author_email: the email address of the dataset's author (optional)
    :type author_email: string
    :param maintainer: the name of the dataset's maintainer (optional)
    :type maintainer: string
    :param maintainer_email: the email address of the dataset's maintainer
        (optional)
    :type maintainer_email: string
    :param license_id: the id of the dataset's license, see ``license_list()``
        for available values (optional)
    :type license_id: license id string
    :param notes: a description of the dataset (optional)
    :type notes: string
    :param url: a URL for the dataset's source (optional)
    :type url: string
    :param version: (optional)
    :type version: string, no longer than 100 characters
    :param state: the current state of the dataset, e.g. ``'active'`` or
        ``'deleted'``, only active datasets show up in search results and
        other lists of datasets, this parameter will be ignored if you are not
        authorized to change the state of the dataset (optional, default:
        ``'active'``)
    :type state: string
    :param type: the type of the dataset (optional), ``IDatasetForm`` plugins
        associate themselves with different dataset types and provide custom
        dataset handling behaviour for these types
    :type type: string
    :param resources: the dataset's resources, see ``resource_create()``
        for the format of resource dictionaries (optional)
    :type resources: list of resource dictionaries
    :param tags: the dataset's tags, see ``tag_create()`` for the format
        of tag dictionaries (optional)
    :type tags: list of tag dictionaries
    :param extras: the dataset's extras (optional), extras are arbitrary
        (key: value) metadata items that can be added to datasets, each extra
        dictionary should have keys ``'key'`` (a string), ``'value'`` (a
        string)
    :type extras: list of dataset extra dictionaries
    :param relationships_as_object: see ``package_relationship_create()`` for
        the format of relationship dictionaries (optional)
    :type relationships_as_object: list of relationship dictionaries
    :param relationships_as_subject: see ``package_relationship_create()`` for
        the format of relationship dictionaries (optional)
    :type relationships_as_subject: list of relationship dictionaries
    :param groups: the groups to which the dataset belongs (optional), each
        group dictionary should have one or more of the following keys which
        identify an existing group:
        ``'id'`` (the id of the group, string), ``'name'`` (the name of the
        group, string), ``'title'`` (the title of the group, string), to see
        which groups exist call ``group_list()``
    :type groups: list of dictionaries
    :param owner_org: the id of the dataset's owning organization, see
        ``organization_list()`` or ``organization_list_for_user`` for
        available values (optional)
    :type owner_org: string

    :returns: the newly created dataset (unless 'return_id_only' is set to True
              in the context, in which case just the dataset id will be returned)
    :rtype: dictionary

    '''
    model = context['model']
    user = context['user']
    log.info('context: %s', context)
    package_type = data_dict.get('type')
    package_plugin = lib_plugins.lookup_package_plugin(package_type)
    if 'schema' in context:
        schema = context['schema']
    else:
        schema = package_plugin.create_package_schema()

    _check_access('package_create', context, data_dict)

    if 'api_version' not in context:
        # check_data_dict() is deprecated. If the package_plugin has a
        # check_data_dict() we'll call it, if it doesn't have the method we'll
        # do nothing.
        check_data_dict = getattr(package_plugin, 'check_data_dict', None)
        if check_data_dict:
            try:
                check_data_dict(data_dict, schema)
            except TypeError:
                # Old plugins do not support passing the schema so we need
                # to ensure they still work
                package_plugin.check_data_dict(data_dict)

    data, errors = _validate(data_dict, schema, context)
    log.debug('package_create validate_errs=%r user=%s package=%s data=%r',
              errors, context.get('user'),
              data.get('name'), data_dict)

    if errors:
        model.Session.rollback()
        raise ValidationError(errors)

    rev = model.repo.new_revision()
    rev.author = user
    if 'message' in context:
        rev.message = context['message']
    else:
        rev.message = _(u'REST API: Create object %s') % data.get("name")

    admins = []
    if user:
        user_obj = model.User.by_name(user.decode('utf8'))
        if user_obj:
            admins = [user_obj]
            data['creator_user_id'] = user_obj.id

    pkg = model_save.package_dict_save(data, context)

    model.setup_default_user_roles(pkg, admins)
    # Needed to let extensions know the package id
    model.Session.flush()
    data['id'] = pkg.id

    context_org_update = context.copy()
    context_org_update['ignore_auth'] = True
    context_org_update['defer_commit'] = True
    _get_action('package_owner_org_update')(context_org_update,
                                            {'id': pkg.id,
                                             'organization_id': pkg.owner_org})

    for item in plugins.PluginImplementations(plugins.IPackageController):
        item.create(pkg)

        item.after_create(context, data)

    if not context.get('defer_commit'):
        model.repo.commit()

    ## need to let rest api create
    context["package"] = pkg
    ## this is added so that the rest controller can make a new location
    context["id"] = pkg.id
    log.debug('Created object %s' % pkg.name)

    # Make sure that a user provided schema is not used on package_show
    context.pop('schema', None)

    return_id_only = context.get('return_id_only', False)

    output = context['id'] if return_id_only \
            else _get_action('package_show')(context, {'id':context['id']})
    
    audit_helper(data_dict, output, 'package_create')
    
    return output

def package_update(context, data_dict):
    '''Update a dataset (package).

    You must be authorized to edit the dataset and the groups that it belongs
    to.

    Plugins may change the parameters of this function depending on the value
    of the dataset's ``type`` attribute, see the ``IDatasetForm`` plugin
    interface.

    For further parameters see ``package_create()``.

    :param id: the name or id of the dataset to update
    :type id: string

    :returns: the updated dataset (if 'return_package_dict' is True in the
              context, which is the default. Otherwise returns just the
              dataset id)
    :rtype: dictionary

    '''
    log.info('context: %s', context)
    model = context['model']
    user = context['user']
    name_or_id = data_dict.get("id") or data_dict['name']
    log.info('package update: %s', data_dict)
    pkg = model.Package.get(name_or_id)
    if pkg is None:
        raise NotFound(_('Package was not found.'))
    context["package"] = pkg
    data_dict["id"] = pkg.id
    pkg_dict = _get_action("package_show")(context, {'id' : pkg.id})
    pkg_dict.update(data_dict)
    _check_access('package_update', context, data_dict)

    # get the schema
    package_plugin = lib_plugins.lookup_package_plugin(pkg.type)
    if 'schema' in context:
        schema = context['schema']
    else:
        schema = package_plugin.update_package_schema()

    if 'api_version' not in context:
        # check_data_dict() is deprecated. If the package_plugin has a
        # check_data_dict() we'll call it, if it doesn't have the method we'll
        # do nothing.
        check_data_dict = getattr(package_plugin, 'check_data_dict', None)
        if check_data_dict:
            try:
                package_plugin.check_data_dict(data_dict, schema)
            except TypeError:
                # Old plugins do not support passing the schema so we need
                # to ensure they still work.
                package_plugin.check_data_dict(data_dict)
    
    data, errors = _validate(pkg_dict, schema, context)
    log.debug('package_update validate_errs=%r user=%s package=%s data=%r',
              errors, context.get('user'),
              context.get('package').name if context.get('package') else '',
              data)

    if errors:
        model.Session.rollback()
        raise ValidationError(errors)

    rev = model.repo.new_revision()
    rev.author = user
    if 'message' in context:
        rev.message = context['message']
    else:
        rev.message = _(u'REST API: Update object %s') % data.get("name")

    #avoid revisioning by updating directly
    model.Session.query(model.Package).filter_by(id=pkg.id).update(
        {"metadata_modified": datetime.datetime.utcnow()})
    model.Session.refresh(pkg)

    pkg = model_save.package_dict_save(data, context)

    context_org_update = context.copy()
    context_org_update['ignore_auth'] = True
    context_org_update['defer_commit'] = True
    _get_action('package_owner_org_update')(context_org_update,
                                            {'id': pkg.id,
                                             'organization_id': pkg.owner_org})

    for item in plugins.PluginImplementations(plugins.IPackageController):
        item.edit(pkg)

        item.after_update(context, data)

    if not context.get('defer_commit'):
        model.repo.commit()

    log.debug('Updated object %s' % pkg.name)

    return_id_only = context.get('return_id_only', False)

    # Make sure that a user provided schema is not used on package_show
    context.pop('schema', None)

    # we could update the dataset so we should still be able to read it.
    context['ignore_auth'] = True
    output = data_dict['id'] if return_id_only \
            else _get_action('package_show')(context, {'id': data_dict['id']})
    #action will be audited in resource_create or resource_update action
    if not context.get('defer_audit', None):
        audit_helper(data_dict, output, 'package_update')
    
    _get_action('package_unlock')(context, {'id': pkg.id})
    
    return output

def resource_create(context, data_dict):
    '''Appends a new resource to a datasets list of resources.

    :param package_id: id of package that the resource needs should be added to.
    :type package_id: string
    :param url: url of resource
    :type url: string
    :param revision_id: (optional)
    :type revisiion_id: string
    :param description: (optional)
    :type description: string
    :param format: (optional)
    :type format: string
    :param hash: (optional)
    :type hash: string
    :param name: (optional)
    :type name: string
    :param resource_type: (optional)
    :type resource_type: string
    :param mimetype: (optional)
    :type mimetype: string
    :param mimetype_inner: (optional)
    :type mimetype_inner: string
    :param webstore_url: (optional)
    :type webstore_url: string
    :param cache_url: (optional)
    :type cache_url: string
    :param size: (optional)
    :type size: int
    :param created: (optional)
    :type created: iso date string
    :param last_modified: (optional)
    :type last_modified: iso date string
    :param cache_last_updated: (optional)
    :type cache_last_updated: iso date string
    :param webstore_last_updated: (optional)
    :type webstore_last_updated: iso date string
    :param upload: (optional)
    :type upload: FieldStorage (optional) needs multipart/form-data

    :returns: the newly created resource
    :rtype: dictionary

    '''
    model = context['model']
    user = context['user']
    log.info('context: %s', context)
    package_id = _get_or_bust(data_dict, 'package_id')
    data_dict.pop('package_id')

    pkg_dict = _get_action('package_show')(context, {'id': package_id})

    _check_access('resource_create', context, data_dict)

    if not 'resources' in pkg_dict:
        pkg_dict['resources'] = []

    upload = uploader.ResourceUpload(data_dict)

    pkg_dict['resources'].append(data_dict)

    try:
        context['defer_commit'] = True
        context['use_cache'] = False
        context['defer_audit'] = True
        if data_dict.get('actor_id', None):
            pkg_dict['actor_id'] = data_dict['actor_id']
        _get_action('package_update')(context, pkg_dict)
        context.pop('defer_commit')
    except ValidationError, e:
        errors = e.error_dict['resources'][-1]
        raise ValidationError(errors)

    ## Get out resource_id resource from model as it will not appear in
    ## package_show until after commit
    upload.upload(context['package'].resources[-1].id,
                  uploader.get_max_resource_size())
    model.repo.commit()

    ##  Run package show again to get out actual last_resource
    pkg_dict = _get_action('package_show')(context, {'id': package_id})
    resource = pkg_dict['resources'][-1]
    audit_helper(data_dict, resource, 'resource_create')
    return resource

def resource_update(context, data_dict):
    '''Update a resource.

    To update a resource you must be authorized to update the dataset that the
    resource belongs to.

    For further parameters see ``resource_create()``.

    :param id: the id of the resource to update
    :type id: string

    :returns: the updated resource
    :rtype: string

    '''
    model = context['model']
    user = context['user']
    id = _get_or_bust(data_dict, "id")
    log.info('context: %s', context)
    resource = model.Resource.get(id)
    context["resource"] = resource
    log.info('resource update: %s', data_dict)
    if not resource:
        logging.error('Could not find resource ' + id)
        raise NotFound(_('Resource was not found.'))

    _check_access('resource_update', context, data_dict)
    del context["resource"]

    package_id = resource.resource_group.package.id
    pkg_dict = _get_action('package_show')(context, {'id': package_id})

    for n, p in enumerate(pkg_dict['resources']):
        if p['id'] == id:
            break
    else:
        logging.error('Could not find resource ' + id)
        raise NotFound(_('Resource was not found.'))
    if not data_dict.get('last_modified', ''):
        data_dict['last_modified'] = datetime.datetime.now()
    upload = uploader.ResourceUpload(data_dict)
    resource_dict = _get_action('resource_show')(context, {'id': id})
    resource_dict.update(data_dict)
    
    pkg_dict['resources'][n] = resource_dict

    try:
        context['defer_commit'] = True
        context['use_cache'] = False
        context['defer_audit'] = True
        if data_dict.get('actor_id', None):
            pkg_dict['actor_id'] = data_dict['actor_id']
        pkg_dict = _get_action('package_update')(context, pkg_dict)
        context.pop('defer_commit')
    except ValidationError, e:
        errors = e.error_dict['resources'][n]
        raise ValidationError(errors)

    upload.upload(id, uploader.get_max_resource_size())
    model.repo.commit()
    res = _get_action('resource_show')(context, {'id': id})
    audit_helper(data_dict, res, 'resource_update')
    return res

@logic.validate(logic.schema.default_activity_list_schema)
def user_activity_list(context, data_dict):
    '''Return a user's public activity stream.

    You must be authorized to view the user's profile.


    :param id: the id or name of the user
    :type id: string
    :param offset: where to start getting activity items from
        (optional, default: 0)
    :type offset: int
    :param limit: the maximum number of activities to return
        (optional, default: 31, the default value is configurable via the
        ckan.activity_list_limit setting)
    :type limit: int

    :rtype: list of dictionaries

    '''
    # FIXME: Filter out activities whose subject or object the user is not
    # authorized to read.
    _check_access('user_show', context, data_dict)

    model = context['model']

    user_ref = data_dict.get('id')  # May be user name or id.
    user = model.User.get(user_ref)
    if user is None:
        raise logic.NotFound

    offset = data_dict.get('offset', 0)
    limit = int(
        data_dict.get('limit', config.get('ckan.activity_list_limit', 31)))
    
    activity_objects = model.activity.user_activity_list(user.id, limit=limit,
            offset=offset)
    res = model_dictize.activity_list_dictize(activity_objects, context)
    for activity in res:
        revision_id = activity.get('revision_id', None)
        if revision_id:
            executor_id = _get_action('revision_executor')(data_dict={'id' : revision_id})
            if executor_id:
                executor_obj = model.User.get(executor_id)
                activity['actor_id'] = executor_id
                activity['actor_fullname'] = executor_obj.fullname
            else:
                activity['actor_id'] = 'XXX-YYY-ZZZ'
                activity['actor_fullname'] = 'TESTER NAME'
    log.info('user activity list: %s', res)
    return res 

@logic.side_effect_free
def probe(context, data_dict):
    ''''''
    sql = '''
         SELECT 1;
    '''
    conn = model.Session.connection()
    try:
        result = conn.execute(sql)
    except sa.exc.OperationalError:
        return 'ERROR'
    return 'FUNGUJE'
