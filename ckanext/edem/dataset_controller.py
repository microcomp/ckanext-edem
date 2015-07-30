import logging
import ckan.lib.helpers as h
import ckan.model as model
from ckan.common import OrderedDict, _, json, request, c, g, response
import ckan.logic as logic
from pylons import config
import ckan.lib.base as base

get_action = logic.get_action
NotFound = logic.NotFound
NotAuthorized = logic.NotAuthorized
ValidationError = logic.ValidationError

render = base.render
abort = base.abort
redirect = base.redirect

log = logging.getLogger(__name__)

class DatasetLockController(base.BaseController):
    def unlock(self, id):
        context = {'model': model, 'session': model.Session,
                   'user': c.user or c.author, 'auth_user_obj': c.userobj}
        try:
            get_action('package_unlock')(context, {'id': id})
        except NotAuthorized:
            abort(401, _('Unauthorized to unlock package %s') % '')
        except NotFound:
            abort(404, _('Dataset not found'))
        
        data = request.GET
        resource_id = data.get('resource_id', None)
        if resource_id:
            url = h.url_for(controller='package', action='resource_read', id=id, resource_id = resource_id)
        else:
            url = h.url_for(controller='package', action='read', id=id)
        redirect(url)