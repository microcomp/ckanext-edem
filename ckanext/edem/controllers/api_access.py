import logging

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import ckan.logic as logic
import ckan.lib.base as base
import ckan.lib.helpers as h
from ckan.common import _, c

from ckanext.edem.model.api_access_db import abort_user_api, allow_user_api

log = logging.getLogger(__name__)

class ApiAccessController(base.BaseController):
    def allow(self):
        allow_user_api(c.userobj.id)
        return h.redirect_to(controller='user', action='read', id=c.userobj.id)
        
    def abort(self):
        abort_user_api(c.userobj.id)
        return h.redirect_to(controller='user', action='read', id=c.userobj.id)

