import datetime
import logging

from ckan.model import domain_object
from ckan.model.meta import metadata, Session, mapper
from sqlalchemy import types, Column, Table, ForeignKey, func, CheckConstraint, UniqueConstraint
import sqlalchemy.exc

log = logging.getLogger(__name__)

class AbortApiUser(domain_object.DomainObject):
    def __init__(self, user_id, abort = True):
        assert user_id
        self.user_id = user_id
        self.abort = abort

    @classmethod
    def get(cls, **kw):
        '''Finds a single entity in the register.'''
        query = Session.query(cls).autoflush(False)
        return query.filter_by(**kw).all()

abort_api_table = Table('ckanext_edem_abort_api', metadata,
        Column('user_id', types.UnicodeText, primary_key=True, nullable=False),
        Column('abort', types.Boolean, default=True, nullable=False)
)

mapper(AbortApiUser, abort_api_table)

def create_abort_api_table():
    if not abort_api_table.exists():
        abort_api_table.create()

def user_make_api_call(user_id):
    create_abort_api_table()
    search = {'user_id' : user_id,
              'abort' : True}
    result = AbortApiUser.get(**search)
    if result:
        return False
    return True

def abort_user_api(user_id):
    _modify_user_api(user_id, True)
    
def allow_user_api(user_id):
    _modify_user_api(user_id, False)

def _modify_user_api(user_id, abort):
    create_abort_api_table()
    search = {'user_id' : user_id}
    result = AbortApiUser.get(**search)
    if result:
        result[0].abort = abort
        result[0].save()
    else:
        new_entry = AbortApiUser(user_id, abort)
        new_entry.save()