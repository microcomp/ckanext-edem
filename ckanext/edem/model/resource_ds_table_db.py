import datetime
import logging

from ckan.model import domain_object
from ckan.model.meta import metadata, Session, mapper
from sqlalchemy import types, Column, Table

log = logging.getLogger(__name__)

class ResourceTableState(domain_object.DomainObject):
    def __init__(self, resource_id, last_modified, to_file_success = False):
        assert resource_id
        assert last_modified
        self.resource_id = resource_id
        self.last_modified = last_modified
        self.to_file_success = to_file_success

    @classmethod
    def get(cls, **kw):
        '''Finds a single entity in the register.'''
        query = Session.query(cls).autoflush(False)
        return query.filter_by(**kw).all()
    
    @classmethod
    def lately_modificated_resources(cls, since):
        query = Session.query(cls).filter(cls.last_modified > since).filter(cls.to_file_success.op('IS')(False))
        return query.all()

resource_table = Table('ckanext_edem_resource_table', metadata,
        Column('resource_id', types.UnicodeText, primary_key=True, nullable=False),
        Column('last_modified', types.DateTime, default=datetime.datetime.utcnow, nullable=False),
        Column('to_file_success', types.Boolean, default=False, nullable=False)
)

mapper(ResourceTableState, resource_table)

def db_operation_decorator(fun):

    def create_resource_table():
        if not resource_table.exists():
            resource_table.create()

    def func_wrapper(*args, **kwargs):
        create_resource_table()
        return fun(*args, **kwargs)
    
    return func_wrapper

@db_operation_decorator
def get_resource_table(resource_id):
    search = {'resource_id' : resource_id}
    result = ResourceTableState.get(**search)
    if result:
        return (result[0].resource_id, result[0].last_modified, result[0].to_file_success)
    return None

@db_operation_decorator    
def get_lately_modified_resources(threshold=1):
    since = datetime.datetime.utcnow() - datetime.timedelta(hours=threshold)
    results = ResourceTableState.lately_modificated_resources(since)
    resources = [item.resource_id for item in results]
    return resources
    
def set_resource_table_update(resource_id):
    now = datetime.datetime.utcnow()
    return _modify_resource_table(resource_id, False, now)

def set_resource_tables_success(resource_id):
    search = {'resource_id' : resource_id, 'to_file_success' : False}
    result = ResourceTableState.get(**search)
    if result:
        result[0].to_file_success = True
        result[0].save()
        return True
    return False
    #return _modify_resource_table(resource_id, True)

@db_operation_decorator
def _modify_resource_table(resource_id, to_file_success=False, last_modified=None):
    search = {'resource_id' : resource_id}
    result = ResourceTableState.get(**search)
    if result:
        if last_modified:
            result[0].last_modified = last_modified
        result[0].to_file_success = to_file_success
        result[0].save()
    else:
        new_entry = ResourceTableState(resource_id, last_modified, to_file_success)
        new_entry.save()
    return True
