import datetime
import uuid
import logging

from ckan.model import domain_object
from ckan.model.meta import metadata, Session, mapper
from sqlalchemy import types, Column, Table, ForeignKey, func, CheckConstraint

log = logging.getLogger(__name__)

def make_uuid():
    return unicode(uuid.uuid4())

class DatasetLock(domain_object.DomainObject):
    def __init__(self, dataset_id, lock_owner_id):
        assert dataset_id
        assert lock_owner_id
        self.dataset_id = dataset_id
        self.lock_owner_id = lock_owner_id
        
    @classmethod
    def get(cls, **kw):
        '''Finds a single entity in the register.'''
        query = Session.query(cls).autoflush(False)
        return query.filter_by(**kw).all()

    @classmethod
    def dataset_lock(cls, **kw):
        '''Finds a single entity in the register.'''
        order = kw.pop('order', False)
        query = Session.query(cls).autoflush(False)
        query = query.filter_by(**kw)
        if order:
            query = query.order_by(cls.order).filter(cls.order != '')
        return query.all()
    
    @classmethod
    def delete(cls, **kw):
        query = Session.query(cls).autoflush(False).filter_by(**kw).all()
        for i in query:
            Session.delete(i)
        return

lock_table = Table('ckanext_edem_lock', metadata,
        Column('id', types.UnicodeText, primary_key=True, default=make_uuid),
        Column('dataset_id', types.UnicodeText, default=u'', nullable=False),
        Column('lock_owner_id', types.UnicodeText, default=u'', nullable=False),
        Column('timestamp', types.DateTime, default=datetime.datetime.utcnow(), nullable=False)
    )

mapper(DatasetLock, lock_table)

def create_lock_table():
    if not lock_table.exists():
        lock_table.create()

def is_locked(dataset_id):
    create_lock_table()
    search = {'dataset_id' : dataset_id}
    result = DatasetLock.get(**search)
    if result:
        return True
    return False

def lock_dataset(dataset_id, lock_owner_id):
    if not is_locked(dataset_id):
        new_lock = DatasetLock(dataset_id, lock_owner_id)
        new_lock.save()
        
def unlock_dataset(dataset_id):
    if is_locked(dataset_id):
        log.info('is locked and will be unlocked')
        lock_table.delete(DatasetLock.dataset_id==dataset_id).execute()
        log.info('lock deleted')
    log.info('unlocked')
        
def authorized_dataset_update(dataset_id, actor_id):
    log.info('package id: %s', dataset_id)
    log.info('actor accesing package: %s', actor_id)
    if not is_locked(dataset_id):
        log.info
        return True
    search = {'dataset_id' : dataset_id}
    result = DatasetLock.get(**search)
    if result:
        if result[0].lock_owner_id==actor_id:
            return True
    return False