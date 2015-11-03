import datetime
import uuid
import logging

import ckan.model as model
from ckan.model import domain_object
from ckan.model.meta import metadata, Session, mapper
from sqlalchemy import types, Column, Table, ForeignKey, func, CheckConstraint
from pylons import session

log = logging.getLogger(__name__)

def make_uuid():
    return unicode(uuid.uuid4())

class DatasetLock(domain_object.DomainObject):
    def __init__(self, dataset_id, lock_owner_subject_id, lock_owner_actor_id = None):
        assert dataset_id
        assert lock_owner_subject_id
        self.dataset_id = dataset_id
        self.lock_owner_subject_id = lock_owner_subject_id
        if lock_owner_actor_id:
            self.lock_owner_actor_id = lock_owner_actor_id
        else:
            self.lock_owner_actor_id = lock_owner_subject_id

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
    def old_locks(cls, since):
        query = Session.query(cls).filter(cls.timestamp < since)
        return query.all()
        

lock_table = Table('ckanext_edem_lock', metadata,
        Column('id', types.UnicodeText, primary_key=True, default=make_uuid),
        Column('dataset_id', types.UnicodeText, default=u'', nullable=False),
        Column('lock_owner_subject_id', types.UnicodeText, default=u'', nullable=False),
        Column('lock_owner_actor_id', types.UnicodeText, default=u'', nullable=False),
        Column('timestamp', types.DateTime, default=datetime.datetime.utcnow, nullable=False)
    )

mapper(DatasetLock, lock_table)

def create_lock_table():
    if not lock_table.exists():
        lock_table.create()

def delete_inactive_locks():
    since = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
    results = DatasetLock.old_locks(since)
    for entity in results:
        entity.delete()
        entity.commit()
    
def is_locked(dataset_id):
    create_lock_table()
    delete_inactive_locks()
    search = {'dataset_id' : dataset_id}
    result = DatasetLock.get(**search)
    res = []
    for entry in result:
        subject = model.User.get(entry.lock_owner_subject_id)
        if subject:
            pair_user = subject.fullname
            if entry.lock_owner_subject_id != entry.lock_owner_actor_id:
                actor = model.User.get(entry.lock_owner_actor_id)
                if actor:            
                    pair_user += ' (' + actor.fullname + ')'
            pair_user += ' - ' + entry.timestamp.strftime('%Y-%m-%d %H:%M:%S')
            res.append(pair_user)
    return list(set(res))

def lock_dataset(dataset_id, lock_owner_subject_id, lock_owner_actor_id=None):
    create_lock_table()
    if not lock_owner_actor_id:
        lock_owner_actor_id = session.get('ckanext-cas-actorid', None)
    new_lock = DatasetLock(dataset_id, lock_owner_subject_id, lock_owner_actor_id)
    new_lock.save()
        
def unlock_dataset(dataset_id, subject_id, actor_id = None):
    create_lock_table()
    if not actor_id and 'save' in dir(session):
        actor_id = session.get('ckanext-cas-actorid', subject_id)
    search = {'dataset_id' : dataset_id, 'lock_owner_subject_id' : subject_id, 'lock_owner_actor_id' : actor_id}
    res = DatasetLock.get(**search)
    log.info('search params: %s', search)
    log.info('results: %s', res)
    for entity in res:
        entity.delete()
        entity.commit()
    log.info('locks deleted')
    log.info('unlocked')
        
def authorized_dataset_update(dataset_id, actor_id):
    log.info('package id: %s', dataset_id)
    log.info('actor accesing package: %s', actor_id)
    if not is_locked(dataset_id):
        return True
    search = {'dataset_id' : dataset_id}
    result = DatasetLock.get(**search)
    if result:
        if result[0].lock_owner_subject_id==actor_id:
            return True
    return False