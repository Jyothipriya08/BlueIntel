# core/db_routers.py

class MalwareIntelRouter:
    """
    Routing controls separating relational operational metrics (SQLite) from 
    unstructured sandbox document matrices (MongoDB) inside the BlueIntel framework.
    """
    route_app_labels = {'analyzer'}  # Maps to your "analyzer" local app

    def db_for_read(self, model, **hints):
        if model._meta.app_label in self.route_app_labels:
            return 'malware_sandbox_pool'
        return 'default'

    def db_for_write(self, model, **hints):
        if model._meta.app_label in self.route_app_labels:
            return 'malware_sandbox_pool'
        return 'default'

    def allow_relation(self, obj1, obj2, **hints):
        if (
            obj1._meta.app_label in self.route_app_labels or
            obj2._meta.app_label in self.route_app_labels
        ):
            return True
        return None

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        if app_label in self.route_app_labels:
            return db == 'malware_sandbox_pool'
        return db == 'default'