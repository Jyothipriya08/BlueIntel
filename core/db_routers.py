# core/db_routers.py

class MalwareIntelRouter:
    """
    Routing controls separating relational operational metrics (SQLite) from 
    unstructured sandbox document matrices (MongoDB) inside the BlueIntel framework.
    """
    sandbox_models = {'threatanalysislog', 'threatintelligencefeed'}

    def db_for_read(self, model, **hints):
        if model._meta.app_label == 'analyzer' and model._meta.model_name in self.sandbox_models:
            return 'malware_sandbox_pool'
        return 'default'

    def db_for_write(self, model, **hints):
        if model._meta.app_label == 'analyzer' and model._meta.model_name in self.sandbox_models:
            return 'malware_sandbox_pool'
        return 'default'

    def allow_relation(self, obj1, obj2, **hints):
        return True

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        if app_label == 'analyzer':
            if model_name in self.sandbox_models:
                return db == 'malware_sandbox_pool'
            else:
                return db == 'default'
        return db == 'default'