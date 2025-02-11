from django.apps import AppConfig


class MindplanManagerConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "mindplan_manager"

    def ready(self):
        import mindplan_manager.signals
