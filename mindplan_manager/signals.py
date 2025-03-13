from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import TaskGroup, AUTH_USER_MODEL


@receiver(post_save, sender=AUTH_USER_MODEL)
def create_default_task_statuses(sender, instance, created, **kwargs):
    if created:
        TaskGroup.objects.bulk_create([
            TaskGroup(name="Tasks", owner=instance, default_status=True),
            TaskGroup(name="To Do", owner=instance, default_status=True),
            TaskGroup(name="In Progress", owner=instance, default_status=True),
            TaskGroup(name="Done", owner=instance, default_status=True),
        ])
