from django.conf import settings
from django.db import models
from django.http import HttpRequest
from rest_framework.exceptions import ValidationError

from MindPlan.settings import AUTH_USER_MODEL


class Task(models.Model):
    class Priority(models.TextChoices):
        LOW = "LOW", "Low"
        MEDIUM = "MEDIUM", "Medium"
        HIGH = "HIGH", "High"

    class Status(models.TextChoices):
        TO_DO = "TD", "To do"
        IN_PROGRESS = "IP", "In progress"
        DONE = "D", "Done"

    title = models.CharField(max_length=100, blank=False, null=False)
    description = models.TextField(max_length=255, blank=True, null=True)
    priority = models.CharField(
        max_length=10, choices=Priority.choices, default=Priority.LOW
    )
    status = models.CharField(
        max_length=15, choices=Status.choices, default=Status.TO_DO
    )
    start_date = models.DateTimeField()
    end_date = models.DateTimeField()
    member = models.ForeignKey(
        AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name="tasks",
        null=True,
        blank=True

    )
    owner = models.ForeignKey(
        AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        null=False,
        editable=False
    )

    def clean(self):
        super().clean()

        if not self.title.strip():
            raise ValidationError({"title": "Title cannot be empty or whitespace."})

        if self.end_date <= self.start_date:
            raise ValidationError({
                "end_date": "End date cannot be earlier than start date."
            })

    def save(self, *args, **kwargs):
        if not self.pk and not self.owner:
            self.owner = kwargs.pop("owner", None)
        self.clean()
        super().save(*args, **kwargs)

    @property
    def due_date(self):
        if self.status and self.start_date:
            return self.end_date - self.start_date
        else:
            raise ValidationError({
                "start_date or end_date": "Date cannot be empty or whitespace."
            })

class Comment(models.Model):
    task = models.ForeignKey(
        Task,
        on_delete=models.CASCADE,
        related_name="comments"
    )
    text = models.TextField(max_length=500, blank=False, null=False)
    member = models.ForeignKey(
        AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name="comments",
        null=True
    )
    created_at = models.DateTimeField(auto_now_add=True)


class Group(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField(max_length=500, blank=True, null=True)
    tasks = models.ManyToManyField(Task, related_name="groups")