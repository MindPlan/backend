from django.db import models
from rest_framework.exceptions import ValidationError

from MindPlan.settings import AUTH_USER_MODEL


class TaskGroup(models.Model):
    name = models.CharField(max_length=100)
    owner = models.ForeignKey(
        AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="group",
    )
    default_status = models.BooleanField(default=False)

    class Meta:
        unique_together = ("owner", "name")

    def __str__(self):
        return f"{self.name}"


class Task(models.Model):

    class Priority(models.TextChoices):
        LOW = "LOW", "Low"
        MEDIUM = "MEDIUM", "Medium"
        HIGH = "HIGH", "High"

    title = models.CharField(max_length=100, blank=False, null=False)
    description = models.TextField(max_length=255, blank=True, null=True)
    priority = models.CharField(
        max_length=10, choices=Priority.choices, default=Priority.LOW
    )
    group = models.ForeignKey(
        TaskGroup,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="tasks",
    )
    start_date = models.DateTimeField()
    end_date = models.DateTimeField()
    tag = models.ManyToManyField("Tag", related_name="tasks", blank=True,)
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

    @staticmethod
    def validate_group(owner, group, error_to_raise):
        """
        Check if a group is owned by an owner.
        """
        if not isinstance(group, TaskGroup):
            try:
                group = TaskGroup.objects.get(id=group)
            except TaskGroup.DoesNotExist:
                raise error_to_raise({"group": f"Group with ID {group} does not exist."})

        if group.owner != owner:
            raise error_to_raise(
                {"group": f"The user cannot add this or these groups."}
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

        if not self.pk and not self.group:
            default_status = TaskGroup.objects.filter(owner=self.owner, name="To Do").first()
            self.status = default_status if default_status else None

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


class Tag(models.Model):
    name = models.CharField(max_length=100)

    def __str__(self):
        return f"id:({self.id}) {self.name}"
