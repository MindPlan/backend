# from django.core.exceptions import ValidationError
# from django.db import models
# from MindPlan.settings import AUTH_USER_MODEL
#
#
# class Project(models.Model):
#
#     name = models.CharField(max_length=100, blank=False, null=False, unique=True)
#     description = models.TextField(max_length=500, blank=True, null=True)
#     owner = models.ForeignKey(
#         AUTH_USER_MODEL,
#         on_delete=models.CASCADE,
#         related_name="owned_projects",
#         verbose_name="owner",
#     )
#     members = models.ManyToManyField(
#         AUTH_USER_MODEL,
#         related_name="projects",
#         blank=True,
#         verbose_name="members",
#     )
#     created_at = models.DateTimeField(auto_now_add=True)
#
#     def __str__(self):
#         return self.name
#
#     # def clean(self):
#     #     super().clean()
#     #     if not self.name.strip():
#     #         raise ValidationError({"name": "Name cannot be empty or whitespace."})
#
#
# class TasksProject(models.Model):
#
#     class Priority(models.TextChoices):
#         LOW = "LOW", "Low"
#         MEDIUM = "MEDIUM", "Medium"
#         HIGH = "HIGH", "High"
#
#     class Status(models.TextChoices):
#         TO_DO = "TD", "To do"
#         IN_PROGRESS = "IP", "In progress"
#         DONE = "D", "Done"
#
#     title = models.CharField(max_length=100, blank=False, null=False)
#     description = models.TextField(max_length=255, blank=True, null=True)
#     priority = models.CharField(
#         max_length=10, choices=Priority.choices, default=Priority.LOW
#     )
#     status = models.CharField(
#         max_length=15, choices=Status.choices, default=Status.TO_DO
#     )
#     start_date = models.DateTimeField()
#     end_date = models.DateTimeField()
#     project = models.ForeignKey(
#         Project,
#         on_delete=models.CASCADE,
#         related_name="tasks",
#         verbose_name="project",
#     )
#     group = models.ManyToManyField("Group", related_name="tasks", blank=True)
#
#     owner = models.ForeignKey(
#         AUTH_USER_MODEL,
#         on_delete=models.CASCADE,
#         related_name="tasks",
#         null=False,
#         verbose_name="task owner",
#     )
#
#     assigned_to = models.ForeignKey(
#         AUTH_USER_MODEL,
#         related_name="assigned_tasks",
#         on_delete=models.SET_NULL,
#         null=True,
#         verbose_name="assigned to",
#     )
#
#     def clean(self):
#         super().clean()
#         if not self.title.strip():
#             raise ValidationError({"title": "Title cannot be empty or whitespace."})
#         if self.end_date <= self.start_date:
#             raise ValidationError({"end_date": "End date cannot be earlier than start date."})
#
#
# class ProjectMembership(models.Model):
#     class Role(models.TextChoices):
#         ADMIN = "ADMIN", "Admin"
#         MODERATOR = "MODERATOR", "Moderator"
#         MEMBER = "MEMBER", "Member"
#
#     user = models.ForeignKey(
#         AUTH_USER_MODEL,
#         on_delete=models.CASCADE,
#         related_name="project_memberships",
#     )
#     project = models.ForeignKey(
#         Project,
#         on_delete=models.CASCADE,
#         related_name="memberships",
#     )
#     role = models.CharField(
#         max_length=10, choices=Role.choices, default=Role.MEMBER
#     )
#     created_at = models.DateTimeField(auto_now_add=True)
#
#     class Meta:
#         constraints = [
#             models.UniqueConstraint(fields=["user", "project"], name="unique_project_membership")
#         ]
#
#     def is_admin(self):
#         return self.role == self.Role.ADMIN
#
#     def is_moderator(self):
#         return self.role == self.Role.MODERATOR