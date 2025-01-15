from django.urls import path, include
from rest_framework import routers

from mindplan_manager.views import TaskViewSet

app_name = "mindplan"

router = routers.DefaultRouter()

router.register("tasks", TaskViewSet, basename="tasks")

urlpatterns = [
    path("", include(router.urls)),
    # path(
    #     "tasks/<int:pk>/", TaskDetailView.as_view(), name="tasks-detail"
    # ),
]