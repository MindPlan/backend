from django.urls import path, include
from rest_framework import routers

from mindplan_manager.views import TaskViewSet, TagViewSet, TaskGroupViewSet

app_name = "mindplan"

router = routers.DefaultRouter()

router.register("tasks", TaskViewSet, basename="tasks")
router.register("tags", TagViewSet, basename="tags")
router.register("groups", TaskGroupViewSet, basename="groups")


urlpatterns = [
    path("", include(router.urls)),

]
