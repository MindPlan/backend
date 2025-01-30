from django.urls import path, include
from rest_framework import routers

from mindplan_manager.views import TaskViewSet, GroupViewSet

app_name = "mindplan"

router = routers.DefaultRouter()

router.register("tasks", TaskViewSet, basename="tasks")
router.register("groups", GroupViewSet, basename="groups")

urlpatterns = [
    path("", include(router.urls)),

]