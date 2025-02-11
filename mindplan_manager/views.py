from rest_framework.permissions import IsAuthenticated
from rest_framework.viewsets import ModelViewSet

from mindplan_manager.models import (
    Tag,
    Task,
    TaskGroup
)
from mindplan_manager.serializers import (
    TaskSerializer,
    TagSerializer,
    TaskGroupSerializer
)


class TaskGroupViewSet(ModelViewSet):
    serializer_class = TaskGroupSerializer
    permission_classes = (IsAuthenticated,)

    def get_queryset(self):
        return TaskGroup.objects.filter(owner=self.request.user)

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)


class TaskViewSet(
    ModelViewSet,
):
    serializer_class = TaskSerializer
    queryset = Task.objects.all()
    permission_classes = (IsAuthenticated,)

    def get_queryset(self):
        return Task.objects.filter(owner=self.request.user)

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)


class TagViewSet(
    ModelViewSet,
):
    serializer_class = TagSerializer
    queryset = Tag.objects.all()
    permission_classes = (IsAuthenticated,)

    def get_queryset(self):
        return Tag.objects.filter(owner=self.request.user)

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)
