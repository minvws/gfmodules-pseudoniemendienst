from typing import Callable, Type, Dict, TypeVar

from app.db.entities.base import Base
from app.db.repositories.repository_base import RepositoryBase

T = TypeVar("T", bound=Type[RepositoryBase])

repository_registry: Dict[Type[Base], Type[RepositoryBase]] = {}


def repository(model_class: Type[Base]) -> Callable[..., T]:
    def decorator(repo_class: T) -> T:
        """
        Decorator to register a repository for a model class

        :param repo_class:
        :return:
        """
        repository_registry[model_class] = repo_class
        return repo_class

    return decorator
