from enum import Enum


class AuthorizationScope(str, Enum):
    CREATE = "prs:create"
    DELETE = "prs:delete"
    READ = "prs:read"
    UPDATE = "prs:update"
