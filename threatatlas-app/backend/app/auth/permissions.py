"""Role-Based Access Control (RBAC) permissions."""

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.models import User, Product, ProductCollaborator
from app.models.enums import UserRole, CollaboratorRole


class PermissionDenied(HTTPException):
    """Exception raised when user lacks required permissions."""

    def __init__(self, detail: str = "Permission denied"):
        super().__init__(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


def require_admin(user: User) -> User:
    """
    Require the user to have admin role.

    Args:
        user: The current authenticated user

    Returns:
        The user if they have admin role

    Raises:
        PermissionDenied: If user does not have admin role
    """
    if user.role != UserRole.ADMIN.value:
        raise PermissionDenied("Admin role required for this action")
    return user


def require_standard_or_admin(user: User) -> User:
    """
    Require the user to have write access (standard or admin role).
    External pentesters and read-only users are blocked.

    Args:
        user: The current authenticated user

    Returns:
        The user if they have standard or admin role

    Raises:
        PermissionDenied: If user does not have standard or admin role
    """
    allowed = {UserRole.ADMIN.value, UserRole.STANDARD.value}
    if user.role not in allowed:
        raise PermissionDenied("Write access required for this action")
    return user


def is_external_pentester(user: User) -> bool:
    """Check if user has the external_pentester role."""
    return user.role == UserRole.EXTERNAL_PENTESTER.value


def require_not_external_pentester(user: User):
    """Block external pentesters from accessing non-pentest resources."""
    if is_external_pentester(user):
        raise PermissionDenied("External pentesters cannot access this resource")


def require_pentest_write_access(user: User):
    """Allow admin, standard, or external_pentester to write pentest data."""
    allowed = {UserRole.ADMIN.value, UserRole.STANDARD.value, UserRole.EXTERNAL_PENTESTER.value}
    if user.role not in allowed:
        raise PermissionDenied("Insufficient permissions")


def can_access_pentest(user: User, pentest, db: Session) -> bool:
    """
    Check if user can access a specific pentest.

    Admins can access all pentests.
    External pentesters can only access pentests they are assigned to.
    Standard/read-only users can access pentests belonging to their products.
    """
    from app.models.pentest_assignment import PentestAssignment

    if user.role == UserRole.ADMIN.value:
        return True
    if user.role == UserRole.EXTERNAL_PENTESTER.value:
        assignment = db.query(PentestAssignment).filter(
            PentestAssignment.pentest_id == pentest.id,
            PentestAssignment.user_id == user.id,
        ).first()
        return assignment is not None
    # Standard / read-only users: check product ownership
    return pentest.product.user_id == user.id


def require_pentest_access(user: User, pentest, db: Session):
    """Raise PermissionDenied if the user cannot access the given pentest."""
    if not can_access_pentest(user, pentest, db):
        raise PermissionDenied("You do not have access to this pentest")


def can_modify_resource(user: User, resource_owner_id: int) -> bool:
    """
    Check if user can modify a resource.

    Admin users can modify any resource.
    Standard users can only modify their own resources.
    Read-only and external_pentester users cannot modify generic resources.

    Args:
        user: The current authenticated user
        resource_owner_id: The ID of the user who owns the resource

    Returns:
        True if user can modify the resource, False otherwise
    """
    if user.role in (UserRole.READ_ONLY.value, UserRole.EXTERNAL_PENTESTER.value):
        return False
    if user.role == UserRole.ADMIN.value:
        return True
    return resource_owner_id == user.id


def require_resource_access(user: User, resource_owner_id: int) -> User:
    """
    Require the user to have permission to modify a resource.

    Args:
        user: The current authenticated user
        resource_owner_id: The ID of the user who owns the resource

    Returns:
        The user if they can modify the resource

    Raises:
        PermissionDenied: If user cannot modify the resource
    """
    if not can_modify_resource(user, resource_owner_id):
        raise PermissionDenied("Not authorized to modify this resource")
    return user


def can_access_product(user: User, product: Product) -> bool:
    """
    Check if user can access a product (view or edit).

    Args:
        user: Current user
        product: Product to check access for

    Returns:
        True if user can access, False otherwise
    """
    # External pentesters cannot access products directly
    if user.role == UserRole.EXTERNAL_PENTESTER.value:
        return False

    # Admins can access all products
    if user.role == UserRole.ADMIN.value:
        return True

    # Product owner can access
    if product.user_id == user.id:
        return True

    # Collaborators can access
    for collab in product.collaborators:
        if collab.user_id == user.id:
            return True

    return False


def can_edit_product(user: User, product: Product) -> bool:
    """
    Check if user can edit a product.

    Args:
        user: Current user
        product: Product to check edit access for

    Returns:
        True if user can edit, False otherwise
    """
    # Read-only and external pentester users cannot edit
    if user.role in (UserRole.READ_ONLY.value, UserRole.EXTERNAL_PENTESTER.value):
        return False

    # Admins can edit all products
    if user.role == UserRole.ADMIN.value:
        return True

    # Product owner can edit
    if product.user_id == user.id:
        return True

    # Collaborators with owner or editor role can edit
    for collab in product.collaborators:
        if collab.user_id == user.id and collab.role in [CollaboratorRole.OWNER.value, CollaboratorRole.EDITOR.value]:
            return True

    return False
