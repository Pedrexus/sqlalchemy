# dialects/postgresql/rls.py
# Copyright (C) 2005-2026 the SQLAlchemy authors and contributors
# <see AUTHORS file>
#
# This module is part of SQLAlchemy and is released under
# the MIT License: https://www.opensource.org/licenses/mit-license.php

from __future__ import annotations

from typing import Any
from typing import ClassVar
from typing import Sequence
from typing import TYPE_CHECKING

from ... import exc
from ... import schema
from ...sql import coercions
from ...sql import roles as sql_roles

if TYPE_CHECKING:
    from ...sql._typing import _TextCoercedExpressionArgument
    from ...sql.elements import ClauseElement


_COMMANDS = {"ALL", "SELECT", "INSERT", "UPDATE", "DELETE"}


class Policy(schema.SchemaItem):
    """Represent one PostgreSQL row security policy.

    :param name: policy name, local to ``table``.
    :param table: table protected by the policy.
    :param command: command governed by the policy. Accepted values are
     ``ALL``, ``SELECT``, ``INSERT``, ``UPDATE``, and ``DELETE``.
    :param roles: one database role or a sequence of roles to which the policy
     applies. The default is ``PUBLIC``.
    :param using: row visibility expression for existing rows.
    :param check: row acceptance expression for inserted or updated rows.
    :param permissive: whether the policy is permissive.
    :param info: optional user-defined data associated with this policy.

    Expressions may be SQLAlchemy expressions or SQL strings. String
    expressions are treated as trusted DDL text in the same way as expressions
    accepted by :class:`_schema.CheckConstraint`.

    .. versionadded:: 2.1
    """

    __visit_name__ = "policy"
    create_drop_stringify_dialect = "postgresql"

    name: str
    table: schema.Table
    command: str
    roles: tuple[str, ...]
    using: ClauseElement | None
    check: ClauseElement | None
    permissive: bool

    def __init__(
        self,
        name: str,
        table: schema.Table,
        *,
        command: str = "ALL",
        roles: str | Sequence[str] = "PUBLIC",
        using: _TextCoercedExpressionArgument[bool] | None = None,
        check: _TextCoercedExpressionArgument[bool] | None = None,
        permissive: bool = True,
        info: dict[Any, Any] | None = None,
    ) -> None:
        command = command.upper()
        normalized_roles = (roles,) if isinstance(roles, str) else tuple(roles)
        if not name:
            raise exc.ArgumentError("Policy name cannot be empty")
        if command not in _COMMANDS:
            raise exc.ArgumentError(
                "Policy command must be one of ALL, SELECT, INSERT, UPDATE, "
                f"or DELETE, got {command!r}"
            )
        if not normalized_roles:
            raise exc.ArgumentError("Policy roles cannot be empty")
        if command == "INSERT" and using is not None:
            raise exc.ArgumentError("INSERT policies cannot define USING")
        if command in ("SELECT", "DELETE") and check is not None:
            raise exc.ArgumentError(
                f"{command} policies cannot define WITH CHECK"
            )

        self.name = name
        self.table = table
        self.command = command
        self.roles = normalized_roles
        self.using = (
            coercions.expect(sql_roles.DDLExpressionRole, using)
            if using is not None
            else None
        )
        self.check = (
            coercions.expect(sql_roles.DDLExpressionRole, check)
            if check is not None
            else None
        )
        self.permissive = permissive
        if info is not None:
            self.info = info


class CreatePolicy(schema._CreateDropBase[Policy]):
    """Represent a PostgreSQL ``CREATE POLICY`` statement."""

    __visit_name__ = "create_policy"


class DropPolicy(schema._CreateDropBase[Policy]):
    """Represent a PostgreSQL ``DROP POLICY`` statement."""

    __visit_name__ = "drop_policy"

    def __init__(
        self,
        element: Policy,
        *,
        if_exists: bool = False,
    ) -> None:
        super().__init__(element)
        self.if_exists = if_exists


class _SetRowLevelSecurity(schema._CreateDropBase[schema.Table]):
    __visit_name__ = "set_row_level_security"
    action: ClassVar[str]


class EnableRowLevelSecurity(_SetRowLevelSecurity):
    """Represent enabling row level security for a table."""

    action = "ENABLE"


class DisableRowLevelSecurity(_SetRowLevelSecurity):
    """Represent disabling row level security for a table."""

    action = "DISABLE"


class ForceRowLevelSecurity(_SetRowLevelSecurity):
    """Represent forcing row level security for a table owner."""

    action = "FORCE"


class NoForceRowLevelSecurity(_SetRowLevelSecurity):
    """Represent restoring the table owner's row security bypass."""

    action = "NO FORCE"
