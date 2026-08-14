# dialects/postgresql/rls.py
# Copyright (C) 2005-2026 the SQLAlchemy authors and contributors
# <see AUTHORS file>
#
# This module is part of SQLAlchemy and is released under
# the MIT License: https://www.opensource.org/licenses/mit-license.php

from __future__ import annotations

from typing import Any
from typing import cast
from typing import Optional
from typing import Sequence
from typing import TYPE_CHECKING

from ... import exc
from ... import schema
from ...sql import coercions
from ...sql import roles as sql_roles

if TYPE_CHECKING:
    from ...sql.elements import ClauseElement


_COMMANDS = ("ALL", "SELECT", "INSERT", "UPDATE", "DELETE")


def _coerce_policy_expression(
    expression: ClauseElement | str | None,
) -> ClauseElement | None:
    if expression is None:
        return None
    return cast(
        "ClauseElement",
        coercions.expect(sql_roles.DDLExpressionRole, expression),
    )


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

    def __init__(
        self,
        name: str,
        table: schema.Table,
        *,
        command: str = "ALL",
        roles: str | Sequence[str] = "PUBLIC",
        using: ClauseElement | str | None = None,
        check: ClauseElement | str | None = None,
        permissive: bool = True,
        info: Optional[dict[Any, Any]] = None,
    ) -> None:
        command = command.upper()
        normalized_roles = (roles,) if isinstance(roles, str) else tuple(roles)
        self._validate(
            name=name,
            command=command,
            roles=normalized_roles,
            using=using,
            check=check,
        )

        self.name = name
        self.table = table
        self.command = command
        self.roles = normalized_roles
        self.using = _coerce_policy_expression(using)
        self.check = _coerce_policy_expression(check)
        self.permissive = permissive
        if info is not None:
            self.info = info

    @staticmethod
    def _validate(
        *,
        name: str,
        command: str,
        roles: Sequence[str],
        using: ClauseElement | str | None,
        check: ClauseElement | str | None,
    ) -> None:
        if not name:
            raise exc.ArgumentError("Policy name cannot be empty")
        if command not in _COMMANDS:
            raise exc.ArgumentError(
                "Policy command must be one of ALL, SELECT, INSERT, UPDATE, "
                f"or DELETE, got {command!r}"
            )
        if not roles:
            raise exc.ArgumentError("Policy roles cannot be empty")
        if command == "INSERT" and using is not None:
            raise exc.ArgumentError("INSERT policies cannot define USING")
        if command in ("SELECT", "DELETE") and check is not None:
            raise exc.ArgumentError(
                f"{command} policies cannot define WITH CHECK"
            )


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


class EnableRowLevelSecurity(schema._CreateDropBase[schema.Table]):
    """Represent enabling row level security for a table."""

    __visit_name__ = "enable_row_level_security"


class DisableRowLevelSecurity(schema._CreateDropBase[schema.Table]):
    """Represent disabling row level security for a table."""

    __visit_name__ = "disable_row_level_security"


class ForceRowLevelSecurity(schema._CreateDropBase[schema.Table]):
    """Represent forcing row level security for a table owner."""

    __visit_name__ = "force_row_level_security"


class NoForceRowLevelSecurity(schema._CreateDropBase[schema.Table]):
    """Represent restoring the table owner's row security bypass."""

    __visit_name__ = "no_force_row_level_security"
