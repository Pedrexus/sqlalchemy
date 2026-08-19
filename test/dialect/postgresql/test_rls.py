from sqlalchemy import Column
from sqlalchemy import event
from sqlalchemy import exc
from sqlalchemy import inspect
from sqlalchemy import Integer
from sqlalchemy import MetaData
from sqlalchemy import String
from sqlalchemy import Table
from sqlalchemy import testing
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects.postgresql import CreatePolicy
from sqlalchemy.dialects.postgresql import DisableRowLevelSecurity
from sqlalchemy.dialects.postgresql import DropPolicy
from sqlalchemy.dialects.postgresql import EnableRowLevelSecurity
from sqlalchemy.dialects.postgresql import ForceRowLevelSecurity
from sqlalchemy.dialects.postgresql import NoForceRowLevelSecurity
from sqlalchemy.dialects.postgresql import Policy
from sqlalchemy.testing import fixtures
from sqlalchemy.testing.assertions import AssertsCompiledSQL
from sqlalchemy.testing.assertions import eq_
from sqlalchemy.testing.assertions import expect_raises_message


class PolicyCompileTest(fixtures.TestBase, AssertsCompiledSQL):
    __dialect__ = postgresql.dialect()

    @classmethod
    def policy_table(cls):
        return Table(
            "Document",
            MetaData(),
            Column("id", Integer),
            Column("owner_id", Integer),
            Column("status", String),
            schema="Secure",
        )

    @testing.combinations(
        (
            "quoted_select",
            lambda table: CreatePolicy(
                Policy(
                    "read policy",
                    table,
                    command="select",
                    roles=("reader", "Current Reader"),
                    using=table.c.owner_id == 7,
                )
            ),
            'CREATE POLICY "read policy" ON "Secure"."Document" '
            'FOR SELECT TO reader, "Current Reader" USING (owner_id = 7)',
        ),
        (
            "restrictive_update",
            lambda table: CreatePolicy(
                Policy(
                    "write",
                    table,
                    command="UPDATE",
                    roles=("PUBLIC", "CURRENT_USER"),
                    using=table.c.owner_id == 7,
                    check=table.c.status == "ready",
                    permissive=False,
                )
            ),
            'CREATE POLICY write ON "Secure"."Document" '
            "AS RESTRICTIVE FOR UPDATE TO PUBLIC, CURRENT_USER "
            "USING (owner_id = 7) WITH CHECK (status = 'ready')",
        ),
        (
            "drop",
            lambda table: DropPolicy(Policy("old", table), if_exists=True),
            'DROP POLICY IF EXISTS "old" ON "Secure"."Document"',
        ),
        (
            "single_role",
            lambda table: CreatePolicy(
                Policy("read", table, command="SELECT", roles="reader")
            ),
            'CREATE POLICY read ON "Secure"."Document" '
            "FOR SELECT TO reader",
        ),
        (
            "enable",
            lambda table: EnableRowLevelSecurity(table),
            'ALTER TABLE "Secure"."Document" ENABLE ROW LEVEL SECURITY',
        ),
        (
            "disable",
            lambda table: DisableRowLevelSecurity(table),
            'ALTER TABLE "Secure"."Document" DISABLE ROW LEVEL SECURITY',
        ),
        (
            "force",
            lambda table: ForceRowLevelSecurity(table),
            'ALTER TABLE "Secure"."Document" FORCE ROW LEVEL SECURITY',
        ),
        (
            "no_force",
            lambda table: NoForceRowLevelSecurity(table),
            'ALTER TABLE "Secure"."Document" NO FORCE ROW LEVEL SECURITY',
        ),
        id_="iaa",
    )
    def test_ddl(self, statement_factory, expected):
        statement = testing.resolve_lambda(
            statement_factory, table=self.policy_table()
        )
        self.assert_compile(statement, expected, literal_binds=True)

    @testing.combinations(
        ("empty_name", "", {}, "Policy name cannot be empty"),
        (
            "invalid_command",
            "read",
            {"command": "UPSERT"},
            "Policy command must be one of",
        ),
        ("empty_roles", "read", {"roles": ()}, "Policy roles cannot be empty"),
        (
            "insert_using",
            "insert",
            {"command": "INSERT", "using": "true"},
            "INSERT policies cannot define USING",
        ),
        (
            "select_check",
            "select",
            {"command": "SELECT", "check": "true"},
            "SELECT policies cannot define WITH CHECK",
        ),
        id_="iaaa",
    )
    def test_rejects_invalid_shape(self, name, options, message):
        with expect_raises_message(exc.ArgumentError, message):
            Policy(name, self.policy_table(), **options)


class PolicyReflectionTest(fixtures.TestBase):
    __only_on__ = "postgresql >= 18"

    def test_reflect_disabled_table_and_missing_table(
        self, metadata, connection
    ):
        table = Table(
            "policy_reflection_empty",
            metadata,
            Column("id", Integer, primary_key=True),
        )
        table.create(connection)
        inspector = inspect(connection)

        state = inspector.get_row_security(table.name)

        eq_(state, {"enabled": False, "forced": False})
        eq_(inspector.get_policies(table.name), [])
        with expect_raises_message(
            exc.NoSuchTableError, "policy_reflection_missing"
        ):
            inspector.get_row_security("policy_reflection_missing")

    def test_reflect_row_security(self, metadata, connection):
        table = Table(
            "policy_reflection",
            metadata,
            Column("id", Integer, primary_key=True),
            Column("owner_id", Integer),
        )
        policy = Policy(
            "read",
            table,
            command="SELECT",
            roles=("PUBLIC",),
            using=table.c.owner_id == 7,
        )
        for ddl in (
            EnableRowLevelSecurity(table),
            ForceRowLevelSecurity(table),
            CreatePolicy(policy),
        ):
            event.listen(table, "after_create", ddl)
        table.create(connection)

        inspector = inspect(connection)
        reflected = {
            "state": inspector.get_row_security(table.name),
            "policies": inspector.get_policies(table.name),
        }

        eq_(
            reflected,
            {
                "state": {"enabled": True, "forced": True},
                "policies": [
                    {
                        "name": "read",
                        "command": "SELECT",
                        "roles": ["public"],
                        "using": "(owner_id = 7)",
                        "check": None,
                        "permissive": True,
                    }
                ],
            },
        )

        eq_(
            inspector.get_multi_row_security(filter_names=(table.name,)),
            {(None, table.name): reflected["state"]},
        )
        eq_(
            inspector.get_multi_policies(filter_names=(table.name,)),
            {(None, table.name): reflected["policies"]},
        )
