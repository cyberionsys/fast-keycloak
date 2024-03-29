from typing import List, Optional

import pytest as pytest
from fastapi import HTTPException
from pydantic import ValidationError

from fast_keycloak import KeycloakError
from fast_keycloak.exceptions import (
    ConfigureTOTPException,
    UpdatePasswordException,
    UpdateProfileException,
    UpdateUserLocaleException,
    UserNotFound,
    VerifyEmailException,
)
from fast_keycloak.model import (
    KeycloakGroup,
    KeycloakRole,
    KeycloakToken,
    KeycloakUser,
    OIDCUser, KeycloakClient, KeycloakClientProtocol, KeycloakAuthScope, KeycloakAuthPolicy, KeycloakAuthPolicyLogic,
    KeycloakAuthPolicyType, IdAndRequired, KeycloakDecisionStrategy, KeycloakAuthResource, KeycloakAuthPermission,
    KeycloakAuthPermissionType,
)
from tests import BaseTestClass

TEST_PASSWORD = "test-password"


class TestAPIFunctional(BaseTestClass):
    @pytest.fixture
    def user(self, idp):
        return idp.create_user(
            first_name="test",
            last_name="user",
            username="user@code-specialist.com",
            email="user@code-specialist.com",
            password=TEST_PASSWORD,
            enabled=True,
            send_email_verification=False,
        )

    @pytest.fixture()
    def users(self, idp):
        assert idp.list_users() == []  # No users yet

        # Create some test users
        user_alice = idp.create_user(  # Create User A
            first_name="test",
            last_name="user",
            username="testuser_alice@code-specialist.com",
            email="testuser_alice@code-specialist.com",
            password=TEST_PASSWORD,
            enabled=True,
            send_email_verification=False,
        )
        assert isinstance(user_alice, KeycloakUser)
        assert len(idp.list_users()) == 1

        # Try to create a user with the same username
        with pytest.raises(KeycloakError):  # 'User exists with same username'
            idp.create_user(
                first_name="test",
                last_name="user",
                username="testuser_alice@code-specialist.com",
                email="testuser_alice@code-specialist.com",
                password=TEST_PASSWORD,
                enabled=True,
                send_email_verification=False,
            )
        assert len(idp.list_users()) == 1

        user_bob = idp.create_user(  # Create User B
            first_name="test",
            last_name="user",
            username="testuser_bob@code-specialist.com",
            email="testuser_bob@code-specialist.com",
            password=TEST_PASSWORD,
            enabled=True,
            send_email_verification=False,
        )
        assert isinstance(user_bob, KeycloakUser)
        assert len(idp.list_users()) == 2
        return user_alice, user_bob

    def test_clients(self, idp):
        all_clients = idp.list_clients()
        assert len(all_clients) == 7
        all_clients_ids = [client.clientId for client in all_clients]
        assert 'admin-cli' in all_clients_ids
        assert 'test-client' in all_clients_ids

        admin_client = idp.get_client_by_uuid('f8f4baad-a231-4a6a-b97c-5d68ac147279')
        assert admin_client is not None
        assert admin_client.clientId == 'admin-cli'
        assert admin_client.secret.get_secret_value() == 'BIcczGsZ6I8W5zf0rZg5qSexlloQLPKB'

        test_client = idp.get_client_by_id('test-client')
        assert test_client is not None
        assert test_client.id == '9a76b2ec-b33e-40b0-9cad-e00ca7e77e40'
        assert test_client.secret.get_secret_value() == 'GzgACcJzhzQ4j8kWhmhazt7WSdxDVUyE'

        client = KeycloakClient(
            clientId='new-client',
            serviceAccountsEnabled=True,
            authorizationServicesEnabled=True,
            frontchannelLogout=False,
            protocol=KeycloakClientProtocol.OPENID_CONNECT
        )
        new_client = idp.create_client(client)
        assert new_client is not None
        assert new_client.id is not None
        assert new_client.access is not None

        new_client.name = "This is an updated client"
        new_client.secret = "GzgACcJzhzQ4j8kWhmhazt7WSdxDVUyE"
        updated_client = idp.update_client(new_client)
        assert updated_client is not None
        assert updated_client.id == new_client.id
        assert updated_client.name == new_client.name
        assert updated_client.secret.get_secret_value() == new_client.secret

    def test_roles(self, idp, users):
        user_alice, user_bob = users

        # Check the roles
        user_alice_roles = idp.list_user_roles(user_id=user_alice.id)
        assert len(user_alice_roles) == 1
        for role in user_alice_roles:
            assert role.name in ["default-roles-test"]

        user_bob_roles = idp.list_user_roles(user_id=user_bob.id)
        assert len(user_bob_roles) == 1
        for role in user_bob_roles:
            assert role.name in ["default-roles-test"]

        # Create a some roles
        all_roles = idp.list_roles()
        assert len(all_roles) == 3
        for role in all_roles:
            assert role.name in [
                "default-roles-test",
                "offline_access",
                "uma_authorization",
            ]

        test_role_saturn = idp.create_role("test_role_saturn")
        all_roles = idp.list_roles()
        assert len(all_roles) == 4
        for role in all_roles:
            assert role.name in [
                "default-roles-test",
                "offline_access",
                "uma_authorization",
                test_role_saturn.name,
            ]

        test_role_mars = idp.create_role("test_role_mars")
        all_roles = idp.list_roles()
        assert len(all_roles) == 5
        for role in all_roles:
            assert role.name in [
                "default-roles-test",
                "offline_access",
                "uma_authorization",
                test_role_saturn.name,
                test_role_mars.name,
            ]

        assert isinstance(test_role_saturn, KeycloakRole)
        assert isinstance(test_role_mars, KeycloakRole)

        # Check the roles again
        user_alice_roles: List[KeycloakRole] = idp.list_user_roles(user_id=user_alice.id)
        assert len(user_alice_roles) == 1
        for role in user_alice_roles:
            assert role.name in ["default-roles-test"]

        user_bob_roles = idp.list_user_roles(user_id=user_bob.id)
        assert len(user_bob_roles) == 1
        for role in user_bob_roles:
            assert role.name in ["default-roles-test"]

        # Assign role to Alice
        idp.add_user_roles(user_id=user_alice.id, roles=[test_role_saturn.name])
        user_alice_roles: List[KeycloakRole] = idp.list_user_roles(user_id=user_alice.id)
        assert len(user_alice_roles) == 2
        for role in user_alice_roles:
            assert role.name in ["default-roles-test", test_role_saturn.name]

        # Assign roles to Bob
        idp.add_user_roles(
            user_id=user_bob.id, roles=[test_role_saturn.name, test_role_mars.name]
        )
        user_bob_roles: List[KeycloakRole] = idp.list_user_roles(user_id=user_bob.id)
        assert len(user_bob_roles) == 3
        for role in user_bob_roles:
            assert role.name in [
                "default-roles-test",
                test_role_saturn.name,
                test_role_mars.name,
            ]

        # Exchange the details for access tokens
        keycloak_token_alice: KeycloakToken = idp.user_login(
            username=user_alice.username, password=TEST_PASSWORD
        )
        assert idp.token_is_valid(keycloak_token_alice.access_token)
        keycloak_token_bob: KeycloakToken = idp.user_login(
            username=user_bob.username, password=TEST_PASSWORD
        )
        assert idp.token_is_valid(keycloak_token_bob.access_token)

        # Check get_current_user Alice
        current_user_function = idp.get_current_user()
        current_user: OIDCUser = current_user_function(
            token=keycloak_token_alice.access_token
        )
        assert current_user.sub == user_alice.id
        assert len(current_user.roles) == 4  # Also includes all implicit roles
        for role in current_user.roles:
            assert role in [
                "default-roles-test",
                "offline_access",
                "uma_authorization",
                test_role_saturn.name,
            ]

        # Check get_current_user Bob
        current_user_function = idp.get_current_user()
        current_user: OIDCUser = current_user_function(
            token=keycloak_token_bob.access_token
        )
        assert current_user.sub == user_bob.id
        assert len(current_user.roles) == 5  # Also includes all implicit roles
        for role in current_user.roles:
            assert role in [
                "default-roles-test",
                "offline_access",
                "uma_authorization",
                test_role_saturn.name,
                test_role_mars.name,
            ]

        # Check get_current_user Alice with role Saturn
        current_user_function = idp.get_current_user(
            required_roles=[test_role_saturn.name]
        )
        # Get Alice
        current_user: OIDCUser = current_user_function(
            token=keycloak_token_alice.access_token
        )
        assert current_user.sub == user_alice.id
        # Get Bob
        current_user: OIDCUser = current_user_function(
            token=keycloak_token_bob.access_token
        )
        assert current_user.sub == user_bob.id

        # Check get_current_user Alice with role Mars
        current_user_function = idp.get_current_user(
            required_roles=[test_role_mars.name]
        )
        # Get Alice
        with pytest.raises(HTTPException):
            current_user_function(
                token=keycloak_token_alice.access_token
            )  # Alice does not posses this role
        # Get Bob
        current_user: OIDCUser = current_user_function(
            token=keycloak_token_bob.access_token
        )
        assert current_user.sub == user_bob.id

        # Remove Role Mars from Bob
        idp.remove_user_roles(user_id=user_bob.id, roles=[test_role_mars.name])
        user_bob_roles: List[KeycloakRole] = idp.list_user_roles(user_id=user_bob.id)
        assert len(user_bob_roles) == 2
        for role in user_bob_roles:
            assert role.name in [
                "default-roles-test",
                "offline_access",
                "uma_authorization",
                test_role_saturn.name,
            ]

        # Delete Role Saturn
        idp.delete_role(role_name=test_role_saturn.name)

        # Check Alice
        user_alice_roles: List[KeycloakRole] = idp.list_user_roles(user_id=user_alice.id)
        assert len(user_alice_roles) == 1
        for role in user_alice_roles:
            assert role.name in ["default-roles-test"]

        # Check Bob
        user_bob_roles = idp.list_user_roles(user_id=user_bob.id)
        assert len(user_bob_roles) == 1
        for role in user_bob_roles:
            assert role.name in ["default-roles-test"]

        # Clean up
        idp.delete_role(role_name=test_role_mars.name)
        idp.delete_user(user_id=user_alice.id)
        idp.delete_user(user_id=user_bob.id)

    def test_user_with_initial_roles(self, idp):
        idp.create_role("role_a")
        idp.create_role("role_b")

        user: KeycloakUser = idp.create_user(
            first_name="test",
            last_name="user",
            username="user@code-specialist.com",
            email="user@code-specialist.com",
            initial_roles=["role_a", "role_b"],
            password=TEST_PASSWORD,
            enabled=True,
            send_email_verification=False,
        )
        assert user

        user_token: KeycloakToken = idp.user_login(
            username=user.username, password=TEST_PASSWORD
        )
        decoded_token = idp._decode_token(
            token=user_token.access_token, audience="account"
        )
        oidc_user: OIDCUser = OIDCUser.parse_obj(decoded_token)
        for role in ["role_a", "role_b"]:
            assert role in oidc_user.roles

        idp.delete_role("role_a")
        idp.delete_role("role_b")
        idp.delete_user(user.id)

    def test_groups(self, idp):

        # None of empty list groups
        none_return = idp.get_root_groups([])
        assert not none_return

        # None of none param
        none_return = idp.get_root_groups(None)
        assert none_return is None

        # Error create group
        with pytest.raises(KeycloakError):
            idp.create_group(group_name=None)

        # Error get group
        with pytest.raises(KeycloakError):
            idp.get_group(group_id=None)

        # Create the first group
        foo_group: KeycloakGroup = idp.create_group(group_name="Foo Group")
        assert foo_group is not None
        assert foo_group.name == "Foo Group"

        # Get Empty Subgroups for group
        empty_subgroups = idp.get_group_by_path(f"{foo_group.path}/nonexistent")
        assert empty_subgroups is None

        # Find Group by invalid Path
        invalid_group = idp.get_group_by_path("/nonexistent")
        assert invalid_group is None

        # Create the second group
        bar_group: KeycloakGroup = idp.create_group(group_name="Bar Group")
        assert bar_group is not None
        assert bar_group.name == "Bar Group"

        # Check if groups are registered
        all_groups: List[KeycloakGroup] = idp.list_root_groups()
        assert len(all_groups) == 2

        # Check get_group_by_path
        group: Optional[KeycloakGroup] = idp.get_group_by_path(foo_group.path)
        assert group.name == foo_group.name

        # Create Subgroup 1 by parent object
        subgroup1: KeycloakGroup = idp.create_group(
            group_name="Subgroup 01", parent=foo_group
        )
        assert subgroup1 is not None
        assert subgroup1.name == "Subgroup 01"
        assert subgroup1.path == f"{foo_group.path}/Subgroup 01"

        # Create Subgroup 2 by parent id
        subgroup2: KeycloakGroup = idp.create_group(
            group_name="Subgroup 02", parent=foo_group.id
        )
        assert subgroup2 is not None
        assert subgroup2.name == "Subgroup 02"
        assert subgroup2.path == f"{foo_group.path}/Subgroup 02"

        # Create Subgroup Level 3
        subgroup_l3: KeycloakGroup = idp.create_group(
            group_name="Subgroup l3", parent=subgroup2
        )
        assert subgroup_l3 is not None
        assert subgroup_l3.name == "Subgroup l3"
        assert subgroup_l3.path == f"{subgroup2.path}/Subgroup l3"

        # Create Subgroup Level 4
        subgroup_l4: KeycloakGroup = idp.create_group(
            group_name="Subgroup l4", parent=subgroup_l3
        )
        assert subgroup_l4 is not None
        assert subgroup_l4.name == "Subgroup l4"
        assert subgroup_l4.path == f"{subgroup_l3.path}/Subgroup l4"

        # Find Group by Path
        foo_group = idp.get_group_by_path(foo_group.path)
        assert foo_group is not None
        assert foo_group.name == "Foo Group"

        # Find Subgroup by Path
        subgroup_by_path = idp.get_group_by_path(subgroup2.path)
        assert subgroup_by_path is not None
        assert subgroup_by_path.id == subgroup2.id

        # Find subgroup that does not exist
        subgroup_by_path = idp.get_group_by_path("/The Subgroup/Not Exists")
        assert subgroup_by_path is None

        # Clean up
        idp.delete_group(group_id=bar_group.id)
        idp.delete_group(group_id=foo_group.id)

    def test_user_groups(self, idp, user):

        # Check initial user groups
        user_groups = idp.get_user_groups(user.id)
        assert len(user_groups) == 0

        # Create the first group and add to user
        foo_group: KeycloakGroup = idp.create_group(group_name="Foo")
        idp.add_user_group(user_id=user.id, group_id=foo_group.id)

        # Check if the user is in the group
        user_groups = idp.get_user_groups(user.id)
        assert len(user_groups) == 1
        assert user_groups[0].id == foo_group.id

        # Remove User of the group
        idp.remove_user_group(user.id, foo_group.id)

        # Check if the user has no group
        user_groups = idp.get_user_groups(user.id)
        assert len(user_groups) == 0

        idp.delete_group(group_id=foo_group.id)
        idp.delete_user(user_id=user.id)

    @pytest.fixture()
    def auth_scopes(self, idp):
        scope = idp.create_auth_scope(KeycloakAuthScope(name="scope"))
        assert scope is not None
        assert scope.id is not None
        assert scope.name == "scope"

        scope.name = "scope1"
        scope1 = idp.update_auth_scope(scope)
        assert scope1 is not None
        assert scope1.name == "scope1"
        assert scope1.id == scope.id

        scope2 = idp.create_auth_scope(KeycloakAuthScope(name="scope2"))

        all_scopes = idp.list_auth_scopes()
        assert len(all_scopes) == 2

        scope = idp.get_auth_scope(scope2.id)
        assert scope is not None
        assert scope.id == scope2.id

        scope = idp.get_auth_scope_by_name(scope1.name)
        assert scope is not None
        assert scope.id == scope1.id

        scope = idp.get_auth_scope_by_name("notexistingscope")
        assert scope is None
        return scope1, scope2

    @pytest.fixture()
    def auth_policies(self, idp, users):
        # Create a client policy
        policy = KeycloakAuthPolicy(
            name="Client Policy",
            type=KeycloakAuthPolicyType.CLIENT,
            logic=KeycloakAuthPolicyLogic.POSITIVE,
            clients=[idp.client_uuid]
        )
        client_policy = idp.create_auth_policy(policy)
        assert client_policy is not None
        assert client_policy.id is not None
        assert client_policy.type == KeycloakAuthPolicyType.CLIENT
        assert client_policy.logic == KeycloakAuthPolicyLogic.POSITIVE

        # Create a user policy
        user_alice, user_bob = users
        policy = KeycloakAuthPolicy(
            name="User Policy",
            type=KeycloakAuthPolicyType.USER,
            logic=KeycloakAuthPolicyLogic.NEGATIVE,
            users=[user_alice.id, user_bob.id]
        )
        user_policy = idp.create_auth_policy(policy)
        assert user_policy is not None
        assert user_policy.id is not None
        assert user_policy.logic == KeycloakAuthPolicyLogic.NEGATIVE
        assert len(user_policy.users) == 2

        # Create Role Policy
        basic_roles = [
            role for role in idp.list_roles()
            if role.name in ["default-roles-test", "offline_access", "uma_authorization"]
        ]
        assert len(basic_roles) == 3

        policy = KeycloakAuthPolicy(
            name="Role Policy",
            type=KeycloakAuthPolicyType.ROLE,
            logic=KeycloakAuthPolicyLogic.NEGATIVE,
            roles=[
                IdAndRequired(id=basic_roles[0].id, required=True),
                IdAndRequired(id=basic_roles[1].id),
                IdAndRequired(id=basic_roles[2].id)
            ]
        )
        role_policy = idp.create_auth_policy(policy)
        assert role_policy is not None
        assert role_policy.id is not None
        assert role_policy.logic == KeycloakAuthPolicyLogic.NEGATIVE
        assert len(role_policy.roles) == 3

        # Create aggregate policy
        policy = KeycloakAuthPolicy(
            name="Aggregate Policy",
            type=KeycloakAuthPolicyType.AGGREGATE,
            logic=KeycloakAuthPolicyLogic.POSITIVE,
            decisionStrategy=KeycloakDecisionStrategy.AFFIRMATIVE,
            policies=[client_policy.id, user_policy.id, role_policy.id]
        )
        aggregate_policy = idp.create_auth_policy(policy)
        assert aggregate_policy is not None
        assert aggregate_policy.id is not None
        assert aggregate_policy.logic == KeycloakAuthPolicyLogic.POSITIVE
        assert aggregate_policy.decisionStrategy == KeycloakDecisionStrategy.AFFIRMATIVE
        assert len(aggregate_policy.policies) == 3

        aggregate_policy.decisionStrategy = KeycloakDecisionStrategy.UNANIMOUS
        result = idp.update_auth_policy(aggregate_policy)
        assert result.id == aggregate_policy.id
        assert result.decisionStrategy == KeycloakDecisionStrategy.UNANIMOUS

        all_policies = idp.list_auth_policies()
        assert len(all_policies) == 4
        for policy in all_policies:
            assert policy.id in [client_policy.id, user_policy.id, role_policy.id, aggregate_policy.id]

        policy = idp.get_auth_policy_by_type_and_id(KeycloakAuthPolicyType.AGGREGATE, aggregate_policy.id)
        assert policy.id == aggregate_policy.id

        policy = idp.get_aggregate_auth_policy_with_dependencies(policy.id)
        assert policy.id == aggregate_policy.id
        assert len(policy.policies) == 3
        for policy in policy.policies:
            assert policy in aggregate_policy.policies

        idp.delete_auth_policy(aggregate_policy.id)
        idp.delete_auth_policy(role_policy.id)

        return client_policy, user_policy

    @pytest.fixture()
    def auth_resources(self, idp, auth_scopes):
        scope1, scope2 = auth_scopes
        resource = KeycloakAuthResource(
            name="resource1",
            type="urn:test-client:resources:resource1",
            uris=["/resource1/*"],
            ownerManagedAccess=True,
            scopes=[scope1],
            attributes={"attribute1": "value1"}
        )
        resource1 = idp.create_auth_resource(resource)
        assert resource1.id is not None
        assert resource1.type == "urn:test-client:resources:resource1"
        assert resource1.ownerManagedAccess is True
        assert len(resource1.scopes) == 1
        assert resource1.scopes[0].id == scope1.id
        assert resource1.attributes["attribute1"][0] == "value1"

        resource = KeycloakAuthResource(
            name="resource2",
            uris=["/resource2/*"],
            scopes=[scope1, scope2]
        )
        resource2 = idp.create_auth_resource(resource)
        assert resource2 is not None
        assert len(resource2.scopes) == 2
        for scope in resource2.scopes:
            assert scope.id in [scope1.id, scope2.id]

        resource = resource2
        resource.type = "urn:test-client:resources:resource2"
        resource2 = idp.update_auth_resource(resource)
        assert resource2.id == resource.id
        assert resource2.type == "urn:test-client:resources:resource2"

        all_resources = idp.list_auth_resources()
        assert len(all_resources) == 2
        for resource in all_resources:
            assert resource.id in [resource1.id, resource2.id]

        resource = idp.get_auth_resource(resource1.id)
        assert resource is not None
        assert resource.id == resource1.id

        idp.delete_auth_resource(resource2.id)
        return resource1

    def test_auth_permissions(self, idp, auth_resources, auth_scopes, auth_policies):
        # Create resource based permission
        resource1 = auth_resources
        client_policy, user_policy = auth_policies

        permission = KeycloakAuthPermission(
            name="Resource Permission",
            type=KeycloakAuthPermissionType.RESOURCE,
            resources=[resource1.id],
            policies=[client_policy.id, user_policy.id]
        )
        resource_permission = idp.create_auth_permission(permission)
        assert resource_permission.id is not None
        assert resource_permission.decisionStrategy == KeycloakDecisionStrategy.UNANIMOUS
        assert len(resource_permission.resources) == 1
        assert len(resource_permission.policies) == 2

        scope1, scope2 = auth_scopes
        with pytest.raises(ValidationError):
            # Resource permission not compatible with scopes
            KeycloakAuthPermission(
                name="Resource Permission",
                type=KeycloakAuthPermissionType.RESOURCE,
                resources=[resource1.id],
                scopes=[scope1.id]
            )

        with pytest.raises(ValidationError):
            # resources and resourceType are mutually exclusive
            KeycloakAuthPermission(
                name="Resource Permission",
                type=KeycloakAuthPermissionType.RESOURCE,
                resourceType="urn:Test:resources:resource1",
                resources=[resource1.id],
            )

        # Creates a scope based permission
        permission = KeycloakAuthPermission(
            name="Scope Permission",
            type=KeycloakAuthPermissionType.SCOPE,
            resources=[resource1.id],
            scopes=[scope1.id],
            decisionStrategy=KeycloakDecisionStrategy.AFFIRMATIVE
        )
        scope_permission = idp.create_auth_permission(permission)
        assert scope_permission.id is not None
        assert len(scope_permission.resources) == 1
        assert scope_permission.resources[0] == resource1.id
        assert len(scope_permission.scopes) == 1
        assert scope_permission.scopes[0] == scope1.id
        assert scope_permission.decisionStrategy == KeycloakDecisionStrategy.AFFIRMATIVE
        assert scope_permission.policies is None or len(scope_permission.policies) == 0

        with pytest.raises(KeycloakError):
            # scope2 was not in resource1 scopes so should throw error
            permission = KeycloakAuthPermission(
                name="Scope Permission",
                type=KeycloakAuthPermissionType.SCOPE,
                resources=[resource1.id],
                scopes=[scope1.id, scope2.id],
                policies=[client_policy.id, user_policy.id],
                decisionStrategy=KeycloakDecisionStrategy.AFFIRMATIVE
            )
            idp.create_auth_permission(permission)

        to_update = scope_permission
        to_update.policies = [client_policy.id, user_policy.id]
        to_update.decisionStrategy = KeycloakDecisionStrategy.UNANIMOUS
        scope_permission = idp.update_auth_permission(to_update)

        assert len(scope_permission.policies) == 2
        for policy in scope_permission.policies:
            assert policy in [client_policy.id, user_policy.id]
        assert scope_permission.decisionStrategy == KeycloakDecisionStrategy.UNANIMOUS

        all_permissions = idp.list_auth_permissions()
        assert len(all_permissions) == 2
        for permission in all_permissions:
            assert permission.id in [resource_permission.id, scope_permission.id]

        permission = idp.get_auth_permission(resource_permission.id)
        assert permission.id == resource_permission.id

        idp.delete_auth_permission(KeycloakAuthPermissionType.RESOURCE, resource_permission.id)
        idp.delete_auth_permission(KeycloakAuthPermissionType.SCOPE, scope_permission.id)

    @pytest.mark.parametrize(
        "action, exception",
        [
            ("update_user_locale", UpdateUserLocaleException),
            ("CONFIGURE_TOTP", ConfigureTOTPException),
            ("VERIFY_EMAIL", VerifyEmailException),
            ("UPDATE_PASSWORD", UpdatePasswordException),
            ("UPDATE_PROFILE", UpdateProfileException),
        ],
    )
    def test_login_exceptions(self, idp, action, exception, user):

        # Get access, refresh and id token for the users
        tokens = idp.user_login(username=user.username, password=TEST_PASSWORD)
        assert tokens.access_token
        assert tokens.refresh_token
        assert tokens.id_token

        user.requiredActions.append(action)  # Add an action
        user: KeycloakUser = idp.update_user(user=user)  # Save the change

        with pytest.raises(
                exception
        ):  # Expect the login to fail due to the verify email action
            idp.user_login(username=user.username, password=TEST_PASSWORD)

        user.requiredActions.remove(action)  # Remove the action
        user: KeycloakUser = idp.update_user(user=user)  # Save the change
        assert idp.user_login(
            username=user.username, password=TEST_PASSWORD
        )  # Login possible again

        # Clean up
        idp.delete_user(user_id=user.id)

    def test_user_not_found_exception(self, idp):
        with pytest.raises(UserNotFound):  # Expect the get to fail due to a non existent user
            idp.get_user(user_id='abc')

        with pytest.raises(UserNotFound):  # Expect the get to fail due to a failed query search
            idp.get_user(query='username="some_non_existant_username"')
