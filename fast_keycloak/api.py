from __future__ import annotations

import functools
import json
from collections.abc import Callable
from http import HTTPStatus
from json import JSONDecodeError
from typing import Any, List, Optional, Type, Union
from urllib.parse import urlencode

import requests
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import ExpiredSignatureError, JWTError, jwt
from jose.exceptions import JWTClaimsError
from pydantic import BaseModel
from requests import Response

import fast_keycloak.model as models
from fast_keycloak.exceptions import (
    ConfigureTOTPException,
    KeycloakError,
    MandatoryActionException,
    UpdatePasswordException,
    UpdateProfileException,
    UpdateUserLocaleException,
    UserNotFound,
    VerifyEmailException,
)


def result_or_error(
        response_model: Type[BaseModel] = None,
        is_list: bool = False,
        pick_list_item: int = None
) -> List[BaseModel] or BaseModel or KeycloakError or IndexError:
    """Decorator used to ease the handling of responses from Keycloak.

    Args:
        response_model (Type[BaseModel]): Object that should be returned based on the payload
        is_list (bool): True if the return value should be a list of the response model provided
        pick_list_item (int): Item to pick if the response is a list

    Returns:
        BaseModel or List[BaseModel]: Based on the given signature and response circumstances

    Raises:
        KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        IndexError: If pick_list_item is out of bounds

    Notes:
        - Keycloak sometimes returns empty payloads but describes the error in its content (byte encoded)
          which is why this function checks for JSONDecode exceptions.
        - Keycloak often does not expose the real error for security measures. You will most likely encounter:
          {'error': 'unknown_error'} as a result. If so, please check the logs of your Keycloak instance to get error
          details, the RestAPI doesn't provide any.
    """

    def inner(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            def create_list(json_data: List[dict]):
                return [response_model.model_validate(entry) for entry in json_data]

            def create_object(json_data: dict):
                return response_model.model_validate(json_data)

            result: Response = f(*args, **kwargs)  # The actual call

            if (
                    type(result) != Response
            ):  # If the object given is not a response object, directly return it.
                return result

            if result.status_code in range(100, 299):  # Successful
                if response_model is None:  # No model given

                    try:
                        return result.json()
                    except JSONDecodeError:
                        return result.content.decode("utf-8")

                else:  # Response model given
                    if is_list:
                        items = create_list(result.json())
                        if pick_list_item is None:
                            return items
                        elif pick_list_item >= 0:
                            if pick_list_item > len(items) + 1:
                                raise IndexError(f"Index {pick_list_item} is out of range")
                            return items[pick_list_item]
                        else:
                            raise IndexError(f"Index {pick_list_item} is out of range")
                    else:
                        return create_object(result.json())

            else:  # Not Successful, forward status code and error
                try:
                    raise KeycloakError(
                        status_code=result.status_code, reason=result.json()
                    )
                except JSONDecodeError:
                    raise KeycloakError(
                        status_code=result.status_code,
                        reason=result.content.decode("utf-8"),
                    )

        return wrapper

    return inner


# noinspection PyTypeChecker
class FastKeycloak:
    """Instance to wrap the Keycloak API with FastAPI

    Attributes: _admin_token (models.KeycloakToken): A models.KeycloakToken instance, containing the access token that is used for
    any admin related request

    Example:
        ```python
        app = FastAPI()
        idp = KeycloakFastAPI(
            server_url="https://auth.some-domain.com/auth",
            client_id="some-test-client",
            client_secret="some-secret",
            admin_client_secret="some-admin-cli-secret",
            realm="Test",
            callback_uri=f"http://localhost:8081/callback"
        )
        idp.add_swagger_config(app)
        ```
    """

    _admin_token: str

    def __init__(
            self,
            server_url: str,
            client_id: str,
            client_secret: str,
            realm: str,
            admin_client_secret: str,
            callback_uri: str,
            admin_client_id: str = "admin-cli",
            scope: str = "openid profile email",
            timeout: int = 10,
    ):
        """FastAPIKeycloak constructor

        Args:
            server_url (str): The URL of the Keycloak server, with `/auth` suffix
            client_id (str): The id of the client used for users
            client_secret (str): The client secret
            realm (str): The realm (name)
            admin_client_id (str): The id for the admin client, defaults to 'admin-cli'
            admin_client_secret (str): Secret for the `admin-cli` client
            callback_uri (str): Callback URL of the instance, used for auth flows. Must match at least one
            `Valid Redirect URIs` of Keycloak and should point to an endpoint that utilizes the authorization_code flow.
            timeout (int): Timeout in seconds to wait for the server
            scope (str): OIDC scope
        """
        self.server_url = server_url
        self.realm = realm
        self.client_id = client_id
        self.client_secret = client_secret
        self.admin_client_id = admin_client_id
        self.admin_client_secret = admin_client_secret
        self.callback_uri = callback_uri
        self.timeout = timeout
        self.scope = scope
        self._get_admin_token()  # Requests an admin access token on startup

    @property
    def admin_token(self):
        """Holds an AccessToken for the `admin-cli` client

        Returns:
            models.KeycloakToken: A token, valid to perform admin actions

        Notes:
            - This might result in an infinite recursion if something unforeseen goes wrong
        """
        if self.token_is_valid(token=self._admin_token):
            return self._admin_token
        self._get_admin_token()
        return self.admin_token

    @admin_token.setter
    def admin_token(self, value: str):
        """Setter for the admin_token

        Args:
            value (str): An access Token

        Returns:
            None: Inplace method, updates the _admin_token
        """
        decoded_token = self._decode_token(token=value)
        if not decoded_token.get("resource_access").get(
                "realm-management"
        ) or not decoded_token.get("resource_access").get("account"):
            raise AssertionError(
                """The access required was not contained in the access token for the `admin-cli`.
                Possibly a Keycloak misconfiguration. Check if the admin-cli client has `Full Scope Allowed`
                and that the `Service Account Roles` contain all roles from `account` and `realm_management`"""
            )
        self._admin_token = value

    def add_swagger_config(self, app: FastAPI):
        """Adds the client id and secret securely to the swagger ui.
        Enabling Swagger ui users to perform actions they usually need the client credentials, without exposing them.

        Args:
            app (FastAPI): Optional FastAPI app to add the config to swagger

        Returns:
            None: Inplace method
        """
        app.swagger_ui_init_oauth = {
            "usePkceWithAuthorizationCodeGrant": True,
            "clientId": self.client_id,
            "clientSecret": self.client_secret,
        }

    @functools.cached_property
    def user_auth_scheme(self) -> OAuth2PasswordBearer:
        """Returns the auth scheme to register the endpoints with swagger

        Returns:
            OAuth2PasswordBearer: Auth scheme for swagger
        """
        return OAuth2PasswordBearer(tokenUrl=self.token_uri)

    def get_current_user(
            self,
            required_roles: List[str] = None,
            extra_fields: List[str] = None
    ) -> Callable[[OAuth2PasswordBearer], models.OIDCUser]:
        """Returns the current user based on an access token in the HTTP-header. Optionally verifies roles are possessed
        by the user

        Args:
            required_roles List[str]: List of role names required for this endpoint
            extra_fields List[str]: The names of the additional fields you need that are encoded in JWT

        Returns:
            Callable[OAuth2PasswordBearer, models.OIDCUser]: Dependency method which returns the decoded JWT content

        Raises:
            ExpiredSignatureError: If the token is expired (exp > datetime.now())
            JWTError: If decoding fails or the signature is invalid
            JWTClaimsError: If any claim is invalid
            HTTPException: If any role required is not contained within the roles of the users
        """

        def current_user(token: OAuth2PasswordBearer = Depends(self.user_auth_scheme), ) -> models.OIDCUser:
            """Decodes and verifies a JWT to get the current user

            Args:
                token OAuth2PasswordBearer: Access token in `Authorization` HTTP-header

            Returns:
                models.OIDCUser: Decoded JWT content

            Raises:
                ExpiredSignatureError: If the token is expired (exp > datetime.now())
                JWTError: If decoding fails or the signature is invalid
                JWTClaimsError: If any claim is invalid
                HTTPException: If any role required is not contained within the roles of the users
            """
            decoded_token = self._decode_token(token=str(token), audience="account")
            user = models.OIDCUser.model_validate(decoded_token)
            if required_roles:
                for role in required_roles:
                    if role not in user.roles:
                        raise HTTPException(
                            status_code=status.HTTP_403_FORBIDDEN,
                            detail=f'Role "{role}" is required to perform this action',
                        )

            if extra_fields:
                for field in extra_fields:
                    user.extra_fields[field] = decoded_token.get(field, None)

            return user

        return current_user

    @functools.cached_property
    def open_id_configuration(self) -> dict:
        """Returns Keycloaks Open ID Connect configuration

        Returns:
            dict: Open ID Configuration
        """
        response = requests.get(
            url=f"{self.realm_uri}/.well-known/openid-configuration",
            timeout=self.timeout,
        )
        return response.json()

    def proxy(
            self,
            relative_path: str,
            method: models.HTTPMethod,
            additional_headers: dict = None,
            payload: dict = None,
    ) -> Response:
        """Proxies a request to Keycloak and automatically adds the required Authorization header. Should not be
        exposed under any circumstances. Grants full API admin access.

        Args:

            relative_path (str): The relative path of the request.
            Requests will be sent to: `[server_url]/[relative_path]`
            method (models.HTTPMethod): The HTTP-verb to be used
            additional_headers (dict): Optional headers besides the Authorization to add to the request
            payload (dict): Optional payload to send

        Returns:
            Response: Proxied response

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        headers = {"Authorization": f"Bearer {self.admin_token}"}
        if additional_headers is not None:
            headers = {**headers, **additional_headers}

        return requests.request(
            method=method.name,
            url=f"{self.server_url}{relative_path}",
            data=json.dumps(payload),
            headers=headers,
            timeout=self.timeout,
        )

    def _get_admin_token(self) -> None:
        """Exchanges client credentials (admin-cli) for an access token.

        Returns:
            None: Inplace method that updated the class attribute `_admin_token`

        Raises:
            KeycloakError: If fetching an admin access token fails,
            or the response does not contain an access_token at all

        Notes:
            - Is executed on startup and may be executed again if the token validation fails
        """
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {
            "client_id": self.admin_client_id,
            "client_secret": self.admin_client_secret,
            "grant_type": "client_credentials",
        }
        response = requests.post(url=self.token_uri, headers=headers, data=data, timeout=self.timeout)
        try:
            self.admin_token = response.json()["access_token"]
        except JSONDecodeError as e:
            raise KeycloakError(
                reason=response.content.decode("utf-8"),
                status_code=response.status_code,
            ) from e

        except KeyError as e:
            raise KeycloakError(
                reason=f"The response did not contain an access_token: {response.json()}",
                status_code=403,
            ) from e

    @functools.cached_property
    def public_key(self) -> str:
        """Returns the Keycloak public key

        Returns:
            str: Public key for JWT decoding
        """
        response = requests.get(url=self.realm_uri, timeout=self.timeout)
        public_key = response.json()["public_key"]
        return f"-----BEGIN PUBLIC KEY-----\n{public_key}\n-----END PUBLIC KEY-----"

    @result_or_error(response_model=models.KeycloakClient, is_list=True)
    def list_clients(self) -> List[models.KeycloakClient]:
        """List all clients in realm

        Returns:
            list[KeycloakClient]: list of clients

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(url=self.clients_uri, method=models.HTTPMethod.GET)

    @result_or_error(response_model=models.KeycloakClient)
    def get_client_by_uuid(self, uuid: str) -> models.KeycloakClient:
        """Get the client with the specified UUID

        Args:
            uuid str: the client UUID

        Returns:
            KeycloakClient:The corresponding client

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(url=f"{self.clients_uri}/{uuid}", method=models.HTTPMethod.GET)

    @result_or_error(response_model=models.KeycloakClient, is_list=True, pick_list_item=0)
    def get_client_by_id(self, client_id: str) -> models.KeycloakClient:
        """Get the client with the specified client_id (not UUID)

        Args:
            client_id str: the client ID (not uuid)

        Returns:
            KeycloakClient:The corresponding client

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(url=f"{self.clients_uri}?clientId={client_id}", method=models.HTTPMethod.GET)

    @result_or_error(response_model=models.KeycloakClient)
    def create_client(self, client: models.KeycloakClient) -> models.KeycloakClient:
        """Create a client on the realm

        Args:
            client (KeycloakClient): Keycloak client data

        Returns:
            KeycloakClient: If creation succeeded, else it will return the error

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        data = FastKeycloak._build_data(client, True)
        response = self._admin_request(url=self.clients_uri, data=data, method=models.HTTPMethod.POST)
        if response.status_code == 201:
            return self.get_client_by_id(client.clientId)
        else:
            return response

    @result_or_error(response_model=models.KeycloakClient)
    def update_client(self, client: models.KeycloakClient) -> models.KeycloakClient:
        """Update a client on the realm

        Args:
            client (KeycloakClient): Keycloak client data

        Returns:
            KeycloakClient: If creation succeeded, else it will return the error

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        if client.id is None:
            raise KeycloakError(status_code=HTTPStatus.BAD_REQUEST, reason="Client UUID is required")

        data = FastKeycloak._build_data(client, True)
        response = self._admin_request(url=f"{self.clients_uri}/{client.id}", data=data, method=models.HTTPMethod.PUT)
        if response.status_code == 204:
            return self.get_client_by_uuid(client.id)
        else:
            return response

    @result_or_error()
    def add_user_roles(self, roles: List[str], user_id: str) -> dict:
        """Adds roles to a specific user

        Args:
            roles List[str]: Roles to add (name)
            user_id str: ID of the user the roles should be added to

        Returns:
            dict: Proxied response payload

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        keycloak_roles = self.get_roles(roles)
        return self._admin_request(
            url=f"{self.users_uri}/{user_id}/role-mappings/realm",
            data=[role.__dict__ for role in keycloak_roles],
            method=models.HTTPMethod.POST,
        )

    @result_or_error()
    def remove_user_roles(self, roles: List[str], user_id: str) -> dict:
        """Removes roles from a specific user

        Args:
            roles List[str]: Roles to remove (name)
            user_id str: ID of the user the roles should be removed from

        Returns:
            dict: Proxied response payload

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        keycloak_roles = self.get_roles(roles)
        return self._admin_request(
            url=f"{self.users_uri}/{user_id}/role-mappings/realm",
            data=[role.__dict__ for role in keycloak_roles],
            method=models.HTTPMethod.DELETE,
        )

    @result_or_error(response_model=models.KeycloakRole, is_list=True)
    def get_roles(self, role_names: List[str]) -> List[Any] | None:
        """Returns full entries of Roles based on role names

        Args:
            role_names List[str]: Roles that should be looked up (names)

        Returns:
             List[models.KeycloakRole]: Full entries stored at Keycloak. Or None if the list of requested roles is None

        Notes:
            - The Keycloak RestAPI will only identify RoleRepresentations that
              use name AND id which is the only reason for existence of this function

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        if role_names is None:
            return
        roles = self.list_roles()
        return list(filter(lambda role: role.name in role_names, roles))

    @result_or_error(response_model=models.KeycloakRole, is_list=True)
    def list_user_roles(self, user_id: str) -> List[models.KeycloakRole]:
        """Gets all roles of a user

        Args:
            user_id (str): ID of the user of interest

        Returns:
            List[models.KeycloakRole]: All roles possessed by the user

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(
            url=f"{self.users_uri}/{user_id}/role-mappings/realm", method=models.HTTPMethod.GET
        )

    @result_or_error(response_model=models.KeycloakRole)
    def create_role(self, role_name: str) -> models.KeycloakRole:
        """Create a role on the realm

        Args:
            role_name (str): Name of the new role

        Returns:
            models.KeycloakRole: If creation succeeded, else it will return the error

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        response = self._admin_request(
            url=self.roles_uri, data={"name": role_name}, method=models.HTTPMethod.POST
        )
        if response.status_code == 201:
            return self.get_roles(role_names=[role_name])[0]
        else:
            return response

    @result_or_error(response_model=models.KeycloakRole, is_list=True)
    def list_roles(self) -> List[models.KeycloakRole]:
        """Get all roles of the Keycloak realm

        Returns:
            List[models.KeycloakRole]: All roles of the realm

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(url=self.roles_uri, method=models.HTTPMethod.GET)

    @result_or_error()
    def delete_role(self, role_name: str) -> dict:
        """Deletes a role on the realm

        Args:
            role_name (str): The role (name) to delte

        Returns:
            dict: Proxied response payload

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(
            url=f"{self.roles_uri}/{role_name}",
            method=models.HTTPMethod.DELETE,
        )

    # TODO: List nested groups!
    @result_or_error(response_model=models.KeycloakGroup, is_list=True)
    def list_root_groups(self) -> List[models.KeycloakGroup]:
        """Get all base groups of the Keycloak realm

        Returns:
            List[KeycloakGroup]: All base groups of the realm

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(url=self.groups_uri, method=models.HTTPMethod.GET)

    @result_or_error(response_model=models.KeycloakGroup, is_list=True)
    def get_root_groups(self, group_names: List[str] = None) -> List[Any] | None:
        """Returns full entries of base Groups based on group names

        Args:
            group_names (List[str]): Groups that should be looked up (names)

        Returns:
            List[KeycloakGroup]: Full entries stored at Keycloak. Or None if the list of requested groups is None

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        if group_names is None:
            return
        groups = self.list_root_groups()
        return list(filter(lambda group: group.name in group_names, groups))

    @result_or_error(response_model=models.KeycloakGroup)
    def get_group(self, group_id: str) -> Optional[models.KeycloakGroup]:
        """Return Group based on group id

        Args:
            group_id (str): Group id to be found

        Returns:
             KeycloakGroup: Keycloak object by id. Or None if the id is invalid

        Notes:
            - The Keycloak RestAPI will only identify GroupRepresentations that
              use name AND id which is the only reason for existence of this function

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(url=f"{self.groups_uri}/{group_id}", method=models.HTTPMethod.GET)

    @result_or_error(response_model=models.KeycloakGroup, is_list=True)
    def _retrieve_subgroups(self, group: models.KeycloakGroup) -> Optional[List[models.KeycloakGroup]]:
        """Retrieve subgroups of a group

        Args:
            group (KeycloakGroup): Parent Group

        Returns:
             Optional[List[KeycloakGroup]]: Optional list of subgroups

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        if group is None or group.subGroupCount == 0:
            return

        return self._admin_request(url=f"{self.groups_uri}/{group.id}/children", method=models.HTTPMethod.GET)

    @result_or_error(response_model=models.KeycloakGroup, is_list=True)
    def _search_group(self, group_name: str) -> List[models.KeycloakGroup]:
        """Search groups based on their name

        Args:
            group_name (str): Group name to be found

        Returns:
             List[KeycloakGroup]: list of groups having that name

        Note:
            Keycloak allow creating many groups with same name

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(
            url=f"{self.groups_uri}?search={group_name}&exact=true", method=models.HTTPMethod.GET
        )

    @result_or_error(response_model=models.KeycloakGroup)
    def get_group_by_path(self, path: str, with_parents=False) -> Optional[models.KeycloakGroup]:
        """Return Group based on path

        Args:
            path (str): Path that should be looked up
            with_parents (bool): Return the group with its parent(s)

        Returns:
            KeycloakGroup: Full entries stored at Keycloak. Or None if the path not found

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        if path is None:
            return None

        group_name = path.split('/')[-1]

        results = self._search_group(group_name)
        for result in results:
            if result.path == path:
                return result

            group = result
            while group.subGroups:
                group = group.subGroups[0]

            if group.path == path:
                return result if with_parents else group

        return None

    @result_or_error()
    def add_user_group(self, user_id: str, group_id: str) -> dict:
        """Add group to a specific user

        Args:
            user_id (str): ID of the user the group should be added to
            group_id (str): Group to add (id)

        Returns:
            dict: Proxied response payload

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(url=f"{self.users_uri}/{user_id}/groups/{group_id}", method=models.HTTPMethod.PUT)

    @result_or_error(response_model=models.KeycloakGroup, is_list=True)
    def get_user_groups(self, user_id: str) -> List[models.KeycloakGroup]:
        """Gets all groups of a user

        Args:
            user_id (str): ID of the user of interest

        Returns:
            List[KeycloakGroup]: All groups possessed by the user

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(url=f"{self.users_uri}/{user_id}/groups", method=models.HTTPMethod.GET)

    @result_or_error(response_model=models.KeycloakUser, is_list=True)
    def get_group_members(self, group_id: str):
        """Get all members of a group.

        Args:
            group_id (str): ID of the group of interest

        Returns:
            List[KeycloakUser]: All users in the group. Note that
            the user objects returned are not fully populated.

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(url=f"{self.groups_uri}/{group_id}/members", method=models.HTTPMethod.GET)

    @result_or_error()
    def remove_user_group(self, user_id: str, group_id: str) -> dict:
        """Remove group from a specific user

        Args:
            user_id str: ID of the user the groups should be removed from
            group_id str: Group to remove (id)

        Returns:
            dict: Proxied response payload

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(
            url=f"{self.users_uri}/{user_id}/groups/{group_id}",
            method=models.HTTPMethod.DELETE,
        )

    @result_or_error(response_model=models.KeycloakGroup)
    def create_group(
            self, group_name: str, parent: Union[models.KeycloakGroup, str] = None
    ) -> models.KeycloakGroup:
        """Create a group on the realm

        Args:
            group_name (str): Name of the new group
            parent (Union[models.KeycloakGroup, str]): Can contain an instance or object id

        Returns:
            KeycloakGroup: If creation succeeded, else it will return the error

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """

        # If it's an object id get an instance of the object
        if isinstance(parent, str):
            parent = self.get_group(parent)

        if parent is not None:
            groups_uri = f"{self.groups_uri}/{parent.id}/children"
            path = f"{parent.path}/{group_name}"
        else:
            groups_uri = self.groups_uri
            path = f"/{group_name}"

        response = self._admin_request(url=groups_uri, data={"name": group_name}, method=models.HTTPMethod.POST)

        if response.status_code == 201:
            return self.get_group_by_path(path=path)
        else:
            return response

    @result_or_error()
    def delete_group(self, group_id: str) -> dict:
        """Deletes a group on the realm

        Args:
            group_id (str): The group (id) to delte

        Returns:
            dict: Proxied response payload

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(url=f"{self.groups_uri}/{group_id}", method=models.HTTPMethod.DELETE)

    @result_or_error(response_model=models.KeycloakUser)
    def create_user(
            self,
            first_name: str,
            last_name: str,
            username: str,
            email: str,
            password: str,
            enabled: bool = True,
            initial_roles: List[str] = None,
            send_email_verification: bool = True,
            attributes: dict[str, Any] = None,
    ) -> models.KeycloakUser:
        """

        Args:
            first_name (str): The first name of the new user
            last_name (str): The last name of the new user
            username (str): The username of the new user
            email (str): The email of the new user
            password (str): The password of the new user
            initial_roles (List[str]): The roles the user should posses. Defaults to `None`
            enabled (bool): True if the user should be able to be used. Defaults to `True`
            send_email_verification (bool): If true, the email verification will be added as an required
                                            action and the email triggered - if the user was created successfully.
                                            Defaults to `True`
            attributes (dict): attributes of new user

        Returns:
            KeycloakUser: If the creation succeeded

        Notes:
            - Also triggers the email verification email

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        data = {
            "email": email,
            "username": username,
            "firstName": first_name,
            "lastName": last_name,
            "enabled": enabled,
            "credentials": [
                {"temporary": False, "type": "password", "value": password}
            ],
            "requiredActions": ["VERIFY_EMAIL" if send_email_verification else None],
            "attributes": attributes,
        }
        response = self._admin_request(
            url=self.users_uri, data=data, method=models.HTTPMethod.POST
        )
        if response.status_code != 201:
            return response
        user = self.get_user(query=f"username={username}")
        if send_email_verification:
            self.send_email_verification(user.id)
        if initial_roles:
            self.add_user_roles(initial_roles, user.id)
            user = self.get_user(user_id=user.id)
        return user

    @result_or_error()
    def change_password(
            self, user_id: str, new_password: str, temporary: bool = False
    ) -> dict:
        """Exchanges a users' password.

        Args:
            temporary (bool): If True, the password must be changed on the first login
            user_id (str): The user ID of interest
            new_password (str): The new password

        Returns:
            dict: Proxied response payload

        Notes:
            - Possibly should be extended by an old password check

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        credentials = {
            "temporary": temporary,
            "type": "password",
            "value": new_password,
        }
        return self._admin_request(
            url=f"{self.users_uri}/{user_id}/reset-password",
            data=credentials,
            method=models.HTTPMethod.PUT,
        )

    @result_or_error()
    def send_email_verification(self, user_id: str) -> dict:
        """Sends the email to verify the email address

        Args:
            user_id (str): The user ID of interest

        Returns:
            dict: Proxied response payload

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(
            url=f"{self.users_uri}/{user_id}/send-verify-email",
            method=models.HTTPMethod.PUT,
        )

    @result_or_error(response_model=models.KeycloakUser)
    def get_user(self, user_id: str = None, query: str = "") -> models.KeycloakUser:
        """Queries the keycloak API for a specific user either based on its ID or any **native** attribute

        Args:
            user_id (str): The user ID of interest
            query: Query string. e.g. `email=testuser@codespecialist.com` or `username=codespecialist`

        Returns:
            KeycloakUser: If the user was found

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        if user_id is None:
            response = self._admin_request(
                url=f"{self.users_uri}?{query}", method=models.HTTPMethod.GET
            )
            if not response.json():
                raise UserNotFound(
                    status_code=status.HTTP_404_NOT_FOUND,
                    reason=f"User query with filters of [{query}] did no match any users"
                )
            return models.KeycloakUser(**response.json()[0])
        else:
            response = self._admin_request(
                url=f"{self.users_uri}/{user_id}", method=models.HTTPMethod.GET
            )
            if response.status_code == status.HTTP_404_NOT_FOUND:
                raise UserNotFound(
                    status_code=status.HTTP_404_NOT_FOUND,
                    reason=f"User with user_id[{user_id}] was not found"
                )
            return models.KeycloakUser(**response.json())

    @result_or_error(response_model=models.KeycloakUser)
    def update_user(self, user: models.KeycloakUser):
        """Updates a user. Requires the whole object.

        Args:
            user (KeycloakUser): The (new) user object

        Returns:
            KeycloakUser: The updated user

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)

        Notes: - You may alter any aspect of the user object, also the requiredActions for instance. There is no
        explicit function for updating those as it is a user update in essence
        """
        response = self._admin_request(
            url=f"{self.users_uri}/{user.id}", data=user.__dict__, method=models.HTTPMethod.PUT
        )
        if response.status_code == 204:  # Update successful
            return self.get_user(user_id=user.id)
        return response

    @result_or_error()
    def delete_user(self, user_id: str) -> dict:
        """Deletes a user

        Args:
            user_id (str): The user ID of interest

        Returns:
            dict: Proxied response payload

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(
            url=f"{self.users_uri}/{user_id}",
            method=models.HTTPMethod.DELETE
        )

    @result_or_error(response_model=models.KeycloakUser, is_list=True)
    def list_users(self) -> List[models.KeycloakUser]:
        """Returns all users of the realm

        Returns:
            List[KeycloakUser]: All Keycloak users of the realm

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(url=self.users_uri, method=models.HTTPMethod.GET)

    @result_or_error(response_model=models.KeycloakIdentityProvider, is_list=True)
    def get_identity_providers(self) -> List[models.KeycloakIdentityProvider]:
        """Returns all configured identity Providers

        Returns:
            List[KeycloakIdentityProvider]: All configured identity providers

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(url=self.providers_uri, method=models.HTTPMethod.GET).json()

    @result_or_error(response_model=models.KeycloakToken)
    def user_login(self, username: str, password: str) -> models.KeycloakToken:
        """Models the password OAuth2 flow. Exchanges username and password for an access token. Will raise detailed
        errors if login fails due to requiredActions

        Args:
            username (str): Username used for login
            password (str): Password of the user

        Returns:
            KeycloakToken: If the exchange succeeds

        Raises:
            HTTPException: If the credentials did not match any user
            MandatoryActionException: If the login is not possible due to mandatory actions
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299, != 400, != 401)
            UpdateUserLocaleException: If the credentials we're correct but the has requiredActions of which the first
            one is to update his locale
            ConfigureTOTPException: If the credentials we're correct but the has requiredActions of which the first one
            is to configure TOTP
            VerifyEmailException: If the credentials we're correct but the has requiredActions of which the first one
            is to verify his email
            UpdatePasswordException: If the credentials we're correct but the has requiredActions of which the first one
            is to update his password
            UpdateProfileException: If the credentials we're correct but the has requiredActions of which the first one
            is to update his profile

        Notes:
            - To avoid calling this multiple times, you may want to check all requiredActions of the user if it fails
            due to a (sub)instance of an MandatoryActionException
        """
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "username": username,
            "password": password,
            "grant_type": "password",
            "scope": self.scope,
        }
        response = requests.post(url=self.token_uri, headers=headers, data=data, timeout=self.timeout)
        if response.status_code == 401:
            raise HTTPException(status_code=401, detail="Invalid user credentials")
        if response.status_code == 400:
            user: models.KeycloakUser = self.get_user(query=f"username={username}")
            if len(user.requiredActions) > 0:
                reason = user.requiredActions[0]
                exception = {
                    "update_user_locale": UpdateUserLocaleException(),
                    "CONFIGURE_TOTP": ConfigureTOTPException(),
                    "VERIFY_EMAIL": VerifyEmailException(),
                    "UPDATE_PASSWORD": UpdatePasswordException(),
                    "UPDATE_PROFILE": UpdateProfileException(),
                }.get(
                    reason,  # Try to return the matching exception
                    # On custom or unknown actions return a MandatoryActionException by default
                    MandatoryActionException(
                        detail=f"This user can't login until the following action has been "
                               f"resolved: {reason}"
                    ),
                )
                raise exception
        return response

    @result_or_error(response_model=models.KeycloakToken)
    def exchange_authorization_code(
            self, session_state: str, code: str
    ) -> models.KeycloakToken:
        """Models the authorization code OAuth2 flow. Opening the URL provided by `login_uri` will result in a
        callback to the configured callback URL. The callback will also create a session_state and code query
        parameter that can be exchanged for an access token.

        Args:
            session_state (str): Salt to reduce the risk of successful attacks
            code (str): The authorization code

        Returns:
            KeycloakToken: If the exchange succeeds

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "session_state": session_state,
            "grant_type": "authorization_code",
            "redirect_uri": self.callback_uri,
        }
        return requests.post(url=self.token_uri, headers=headers, data=data, timeout=self.timeout)

    @result_or_error(response_model=models.KeycloakAuthScope, is_list=True)
    def list_auth_scopes(self) -> List[models.KeycloakAuthScope]:
        """Returns all authorization scopes defined for the client

        Returns:
            List[KeycloakAuthScope]: All Keycloak authorization scopes of the client

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(
            url=f"{self.auth_scope_uri}?deep=false", method=models.HTTPMethod.GET
        )

    @result_or_error(response_model=models.KeycloakAuthScope)
    def get_auth_scope(self, auth_scope_uuid: str) -> models.KeycloakAuthScope:
        """Queries the keycloak API for a specific authorization scope based on its UUID

        Args:
            auth_scope_uuid (str): The authorization scope UUID of interest

        Returns:
            KeycloakAuthScope: If the authorization scope was found

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(
            url=f"{self.auth_scope_uri}/{auth_scope_uuid}?deep=false", method=models.HTTPMethod.GET
        )

    @result_or_error(response_model=models.KeycloakAuthScope, is_list=True)
    def search_auth_scopes(self, auth_scope_name: str) -> List[models.KeycloakAuthScope]:
        """Search authorization scopes based on their name

        Args:
            auth_scope_name (str): Authorization scope name to be found

        Returns:
             List[KeycloakAuthScope]: list of authorization scope having that name

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(
            url=f"{self.auth_scope_uri}?name={auth_scope_name}&deep=false",
            method=models.HTTPMethod.GET
        )

    def get_auth_scope_by_name(self, auth_scope_name: str) -> Optional[models.KeycloakAuthScope]:
        """Queries the keycloak API for a specific authorization scope based on its name

        Args:
            auth_scope_name (str): The authorization scope name

        Returns:
            KeycloakAuthScope: If an authorization scope with that specific name was found

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        results = self.search_auth_scopes(auth_scope_name)
        for result in results:
            if result.name == auth_scope_name:
                return result
        return None

    @result_or_error(response_model=models.KeycloakAuthScope)
    def create_auth_scope(self, scope: models.KeycloakAuthScope) -> models.KeycloakAuthScope:
        """Creates a new authorization scope in client

        Args:
            scope (KeycloakAuthScope): The scope to add

        Returns:
            KeycloakAuthScope: The created authorization scope

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(
            url=self.auth_scope_uri, data=scope.model_dump(), method=models.HTTPMethod.POST
        )

    @result_or_error(response_model=models.KeycloakAuthScope)
    def update_auth_scope(self, scope: models.KeycloakAuthScope) -> models.KeycloakAuthScope:
        """Updates an authorization scope in client

        Args:
            scope (KeycloakAuthScope): The scope to update

        Returns:
            KeycloakAuthScope: The updated authorization scope

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        if scope.id is None:
            raise KeycloakError(status_code=HTTPStatus.BAD_REQUEST, reason="Missing id for scope")

        response = self._admin_request(
            url=f"{self.auth_scope_uri}/{scope.id}", data=scope.model_dump(), method=models.HTTPMethod.PUT
        )
        if response.status_code == 204:
            return self.get_auth_scope(scope.id)
        else:
            return response

    @result_or_error()
    def delete_auth_scope(self, scope_id: str):
        """Deletes an authorization scope

        Args:
            scope_id (str): the authorization scope id to delete

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(
            url=f"{self.auth_scope_uri}/{scope_id}", method=models.HTTPMethod.DELETE
        )

    @result_or_error(response_model=models.KeycloakAuthPolicy, is_list=True)
    def list_auth_policies(self) -> List[models.KeycloakAuthPolicy]:
        """Returns all authorization policies defined for the client

        Returns:
            List[KeycloakAuthPolicy]: All Keycloak authorization policies of the client

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(url=f"{self.auth_policy_uri}?permission=false", method=models.HTTPMethod.GET)

    @result_or_error(response_model=models.KeycloakAuthPolicy)
    def get_auth_policy_by_type_and_id(
            self,
            policy_type: models.KeycloakAuthPolicyType,
            policy_id: str
    ) -> models.KeycloakAuthPolicy:
        """Get Authorization policy by type and uuid

        Args:
            policy_type (KeycloakAuthPolicyType): The type of the policy
            policy_id (str): UUID of the policy

        Returns:
             KeycloakAuthPolicy: The policy if found

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(
            url=f"{self.auth_policy_typed_uri(policy_type)}/{policy_id}",
            method=models.HTTPMethod.GET
        )

    @result_or_error(response_model=models.KeycloakAuthPolicy, is_list=True)
    def _get_aggregate_auth_policy_dependencies(self, policy_uuid: str) -> List[models.KeycloakAuthPolicy]:
        """Retrieve the linked aggregated policies of an aggregate policy

        Args:
            policy_uuid (str): UUID of the policy

        Returns:
             List[KeycloakAuthPolicy]: List of aggregated policies

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(
            url=f"{self.auth_policy_typed_uri(models.KeycloakAuthPolicyType.AGGREGATE)}/{policy_uuid}/associatedPolicies",
            method=models.HTTPMethod.GET
        )

    @result_or_error(response_model=models.KeycloakAuthPolicy, is_list=True)
    def get_associated_policies(self, policy_uuid: str) -> List[models.KeycloakAuthPolicy]:
        return self._admin_request(
            url=f"{self.auth_policy_uri}/{policy_uuid}/associatedPolicies",
            method=models.HTTPMethod.GET
        )

    def get_aggregate_auth_policy_with_dependencies(self, policy_id: str) -> models.KeycloakAuthPolicy:
        """Retrieve aggregate policy with linked aggregated policies

        Args:
            policy_id (str): UUID of the policy

        Returns:
             KeycloakAuthPolicy: Aggregate policy with linked policies

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        policy_type = models.KeycloakAuthPolicyType.AGGREGATE
        policy = self.get_auth_policy_by_type_and_id(policy_type, policy_id)
        # Retrieved associated policies
        associated_policies = self._get_aggregate_auth_policy_dependencies(policy_id)
        policy.policies = [p.id for p in associated_policies]
        return policy

    @result_or_error(response_model=models.KeycloakAuthPolicy)
    def create_auth_policy(self, policy: models.KeycloakAuthPolicy) -> models.KeycloakAuthPolicy:
        """Creates a new authorization policy in client

        Args:
            policy (KeycloakAuthPolicy): The policy to add

        Returns:
            KeycloakAuthScope: The created authorization scope

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(
            url=f"{self.auth_policy_typed_uri(policy.type)}",
            method=models.HTTPMethod.POST,
            data=FastKeycloak._build_data(policy)
        )

    @result_or_error(response_model=models.KeycloakAuthPolicy)
    def update_auth_policy(self, policy: models.KeycloakAuthPolicy) -> models.KeycloakAuthPolicy:
        """Updates a new authorization policy in client

        Args:
            policy (KeycloakAuthPolicy): The policy to update

        Returns:
            KeycloakAuthScope: The updated authorization scope

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        if not policy.id:
            raise KeycloakError(status_code=HTTPStatus.BAD_REQUEST, reason="ID not found for policy")

        response = self._admin_request(
            url=f"{self.auth_policy_typed_uri(policy.type)}/{policy.id}",
            method=models.HTTPMethod.PUT,
            data=FastKeycloak._build_data(policy)
        )

        if response.status_code == 201:
            return self.get_auth_policy_by_type_and_id(policy.type, policy.id)
        else:
            return response

    @result_or_error()
    def delete_auth_policy(self, policy_id: str):
        """Deletes an authorization policy in client

        Args:
            policy_id (str): The id of the authorization policy to delete

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(url=f"{self.auth_policy_uri}/{policy_id}", method=models.HTTPMethod.DELETE)

    @result_or_error(response_model=models.KeycloakAuthResource, is_list=True)
    def list_auth_resources(self) -> List[models.KeycloakAuthResource]:
        """Returns all authorization resources defined for the client

        Returns:
            List[KeycloakAuthResource]: All Keycloak authorization resources of the client

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(url=f"{self.auth_resource_uri}", method=models.HTTPMethod.GET)

    @result_or_error(response_model=models.KeycloakAuthResource)
    def get_auth_resource(self, resource_uuid: str) -> models.KeycloakAuthResource:
        """Queries the keycloak API for a specific authorization resource based on its UUID

        Args:
            resource_uuid (str): The authorization resource UUID of interest

        Returns:
            KeycloakAuthResource: If the resource as found

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(url=f"{self.auth_resource_uri}/{resource_uuid}", method=models.HTTPMethod.GET)

    @result_or_error(response_model=models.KeycloakAuthResource)
    def create_auth_resource(self, resource: models.KeycloakAuthResource) -> models.KeycloakAuthResource:
        """Creates a new authorization resource in client

        Args:
            resource (KeycloakAuthResource): The resource to add

        Returns:
            KeycloakAuthResource: The created authorization resource

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(
            url=self.auth_resource_uri, method=models.HTTPMethod.POST,
            data=FastKeycloak._build_data(resource, True)
        )

    @result_or_error(response_model=models.KeycloakAuthResource)
    def update_auth_resource(self, resource: models.KeycloakAuthResource) -> models.KeycloakAuthResource:
        """Updates a new authorization resource in client

        Args:
            resource (KeycloakAuthResource): The resource to update

        Returns:
            KeycloakAuthResource: The updated authorization resource

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        if not resource.id:
            raise KeycloakError(status_code=HTTPStatus.BAD_REQUEST, reason="ID not found for policy")

        data = FastKeycloak._build_data(resource, True)
        response = self._admin_request(
            url=f"{self.auth_resource_uri}/{resource.id}",
            method=models.HTTPMethod.PUT,
            data=data
        )

        if response.status_code == 204:
            return self.get_auth_resource(resource.id)
        else:
            return response

    @result_or_error()
    def delete_auth_resource(self, resource_id: str) -> models.KeycloakAuthResource:
        """Deletes an authorization resource in client

        Args:
            resource_id (str): The id of the authorization resource to delete

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(url=f"{self.auth_resource_uri}/{resource_id}", method=models.HTTPMethod.DELETE)

    @result_or_error(response_model=models.KeycloakAuthPermission, is_list=True)
    def list_auth_permissions(self) -> List[models.KeycloakAuthPermission]:
        """Returns all authorization permissions defined for the client

        Returns:
            List[KeycloakAuthPermission]: All Keycloak authorization permissions of the client

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(url=self._auth_permission_uri, method=models.HTTPMethod.GET)

    @result_or_error(response_model=models.KeycloakAuthPermission)
    def get_auth_permission(self, permission_uuid: str) -> models.KeycloakAuthPermission:
        """Queries the keycloak API for a specific authorization permission based on its UUID

        Args:
            permission_uuid (str): The authorization permission UUID of interest

        Returns:
            KeycloakAuthResource: If the resource as found

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        response = self._admin_request(
            url=f"{self._auth_permission_uri}/{permission_uuid}", method=models.HTTPMethod.GET
        )
        if response.status_code == 200:
            permission_json = response.json()
            # Retrieve associated policies
            policies = self.get_associated_policies(permission_uuid)
            permission_json['policies'] = [policy.id for policy in policies]

            try:
                without_resource_type = not permission_json['resourceType']
            except KeyError:
                without_resource_type = True

            if without_resource_type:
                # Retrieve resources
                response = self._admin_request(
                    url=f"{self.auth_policy_uri}/{permission_uuid}/resources",
                    method=models.HTTPMethod.GET
                )
                if response.status_code == 200:
                    permission_json['resources'] = [resource['_id'] for resource in response.json()]

            if permission_json['type'] == models.KeycloakAuthPermissionType.SCOPE.value:
                # Retrieve scopes
                response = self._admin_request(
                    url=f"{self.auth_policy_uri}/{permission_uuid}/scopes",
                    method=models.HTTPMethod.GET
                )
                if response.status_code == 200:
                    permission_json['scopes'] = [scope['id'] for scope in response.json()]
            return models.KeycloakAuthPermission.model_validate(permission_json)
        else:
            return response

    @result_or_error(response_model=models.KeycloakAuthPermission)
    def create_auth_permission(self, permission: models.KeycloakAuthPermission) -> models.KeycloakAuthPermission:
        """Creates a new authorization permission in client

        Args:
            permission (KeycloakAuthPermission): The permission to add

        Returns:
            KeycloakAuthPermission: The created authorization permission

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        if not permission.type:
            raise KeycloakError(status_code=HTTPStatus.BAD_REQUEST, reason="Unknown permission type")

        return self._admin_request(
            url=self.auth_permission_typed_uri(permission.type),
            data=FastKeycloak._build_data(permission),
            method=models.HTTPMethod.POST
        )

    @result_or_error(response_model=models.KeycloakAuthPermission)
    def update_auth_permission(self, permission: models.KeycloakAuthPermission) -> models.KeycloakAuthPermission:
        """Updates a new authorization permission in client

        Args:
            permission (KeycloakAuthPermission): The permission to update

        Returns:
            KeycloakAuthPermission: The updated authorization permission

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        if not permission.type:
            raise KeycloakError(status_code=HTTPStatus.BAD_REQUEST, reason="Unknown permission type")
        if not permission.id:
            raise KeycloakError(status_code=HTTPStatus.BAD_REQUEST, reason="No permission ID found")

        response = self._admin_request(
            url=f"{self.auth_permission_typed_uri(permission.type)}/{permission.id}",
            data=FastKeycloak._build_data(permission),
            method=models.HTTPMethod.PUT
        )
        if response.status_code == 201:
            return self.get_auth_permission(permission.id)
        else:
            return response

    @result_or_error()
    def delete_auth_permission(self, permission_type: str, permission_uuid: str):
        """Deletes an authorization permission in client

        Args:
            permission_type (str): The permission type to delete
            permission_uuid (str): The id of the authorization permission to delete

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(
            url=f"{self.auth_permission_typed_uri(permission_type)}/{permission_uuid}",
            method=models.HTTPMethod.DELETE
        )

    @classmethod
    def _build_data(cls, model: BaseModel, by_alias: bool = False) -> dict:
        return {
            key: value for key, value in model.model_dump(by_alias=by_alias).items()
            if value is not None
        }

    def _admin_request(
            self,
            url: str,
            method: models.HTTPMethod,
            data: dict = None,
            content_type: str = "application/json",
    ) -> Response:
        """Private method that is the basis for any requests requiring admin access to the api. Will append the
        necessary `Authorization` header

        Args:
            url (str): The URL to be called
            method (models.HTTPMethod): The HTTP verb to be used
            data (dict): The payload of the request
            content_type (str): The content type of the request

        Returns:
            Response: Response of Keycloak
        """
        headers = {
            "Content-Type": content_type,
            "Authorization": f"Bearer {self.admin_token}",
        }
        return requests.request(
            method=method.name, url=url, data=json.dumps(data), headers=headers, timeout=self.timeout,
        )

    @functools.cached_property
    def login_uri(self):
        """The URL for users to login on the realm. Also adds the client id, the callback and the scope."""
        params = {
            "scope": self.scope,
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.callback_uri,
        }
        return f"{self.authorization_uri}?{urlencode(params)}"

    @functools.cached_property
    def authorization_uri(self):
        """The authorization endpoint URL"""
        return self.open_id_configuration.get("authorization_endpoint")

    @functools.cached_property
    def token_uri(self):
        """The token endpoint URL"""
        return self.open_id_configuration.get("token_endpoint")

    @functools.cached_property
    def logout_uri(self):
        """The logout endpoint URL"""
        return self.open_id_configuration.get("end_session_endpoint")

    @functools.cached_property
    def realm_uri(self):
        """The realm's endpoint URL"""
        return f"{self.server_url}/realms/{self.realm}"

    @functools.cached_property
    def clients_uri(self):
        """The clients endpoint URL"""
        return self.admin_uri(resource="clients")

    @functools.cached_property
    def users_uri(self):
        """The users endpoint URL"""
        return self.admin_uri(resource="users")

    @functools.cached_property
    def userinfo_uri(self):
        """The userinfo endpoint URL"""
        return self.open_id_configuration.get("userinfo_endpoint")

    @functools.cached_property
    def roles_uri(self):
        """The roles endpoint URL"""
        return self.admin_uri(resource="roles")

    @functools.cached_property
    def groups_uri(self):
        """The groups endpoint URL"""
        return self.admin_uri(resource="groups")

    @functools.cached_property
    def _admin_uri(self):
        """The base endpoint for any admin related action"""
        return f"{self.server_url}/admin/realms/{self.realm}"

    @functools.cached_property
    def _open_id(self):
        """The base endpoint for any opendid connect config info"""
        return f"{self.realm_uri}/protocol/openid-connect"

    @functools.cached_property
    def providers_uri(self):
        """The endpoint that returns all configured identity providers"""
        return self.admin_uri(resource="identity-provider/instances")

    @functools.cached_property
    def client_uuid(self) -> str:
        """Client UUID"""
        return self.get_client_by_id(self.client_id).id

    def admin_uri(self, resource: str):
        """Returns a admin resource URL"""
        return f"{self._admin_uri}/{resource}"

    def open_id(self, resource: str):
        """Returns a openip connect resource URL"""
        return f"{self._open_id}/{resource}"

    def token_is_valid(self, token: str, audience: str = None) -> bool:
        """Validates an access token, optionally also its audience

        Args:
            token (str): The token to be verified
            audience (str): Optional audience. Will be checked if provided

        Returns:
            bool: True if the token is valid
        """
        try:
            self._decode_token(token=token, audience=audience)
            return True
        except (ExpiredSignatureError, JWTError, JWTClaimsError):
            return False

    def _decode_token(
            self, token: str, options: dict = None, audience: str = None
    ) -> dict:
        """Decodes a token, verifies the signature by using Keycloaks public key. Optionally verifying the audience

        Args:
            token (str):
            options (dict):
            audience (str): Name of the audience, must match the audience given in the token

        Returns:
            dict: Decoded JWT

        Raises:
            ExpiredSignatureError: If the token is expired (exp > datetime.now())
            JWTError: If decoding fails or the signature is invalid
            JWTClaimsError: If any claim is invalid
        """
        if options is None:
            options = {
                "verify_signature": True,
                "verify_aud": audience is not None,
                "verify_exp": True,
            }
        return jwt.decode(
            token=token, key=self.public_key, options=options, audience=audience
        )

    def _resource_server_uri(self, resource: str) -> str:
        return self.admin_uri(f"clients/{self.client_uuid}/authz/resource-server/{resource}")

    @functools.cached_property
    def auth_scope_uri(self) -> str:
        return self._resource_server_uri('scope')

    @functools.cached_property
    def auth_policy_uri(self) -> str:
        return self._resource_server_uri('policy')

    def auth_policy_typed_uri(self, policy_type: models.KeycloakAuthPolicyType) -> str:
        return f"{self.auth_policy_uri}/{policy_type}"

    @functools.cached_property
    def auth_resource_uri(self) -> str:
        return self._resource_server_uri('resource')

    @functools.cached_property
    def _auth_permission_uri(self) -> str:
        return self._resource_server_uri("permission")

    def auth_permission_typed_uri(self, perm_type: models.KeycloakAuthPermissionType) -> str:
        return f"{self._auth_permission_uri}/{perm_type}"

    def __str__(self):
        """String representation"""
        return "FastAPI Keycloak Integration"

    def __repr__(self):
        """Debug representation"""
        return f"{self.__str__()} <class {self.__class__} >"
