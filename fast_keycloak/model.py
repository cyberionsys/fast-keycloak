from enum import Enum, StrEnum
from typing import List, Optional, Any

from pydantic import (
    AliasChoices,
    BaseModel as PydanticBaseModel,
    ConfigDict,
    Field,
    SecretStr,
)

from fast_keycloak.exceptions import KeycloakError


class HTTPMethod(Enum):
    """Represents the basic HTTP verbs

    Values:
        - GET: get
        - POST: post
        - DELETE: delete
        - PUT: put
    """

    GET = "get"
    POST = "post"
    DELETE = "delete"
    PUT = "put"


class KeycloakClientAuthenticatorTypes(StrEnum):
    CLIENT_SECRET = "client-secret"
    CLIENT_JWT = "client-jwt"


class KeycloakClientProtocol(StrEnum):
    OPENID_CONNECT = "openid-connect"
    SAML = "saml"


class BaseModel(PydanticBaseModel):
    model_config = ConfigDict(from_attributes=True)


class KeycloakProtocolMapperConfig(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra='allow')

    multivalued: Optional[bool] = None
    aggregateAttributes: Optional[bool] = Field(
        default=None,
        validation_alias=AliasChoices("aggregateAttributes", "aggregate.attrs"),
        serialization_alias="aggregate.attrs"
    )
    showInUserinfo: Optional[bool] = Field(
        default=None,
        validation_alias=AliasChoices("showInUserinfo", "userinfo.token.claim"),
        serialization_alias="userinfo.token.claim"
    )
    showInIntrospectionToken: Optional[bool] = Field(
        default=None,
        validation_alias=AliasChoices("showInIntrospectionToken", "introspection.token.claim"),
        serialization_alias="introspection.token.claim"
    )
    showInIdToken: Optional[bool] = Field(
        default=None,
        validation_alias=AliasChoices("showInIdToken", "id.token.claim"),
        serialization_alias="id.token.claim"
    )
    showInAccessToken: Optional[bool] = Field(
        default=None,
        validation_alias=AliasChoices("showInAccessToken", "access.token.claim"),
        serialization_alias="access.token.claim"
    )
    claimName: Optional[str] = Field(
        default=None,
        validation_alias=AliasChoices("claimName", "claim.name"),
        serialization_alias="claim.name"
    )
    jsonTypeLabel: Optional[str] = Field(
        default=None,
        validation_alias=AliasChoices("jsonTypeLabel", "jsonType.label"),
        serialization_alias="jsonType.label"
    )


class KeycloakProtocolMapper(BaseModel):
    id: Optional[str] = None
    name: str
    protocol: KeycloakClientProtocol
    protocolMapper: str
    consentRequired: bool = False
    config: Optional[KeycloakProtocolMapperConfig] = None


class KeycloakClientAccess(BaseModel):
    view: bool = True
    configure: bool = True
    manage: bool = True


class KeycloakClient(BaseModel):
    id: Optional[str] = None
    clientId: str
    name: str = ""
    description: str = ""
    rootUrl: str = ""
    adminUrl: str = ""
    baseUrl: str = ""
    surrogateAuthRequired: bool = False
    enabled: bool = True
    alwaysDisplayInConsole: bool = False
    clientAuthenticatorType: KeycloakClientAuthenticatorTypes = KeycloakClientAuthenticatorTypes.CLIENT_SECRET
    secret: Optional[SecretStr] = None
    registrationAccessToken: Optional[SecretStr] = None
    defaultRoles: Optional[list[str]] = None
    redirectUris: list[str] = ['/*']
    webOrigins: list[str] = ['/*']
    notBefore: int = 0
    bearerOnly: bool = False
    consentRequired: bool = False
    standardFlowEnabled: bool = True
    implicitFlowEnabled: bool = False
    directAccessGrantsEnabled: bool = True
    serviceAccountsEnabled: bool = False
    authorizationServicesEnabled: Optional[bool] = False
    directGrantsOnly: Optional[bool] = None
    publicClient: bool = False
    frontchannelLogout: bool = True
    protocol: KeycloakClientProtocol
    attributes: dict[str, Any] = None
    authenticationFlowBindingOverrides: dict[str, Any] = {}
    fullScopeAllowed: bool = True
    nodeReRegistrationTimeout: int = -1
    registeredNodes: Optional[dict[str, int]] = None
    protocolMappers: Optional[list[KeycloakProtocolMapper]] = None
    clientTemplate: Optional[str] = None
    useTemplateConfig: Optional[bool] = None
    useTemplateScope: Optional[bool] = None
    useTemplateMappers: Optional[bool] = None
    defaultClientScopes: Optional[list[str]] = None
    optionalClientScopes: Optional[list[str]] = None
    authorizationSettings: Optional[dict[str, Any]] = None
    access: Optional[KeycloakClientAccess] = None
    origin: Optional[str] = None


class KeycloakUser(BaseModel):
    """Represents a user object of Keycloak.

    Attributes:
        id (str):
        createdTimestamp (int):
        username (str):
        enabled (bool):
        totp (bool):
        emailVerified (bool):
        firstName (Optional[str]):
        lastName (Optional[str]):
        email (Optional[str]):
        disableableCredentialTypes (List[str]):
        requiredActions (List[str]):
        realmRoles (List[str]):
        notBefore (int):
        access (dict):
        attributes (Optional[dict]):

    Notes: Check the Keycloak documentation at https://www.keycloak.org/docs-api/15.0/rest-api/index.html for
    details. This is a mere proxy object.
    """

    id: str
    createdTimestamp: int
    username: str
    enabled: bool
    totp: bool
    emailVerified: bool
    firstName: Optional[str] = None
    lastName: Optional[str] = None
    email: Optional[str] = None
    disableableCredentialTypes: List[str]
    requiredActions: List[str]
    realmRoles: Optional[List[str]] = None
    notBefore: int
    access: Optional[dict] = None
    attributes: Optional[dict] = None


class UsernamePassword(BaseModel):
    """Represents a request body that contains username and password

    Attributes:
        username (str): Username
        password (str): Password, masked by swagger
    """

    username: str
    password: SecretStr


class OIDCUser(BaseModel):
    """Represents a user object of Keycloak, parsed from access token

    Attributes:
        sub (str):
        iat (int):
        exp (int):
        scope (str):
        email_verified (bool):
        name (Optional[str]):
        given_name (Optional[str]):
        family_name (Optional[str]):
        email (Optional[str]):
        preferred_username (Optional[str]):
        realm_access (dict):
        resource_access (dict):
        extra_fields (dict):

    Notes: Check the Keycloak documentation at https://www.keycloak.org/docs-api/15.0/rest-api/index.html for
    details. This is a mere proxy object.
    """

    azp: Optional[str] = None
    sub: str
    iat: int
    exp: int
    scope: Optional[str] = None
    email_verified: bool
    name: Optional[str] = None
    given_name: Optional[str] = None
    family_name: Optional[str] = None
    email: Optional[str] = None
    preferred_username: Optional[str] = None
    realm_access: Optional[dict] = None
    resource_access: Optional[dict] = None
    extra_fields: dict = Field(default_factory=dict)

    @property
    def roles(self) -> List[str]:
        """Returns the roles of the user

        Returns:
            List[str]: If the realm access dict contains roles
        """
        if not self.realm_access and not self.resource_access:
            raise KeycloakError(
                status_code=404,
                reason="The 'realm_access' and 'resource_access' sections of the provided access token are missing.",
            )
        roles = []
        if self.realm_access:
            if "roles" in self.realm_access:
                roles += self.realm_access["roles"]
        if self.azp and self.resource_access:
            if self.azp in self.resource_access:
                if "roles" in self.resource_access[self.azp]:
                    roles += self.resource_access[self.azp]["roles"]
        if not roles:
            raise KeycloakError(
                status_code=404,
                reason="The 'realm_access' and 'resource_access' sections of the provided access token did not "
                       "contain any 'roles'",
            )
        return roles

    def __str__(self) -> str:
        """String representation of an OIDCUser"""
        return self.preferred_username


class KeycloakIdentityProvider(BaseModel):
    """Keycloak representation of an identity provider

    Attributes:
        alias (str):
        internalId (str):
        providerId (str):
        enabled (bool):
        updateProfileFirstLoginMode (str):
        trustEmail (bool):
        storeToken (bool):
        addReadTokenRoleOnCreate (bool):
        authenticateByDefault (bool):
        linkOnly (bool):
        firstBrokerLoginFlowAlias (str):
        config (dict):

    Notes: Check the Keycloak documentation at https://www.keycloak.org/docs-api/15.0/rest-api/index.html for
    details. This is a mere proxy object.
    """

    alias: str
    internalId: str
    providerId: str
    enabled: bool
    updateProfileFirstLoginMode: str
    trustEmail: bool
    storeToken: bool
    addReadTokenRoleOnCreate: bool
    authenticateByDefault: bool
    linkOnly: bool
    firstBrokerLoginFlowAlias: str
    config: dict


class KeycloakRole(BaseModel):
    """Keycloak representation of a role

    Attributes:
        id (str):
        name (str):
        composite (bool):
        clientRole (bool):
        containerId (str):

    Notes: Check the Keycloak documentation at https://www.keycloak.org/docs-api/15.0/rest-api/index.html for
    details. This is a mere proxy object.
    """

    id: str
    name: str
    composite: bool
    clientRole: bool
    containerId: str


class KeycloakToken(BaseModel):
    """Keycloak representation of a token object

    Attributes:
        access_token (str): An access token
        refresh_token (str): An a refresh token, default None
        id_token (str): An issued by the Authorization Server token id, default None
    """

    access_token: str
    expires_in: int
    refresh_token: Optional[str] = None
    refresh_expires_in: Optional[int] = None
    id_token: Optional[str] = None

    def __str__(self):
        """String representation of KeycloakToken"""
        return f"Bearer {self.access_token}"


class KeycloakGroup(BaseModel):
    """Keycloak representation of a group

    Attributes:
        id (str):
        name (str):
        path (Optional[str]):
        subGroupCount(int)
        realmRoles (Optional[str]):
    """

    id: str
    name: str
    path: Optional[str] = None
    realmRoles: Optional[List[str]] = None
    subGroupCount: int = 0
    subGroups: Optional[List["KeycloakGroup"]] = None


KeycloakGroup.update_forward_refs()


class KeycloakAuthScope(BaseModel):
    id: Optional[str] = None
    name: str
    displayName: str = ""
    iconUri: str = ""
