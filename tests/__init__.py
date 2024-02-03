import pytest

from fast_keycloak import FastKeycloak


class BaseTestClass:
    @pytest.fixture
    def idp(self):
        return FastKeycloak(
            server_url="http://localhost:8085",
            client_id="test-client",
            client_secret="GzgACcJzhzQ4j8kWhmhazt7WSdxDVUyE",
            admin_client_secret="BIcczGsZ6I8W5zf0rZg5qSexlloQLPKB",
            realm="Test",
            callback_uri="http://localhost:8081/callback",
        )
