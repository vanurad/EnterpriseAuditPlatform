from src.winrm.winrm_client import SecureWinRMClient


class ConnectionFactory:

    @staticmethod
    def create_connection(host, username, password):

        return SecureWinRMClient(
            host,
            username,
            password
        )