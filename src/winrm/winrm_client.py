import base64
import winrm


class SecureWinRMClient:

    def __init__(self, host, username, password):
        self.session = winrm.Session(
            target=host,
            auth=(username, password),
            transport="ntlm",
            server_cert_validation="ignore"
        )

    def execute_ps(self, script):
        encoded_script = base64.b64encode(
            script.encode("utf-16le")
        ).decode("ascii")

        result = self.session.run_cmd(
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            [
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-EncodedCommand",
                encoded_script
            ]
        )

        stdout = result.std_out.decode(errors="ignore")
        stderr = result.std_err.decode(errors="ignore")

        if result.status_code != 0:
            raise Exception(
                f"Status Code: {result.status_code}\n\n"
                f"STDOUT:\n{stdout}\n\n"
                f"STDERR:\n{stderr}"
            )

        return stdout