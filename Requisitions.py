from CommonsRH import CommonsRH
import requests
import urllib3


class Requisitions:
    @staticmethod
    def requisitions(url, type="get", headers=None, payloads=None, binary=False):
        # Disable urllib3's warning
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        print(f"{CommonsRH.head_log()} Iniciando acesso para '{url}'")
        if headers is None:
            headers = {}
        elif headers is not {}:
            headers = {"Authorization": f"Bearer {headers}"}
        if payloads is None:
            payloads = {}

        if type.lower() == "get":
            print(f"{CommonsRH.head_log()} Definindo tipo de acesso: '{type}'")
            req_response = requests.get(
                url, headers=headers, json=payloads, verify=False # type: ignore
            )
        elif type.lower() == "post":
            print(f"{CommonsRH.head_log()} Definindo tipo de acesso: '{type}'")
            req_response = requests.post(
                url, headers=headers, json=payloads, verify=False
            )
        print(f"{CommonsRH.head_log()} Tipo de acesso Definido: '{type}'")

        if 200 <= req_response.status_code < 300:
            print(f"{CommonsRH.head_log()} Dados obtidos.")
            if not binary:
                return req_response
            elif binary:
                return req_response.content
