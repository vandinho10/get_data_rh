from Conf import USERS
from CommonsRH import CommonsRH
from FileManager import FileManager
from ServerData import ServerData
from Requisitions import Requisitions
import json
from bs4 import BeautifulSoup
from datetime import datetime


class SistemaLogin:
    @staticmethod
    def user_data_valid():
        print(f"{CommonsRH.head_log()} Buscando dados para Efetuar Login.")
        data = FileManager.read_json(USERS)
        if data.get("users"):
            return json.dumps(data["users"])
        else:
            print(
                f"{CommonsRH.head_log()} Arquivo de configuração invalido: '{USERS}'."
            )
            return "Arquivo de Configuração Inválido."

    @staticmethod
    def get_user_info(username, user_info):
        data = json.loads(SistemaLogin.user_data_valid())
        if data and not data == [{}]:
            print(
                f"{CommonsRH.head_log()} Processando dados de usuario para efetuar Login."
            )
            for user in data:
                if user.get("user") == username:
                    if user_info in user:
                        data_user = user[user_info]

            return data_user
        #         return f"Usuário não encontrado: {username}"
        # else:
        #     return "Arquivo de Configuração Inválido"

    @staticmethod
    def process_login(server_name, user):
        print(f"{CommonsRH.head_log()} Buscando dados para Login.")
        password = SistemaLogin.get_user_info(user, "password")
        app_url = ServerData.get_server_info(server_name, "app_url") + "/auth/login"
        payload = {"user": user, "password": password}
        print(f"{CommonsRH.head_log()} Enviando requisição de login.")
        token_raw = Requisitions.requisitions(app_url, "post", payloads=payload)
        return token_raw.text  # type: ignore

    @staticmethod
    def extract_token(server_name, username):
        print(f"{CommonsRH.head_log()} Processando retorno para extrar TOKEN.")
        html = SistemaLogin.process_login(server_name, username)
        soup = BeautifulSoup(html, "html.parser")
        data = soup.find("script").text  # type: ignore
        start_index = data.find("token=") + len("token=")
        end_index = data.find("&", start_index)
        token = data[start_index:end_index]
        return token

    @staticmethod
    def update_token(username, token):
        data = FileManager.read_json(USERS)
        for user in data["users"]:
            if user["user"] == username:
                user["token"] = token
                user["token_update"] = f"{CommonsRH.time_update()}"
                user["token_expire"] = f"{CommonsRH.time_update(expire=True)}"
            print(f"{CommonsRH.head_log()} Atualizando TOKEN no arquivo: '{USERS}'.")
            FileManager.update_json(USERS, data)
        print(f"{CommonsRH.head_log()} TOKEN Atualizado: '{USERS}'.")
        return "Updated successfully."

    # return "User not found."

    @staticmethod
    def token(server_name, username):
        token_expire = SistemaLogin.get_user_info(username, "token_expire")
        if token_expire is not None:
            print(f"{CommonsRH.head_log()} Obtendo validade do TOKEN salvo.")
            token_expire = datetime.strptime(token_expire, "%Y-%m-%d %H:%M:%S.%f")
        if token_expire is None or token_expire < CommonsRH.time_update():
            print(f"{CommonsRH.head_log()} TOKEN Vazio ou Expirado. Requisitando novo.")
            token = SistemaLogin.extract_token(server_name, username)
            SistemaLogin.update_token(username, token)
        else:
            print(f"{CommonsRH.head_log()} TOKEN valido encontrado localmente.")
            token = SistemaLogin.get_user_info(username, "token")
        return token
