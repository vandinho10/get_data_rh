from Conf import TIME_EXPIRE, SERVERS, USERS
from FileManager import FileManager
import os
import inspect
from colorama import Fore, Style
from datetime import datetime, timedelta


class CommonsRH:
    @staticmethod
    def head_log():
        # Obtém o nome do método atual a partir da pilha de chamadas
        frame = inspect.currentframe().f_back  # type: ignore
        actual_method = frame.f_code.co_name  # type: ignore

        # Obtém o nome da classe atual a partir do contexto de execução
        caller_locals = frame.f_locals  # type: ignore
        actual_class = caller_locals.get("__qualname__", None)

        # Constrói o relatório de cabeçalho
        if actual_class:
            report_head = f"{Fore.LIGHTWHITE_EX}{datetime.now()} | {Fore.GREEN}{Style.BRIGHT}{actual_class}.{actual_method} | {Style.RESET_ALL}"
        else:
            report_head = f"{Fore.LIGHTWHITE_EX}{datetime.now()} | {Fore.GREEN}{Style.BRIGHT}{actual_method} | {Style.RESET_ALL}"
        return report_head

    @staticmethod
    def time_update(expire=False):
        # Se o parâmetro expire for True, adiciona um tempo de expiração
        if expire:
            # Aqui falta a definição da variável TIME_EXPIRE
            print(f"{CommonsRH.head_log()} Calculando tempo de expiração do Cookie")
            datetime_atual = datetime.now() + timedelta(minutes=TIME_EXPIRE)
        else:
            # Retorna a data e hora atual
            print(f"{CommonsRH.head_log()} Obtendo hora Atual")
            datetime_atual = datetime.now()

        return datetime_atual

    @staticmethod
    def month_name(month):  # add
        # Dicionário que mapeia números de mês para nomes de mês abreviados em português
        data = {
            "01": "Jan",
            "02": "Fev",
            "03": "Mar",
            "04": "Abr",
            "05": "Mai",
            "06": "Jun",
            "07": "Jul",
            "08": "Ago",
            "09": "Set",
            "10": "Out",
            "11": "Nov",
            "12": "Dez",
        }
        # Retorna o nome do mês correspondente ao número fornecido
        # print(f"{CommonsRH.head_log()} Obtendo nome do mês a partir do numeral.")

        nome_mes = data.get(month)
        return nome_mes

    @staticmethod
    def user_dir(username):  # add
        # Retorna o caminho do diretório do usuário com base no nome de usuário fornecido
        # print(f"{CommonsRH.head_log()} Definindo o diretorio do usuario: '{username}'")
        user_dir = f"user/{username}"
        return user_dir

    @staticmethod
    def make_dir(file_path):
        # Cria diretórios recursivamente se eles não existirem
        print(f"{CommonsRH.head_log()} Criando pasta se ela não existir")
        os.makedirs(os.path.dirname(file_path), exist_ok=True)

    @staticmethod
    def get_data_for_loop():
        servers_data = FileManager.read_json(SERVERS)
        users_data = FileManager.read_json(USERS)

        if "users" in users_data:
            users = users_data["users"]
            usernames = []  # Lista para armazenar os nomes de usuário

            for user in users:
                username = user.get("user")
                if username:
                    usernames.append(username)

        if "servers" in servers_data:
            servers = servers_data["servers"]
            servernames = []  # Lista para armazenar os servidores

            for server in servers:
                servername = server.get("server_name")
                if servername:
                    servernames.append(servername)

        return usernames, servernames
