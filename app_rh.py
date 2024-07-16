#!/usr/bin/env python3
import inspect
import json
import os
import requests
import urllib3
from bs4 import BeautifulSoup
from colorama import Fore, Style
from datetime import datetime, timedelta

# CONSTANTS
BASE_DIR = os.path.dirname(__file__)
TIME_EXPIRE = 15
os.chdir(BASE_DIR)

# Files CONF
SERVERS = f"{BASE_DIR}/conf/servers.json"
USERS = f"{BASE_DIR}/conf/users.json"
FILES_USERS = f"{BASE_DIR}/conf/files.json"
PERIODS = f"{BASE_DIR}/conf/periods.json"


class CommonsRH:
    @staticmethod
    def head_log() -> str:
        """
        Cria um cabeçalho de log com a data, hora, nome do método e nome da classe (se aplicável).

        Returns:
            str: O cabeçalho de log formatado.
        """
        frame = inspect.currentframe().f_back  # type: ignore
        actual_method = frame.f_code.co_name  # type: ignore
        caller_locals = frame.f_locals  # type: ignore
        actual_class = caller_locals.get("__qualname__", None)

        if actual_class:
            report_head = f"{Fore.LIGHTWHITE_EX}{datetime.now()} | {Fore.GREEN}{Style.BRIGHT}{actual_class}.{actual_method} | {Style.RESET_ALL}"
        else:
            report_head = f"{Fore.LIGHTWHITE_EX}{datetime.now()} | {Fore.GREEN}{Style.BRIGHT}{actual_method} | {Style.RESET_ALL}"
        return report_head

    @staticmethod
    def time_update(expire: bool = False) -> datetime:
        """
        Retorna a data e hora atual ou a data e hora atual mais um tempo de expiração.

        Args:
            expire (bool, optional): Indica se um tempo de expiração deve ser adicionado. Defaults to False.

        Returns:
            datetime: A data e hora atual.
        """
        if expire:
            print(f"{CommonsRH.head_log()} Calculando tempo de expiração do Cookie")
            datetime_atual = datetime.now() + timedelta(minutes=TIME_EXPIRE)
        else:
            print(f"{CommonsRH.head_log()} Obtendo hora Atual")
            datetime_atual = datetime.now()

        return datetime_atual

    @staticmethod
    def month_name(month: str) -> str:
        """
        Obtém o nome abreviado de um mês com base no seu número.

        Args:
            month (str): O número do mês.

        Returns:
            str: O nome abreviado do mês.
        """
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
        print(f"{CommonsRH.head_log()} Obtendo nome do mês a partir do numeral.")
        nome_mes = data.get(month)
        return nome_mes  # type: ignore

    @staticmethod
    def user_dir(username: str) -> str:
        """
        Obtém o caminho do diretório do usuário com base no nome de usuário fornecido.

        Args:
            username (str): O nome de usuário.

        Returns:
            str: O caminho do diretório do usuário.
        """
        print(f"{CommonsRH.head_log()} Definindo o diretorio do usuario: '{username}'")
        user_dir = f"user/{username}"
        return user_dir

    @staticmethod
    def make_dir(file_path: str) -> None:
        """
        Cria diretórios recursivamente se eles não existirem.

        Args:
            file_path (str): O caminho do diretório a ser criado.

        Returns:
            None
        """
        print(f"{CommonsRH.head_log()} Criando pasta se ela não existir")
        os.makedirs(os.path.dirname(file_path), exist_ok=True)

    @staticmethod
    def get_data_for_loop() -> tuple[list[str], list[str]]:
        """
        Obtém dados de usuários e servidores de arquivos JSON e retorna listas de nomes de usuário e nomes de servidor.

        Returns:
            Tuple[List[str], List[str]]: Uma tupla contendo duas listas, a primeira contendo nomes de usuário e a segunda contendo nomes de servidor.
        """
        print(f"{CommonsRH.head_log()} Obtendo dados de usuários e servidores...")

        servers_data = FileManager.read_json(SERVERS)
        users_data = FileManager.read_json(USERS)

        usernames = []  # Lista para armazenar os nomes de usuário
        servernames = []  # Lista para armazenar os nomes de servidor

        if "users" in users_data:
            users = users_data["users"]

            for user in users:
                username = user.get("user")
                if username:
                    usernames.append(username)

        if "servers" in servers_data:
            servers = servers_data["servers"]

            for server in servers:
                servername = server.get("server_name")
                if servername:
                    servernames.append(servername)

        print(
            f"{CommonsRH.head_log()} Dados de usuários e servidores obtidos com sucesso."
        )

        return usernames, servernames


class FileManager:
    @staticmethod
    def read_json(file_name: str) -> dict:
        """
        Lê dados de um arquivo JSON.

        Args:
            file_name (str): O nome do arquivo JSON.

        Returns:
            dict: Os dados lidos do arquivo JSON.
        """
        print(f"{CommonsRH.head_log()} Fazendo leitura do JSON: '{file_name}'")
        with open(file_name) as file:
            file_data = json.load(file)
        return file_data

    @staticmethod
    def update_json(file_name: str, data: dict) -> None:
        """
        Atualiza um arquivo JSON com os dados fornecidos.

        Args:
            file_name (str): O nome do arquivo JSON.
            data (dict): Os novos dados a serem escritos no arquivo JSON.

        Returns:
            None
        """
        print(f"{CommonsRH.head_log()} Atualizando dados do JSON: '{file_name}'")
        with open(file_name, "w") as file:
            json.dump(data, file, indent=4)

    @staticmethod
    def save_pdf(file_name: str, data: bytes) -> None:
        """
        Salva dados em um arquivo PDF.

        Args:
            file_name (str): O nome do arquivo PDF.
            data (bytes): Os dados a serem escritos no arquivo PDF.

        Returns:
            None
        """
        print(f"{CommonsRH.head_log()} Salvando arquivo PDF: '{file_name}'")
        with open(file_name, "wb") as file:
            file.write(data)


class ServerData:
    @staticmethod
    def server_data_valid() -> str:
        """
        Valida os dados do arquivo de configuração do servidor.

        Returns:
            str: Os dados dos servidores em formato JSON, se o arquivo for válido.
                 Uma mensagem de erro se o arquivo de configuração for inválido.
        """
        print(f"{CommonsRH.head_log()} Solicitado leitura do arquivo: '{SERVERS}'.")
        data = FileManager.read_json(SERVERS)
        if data.get("servers"):
            print(f"{CommonsRH.head_log()} Dados obtidos.")
            return json.dumps(data["servers"])
        else:
            print(
                f"{CommonsRH.head_log()} Erro ao Obter os Dados - Arquivo de Configuração Inválido."
            )
            return "Arquivo de Configuração Inválido."

    @staticmethod
    def get_server_info(servername: str, property_name: str) -> str:
        """
        Obtém informações específicas de um servidor a partir de seu nome.

        Args:
            server_name (str): O nome do servidor.
            property_name (str): O nome da propriedade que deseja recuperar.

        Returns:
            str: O valor da propriedade se encontrado.
                 Uma mensagem de erro se o servidor não for encontrado ou a propriedade não existir.
        """
        data = json.loads(ServerData.server_data_valid())
        print(f"{CommonsRH.head_log()} Buscando dados do servidor: '{servername}'.")
        if data and not data == [{}]:
            for server in data:
                if server.get("server_name") == servername:
                    if property_name in server:
                        print(
                            f"{CommonsRH.head_log()} Dados localizados: '{servername}'."
                        )
                        return server[property_name]
            print(
                f"{CommonsRH.head_log()} Servidor não cadastrado: '{servername}' - '{property_name}'."
            )
            return f"Servidor não cadastrado: {servername} - {property_name}"
        else:
            print(
                f"{CommonsRH.head_log()} Erro ao Obter os Dados - Arquivo de Configuração Inválido."
            )
            return "Arquivo de Configuração Inválido"

    @staticmethod
    def update_base_url(servername: str, app_url: str) -> str:
        """
        Atualiza a URL base de um servidor.

        Args:
            server_name (str): O nome do servidor.
            app_url (str): A nova URL base.

        Returns:
            str: Uma mensagem indicando se a atualização foi bem-sucedida ou não.
        """
        data = FileManager.read_json(SERVERS)
        for server in data["servers"]:
            if server["server_name"] == servername:
                server["app_url"] = app_url
                server["updated"] = f"{CommonsRH.time_update()}"
                FileManager.update_json(SERVERS, data)
                f"{CommonsRH.head_log()} Dados atualizados com sucesso: '{servername}'."
                return "Atualizado com sucesso."
        f"{CommonsRH.head_log()} Servidor não encontrado: '{servername}'."
        return "Servidor não encontrado."

    @staticmethod
    def get_app_url(servername: str) -> str:
        """
        Obtém a URL da aplicação de um servidor.

        Args:
            server_name (str): O nome do servidor.

        Returns:
            str: Uma mensagem indicando se a URL foi obtida com sucesso ou não.
        """
        print(f"{CommonsRH.head_log()} Buscando dados do servidor: '{servername}'.")
        server_data = ServerData.get_server_info(servername, "server_propertie_url")
        print(f"{CommonsRH.head_log()} Buscando dados do remotamente: '{servername}'.")
        response = Requisitions.requisitions(server_data)
        properties_data = response.json()  # type: ignore
        if "PROPS" in properties_data and "baseUrl" in properties_data["PROPS"]:
            base_url = properties_data["PROPS"]["baseUrl"]
            print(
                f"{CommonsRH.head_log()} Atualizando dados do servidor: '{servername}'."
            )
            return ServerData.update_base_url(servername, base_url)
        else:
            return 'Erro ao atualizar "app_url".'


class UserProfile:
    @staticmethod
    def user_profile_get(servername: str, username: str) -> dict:
        """
        Obtém o perfil do usuário de um determinado servidor.

        Args:
            servername (str): O nome do servidor.
            username (str): O nome de usuário.

        Returns:
            dict: Dados do perfil do usuário em formato JSON.
        """
        print(
            f"{CommonsRH.head_log()} Obtendo perfil do usuário de '{servername}' para '{username}'."
        )
        token = SistemaLogin.main(servername, username)
        base_url = (
            ServerData.get_server_info(servername, "app_url")
            + "/data/profile/summary/%7Bcurrent%7D/?"
        )
        user_data = Requisitions.requisitions(base_url, headers=token)
        print(f"{CommonsRH.head_log()} Perfil do usuário obtido com sucesso.")
        return user_data.json()  # type: ignore

    @staticmethod
    def user_profile_process(servername: str, username: str) -> tuple:
        """
        Processa os dados do perfil do usuário.

        Args:
            servername (str): O nome do servidor.
            username (str): O nome de usuário.

        Returns:
            tuple: Uma tupla contendo ID, nome, descrição da função, data de admissão e data de nascimento do usuário.
        """
        print(
            f"{CommonsRH.head_log()} Processando perfil do usuário de '{servername}' para '{username}'."
        )
        data = UserProfile.user_profile_get(servername, username)
        users_profiles = json.loads(json.dumps(data))
        id = users_profiles["data"]["id"].split("|")[1]
        name = users_profiles["data"]["name"]
        role_description = users_profiles["data"]["roleDescription"]
        admission_date = users_profiles["data"]["admissionDate"]
        born_date = users_profiles["data"]["bornDate"]
        print(f"{CommonsRH.head_log()} Perfil do usuário processado com sucesso.")
        return id, name, role_description, admission_date, born_date

    @staticmethod
    def main(servername: str, username: str) -> str:
        """
        Atualiza os dados do perfil do usuário.

        Args:
            servername (str): O nome do servidor.
            username (str): O nome de usuário.

        Returns:
            str: Uma mensagem indicando que a atualização foi bem-sucedida.
        """
        print(
            f"{CommonsRH.head_log()} Atualizando perfil do usuário de {servername} para {username}."
        )
        id, name, role_description, admission_date, born_date = (
            UserProfile.user_profile_process(servername, username)
        )
        data = FileManager.read_json(USERS)
        for user in data["users"]:
            if user["user"] == username:
                user["id_rh"] = id
                user["name"] = name
                user["role_description"] = role_description
                user["admission_date"] = admission_date
                user["born_date"] = born_date
                user["updated"] = f"{CommonsRH.time_update()}"
                FileManager.update_json(USERS, data)
                print(
                    f"{CommonsRH.head_log()} Perfil do usuário atualizado com sucesso."
                )
        return "Updated successfully."


class SistemaLogin:
    @staticmethod
    def user_data_valid() -> str:
        """
        Valida os dados de usuário do arquivo de configuração.

        Returns:
            str: Os dados dos usuários em formato JSON, se o arquivo for válido.
                 Uma mensagem de erro se o arquivo de configuração for inválido.
        """
        print(f"{CommonsRH.head_log()} Buscando dados para Efetuar Login.")
        data = FileManager.read_json(USERS)
        if data.get("users"):
            return json.dumps(data["users"])
        else:
            print(
                f"{CommonsRH.head_log()} Arquivo de configuração inválido: '{USERS}'."
            )
            return "Arquivo de Configuração Inválido."

    @staticmethod
    def get_user_info(username: str, user_info: str):
        """
        Obtém informações específicas de um usuário a partir do nome de usuário.

        Args:
            username (str): O nome de usuário.
            user_info (str): O tipo de informação do usuário que deseja recuperar.

        Returns:
            str: O valor da informação do usuário se encontrado.
                 Uma mensagem de erro se o usuário não for encontrado ou a informação não existir.
        """
        data = json.loads(SistemaLogin.user_data_valid())
        if data and not data == [{}]:
            print(
                f"{CommonsRH.head_log()} Processando dados de usuário para efetuar Login."
            )
            for user in data:
                if user.get("user") == username:
                    if user_info in user:
                        data_user = user[user_info]

            return data_user

    @staticmethod
    def process_login(servername: str, username: str) -> str:
        """
        Processa o login do usuário em um determinado servidor.

        Args:
            servername (str): O nome do servidor.
            user (str): O nome de usuário.

        Returns:
            str: O token de autenticação se o login for bem-sucedido.
        """
        print(f"{CommonsRH.head_log()} Buscando dados para Login.")
        password = SistemaLogin.get_user_info(username, "password")
        app_url = ServerData.get_server_info(servername, "app_url") + "/auth/login"
        payload = {"user": username, "password": password}
        print(f"{CommonsRH.head_log()} Enviando requisição de login.")
        token_raw = Requisitions.requisitions(app_url, "post", payloads=payload)
        return token_raw.text  # type: ignore

    @staticmethod
    def extract_token(servername: str, username: str) -> str:
        """
        Extrai o token de autenticação do HTML retornado após o login.

        Args:
            servername (str): O nome do servidor.
            username (str): O nome de usuário.

        Returns:
            str: O token de autenticação.
        """
        print(f"{CommonsRH.head_log()} Processando retorno para extrair TOKEN.")
        html = SistemaLogin.process_login(servername, username)
        soup = BeautifulSoup(html, "html.parser")
        data = soup.find("script").text  # type: ignore
        start_index = data.find("token=") + len("token=")
        end_index = data.find("&", start_index)
        token = data[start_index:end_index]
        return token

    @staticmethod
    def update_token(username: str, token: str) -> str:
        """
        Atualiza o token de autenticação do usuário no arquivo de configuração.

        Args:
            username (str): O nome de usuário.
            token (str): O novo token de autenticação.

        Returns:
            str: Uma mensagem indicando se a atualização foi bem-sucedida ou não.
        """
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

    @staticmethod
    def main(servername: str, username: str):
        """
        Obtém o token de autenticação do usuário para um determinado servidor.

        Args:
            servername (str): O nome do servidor.
            username (str): O nome de usuário.

        Returns:
            str: O token de autenticação.
        """
        token_expire = SistemaLogin.get_user_info(username, "token_expire")
        if token_expire is not None:
            print(f"{CommonsRH.head_log()} Obtendo validade do TOKEN salvo.")
            token_expire = datetime.strptime(token_expire, "%Y-%m-%d %H:%M:%S.%f")
        if token_expire is None or token_expire < CommonsRH.time_update():
            print(f"{CommonsRH.head_log()} TOKEN Vazio ou Expirado. Requisitando novo.")
            token = SistemaLogin.extract_token(servername, username)
            SistemaLogin.update_token(username, token)
        else:
            print(f"{CommonsRH.head_log()} TOKEN válido encontrado localmente.")
            token = SistemaLogin.get_user_info(username, "token")
        return token


class Requisitions:
    @staticmethod
    def requisitions(
        url: str,
        type: str = "get",
        headers=None,
        payloads=None,
        binary: bool = False,
    ):
        """
        Realiza uma requisição HTTP para a URL especificada.

        Args:
            url (str): A URL para a qual a requisição será feita.
            type (str, optional): O tipo de requisição HTTP a ser realizada, 'get' por padrão.
                                  Pode ser 'get' ou 'post'.
            headers (dict, optional): Os cabeçalhos HTTP a serem enviados com a requisição, None por padrão.
            payloads (dict, optional): Os payloads a serem enviados com a requisição, None por padrão.
            binary (bool, optional): Indica se a resposta deve ser tratada como dados binários, False por padrão.

        Returns:
            Union[bytes, dict]: Os dados da resposta. Se `binary` for True, retorna os dados binários.
                                Caso contrário, retorna um dicionário com os dados JSON da resposta.
        """
        # Desativa o aviso do urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        print(f"{CommonsRH.head_log()} Iniciando acesso para '{url}'")
        if headers is None:
            headers = {}
        elif headers:
            headers = {"Authorization": f"Bearer {headers}"}
        if payloads is None:
            payloads = {}

        if type.lower() == "get":
            print(f"{CommonsRH.head_log()} Definindo tipo de acesso: '{type}'")
            req_response = requests.get(
                url, headers=headers, json=payloads, verify=False
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


class Payments:
    @staticmethod
    def payments_periods_get(servername: str, username: str) -> dict:
        """
        Obtém os períodos de pagamento para um usuário em um servidor.

        Args:
            servername (str): O nome do servidor.
            username (str): O nome de usuário.

        Returns:
            dict: Dados dos períodos de pagamento em formato JSON.
        """
        print(
            f"{CommonsRH.head_log()} Obtendo períodos de pagamento para o usuário '{username}' no servidor '{servername}'."
        )
        token = SistemaLogin.main(servername, username)
        base_url = (
            ServerData.get_server_info(servername, "app_url")
            + "/payment/payments/%7Bcurrent%7D/?initView=2010-01-01T00:00:00.000Z&endView=2030-12-01T00:00:00.000Z"
        )
        user_data = Requisitions.requisitions(base_url, headers=token)
        print(f"{CommonsRH.head_log()} Períodos de pagamento obtidos com sucesso.")
        return user_data.json()  # type: ignore

    @staticmethod
    def payments_get_data(servername: str, username: str) -> list:
        """
        Processa os dados dos períodos de pagamento para um usuário em um servidor.

        Args:
            servername (str): O nome do servidor.
            username (str): O nome de usuário.

        Returns:
            list: Lista de dicionários contendo dados dos períodos de pagamento.
        """
        print(
            f"{CommonsRH.head_log()} Processando dados de pagamento para o usuário '{username}' no servidor '{servername}'."
        )
        data = Payments.payments_periods_get(servername, username)
        data_payments = []
        for period in data["data"]:
            payment_id = period["id"]
            payment_date = period["paymentDate"][:10]
            payment_ref = period["referenceDate"][:7]
            payment_value = period["value"]
            payment_type = period["type"].strip()
            data_payments.append(
                {
                    "payment_id": payment_id,
                    "payment_date": payment_date,
                    "payment_ref": payment_ref,
                    "payment_value": payment_value,
                    "payment_type": payment_type,
                }
            )
        print(f"{CommonsRH.head_log()} Dados de pagamento processados com sucesso.")
        return data_payments

    @staticmethod
    def payments_check_file_exists_in_json(
        username: str, file_type: str, payment_file: str, json_data: dict
    ) -> bool:
        """
        Verifica se um determinado arquivo de pagamento já existe no arquivo JSON.

        Args:
            username (str): O nome de usuário.
            file_type (str): O tipo de arquivo do pagamento ("pdf" ou "json").
            payment_file (str): O caminho do arquivo de pagamento.
            json_data (dict): Os dados JSON.

        Returns:
            bool: True se o arquivo de pagamento existir no JSON, False caso contrário.
        """
        print(
            f"{CommonsRH.head_log()} Verificando a existência do arquivo de pagamento no JSON."
        )
        payments = json_data[0]["payments"]
        for payment in payments:
            if (
                payment["user"] == username
                and payment["file_type"] == file_type
                and payment["payment_file"] == payment_file
            ):
                print(
                    f"{CommonsRH.head_log()} O arquivo de pagamento já existe no JSON."
                )
                return True
        print(f"{CommonsRH.head_log()} O arquivo de pagamento não existe no JSON.")
        return False

    @staticmethod
    def payments_report(servername: str, username: str, id: str, file_type: str):
        """
        Gera um relatório de pagamento para um usuário em um servidor.

        Args:
            servername (str): O nome do servidor.
            username (str): O nome de usuário.
            id (str): O ID do pagamento.
            file_type (str): O tipo de arquivo do relatório ("pdf" ou "json").

        Returns:
            bytes or dict: O relatório de pagamento em bytes (se for PDF) ou em formato JSON (se for JSON).
        """
        print(
            f"{CommonsRH.head_log()} Gerando relatório de pagamento para o usuário {username} no servidor {servername}."
        )
        token = SistemaLogin.main(servername, username)
        if file_type == "pdf":
            endpoint = f"/payment/payments/report/%7Bcurrent%7D/{id}"
            binary_file = True
        elif file_type == "json":
            endpoint = f"/payment/detail/{id}"
            binary_file = False

        base_url = ServerData.get_server_info(servername, "app_url") + endpoint
        user_data = Requisitions.requisitions(
            base_url, headers=token, binary=binary_file
        )
        print(f"{CommonsRH.head_log()} Relatório de pagamento gerado com sucesso.")
        return user_data

    @staticmethod
    def payments_call_download(
        servername: str, username: str, file_name: str, file_type: str, payment_id: str
    ) -> str:
        """
        Baixa o arquivo de pagamento para um usuário.

        Args:
            servername (str): O nome do servidor.
            username (str): O nome de usuário.
            file_name (str): O nome do arquivo.
            file_type (str): O tipo de arquivo ("pdf" ou "json").
            payment_id (str): O ID do pagamento.

        Returns:
            str: O caminho do arquivo baixado.
        """
        print(
            f"{CommonsRH.head_log()} Baixando arquivo de pagamento para o usuário {username}."
        )
        file_path = f"{file_name}"
        while not os.path.exists(file_path):
            alfa_zero = Payments.payments_report(
                servername, username, payment_id, file_type
            )
            file_path = os.path.join(BASE_DIR, file_name)
            CommonsRH.make_dir(f"{file_name}")

            if file_type == "pdf":
                FileManager.save_pdf(file_path, alfa_zero)  # type: ignore
            elif file_type == "json":
                FileManager.update_json(file_path, alfa_zero.json())  # type: ignore
            print(f"{CommonsRH.head_log()} Arquivo de pagamento criado em: {file_path}")
        print(f"{CommonsRH.head_log()} Arquivo de pagamento baixado com sucesso.")
        return file_path

    @staticmethod
    def payments_add_data_to_json(
        username: str,
        file_type: str,
        payment_file: str,
        payment_ref: str,
        payment_type: str,
        json_data: dict,
    ) -> None:
        """
        Adiciona dados do pagamento ao arquivo JSON.

        Args:
            user (str): O nome de usuário.
            file_type (str): O tipo de arquivo do pagamento ("pdf" ou "json").
            payment_file (str): O caminho do arquivo de pagamento.
            payment_ref (str): A referência do pagamento.
            payment_type (str): O tipo de pagamento.
            json_data (dict): Os dados JSON.

        Returns:
            None
        """
        if not Payments.payments_check_file_exists_in_json(
            username, file_type, payment_file, json_data
        ):
            new_data = {
                "user": username,
                "payment_type": payment_type,
                "payment_ref": payment_ref,
                "file_type": file_type,
                "imported": True,
                "imported_datetime": f"{datetime.now()}",
                "payment_file": payment_file,
            }
            json_data[0]["payments"].append(new_data)
            FileManager.update_json(FILES_USERS, json_data)
            print(f"{CommonsRH.head_log()} Dados adicionados ao JSON com sucesso.")

    @staticmethod
    def sort_json_data(json_data: dict) -> None:
        """
        Ordena os dados no arquivo JSON.

        Args:
            json_data (dict): Os dados JSON a serem ordenados.

        Returns:
            None
        """
        json_data[0]["payments"] = sorted(
            json_data[0]["payments"], key=lambda x: (x["user"], x["payment_file"])
        )

    @staticmethod
    def main(servername: str, username: str) -> None:
        """
        Inicia o processamento de pagamentos para um usuário em um servidor.

        Args:
            servername (str): O nome do servidor.
            username (str): O nome de usuário.

        Returns:
            None
        """
        print(
            f"{CommonsRH.head_log()} Iniciando processamento de pagamento para o usuário {username} no servidor {servername}."
        )
        json_data = FileManager.read_json(FILES_USERS)
        files_names = Payments.payments_get_data(servername, username)

        for payment in files_names:
            payment_id = payment["payment_id"]
            payment_ref = payment["payment_ref"]
            payment_type = payment["payment_type"]

            for file_type in ["json", "pdf"]:
                file_name = f"{CommonsRH.user_dir(username)}/{payment_ref[:4]}/{payment_ref[5:]}_{CommonsRH.month_name(payment_ref[5:])}_Payment_{payment_type}.{file_type}"

                file_path = Payments.payments_call_download(
                    servername, username, file_name, file_type, payment_id
                )
                print(f"{CommonsRH.head_log()} Arquivo completo em: {file_path}")
                if os.path.exists(file_path):
                    if not Payments.payments_check_file_exists_in_json(
                        username, file_type, file_path, json_data
                    ):
                        Payments.payments_add_data_to_json(
                            username,
                            file_type,
                            file_path,
                            payment_ref,
                            payment_type,
                            json_data,
                        )
        Payments.sort_json_data(json_data)
        FileManager.update_json(FILES_USERS, json_data)
        print(f"{CommonsRH.head_log()} Processamento de pagamento concluído.")


class Timesheets:
    @staticmethod
    def timesheet_periods_get(servername: str, username: str) -> dict:
        """
        Obtém os períodos de folha de ponto para um determinado servidor e usuário.

        Args:
            server_name (str): O nome do servidor.
            username (str): O nome de usuário.

        Returns:
            dict: Os períodos de folha de ponto em formato JSON.
        """
        token = SistemaLogin.main(servername, username)
        base_url = (
            ServerData.get_server_info(servername, "app_url")
            + "/timesheet/periods/%7Bcurrent%7D"
        )
        user_data = Requisitions.requisitions(base_url, headers=token)
        return user_data.json()  # type: ignore

    @staticmethod
    def timesheet_periods_process(servername: str, username: str) -> list:
        """
        Processa os períodos de folha de ponto para um determinado servidor e usuário.

        Args:
            server_name (str): O nome do servidor.
            username (str): O nome de usuário.

        Returns:
            list: Uma lista de dicionários contendo os períodos de folha de ponto processados.
        """
        data = Timesheets.timesheet_periods_get(servername, username)
        data_include = []
        for period in data["items"]:
            if not period["actualPeriod"]:
                period_ref = period["initDate"][:7]
                period_init = period["initDate"]
                period_end = period["endDate"]
                data_include.append(
                    {
                        "period_ref": period_ref,
                        "period_init": period_init,
                        "period_end": period_end,
                        "inserted": f"{CommonsRH.time_update()}",
                    }
                )
        return data_include

    @staticmethod
    def timesheet_periods_valids(servername: str, username: str) -> list:
        """
        Valida os períodos de folha de ponto para um determinado servidor e usuário.

        Args:
            server_name (str): O nome do servidor.
            username (str): O nome de usuário.

        Returns:
            list: Uma lista de dicionários contendo os períodos de folha de ponto válidos.
        """
        data = Timesheets.timesheet_periods_process(servername, username)
        data_valid = FileManager.read_json(PERIODS)

        valid_period_refs = [
            period["period_ref"] for period in data_valid.get("periods", [])
        ]

        periods_valid = [
            {
                "period_ref": period["period_ref"],
                "period_init": period["period_init"],
                "period_end": period["period_end"],
            }
            for period in data
            if period["period_ref"] not in valid_period_refs
        ]
        return periods_valid

    @staticmethod
    def timesheet_periods_include(servername: str, username: str) -> str:
        """
        Inclui os períodos de folha de ponto válidos para um determinado servidor e usuário.

        Args:
            server_name (str): O nome do servidor.
            username (str): O nome de usuário.

        Returns:
            str: Uma mensagem indicando se a inclusão foi bem-sucedida ou não.
        """
        periods_valid = Timesheets.timesheet_periods_valids(servername, username)
        data = FileManager.read_json(PERIODS)

        for period in periods_valid:
            period["inserted"] = f"{CommonsRH.time_update()}"

        data["periods"].extend(periods_valid)
        FileManager.update_json(PERIODS, data)

        return "Updated successfully."

    @staticmethod
    def timesheet_report(
        servername: str, username: str, period_init: str, period_end: str
    ):
        """
        Gera o relatório de folha de ponto para um determinado servidor, usuário e período.

        Args:
            server_name (str): O nome do servidor.
            username (str): O nome de usuário.
            period_init (str): A data de início do período.
            period_end (str): A data de término do período.

        Returns:
            bytes: Os dados do relatório de folha de ponto em formato binário.
        """
        token = SistemaLogin.main(servername, username)
        base_url = (
            ServerData.get_server_info(servername, "app_url")
            + "/timesheet/clockings/report/%7Bcurrent%7D/?initPeriod="
            + period_init
            + "&endPeriod="
            + period_end
            + "&id="
        )
        user_data = Requisitions.requisitions(
            base_url, "get", headers=token, binary=True
        )
        return user_data

    @staticmethod
    def timesheets_outdated_periods(username: str) -> None:
        """
        Verifica se o arquivo de Periodos esta atualizado.
        Está sendo considerado arquivo de Periodos desatualizado se com modificação superior a 10 dias.

        Args:
            username (str): O nome de usuário.
        """
        # Obtem o data de modificação do Arquivo
        modification_time = os.path.getmtime(PERIODS)
        modification_date = datetime.fromtimestamp(modification_time)

        # Calcula a diferença entre a data atual e a data de modificação
        current_date = datetime.now()
        difference = current_date - modification_date

        # Verifica se a diferença é maior que 10 dias
        if difference.days > 10:
            print(f"{CommonsRH.head_log()} Arquivo de Periodos está Desatualizados")
            Timesheets.timesheet_periods_include(servername, username)
            print(f"{CommonsRH.head_log()} Arquivo de Periodos foi Atualizado.")
        else:
            print(f"{CommonsRH.head_log()} Arquivo de Periodos está Atualizado.")

    @staticmethod
    def main(servername: str, username: str) -> None:
        """
        Processa o relatório de folha de ponto para um determinado servidor e usuário.

        Args:
            servername (str): O nome do servidor.
            username (str): O nome de usuário.
        """
        Timesheets.timesheets_outdated_periods(username)
        admission_date = SistemaLogin.get_user_info(username, "admission_date")
        data = FileManager.read_json(PERIODS)["periods"]
        for period in data:
            if (
                period["period_init"] > admission_date
                and period["period_init"] > admission_date
            ):
                period_ref = period["period_ref"]
                period_init = period["period_init"]
                period_end = period["period_end"]

                file_name = f"{CommonsRH.user_dir(username)}/{period_ref[:4]}/{period_ref[5:]}_{CommonsRH.month_name(period_ref[5:])}_Timesheet.pdf"
                print(f"{CommonsRH.head_log()} {file_name}")

                CommonsRH.make_dir(f"{file_name}")

                if os.path.exists(file_name):
                    files_data = FileManager.read_json(FILES_USERS)
                    timesheets_data = None

                    for entry in files_data:
                        if "timesheets" in entry:
                            timesheets_data = entry["timesheets"]
                            break

                    if timesheets_data is None:
                        timesheets_data = []

                    for item in timesheets_data:
                        if item["user"] == username and (
                            item["timesheet_ref"] == period_ref
                            or item["timesheet_file"] == file_name
                        ):
                            if not item["imported"] or not item.get(
                                "imported_datetime"
                            ):
                                item["user"] = username
                                item["imported"] = True
                                item["imported_datetime"] = f"{CommonsRH.time_update()}"
                                item["timesheet_file"] = file_name
                                FileManager.update_json(FILES_USERS, files_data)
                                break
                            else:
                                break
                    else:
                        FileManager.save_pdf(
                            os.path.join(BASE_DIR, file_name),
                            Timesheets.timesheet_report(
                                servername, username, period_init, period_end
                            ),  # type: ignore
                        )
                        timesheets_data.append(
                            {
                                "user": username,
                                "imported": True,
                                "imported_datetime": f"{CommonsRH.time_update()}",
                                "timesheet_file": file_name,
                                "timesheet_ref": period_ref,
                            }
                        )
                        FileManager.update_json(FILES_USERS, files_data)
                else:
                    FileManager.save_pdf(
                        os.path.join(BASE_DIR, file_name),
                        Timesheets.timesheet_report(
                            servername, username, period_init, period_end
                        ),  # type: ignore
                    )

                    files_data = FileManager.read_json(FILES_USERS)
                    timesheets_data = None

                    for entry in files_data:
                        if "timesheets" in entry:
                            timesheets_data = entry["timesheets"]
                            break

                    if timesheets_data is None:
                        timesheets_data = []

                    for item in timesheets_data:
                        if item["user"] == username and (
                            item["timesheet_ref"] == period_ref
                            or item["timesheet_file"] == file_name
                        ):
                            item["imported"] = True
                            item["imported_datetime"] = f"{CommonsRH.time_update()}"
                            item["timesheet_file"] = file_name
                            item["timesheet_ref"] = period_ref
                            FileManager.update_json(FILES_USERS, files_data)
                            break
                    else:
                        timesheets_data.append(
                            {
                                "user": username,
                                "imported": True,
                                "imported_datetime": f"{CommonsRH.time_update()}",
                                "timesheet_file": file_name,
                                "timesheet_ref": period_ref,
                            }
                        )
                        FileManager.update_json(FILES_USERS, files_data)


def main():
    """
    Executa operações para cada usuário em cada servidor.

    Este script itera sobre os usuários e servidores obtidos da função get_data_for_loop em CommonsRH.
    Para cada combinação de usuário e servidor, executa as seguintes operações:
    - Chama o método main da classe Payments para atualizar os dados de pagamento do usuário no servidor.
    - Chama a função report_process da classe Timesheets para processar os relatórios de timesheets do usuário no servidor.
    - Chama o método main da classe UserProfile para atualizar os dados do perfil do usuário no servidor.
    """
    usernames, servers = CommonsRH.get_data_for_loop()

    for servername in servers:
        for username in usernames:
            Payments.main(servername, username)
            Timesheets.main(servername, username)
            UserProfile.main(servername, username)


if __name__ == "__main__":
    main()
