#!/usr/bin/env python3
import os
import inspect
import json
import requests
import urllib3
from bs4 import BeautifulSoup
from colorama import Fore, Back, Style
from datetime import datetime, timedelta

# Disable urllib3's warning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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


class FileManager:
    @staticmethod
    def read_json(file_name: str) -> dict:
        print(f"{CommonsRH.head_log()} Fazendo leitura do JSON: '{file_name}'")
        with open(file_name) as file:
            file_data = json.load(file)
        return file_data

    @staticmethod
    def update_json(file_name: str, data: dict) -> None:
        print(f"{CommonsRH.head_log()} Atualizando dados do JSON: '{file_name}'")
        with open(file_name, "w") as file:
            json.dump(data, file, indent=4)

    @staticmethod
    def save_pdf(file_name: str, data) -> None:
        print(f"{CommonsRH.head_log()} Salvando arquivo PDF: '{file_name}'")
        with open(file_name, "wb") as file:
            file.write(data)


class Requisitions:
    @staticmethod
    def requisitions(url, type="get", headers=None, payloads=None, binary=False):
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


class ServerData:
    @staticmethod
    def server_data_valid():
        print(f"{CommonsRH.head_log()} Solicitado leitura do arquivo: '{SERVERS}'.")
        data = FileManager.read_json(SERVERS)
        if data.get("servers"):
            print(f"{CommonsRH.head_log()} Dados obtidos.")
            return json.dumps(data["servers"])
        else:
            print(
                f"{CommonsRH.head_log()} Erro ao Obter os Dados - Arquivo de Configuração Invalido."
            )
            return "Arquivo de Configuração Inválido."

    @staticmethod
    def get_server_info(server_name, property_name):
        data = json.loads(ServerData.server_data_valid())
        print(f"{CommonsRH.head_log()} Buscando dados do servidor: '{server_name}'.")
        if data and not data == [{}]:
            for server in data:
                if server.get("server_name") == server_name:
                    if property_name in server:
                        print(
                            f"{CommonsRH.head_log()} Dados do localizados: '{server_name}'."
                        )
                        return server[property_name]
            print(
                f"{CommonsRH.head_log()} Servidor não cadastrado: '{server_name}' - '{property_name}'."
            )
            return f"Servidor não cadastrado: {server_name} - {property_name}"
        else:
            print(
                f"{CommonsRH.head_log()} Erro ao Obter os Dados - Arquivo de Configuração Invalido."
            )
            return "Arquivo de Configuração Inválido"

    @staticmethod
    def update_base_url(server_name, app_url):
        data = FileManager.read_json(SERVERS)
        for server in data["servers"]:
            if server["server_name"] == server_name:
                server["app_url"] = app_url
                server["updated"] = f"{CommonsRH.time_update()}"
                FileManager.update_json(SERVERS, data)
                f"{CommonsRH.head_log()} Dados atualizados com sucesso: '{server_name}'."
                return "Atualizado com sucesso."
        f"{CommonsRH.head_log()} Servidor não encontrado: '{server_name}'."
        return "Servidor não encontrado."

    @staticmethod
    def get_app_url(server_name):
        print(f"{CommonsRH.head_log()} Buscando dados do servidor: '{server_name}'.")
        server_data = ServerData.get_server_info(server_name, "server_propertie_url")
        print(f"{CommonsRH.head_log()} Buscando dados do remotamente: '{server_name}'.")
        response = Requisitions.requisitions(server_data)
        properties_data = response.json()  # type: ignore
        if "PROPS" in properties_data and "baseUrl" in properties_data["PROPS"]:
            base_url = properties_data["PROPS"]["baseUrl"]
            print(
                f"{CommonsRH.head_log()} Atualizando dados do servidor: '{server_name}'."
            )
            return ServerData.update_base_url(server_name, base_url)
        else:
            return 'Erro ao atualizar "app_url".'


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


class UserProfile:
    @staticmethod
    def user_profile_get(server_name, username):
        token = SistemaLogin.token(server_name, username)
        base_url = (
            ServerData.get_server_info(server_name, "app_url")
            + "/data/profile/summary/%7Bcurrent%7D/?"
        )
        user_data = Requisitions.requisitions(base_url, headers=token)
        return user_data.json()  # type: ignore

    @staticmethod
    def user_profile_process(server_name, username):
        data = UserProfile.user_profile_get(server_name, username)
        users_profiles = json.loads(json.dumps(data))
        id = users_profiles["data"]["id"].split("|")[1]
        name = users_profiles["data"]["name"]
        role_description = users_profiles["data"]["roleDescription"]
        admission_date = users_profiles["data"]["admissionDate"]
        born_date = users_profiles["data"]["bornDate"]
        return id, name, role_description, admission_date, born_date

    @staticmethod
    def user_profile_update(server_name, username):
        id, name, role_description, admission_date, born_date = (
            UserProfile.user_profile_process(server_name, username)
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
        return "Updated successfully."
        # return "User not found."


class Timesheets:
    @staticmethod
    def timesheet_periods_get(server_name, username):
        token = SistemaLogin.token(server_name, username)
        base_url = (
            ServerData.get_server_info(server_name, "app_url")
            + "/timesheet/periods/%7Bcurrent%7D"
        )
        user_data = Requisitions.requisitions(base_url, headers=token)
        return user_data.json()  # type: ignore

    @staticmethod
    def timesheet_periods_process(server_name, username):
        data = Timesheets.timesheet_periods_get(server_name, username)
        data_include = []
        for period in data["items"]:
            if not period["actualPeriod"]:
                period_ref = period["initDate"][:7]
                period_init = period["initDate"]
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
    def timesheet_periods_valids(server_name, username):
        data = Timesheets.timesheet_periods_process(server_name, username)
        data_valid = FileManager.read_json(PERIODS)

        # Extrair os period_ref dos períodos válidos
        valid_period_refs = [
            period["period_ref"] for period in data_valid.get("periods", [])
        ]

        # Filtrar os períodos que têm period_ref não presentes nos períodos válidos
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
    def timesheet_periods_include(server_name, username):
        periods_valid = Timesheets.timesheet_periods_valids(server_name, username)
        data = FileManager.read_json(PERIODS)

        for period in periods_valid:
            period["inserted"] = f"{CommonsRH.time_update()}"

        # Extendendo a lista de períodos válidos em data["periods"] uma única vez
        data["periods"].extend(periods_valid)
        FileManager.update_json(PERIODS, data)

        return "Updated successfully."

    @staticmethod
    def timesheet_report(server_name, username, period_init, period_end):
        token = SistemaLogin.token(server_name, username)
        base_url = (
            ServerData.get_server_info(server_name, "app_url")
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
    def report_process(servername, username):
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

                # Realiza a montagem do nome do Arquivo.
                file_name = f"{CommonsRH.user_dir(username)}/{period_ref[:4]}/{period_ref[5:]}_{CommonsRH.month_name(period_ref[5:])}_Timesheet.pdf"
                print(f"{CommonsRH.head_log()} {file_name}")

                # Cria as pastas para salvar o arquivo, se essa não existir
                CommonsRH.make_dir(f"{file_name}")

                # Verificar se o arquivo do loop existe existe
                if os.path.exists(file_name):
                    # Se o Arquivo do Loop existe, executa os processos abaixo

                    # Ler os dados de FILES_USERS
                    files_data = FileManager.read_json(FILES_USERS)
                    timesheets_data = None

                    # Encontrar a entrada de timesheet para o usuário atual
                    for entry in files_data:
                        if "timesheets" in entry:
                            timesheets_data = entry["timesheets"]
                            break

                    # Se não houver entrada para timesheets, criar uma lista vazia
                    if timesheets_data is None:
                        timesheets_data = []

                    # Localiza os dados do user, timesheet_ref e timesheet_file
                    for item in timesheets_data:
                        if item["user"] == username and (
                            item["timesheet_ref"] == period_ref
                            or item["timesheet_file"] == file_name
                        ):
                            # Verifica se imported é false ou se imported_datetime é null
                            if not item["imported"] or not item.get(
                                "imported_datetime"
                            ):
                                # Atualizar o json
                                item["user"] = username
                                item["imported"] = True
                                item["imported_datetime"] = f"{CommonsRH.time_update()}"
                                item["timesheet_file"] = file_name
                                FileManager.update_json(FILES_USERS, files_data)
                                break
                            else:
                                break
                    else:
                        # Se não exister os dados no Json, fazer um novo download e inserir os dados no json
                        FileManager.save_pdf(
                            os.path.join(BASE_DIR, file_name),
                            Timesheets.timesheet_report(
                                servername, username, period_init, period_end
                            ),
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
                    # Se o Arquivo não existir
                    # Efetuar o Download do Arquivo
                    FileManager.save_pdf(
                        os.path.join(BASE_DIR, file_name),
                        Timesheets.timesheet_report(
                            servername, username, period_init, period_end
                        ),
                    )

                    # Ler os dados de FILES_USERS
                    files_data = FileManager.read_json(FILES_USERS)
                    timesheets_data = None

                    # Encontrar a entrada de timesheet para o usuário atual
                    for entry in files_data:
                        if "timesheets" in entry:
                            timesheets_data = entry["timesheets"]
                            break

                    # Se não houver entrada para timesheets, criar uma lista vazia
                    if timesheets_data is None:
                        timesheets_data = []

                    # Verifica se esses dados estão no JSON.
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
                        # Se o timesheet_ref não existir na lista, adicionar um novo item
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


class Payments:
    @staticmethod
    def payments_periods_get(server_name, username):
        token = SistemaLogin.token(server_name, username)
        base_url = (
            ServerData.get_server_info(server_name, "app_url")
            + "/payment/payments/%7Bcurrent%7D/?initView=2010-01-01T00:00:00.000Z&endView=2030-12-01T00:00:00.000Z"
        )
        user_data = Requisitions.requisitions(base_url, headers=token)
        return user_data.json()  # type: ignore

    @staticmethod
    def payments_get_data(server_name, username):
        data = Payments.payments_periods_get(server_name, username)
        data_payments = []
        for period in data["data"]:
            # if not period["actualPeriod"]:
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
        return data_payments

    @staticmethod
    def payments_report(server_name, username, id, file_type):
        token = SistemaLogin.token(server_name, username)
        if file_type == "pdf":
            endpoint = f"/payment/payments/report/%7Bcurrent%7D/{id}"
            binary_file = True
        elif file_type == "json":
            endpoint = f"/payment/detail/{id}"
            binary_file = False

        base_url = ServerData.get_server_info(server_name, "app_url") + endpoint
        user_data = Requisitions.requisitions(
            base_url, headers=token, binary=binary_file
        )
        return user_data

    @staticmethod
    def payments_check_file_exists_in_json(user, file_type, payment_file, json_data):
        payments = json_data[0]["payments"]
        for payment in payments:
            if (
                payment["user"] == user
                and payment["file_type"] == file_type
                and payment["payment_file"] == payment_file
            ):
                return True
        return False

    @staticmethod
    def payments_call_download(user, file_name, file_type, servername, payment_id):
        file_path = f"{file_name}"
        while not os.path.exists(file_path):
            # Se o arquivo não existir, cria um arquivo vazio
            alfa_zero = Payments.payments_report(
                servername, user, payment_id, file_type
            )
            file_path = os.path.join(BASE_DIR, file_name)
            CommonsRH.make_dir(f"{file_name}")

            if file_type == "pdf":
                FileManager.save_pdf(file_path, alfa_zero)
            elif file_type == "json":
                FileManager.update_json(file_path, alfa_zero.json())  # type: ignore
            print(
                f"{CommonsRH.head_log()} {Fore.YELLOW} Arquivo Criado:{Fore.RESET} {file_path}"
            )
        print(
            f"{CommonsRH.head_log()} {Fore.GREEN} Arquivo Existente:{Fore.RESET} {file_path}"
        )
        return file_path

    @staticmethod
    def payments_add_data_to_json(
        user, file_type, payment_file, payment_ref, payment_type, json_data
    ):
        # Verificar se os dados já existem no JSON
        if not Payments.payments_check_file_exists_in_json(
            user, file_type, payment_file, json_data
        ):
            # Adicionar dados ao JSON
            new_data = {
                "user": user,
                "payment_type": payment_type,
                "payment_ref": payment_ref,
                "file_type": file_type,
                "imported": True,
                "imported_datetime": f"{datetime.now()}",
                "payment_file": payment_file,
                # Adicionar outras chaves e valores conforme necessário
            }
            json_data[0]["payments"].append(new_data)
            FileManager.update_json(FILES_USERS, json_data)
            print(
                f"{CommonsRH.head_log()} {Fore.YELLOW}  Inserindo Dados no JSON...{Fore.RESET}"
            )

    @staticmethod
    def sort_json_data(json_data):
        # Ordenar os dados no JSON pelo nome de usuário e tipo de arquivo
        json_data[0]["payments"] = sorted(
            json_data[0]["payments"], key=lambda x: (x["user"], x["payment_file"])
        )

    @staticmethod
    def process(username, servername):
        json_data = FileManager.read_json(FILES_USERS)
        files_names = Payments.payments_get_data(servername, username)

        for payment in files_names:
            payment_id = payment["payment_id"]
            payment_ref = payment["payment_ref"]
            payment_type = payment["payment_type"]

            # for file_name in files_names:  # equivalent payment get data
            for file_type in ["json", "pdf"]:
                file_name = f"{CommonsRH.user_dir(username)}/{payment_ref[:4]}/{payment_ref[5:]}_{CommonsRH.month_name(payment_ref[5:])}_Payment_{payment_type}.{file_type}"

                file_path = Payments.payments_call_download(
                    username, file_name, file_type, servername, payment_id
                )
                print(
                    f"{CommonsRH.head_log()} {Fore.WHITE}Arquivo Completo :{Fore.RESET} {file_path}"
                )
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
        # Ordenar os dados no JSON antes de gravá-los no arquivo
        Payments.sort_json_data(json_data)
        # Gravar os dados ordenados no arquivo JSON
        FileManager.update_json(FILES_USERS, json_data)


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


usernames, servers = get_data_for_loop()

for server in servers:
    for username in usernames:
        Payments.process(username=username, servername=server)
        Timesheets.report_process(username=username, servername=server)
        UserProfile.user_profile_update(username=username, server_name=server)
