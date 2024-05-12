from Conf import BASE_DIR, FILES_USERS
from SistemaLogin import SistemaLogin
from ServerData import ServerData
from Requisitions import Requisitions
from CommonsRH import CommonsRH
from FileManager import FileManager
from datetime import datetime
from colorama import Fore
import os


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
