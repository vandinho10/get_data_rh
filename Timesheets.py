from Conf import PERIODS, FILES_USERS, BASE_DIR
from SistemaLogin import SistemaLogin
from ServerData import ServerData
from Requisitions import Requisitions
from CommonsRH import CommonsRH
from FileManager import FileManager
import os


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
