from Conf import SERVERS
from CommonsRH import CommonsRH
from FileManager import FileManager
from Requisitions import Requisitions
import json


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
