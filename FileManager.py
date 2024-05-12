from CommonsRH import CommonsRH
import json


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
