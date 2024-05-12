from Conf import USERS
from SistemaLogin import SistemaLogin
from ServerData import ServerData
from Requisitions import Requisitions
from FileManager import FileManager
from CommonsRH import CommonsRH
import json


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
