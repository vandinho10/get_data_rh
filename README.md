# GET_DATA_RH

### Sistema para obter dados do usuarios no sistema MeuRH - TOTVS

O sistema foi desenvolvido em Python com o intuito de facilitar ao colaborador obter os dados salvas no sistema MeuRH TOTVS.

> Para correto funcionamento é necessario alguns ajustes nos arquivos de *"conf/servers.json"* e *"conf/users.json"*.

> No arquivo *"conf/servers.json"* altere os valores das chaves :

    "server_name": "Nome da sua empresa",
    "server_propertie_url": "https://URL_DO_ARQUIVO_DE_CONFIGURAÇÂO:8138/01/properties.json",

> No arquivo *"conf/users.json"* altere os valores das chaves:


    "user": "SEU_USUARIO",
    "password": "SUA_SENHA",

#### OS DADOS APRESENTADOS ACIMA SÃO TODOS, CORRIJA DE ACORDO COM O SISTEMA QUE PRETENDE OBTER OS DADOS.

Os arquivos que estão configurados atualmente para serem obtidos do sistema são:

    >> Dados do Usuario (user_profile)
    >> Folha Ponto (timesheets).
    >> Holerite (payment_report).


PS.: Não sou profissional na area de desenvolvimento. Estou aprendendo no meu tempo livre.
Criticas construtivas serão muito bem vindas.