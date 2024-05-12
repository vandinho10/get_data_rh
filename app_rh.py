#!/usr/bin/env python3
from CommonsRH import CommonsRH
from UserProfile import UserProfile
from Timesheets import Timesheets
from Payments import Payments


usernames, servers = CommonsRH.get_data_for_loop()

for server in servers:
    for username in usernames:
        Payments.process(username=username, servername=server)
        Timesheets.report_process(username=username, servername=server)
        UserProfile.user_profile_update(username=username, server_name=server)
