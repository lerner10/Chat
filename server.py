import socket
import select
import sqlite3
import random

# Import smtplib for the actual sending function
import smtplib

from email.MIMEMultipart import MIMEMultipart
from email.MIMEText import MIMEText

SPECIAL_SIGN = "^"
PORT_NUMBER = 8820

food_room_users_to_send = []
sport_room_users_to_send = []
gaming_room_users_to_send = []
movies_room_users_to_send = []

food_room_users_list = []
sport_room_users_list = []
gaming_room_users_list = []
movies_room_users_list = []


def sending_to_client(client_socket, parameters):
    data = ""
    for parameter in parameters:
        data += str(parameter) + SPECIAL_SIGN
    print "send to the client: " + data
    try:
        client_socket.send(data)
    except Exception, ex:
        print 'while trying to send message to client, he was disconnected.\n error: {0}'.format(ex.strerror)


def request_to_parameters(request_content):
    parameters = []
    num_of_parameters = request_content.count("^")
    for x in range(num_of_parameters):
        parameters.append(request_content[:request_content.index("^")])
        request_content = request_content[request_content.index("^") + 1:]
    return parameters


def get_username_by_socket(user_socket):
    for x in food_room_users_to_send:
        if x[1] == user_socket:
            return x[0], 'food'

    for x in gaming_room_users_to_send:
        if x[1] == user_socket:
            return x[0], 'gaming'

    for x in sport_room_users_to_send:
        if x[1] == user_socket:
            return x[0], 'sport'

    for x in movies_room_users_to_send:
        if x[1] == user_socket:
            return x[0], 'movies'
    return '',''


def user_exit(user_socket):
    username, room_name = get_username_by_socket(user_socket)

    if username == '' and room_name == '':
        return

    room_to_send = get_room_by_name_to_send(room_name)
    for tuple in room_to_send:
        if tuple[0] == username:
            room_to_send.remove(tuple)

    room_list = get_room_by_name_list(room_name)
    username_index = room_list.index(username)
    room_list.pop(username_index)
    room_list.pop(username_index)

    send_message_to_all_users_in_room(room_to_send, ['update_users'] + room_list)


def login(parameters, server_socket):
    validate = "True"
    error_msg = ""

    username, password = parameters[1:]
    connection = sqlite3.connect('tblUsers.db')
    cursor = connection.cursor()
    params = (username,)
    cursor.execute("SELECT usrPWD FROM tblUsers WHERE usrNickName = ?", params)
    user_password_from_db = cursor.fetchone()
    if not user_password_from_db:
        validate = "False"
        error_msg = "Username is incorrect"
    else:
        user_password_from_db = user_password_from_db[0]
        # if sha(password) != user_password_from_db:
        if password != user_password_from_db:
            validate = "False"
            error_msg = "Password is incorrect"

    # Close the connection
    connection.close()

    sending_to_client(server_socket, [validate, error_msg])


# request = register
def register(parameters, server_socket):
    validate = "False"
    error_msg = ""

    username, password, first_name, last_name, birthday, mail, picture = parameters[1:]

    if len(username) < 5:
        error_msg = "Username should contain\nat least 5 letters"

    elif len(first_name) < 2:
        error_msg = "First name must contain\nat least 2 letters"
    elif len(last_name) < 2:
        error_msg = "Last name must contain\nat least 2 letters"
    elif int(birthday) > 2004:
        error_msg = "you have to be\nat least 14 years old"
    else:
        validate = "True"
        connection = sqlite3.connect('tblUsers.db')
        cursor = connection.cursor()

        # Create table
        cursor.execute(
            '''CREATE TABLE IF NOT EXISTS tblUsers (usrNickName TEXT, usrPWD TEXT, usrFirstName TEXT, usrLastName TEXT, usrBDate TEXT, usrEmail TEXT, usrPicID TEXT)''')

        # l = cursor.fetchall()
        # Insert new score
        params = (username, password, first_name, last_name, birthday, mail, picture)

        cursor.execute("INSERT INTO tblUsers VALUES ( ?, ?, ?, ?, ?, ?, ?)", params)
        # cursor.execute("INSERT INTO tblUsers VALUES('{0}', '{1}', '{2}', '{3}', '{4}', '{5}', {6})".format(username, password, name, last_name, birthday, mail, picture))

        # Save the changes
        connection.commit()

        # Close the connection
        connection.close()

    sending_to_client(server_socket, [validate, error_msg])


def send_email(parameters, server_socket):
    username = parameters[1]
    connection = sqlite3.connect('tblUsers.db')
    cursor = connection.cursor()
    params = (username,)
    cursor.execute("SELECT usrEmail FROM tblUsers WHERE usrNickName = ?", params)
    client_email = cursor.fetchone()
    if not client_email:
        message_to_client = 'Username is incorrect'
        sending_to_client(server_socket, [message_to_client])
    else:
        client_email = client_email[0]
        reset_code = random.randint(99999, 999999)
        my_email = "avivlerner10@gmail.com"
        msg = MIMEMultipart()
        msg['From'] = my_email
        msg['To'] = client_email
        msg['Subject'] = "Reset password"

        body = "This is the code for resetting your password:  {0}".format(reset_code)
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(my_email, "tchcaviv")
        text = msg.as_string()
        server.sendmail(my_email, client_email, text)
        server.quit()

        message_to_client = 'A code for resetting password was sent to\n{0}, please write the code here:'.format(
            client_email)
        sending_to_client(server_socket, [message_to_client, reset_code])


def change_password(parameters, server_socket):
    validate = "False"
    error_msg = ""

    username, new_password = parameters[1:]

    if len(new_password) < 7:
        error_msg = "Password should contain\nat least 8 letters"
    elif new_password.isdigit():
        error_msg = "Password should contain\nat least one letter"
    elif new_password.isalpha():
        error_msg = "Password should contain\nat least one digit"
    else:
        validate = "True"
        connection = sqlite3.connect('tblUsers.db')
        cursor = connection.cursor()
        params = (new_password, username)
        cursor.execute('UPDATE tblUsers SET usrPWD = ? WHERE usrNickName = ?', params)
        # Save the changes
        connection.commit()

        # Close the connection
        connection.close()

    sending_to_client(server_socket, [validate, error_msg])


def send_message(parameters, server_socket):
    print parameters
    room_name, username, message = parameters[1:]
    room_to_send = get_room_by_name_to_send(room_name)
    send_message_to_all_users_in_room(room_to_send, ['user_message', username, message])


def join_room(parameters, user_socket):
    room_name, username = parameters[1:]
    room_to_send = get_room_by_name_to_send(room_name)
    room_list = get_room_by_name_list(room_name)
    if room_to_send is not None:
        room_to_send.append((username, user_socket))

        #  open db for getting user's pucture
        connection = sqlite3.connect('tblUsers.db')
        cursor = connection.cursor()
        params = (username,)
        cursor.execute("SELECT usrPicID FROM tblUsers WHERE usrNickName = ?", params)
        user_picture = cursor.fetchone()[0]
        room_list.append(username)
        room_list.append(user_picture)
        send_message_to_all_users_in_room(room_to_send, ['update_users'] + room_list)


def get_room_by_name_to_send(room_name):
    if room_name == "food":
        return food_room_users_to_send
    elif room_name == "movies":
        return movies_room_users_to_send
    elif room_name == 'gaming':
        return gaming_room_users_to_send
    elif room_name == 'sport':
        return sport_room_users_to_send
    return None


def get_room_by_name_list(room_name):
    if room_name == "food":
        return food_room_users_list
    elif room_name == "movies":
        return movies_room_users_list
    elif room_name == 'gaming':
        return gaming_room_users_list
    elif room_name == 'sport':
        return sport_room_users_list
    return None


def send_message_to_all_users_in_room(room_to_send, message_parameters):
    for (current_username, current_user_socket) in room_to_send:
        sending_to_client(current_user_socket, message_parameters)


# Reference the request to its purpose
def handle_request(wlist, requests):
    for current_request in requests:
        (sender_client_socket, request_content) = current_request
        parameters = request_to_parameters(request_content)
        if parameters[0] == "login":
            login(parameters, sender_client_socket)
        elif parameters[0] == "register":
            register(parameters, sender_client_socket)
        elif parameters[0] == 'send_email':
            send_email(parameters, sender_client_socket)
        elif parameters[0] == 'change_password':
            change_password(parameters, sender_client_socket)
        elif parameters[0] == 'send_message':
            send_message(parameters, sender_client_socket)
        elif parameters[0] == 'join_room':
            join_room(parameters, sender_client_socket)
        requests.remove(current_request)


# main
def main():
    server_socket = socket.socket()
    server_socket.bind(('0.0.0.0', PORT_NUMBER))
    server_socket.listen(5)
    open_client_sockets = []
    requests = []
    while True:
        rlist, wlist, xlist = select.select([server_socket] + open_client_sockets, open_client_sockets, [])

        for current_socket in rlist:
            if current_socket is server_socket:
                (new_socket, address) = server_socket.accept()
                open_client_sockets.append(new_socket)
            else:
                try:
                    data = current_socket.recv(1024)
                    # If the client has disconnected
                    if data == "":
                        open_client_sockets.remove(current_socket)
                        user_exit(current_socket)
                        print "Connection with client closed"
                    else:
                        print 'recieve from client: ', data
                        requests.append((current_socket, data))
                except Exception, ex:
                    print ex.strerror
                    open_client_sockets.remove(current_socket)
                    user_exit(current_socket)
                    pass

        handle_request(wlist, requests)


if __name__ == "__main__":
    main()
