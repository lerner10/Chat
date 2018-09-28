# Lerner Aviv
# Chat - server

import socket
import select
import sqlite3
import random
import pickle  # Module for turning an instance to a string and the opposite
import re  # Module for validating the mail address

# Modules for sending an email
import smtplib
from email.MIMEMultipart import MIMEMultipart
from email.MIMEText import MIMEText

# Modules for encryption
from Crypto import Random
from Crypto.PublicKey import RSA
import base64

SPECIAL_SIGN = "^"
PORT_NUMBER = 8820

# lists contain tuples of the socket and the username of the users in each room
food_room_users_to_send = []
sport_room_users_to_send = []
gaming_room_users_to_send = []
movies_room_users_to_send = []

# lists contain usernames in each room
food_room_users_list = []
sport_room_users_list = []
gaming_room_users_list = []
movies_room_users_list = []

# list contains tuples of the socket and the username of the users using the chat
users_in_chat = []

encryption_keys = {}
decryption_keys = {}


# generate a public and a private key
def generate_keys():
    # RSA modulus length must be a multiple of 256 and >= 1024
    modulus_length = 256 * 4  # use larger value in production
    private_key = RSA.generate(modulus_length, Random.new().read)
    public_key = private_key.publickey()
    return private_key, public_key


# Encrypt a string using a public key
def encrypt_message(a_message, public_key):
    encrypted_msg = public_key.encrypt(a_message, 32)[0]
    encoded_encrypted_msg = base64.b64encode(encrypted_msg)  # base64 encoded strings are database friendly
    return encoded_encrypted_msg


# Decrypt a string using a private key
def decrypt_message(encoded_encrypted_msg, client_socket):
    private_key = decryption_keys[client_socket]
    decoded_encrypted_msg = base64.b64decode(encoded_encrypted_msg)
    decoded_decrypted_msg = private_key.decrypt(decoded_encrypted_msg)
    return decoded_decrypted_msg


# Sending a list to the client by turning it to a string and encrypting it
def sending_to_client(client_socket, parameters):
    data = ""
    for parameter in parameters:
        data += str(parameter) + SPECIAL_SIGN
    print "sending to the client before encryption: " + data
    public_key = encryption_keys[client_socket]
    data = encrypt_message(data, public_key)
    print "sending to the client after encryption: " + data
    try:
        client_socket.send(data)
    except Exception, ex:
        print 'while trying to send message to client, he was disconnected.\n error: {0}'.format(ex.strerror)


# Turning the string got from the client to a list
def request_to_parameters(sender_client_socket, request_content):
    print 'got from server before decryption:' + request_content
    request_content = decrypt_message(request_content, sender_client_socket)
    print 'got from server after decryption:' + request_content
    parameters = []
    num_of_parameters = request_content.count(SPECIAL_SIGN)
    for x in range(num_of_parameters):
        parameters.append(request_content[:request_content.index(SPECIAL_SIGN)])
        request_content = request_content[request_content.index(SPECIAL_SIGN) + 1:]
    return parameters


# returning username by getting the socket, for users using the chat
def get_username_by_socket(user_socket):
    for (server_socket, username) in users_in_chat:
        if server_socket == user_socket:
            return username
    return ''


# returning the list of the room by getting the name of the room as a string
def get_room_by_username(username):
    for (username_in_list, user_socket) in food_room_users_to_send:
        if username_in_list == username:
            return 'food'

    for (username_in_list, user_socket) in gaming_room_users_to_send:
        if username_in_list == username:
            return 'gaming'

    for (username_in_list, user_socket) in sport_room_users_to_send:
        if username_in_list == username:
            return 'sport'

    for (username_in_list, user_socket) in movies_room_users_to_send:
        if username_in_list == username:
            return 'movies'
    return ''


# handling the case of a user exits abruptly
def user_exit(user_socket):
    username = get_username_by_socket(user_socket)
    if not username:
        return
    users_in_chat.remove((user_socket, username))
    room_name = get_room_by_username(username)
    if room_name == '':
        return
    room_to_send = get_room_by_name_to_send(room_name)
    for tuple in room_to_send:
        if tuple[0] == username:
            room_to_send.remove(tuple)

    room_list = get_room_by_name_list(room_name)
    username_index = room_list.index(username)
    room_list.pop(username_index)

    send_message_to_all_users_in_room(room_to_send, ['update_users'] + room_list)


# handling client request to login the chat
def login(parameters, server_socket):
    validate = "True"
    error_msg = ""

    username, password = parameters[1:]
    connection = sqlite3.connect('tblUsers.db')
    cursor = connection.cursor()
    # Create table
    cursor.execute(
        '''CREATE TABLE IF NOT EXISTS tblUsers (usrNickName TEXT, usrPWD TEXT, usrFirstName TEXT, usrLastName TEXT, usrBDate TEXT, usrEmail TEXT, usrPicID TEXT)''')
    params = (username,)
    cursor.execute("SELECT usrPWD FROM tblUsers WHERE usrNickName = ?", params)
    user_password_from_db = cursor.fetchone()
    for (socket_in_list, username_in_list) in users_in_chat:
        if username_in_list == username:
            validate = 'False'
            error_msg = 'you are already logged in'
    if not user_password_from_db:
        validate = "False"
        error_msg = "Username is incorrect"
    else:
        user_password_from_db = user_password_from_db[0]
        # if sha(password) != user_password_from_db:
        if password != user_password_from_db:
            validate = "False"
            error_msg = "Password is incorrect"

    if validate == 'True':
        users_in_chat.append((server_socket, username))

    # Close the connection
    connection.close()

    sending_to_client(server_socket, [validate, error_msg])


# handling client request to register
def register(parameters, server_socket):
    validate = "False"
    error_msg = ""

    username, password, first_name, last_name, birthday, mail, picture = parameters[1:]

    match = re.match('^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,4})$', mail)
    if not match:
        error_msg = 'Email address is incorrect'
    elif len(username) < 5:
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


# sending an email for resetting code
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


#  change the user password to a new one
def change_password(parameters, server_socket):
    username, new_password = parameters[1:]

    connection = sqlite3.connect('tblUsers.db')
    cursor = connection.cursor()
    params = (new_password, username)
    cursor.execute('UPDATE tblUsers SET usrPWD = ? WHERE usrNickName = ?', params)
    # Save the changes
    connection.commit()

    # Close the connection
    connection.close()


# handling client request to send a messgae to all users in room
def send_message(parameters, server_socket):
    room_name, username, message = parameters[1:]
    room_to_send = get_room_by_name_to_send(room_name)
    send_message_to_all_users_in_room(room_to_send, ['user_message', username, message])


# handling client request to join a room
def join_room(parameters, user_socket):
    room_name, username = parameters[1:]
    room_to_send = get_room_by_name_to_send(room_name)
    room_list = get_room_by_name_list(room_name)
    if room_to_send is not None:
        room_to_send.append((username, user_socket))
        room_list.append(username)
        send_message_to_all_users_in_room(room_to_send, ['update_users'] + room_list)


# returning the list of the room by getting the name of the room as a string
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


# returning the list of the room by getting the name of the room as a string
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


# send the message of the client to all users in the room
def send_message_to_all_users_in_room(room_to_send, message_parameters):
    for (current_username, current_user_socket) in room_to_send:
        sending_to_client(current_user_socket, message_parameters)


# handling client request to log out
def change_account(parameters, sender_client_socket):
    sending_to_client(sender_client_socket, ['exit room'])
    username, type_of_room = parameters[1:]
    room_to_send = get_room_by_name_to_send(type_of_room)
    for tuple in room_to_send:
        if tuple[0] == username:
            room_to_send.remove(tuple)

    room_list = get_room_by_name_list(type_of_room)
    username_index = room_list.index(username)
    room_list.pop(username_index)

    users_in_chat.remove((sender_client_socket, username))

    send_message_to_all_users_in_room(room_to_send, ['update_users'] + room_list)


# handling client request to change room
def change_room(sender_client_socket, parameters):
    sending_to_client(sender_client_socket, ['exit room'])
    username, room_name = parameters[1:]
    room_to_send = get_room_by_name_to_send(room_name)
    for tuple in room_to_send:
        if tuple[0] == username:
            room_to_send.remove(tuple)

    room_list = get_room_by_name_list(room_name)
    username_index = room_list.index(username)
    room_list.pop(username_index)

    send_message_to_all_users_in_room(room_to_send, ['update_users'] + room_list)


# Reference the request to its purpose
def handle_request(wlist, requests):
    for current_request in requests:
        (sender_client_socket, request_content) = current_request
        parameters = request_to_parameters(sender_client_socket, request_content)
        client_request = parameters[0]
        if client_request == "login":
            login(parameters, sender_client_socket)
        elif client_request == "register":
            register(parameters, sender_client_socket)
        elif client_request == 'send_email':
            send_email(parameters, sender_client_socket)
        elif client_request == 'change_password':
            change_password(parameters, sender_client_socket)
        elif client_request == 'send_message':
            send_message(parameters, sender_client_socket)
        elif client_request == 'join_room':
            join_room(parameters, sender_client_socket)
        elif client_request == 'change_account_from_room':
            change_account(parameters, sender_client_socket)
        elif client_request == 'change_account_from_menu':
            user_exit(sender_client_socket)
        elif client_request == 'exit_room':
            change_room(sender_client_socket, parameters)
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

                # sending and geting the keys
                private_key, public_key_for_client = generate_keys()
                public_key = new_socket.recv(1024)
                public_key = pickle.loads(public_key)
                public_key_for_client = pickle.dumps(public_key_for_client)
                new_socket.send(public_key_for_client)
                decryption_keys[new_socket] = private_key
                encryption_keys[new_socket] = public_key

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
