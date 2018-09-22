from Tkinter import *
import tkMessageBox as messagebox
import socket
from Crypto.Hash import SHA
from Crypto import Random
from Crypto.PublicKey import RSA
import base64
import pickle

# The dimensions of the windows
from threading import Thread

SCREEN_SETTINGS = "607x530+400+100"
# The Title of the windows
SCREEN_TITLE = "Chat"
SCREEN_COLOUR = "dodger blue"
SPECIAL_SIGN = "^"
PORT_NUMBER = 8820
BUFFER_SIZE = 1024
login_screen = None
register_screen = None
forgot_password_screen = None
join_room_screen = None
room_screen = None
my_socket = None
code_for_reset_password = ''
private_key = None
public_key = None

USER_PICTURE_X_START = 2
USER_PICTURE_Y_START = 2


def generate_keys():
    # RSA modulus length must be a multiple of 256 and >= 1024
    modulus_length = 256*4 # use larger value in production
    private_key = RSA.generate(modulus_length, Random.new().read)
    public_key = private_key.publickey()
    return private_key, public_key


def encrypt_message(a_message ,public_key):
    encrypted_msg = public_key.encrypt(a_message, 32)[0]
    encoded_encrypted_msg = base64.b64encode(encrypted_msg)  # base64 encoded strings are database friendly
    return encoded_encrypted_msg


def decrypt_message(encoded_encrypted_msg, privatekey):
    decoded_encrypted_msg = base64.b64decode(encoded_encrypted_msg)
    decoded_decrypted_msg = privatekey.decrypt(decoded_encrypted_msg)
    return decoded_decrypted_msg


def response_to_parameters(response):
    print 'got from server before decryption:' + response
    response = decrypt_message(response, private_key)
    print 'got from server after decryption:' + response
    parameters = []
    num_of_parameters = response.count("^")
    for x in range(num_of_parameters):
        parameters.append(response[:response.index("^")])
        response = response[response.index("^") + 1:]
    return parameters


def get_hashed_password(password):
    h = SHA.new()
    h.update(password)
    return h.hexdigest()


# Connect the client to the server
def connecting_to_server():
    global public_key
    global private_key
    global my_socket
    try:
        my_socket = socket.socket()
        my_socket.connect(('127.0.0.1', PORT_NUMBER))
        print 'connected to server'
        private_key, public_key_for_server = generate_keys()
        public_key_for_server = pickle.dumps(public_key_for_server)
        my_socket.send(public_key_for_server)
        public_key = my_socket.recv(1024)
        public_key = pickle.loads(public_key)


    except:
        print 'no server to connect'
        quit()


# Closing the last open window
def destroying_last_window():
    global login_screen
    global register_screen
    global join_room_screen
    global forgot_password_screen
    global room_screen
    try:
        login_screen.destroy()
    except:
        try:
            register_screen.destroy()
        except:
            try:
                join_room_screen.destroy()
            except:
                try:
                    forgot_password_screen.destroy()
                except:
                    try:
                        room_screen.destroy()
                    except:
                        pass


# Gets a list of parameters and sends them to the server as a string
def sending_to_server(parameters):
    data = ""
    for parameter in parameters:
        data += parameter + SPECIAL_SIGN
    print "sending to the server before encryption" + data
    data = encrypt_message(data, public_key)
    print "sending to the server after encryption" + data
    my_socket.send(data)

# Open the login window
def login_window():
    def exit():
        login_screen.destroy()

    # Login command
    def login(parameters):
        username = parameters[1]
        password = parameters[2]
        hashed_password = get_hashed_password(password)
        print 'password: {0}, hash: {1}'.format(password, hashed_password)
        parameters[2] = hashed_password
        sending_to_server(parameters)
        response = my_socket.recv(BUFFER_SIZE)
        print 'recieve from server: ', response
        parameters = response_to_parameters(response)
        validate, error_msg = parameters
        if validate == "False":
            lbl_error_msg.configure(text=error_msg)
        else:
            join_room_window(username)

    destroying_last_window()

    global login_screen
    login_screen = Tk()
    login_screen.title(SCREEN_TITLE)
    login_screen.geometry(SCREEN_SETTINGS)
    login_screen.configure(background=SCREEN_COLOUR)

    username = StringVar()
    password = StringVar()

    lbl_title = Label(login_screen, text="Welcome to the chat", font='times 23 bold italic underline')
    lbl_title.place(x=175, y=40)

    lbl_instructions = Label(login_screen, text="Enter your details", font="arial 17 bold")
    lbl_instructions.place(x=70, y=140)

    lbl_username = Label(login_screen, text="Username:", font="arial 14 bold")
    lbl_username.place(x=70, y=200)
    etr_username = Entry(login_screen, font="arial 13", width=20, textvariable=username)
    etr_username.place(x=70, y=230)

    lbl_password = Label(login_screen, text="Password:", font="arial 14 bold")
    lbl_password.place(x=70, y=290)
    etr_password = Entry(login_screen, font="arial 13", width=20, show="*", textvariable=password)
    etr_password.place(x=70, y=320)

    btn_forgot_password = Button(login_screen, text="Forgot your password?", font="arial 8",
                                 command=forgot_password_window)
    btn_forgot_password.place(x=70, y=360)

    lbl_error_msg = Label(login_screen, bg=SCREEN_COLOUR, foreground="red", text="", font="arial 14 bold")
    lbl_error_msg.place(x=70, y=400)

    btn_login = Button(login_screen, text="Login", font="arial 12",
                       command=lambda: login(["login", username.get(), password.get()]))
    btn_login.place(x=70, y=440)

    lbl_register = Label(login_screen, text="Not yet registered? \n press here to register", font="arial 14 bold")
    lbl_register.place(x=350, y=200)
    btn_register = Button(login_screen, text="Register", font="arial 12", command=registration_window)
    btn_register.place(x=410, y=280)

    btn_exit = Button(login_screen, text="Exit", font="arial 12", command=exit)
    btn_exit.place(x=420, y=440)

    login_screen.mainloop()


# Open the forgot password window
def forgot_password_window():
    def exit():
        forgot_password_screen.destroy()

    def send_email(parameters):
        global code_for_reset_password
        sending_to_server(parameters)
        response = my_socket.recv(BUFFER_SIZE)
        parameters = response_to_parameters(response)
        text = parameters[0]

        lbl_enter_code.place(x=70, y=210)
        lbl_enter_code.configure(text=text)

        if len(parameters) == 2:
            code_for_reset_password = parameters[1]

            etr_username.configure(state=DISABLED)
            btn_send_to_mail.configure(state=DISABLED)

            etr_code.place(x=70, y=265)
            btn_confirm_code.place(x=70, y=295)

    def confirm_code(confirm_code):
        global code_for_reset_password
        lbl_change_password.place(x=70, y=340)
        if code_for_reset_password == confirm_code:
            lbl_change_password.configure(text='Please enter your new password')

            etr_code.configure(state=DISABLED)
            btn_confirm_code.configure(state=DISABLED)

            etr_new_password.place(x=70, y=375)
            btn_change_password.place(x=70, y=405)
        else:
            lbl_change_password.configure(text='The code is incorrect')

    def change_password(parameters):
        sending_to_server(parameters)
        response = my_socket.recv(BUFFER_SIZE)
        print 'recieve from server: ', response

        parameters = response_to_parameters(response)
        validate, error_msg = parameters
        lbl_error_msg.place(x=320, y=375)
        if validate == "False":
            lbl_error_msg.configure(text=error_msg)
        else:
            etr_new_password.configure(state=DISABLED)
            btn_change_password.configure(state=DISABLED)

            lbl_error_msg.configure(text='password was changed')

    destroying_last_window()
    global forgot_password_screen
    forgot_password_screen = Tk()
    forgot_password_screen.title(SCREEN_TITLE)
    forgot_password_screen.geometry(SCREEN_SETTINGS)
    forgot_password_screen.configure(background=SCREEN_COLOUR)

    username = StringVar()
    code = StringVar()
    new_password = StringVar()

    lbl_title = Label(forgot_password_screen, text="Reset your password", font='times 20 bold underline')
    lbl_title.place(x=170, y=30)

    lbl_username = Label(forgot_password_screen, text="Enter your username:", font="arial 14 bold")
    lbl_username.place(x=70, y=100)
    etr_username = Entry(forgot_password_screen, font="arial 13", width=20, textvariable=username)
    etr_username.place(x=70, y=135)
    btn_send_to_mail = Button(forgot_password_screen, text="send email for resetting password", font="arial 12",
                              command=lambda: send_email(['send_email', username.get()]))
    btn_send_to_mail.place(x=70, y=165)

    lbl_enter_code = Label(forgot_password_screen, text="", font="arial 14 bold")
    etr_code = Entry(forgot_password_screen, font="arial 13", width=20, textvariable=code)
    btn_confirm_code = Button(forgot_password_screen, text="Confirm code", font="arial 12",
                              command=lambda: confirm_code(code.get()))

    lbl_change_password = Label(forgot_password_screen, text="", font="arial 14 bold")
    etr_new_password = Entry(forgot_password_screen, show='*', font="arial 13", width=20, textvariable=new_password)
    btn_change_password = Button(forgot_password_screen, text="change password", font="arial 12",
                                 command=lambda: change_password(
                                     ['change_password', username.get(), new_password.get()]))

    lbl_error_msg = Label(forgot_password_screen, bg=SCREEN_COLOUR, foreground="red", text="", font="arial 14 bold")

    btn_back = Button(forgot_password_screen, text="Back", font="arial 12", command=login_window)
    btn_back.place(x=70, y=450)

    btn_exit = Button(forgot_password_screen, text="Exit", font="arial 12", command=exit)
    btn_exit.place(x=510, y=450)


# Open the register window
def registration_window():
    def exit():
        register_screen.destroy()

    # Register command
    def register(parameters):
        password = parameters[2]
        confirm_password = parameters[3]
        error_msg = ''
        if len(password) < 7:
            error_msg = "Password should contain\nat least 8 letters"
        elif password.isdigit():
            error_msg = "Password should contain\nat least one letter"
        elif password.isalpha():
            error_msg = "Password should contain\nat least one digit"
        elif password != confirm_password:
            error_msg = "Passwords do not match"
        elif picture == '':
            error_msg = "Must choose a picture"
        if error_msg:
            lbl_error_msg.configure(text=error_msg)
        else:
            hashed_password = get_hashed_password(password)
            print 'password: {0}, hash: {1}'.format(password, hashed_password)
            parameters[2] = hashed_password
            del parameters[3]  # delete confirm_password element
            sending_to_server(parameters)
            response = my_socket.recv(BUFFER_SIZE)
            print 'recieve from server: ', response
            parameters = response_to_parameters(response)
            validate, error_msg = parameters
            if validate == "False":
                lbl_error_msg.configure(text=error_msg)
            else:
                login_window()

    def arthur_picture():
        global picture
        picture = 'arthur.gif'
        btn_arthur_picture.configure(state=DISABLED)
        btn_cosmo_picture.configure(state=NORMAL)
        btn_spongebob_picture.configure(state=NORMAL)

    def spongebob_picture():
        global picture
        picture = 'spongebob.gif'
        btn_arthur_picture.configure(state=NORMAL)
        btn_cosmo_picture.configure(state=NORMAL)
        btn_spongebob_picture.configure(state=DISABLED)

    def cosmo_picture():
        global picture
        picture = 'cosmo.gif'
        btn_arthur_picture.configure(state=NORMAL)
        btn_cosmo_picture.configure(state=DISABLED)
        btn_spongebob_picture.configure(state=NORMAL)

    destroying_last_window()
    global register_screen
    register_screen = Tk()
    picture = ''
    arthur_photo = PhotoImage(file="images/arthur.gif")
    spongebob_photo = PhotoImage(file="images/spongebob.gif")
    cosmo_photo = PhotoImage(file="images/cosmo.gif")

    register_screen.title(SCREEN_TITLE)
    register_screen.geometry(SCREEN_SETTINGS)
    register_screen.configure(background=SCREEN_COLOUR)

    username = StringVar()
    password = StringVar()
    confirm_password = StringVar()
    first_name = StringVar()
    last_name = StringVar()
    birthday = StringVar()
    mail = StringVar()

    lbl_title = Label(register_screen, text="Registration", font='times 20 bold underline')
    lbl_title.place(x=225, y=30)

    lbl_instructions = Label(register_screen, text="Fill in your details", font="arial 15 bold")
    lbl_instructions.place(x=70, y=90)

    lbl_username = Label(register_screen, text="Username:", font="arial 12 bold")
    lbl_username.place(x=70, y=140)
    etr_username = Entry(register_screen, font="arial 13", width=20, textvariable=username)
    etr_username.place(x=70, y=170)

    lbl_password = Label(register_screen, text="Password:", font="arial 12 bold")
    lbl_password.place(x=70, y=210)
    etr_password = Entry(register_screen, font="arial 13", width=20, show="*", textvariable=password)
    etr_password.place(x=70, y=240)

    lbl_confirm_password = Label(register_screen, text="Confirm password:", font="arial 12 bold")
    lbl_confirm_password.place(x=70, y=280)
    etr_confirm_password = Entry(register_screen, font="arial 13", width=20, show="*", textvariable=confirm_password)
    etr_confirm_password.place(x=70, y=310)

    lbl_first_name = Label(register_screen, text="First name:", font="arial 12 bold")
    lbl_first_name.place(x=70, y=350)
    etr_first_name = Entry(register_screen, font="arial 13", width=20, textvariable=first_name)
    etr_first_name.place(x=70, y=380)

    lbl_last_name = Label(register_screen, text="Last name:", font="arial 12 bold")
    lbl_last_name.place(x=70, y=420)
    etr_last_name = Entry(register_screen, font="arial 13", width=20, textvariable=last_name)
    etr_last_name.place(x=70, y=450)

    lbl_birthday = Label(register_screen, text="Birthday year:", font="arial 12 bold")
    lbl_birthday.place(x=350, y=140)
    etr_birthday = Entry(register_screen, font="arial 13", width=20, textvariable=birthday)
    etr_birthday.place(x=350, y=170)

    lbl_mail = Label(register_screen, text="Mail:", font="arial 12 bold")
    lbl_mail.place(x=350, y=210)
    etr_mail = Entry(register_screen, font="arial 13", width=20, textvariable=mail)
    etr_mail.place(x=350, y=240)

    lbl_picture = Label(register_screen, text="Choose picture:", font="arial 12 bold")
    lbl_picture.place(x=350, y=280)
    btn_arthur_picture = Button(register_screen, image=arthur_photo, command=arthur_picture)
    btn_arthur_picture.place(x=350, y=310)
    btn_spongebob_picture = Button(register_screen, image=spongebob_photo, command=spongebob_picture)
    btn_spongebob_picture.place(x=430, y=310)
    btn_cosmo_picture = Button(register_screen, image=cosmo_photo, command=cosmo_picture)
    btn_cosmo_picture.place(x=510, y=310)

    lbl_error_msg = Label(register_screen, bg=SCREEN_COLOUR, foreground="red", text="", font="arial 14 bold")
    lbl_error_msg.place(x=340, y=390)

    btn_register = Button(register_screen, text="register", font="arial 12",
                          command=lambda: register(
                              ["register", username.get(), password.get(), confirm_password.get(), first_name.get(),
                               last_name.get(), birthday.get(), mail.get(),
                               picture]))
    btn_register.place(x=350, y=450)

    btn_back = Button(register_screen, text="Back", font="arial 12", command=login_window)
    btn_back.place(x=440, y=450)

    btn_exit = Button(register_screen, text="Exit", font="arial 12", command=exit)
    btn_exit.place(x=510, y=450)

    register_screen.mainloop()


# Open the menu window
def join_room_window(username):
    def exit():
        join_room_screen.destroy()

    destroying_last_window()
    global join_room_screen
    join_room_screen = Tk()

    photo_sport = PhotoImage(file="images/sport.gif")
    photo_movies = PhotoImage(file="images/movies.gif")
    photo_food = PhotoImage(file="images/food.gif")
    photo_gaming = PhotoImage(file="images/gaming.gif")

    join_room_screen.title(SCREEN_TITLE)
    join_room_screen.geometry(SCREEN_SETTINGS)
    join_room_screen.configure(background=SCREEN_COLOUR)

    lbl_title = Label(join_room_screen, text="Hi " + username + ", please choose the room \n you want to enter",
                      font='times 20 bold ')
    lbl_title.place(x=80, y=40)

    btn_gaming = Button(join_room_screen, image=photo_gaming, font="arial 12",
                        command=lambda: room_window(username, 'gaming'))
    btn_gaming.place(x=30, y=125)

    btn_movies = Button(join_room_screen, image=photo_movies, font="arial 12",
                        command=lambda: room_window(username, 'movies'))
    btn_movies.place(x=300, y=125)

    btn_food = Button(join_room_screen, image=photo_food, font="arial 12",
                      command=lambda: room_window(username, 'food'))
    btn_food.place(x=30, y=285)

    btn_sport = Button(join_room_screen, image=photo_sport, font="arial 12",
                       command=lambda: room_window(username, 'sport'))
    btn_sport.place(x=300, y=285)

    btn_back = Button(join_room_screen, text="Change account", font="arial 12", command=login_window)
    btn_back.place(x=70, y=450)

    btn_exit = Button(join_room_screen, text="Exit", font="arial 12", command=exit)
    btn_exit.place(x=510, y=450)

    join_room_screen.mainloop()


# Open room window
def room_window(username, type_of_room):
    def exit():
        room_screen.destroy()

    def send_message(parameters):
        etr_message.delete(0, 'end')
        sending_to_server(parameters)

    # Handles receiving of messages
    def receive():
        def handle_mesage_from_server(message):
            global room_screen
            message_parameters = response_to_parameters(message)

            if len(message_parameters) == 0:
                return

            message_type = message_parameters[0]
            if message_type == 'user_message':
                username, message_content = message_parameters[1:]
                lbx_messages.insert(END, '{0}: {1}'.format(username, message_content))
            elif message_type == 'update_users':
                flag_username = True

                frame.delete("all")

                for widget in frame.winfo_children():
                    widget.destroy()

                i = 0
                for x in message_parameters[1:]:
                    if flag_username:
                        username = x
                        lbl_username = Label(frame, text=username)
                        lbl_username.place(x=USER_PICTURE_X_START + 45, y=USER_PICTURE_Y_START + 45 * i)


                    else:
                        user_picture = x
                        photo = PhotoImage(file='images/{0}'.format(user_picture)).subsample(2)
                        lbl_user_picture = Label(frame, image=photo)
                        lbl_user_picture.image = photo
                        lbl_user_picture.place(x=USER_PICTURE_X_START, y=USER_PICTURE_Y_START + 45 * i)

                        # frame.create_image(20, 20, image=photo)

                        i += 1
                    flag_username = not flag_username


            elif message_type == 'user_exit':
                pass

        while True:
            try:
                # msg = my_socket.recv(BUFFER_SIZE).decode("utf8")
                message = my_socket.recv(BUFFER_SIZE)
                print message
                handle_mesage_from_server(message)
            except OSError:  # Possibly client has left the chat.
                break

    destroying_last_window()

    sending_to_server(['join_room', type_of_room, username])

    global room_screen

    def on_closing():
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            room_screen.destroy()

    room_screen = Tk()
    room_screen.protocol("WM_DELETE_WINDOW", on_closing)

    message = StringVar()

    room_screen.title(SCREEN_TITLE)
    room_screen.geometry(SCREEN_SETTINGS)
    room_screen.configure(background=SCREEN_COLOUR)

    lbl_title = Label(room_screen, text="welcome " + username + " to the " + type_of_room + " room",
                      font='times 20 bold')
    lbl_title.place(x=50, y=40)

    lbx_messages = Listbox(room_screen, width=48, height=18)
    lbx_messages.place(x=50, y=85)
    slb_messages = Scrollbar(room_screen)
    slb_messages.place(x=342, y=85)
    lbx_messages.config(yscrollcommand=slb_messages.set)
    slb_messages.config(command=lbx_messages.yview)

    etr_message = Entry(room_screen, font="arial 13", width=30, textvariable=message)
    etr_message.place(x=50, y=395)

    btn_send = Button(room_screen, text="send", font="arial 10 bold",
                      command=lambda: send_message(['send_message', type_of_room, username, message.get()]))
    btn_send.place(x=330, y=394)

    lbl_users = Label(room_screen, text='Users in this room', font="arial 12 bold")
    lbl_users.place(x=390, y=85)

    frame = Canvas(room_screen, width=180, height=200)
    frame.place(x=390, y=120)
    slb_frame = Scrollbar(room_screen)
    slb_frame.place(x=574, y=120)
    frame.config(yscrollcommand=slb_frame.set)
    slb_frame.config(command=frame.yview)

    btn_back = Button(room_screen, text="Back", font='arial 12', command=lambda: join_room_window(username))
    btn_back.place(x=70, y=450)

    btn_change_account = Button(room_screen, text="Change account", font='arial 12', command=login_window)
    btn_change_account.place(x=250, y=450)

    btn_exit = Button(room_screen, text="Exit", font="arial 12", command=exit)
    btn_exit.place(x=510, y=450)

    receive_thread = Thread(target=receive)
    receive_thread.daemon = True
    receive_thread.start()

    room_screen.mainloop()


# main
def main():
    connecting_to_server()
    login_window()
    # room_window('avler', 'movies')


if __name__ == "__main__":
    main()
