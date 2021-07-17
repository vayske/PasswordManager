import sqlite3
from sqlite3 import Error
from os import system
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
from getpass import getpass

key = b'16 byte password'


def encode_data(data):
    encrypt = []
    for info in data:
        cipher = AES.new(key, AES.MODE_CFB)
        ciphertext = cipher.encrypt(bytearray(info, 'utf-8'))
        ciphertext = b64encode(ciphertext).decode('utf-8')
        tag = b64encode(cipher.iv).decode('utf-8')
        encrypt.append(ciphertext)
        encrypt.append(tag)
    return encrypt


def decode_data(data):
    decrypt = []
    for i in range(1, len(data)-1, 2):
        ciphertext = b64decode(data[i])
        tag = b64decode(data[i+1])
        cipher = AES.new(key, AES.MODE_CFB, iv=tag)
        info = cipher.decrypt(ciphertext)
        decrypt.append(info.decode('utf-8'))
    return decrypt


def connect_database(db):
    connect = None
    try:
        connect = sqlite3.connect(db)
    except Error as e:
        print(e)
    finally:
        return connect


def create_table(connect):
    connect: sqlite3.Connection
    try:
        sql = '''CREATE TABLE IF NOT EXISTS manager (
                    id integer PRIMARY KEY,
                    name text NOT NULL,
                    tag1 text NOT NULL,
                    account text NOT NULL,
                    tag2 text NOT NULL,
                    password text NOT NULL,
                    tag3 text NOT NULL,
                    desc text NOT NULL,
                    tag4 text NOT NULL);'''
        cursor = connect.cursor()
        cursor.execute(sql)
    except Error as e:
        print(e)


def insert_password(connect, data):
    connect: sqlite3.Connection
    try:
        sql = '''INSERT INTO manager(name,tag1,account,tag2,password,tag3,desc,tag4)
                 VALUES(?,?,?,?,?,?,?,?)'''
        data = encode_data(data)
        cursor = connect.cursor()
        cursor.execute(sql, data)
        connect.commit()
    except Error as e:
        print(e)


def update_password(connect, data):
    connect: sqlite3.Connection
    try:
        id = data[2]
        field, value = data[:2]
        tag = ''
        if field == 'name':
            tag = 'tag1'
        elif field == 'account':
            tag = 'tag2'
        elif field == 'password':
            tag = 'tag3'
        elif field == 'desc':
            tag = 'tag4'
        sql = '''UPDATE manager
                 SET {}=?,
                     {}=?
                 WHERE id = ?'''.format(field, tag)
        encrypt = encode_data([value])
        encrypt.append(id)
        cursor = connect.cursor()
        cursor.execute(sql, encrypt)
        connect.commit()
    except Error as e:
        print(e)


def delete_password(connect, id):
    connect: sqlite3.Connection
    try:
        sql = '''DELETE FROM manager WHERE id=?'''
        cursor = connect.cursor()
        cursor.execute(sql, (id,))
        connect.commit()
    except Error as e:
        print(e)


def select_tag(connect, tag, value):
    connect: sqlite3.Connection
    try:
        sql = '''SELECT * FROM manager WHERE {}=?'''.format(tag)
        cursor = connect.cursor()
        cursor.execute(sql, (value,))
        rows = cursor.fetchall()
        for row in rows:
            id = row[0]
            name, account, password, desc = decode_data(row)
            print('ID {}:\n    Name: {}\n    Account: {}\n    Password: {}\n    Description: {}'
                  .format(id, name, account, password, desc))
    except Error as e:
        print(e)


def list_all(connect):
    connect: sqlite3.Connection
    try:
        sql = '''SELECT * FROM manager'''
        cursor = connect.cursor()
        cursor.execute(sql)
        rows = cursor.fetchall()
        for row in rows:
            id = row[0]
            name, account, password, desc = decode_data(row)
            print('ID {}:\n    Name: {}\n    Account: {}\n    Password: {}\n    Description: {}'
                  .format(id, name, account, password, desc))
    except Error as e:
        print(e)


def user_select(connect):
    tag = 'id'
    value = input('Enter id: ')
    select_tag(connect, tag, value)


def user_insert(connect):
    name = input('Enter Name: ')
    account = input('Enter Account: ')
    password = input('Enter Password: ')
    desc = input('Enter Description: ')
    insert_password(connect, (name, account, password, desc))
    print('Insertion Completed')


def user_update(connect):
    id = input('Enter ID: ')
    field = input('Enter a field to update: ').lower()
    if field != 'name' and field != 'account' and field != 'password' and field != 'desc':
        print('Invalid Field {} (Available fields: name, account, password, desc)'.format(field))
        return
    value = input('Enter new value: ')
    update_password(connect, (field, value, id))


def user_delete(connect):
    id = input('Enter ID: ')
    sure = input('Are You Sure?(y/n)\n')
    if sure.capitalize() == 'Y':
        delete_password(connect, id)
        print('ID {} Deleted'.format(id))
    else:
        print('Deletion Cancelled')


def command_handler(connect, command):
    command = command.lower()
    if command == 'select':
        user_select(connect)
    elif command == 'insert':
        user_insert(connect)
    elif command == 'update':
        user_update(connect)
    elif command == 'delete':
        user_delete(connect)
    elif command == 'ls':
        list_all(connect)
    elif command == 'cls':
        system('cls')
    elif command == 'help':
        print('Command List:',
              '\n\tselect \t--- Select information by ID',
              '\n\tinsert \t--- Insert new information',
              '\n\tupdate \t--- Update information',
              '\n\tdelete \t--- Delete information by ID',
              '\n\tls \t--- List all information',
              '\n\tcls \t--- Clear screen')


def main():
    system('cls')
    password = bytes(getpass(prompt='Enter password: '), 'utf-8')
    while password != key[:15]:
        print('Wrong password, Try again...')
        password = bytearray(getpass(prompt='Enter key: '), 'utf-8')
    database = 'manager'
    connect = connect_database(database)
    if connect is not None:
        create_table(connect)
        run = True
        system('cls')
        try:
            while run:
                try:
                    command = input('manager> ')
                    if command == 'exit()':
                        connect.close()
                        run = False
                    else:
                        command_handler(connect, command)
                except UnicodeError:
                    print('Decrypt Error...')
        except KeyboardInterrupt:
            connect.close()
            exit(0)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        exit(0)

