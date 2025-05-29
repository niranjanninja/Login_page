import psycopg2
import re
import smtplib
import logging
from logging.handlers import TimedRotatingFileHandler

class Connect_db:
    def connect_to_db(self):
        # This method returns the connection object
        ninja = psycopg2.connect(database="Customers",user="niranjansabari56",password="ninja2501",host="127.0.0.1",port=5432)
        return ninja
    
    def check_db_connection(self): 
        connection_obj = self.connect_to_db()
        if connection_obj:
            # print("Connected to db successfully")
            return connection_obj
        else:
            # print("Failed")
            return False


class Sql_commands:
    def sign_up_page(self):
        db=Connect_db()
        connection_obj=db.check_db_connection()
        curr=connection_obj.cursor()
        def sign_up_user_name():
            try:
                # global username
                # username=str(input("Enter user name : "))
                u_name=f"SELECT * FROM sign_up_page WHERE user_name = '{username}'"
                curr.execute(u_name)
                fetch_name=curr.fetchone()
                if fetch_name:
                    print("User name already exist")
                    return sign_up_user_name()
            except Exception as e:
                print(f"Something went wrong -> {e} ")
        # sign_up_user_name()

        def sign_up_password():
            try:
                # global password
                pass_pattern = r'\w{10,100}$'
                print("Password should have at least 10 characters Can be  mix of alphabets and numbers")
                # password=str(input("Enter password : "))
                # confirm_pass=str(input("Confirm  password again : "))
                if password==confirm_pass:
                    if re.search(pass_pattern,password):
                        print("Valid password")
                    else:
                        print("Enter a valid password")
                        return sign_up_password()
                else:
                    print("Password does not match")
                    return sign_up_password()
            except Exception as e:
                print(f"Something went wrong -> {e}")
        # sign_up_password()


        def sign_up_phone_number():
            try:
                # global phone_number
                phn_pattern =r'^\d{10}$'
                # phone_number=str(input("Enter phone number : "))
                if re.search(phn_pattern,phone_number):
                    print("Valid number")
                    num=f"SELECT * FROM sign_up_page WHERE phone_number = '{phone_number}'"
                    curr.execute(num)
                    fetch_num=curr.fetchone()
                    if fetch_num:
                        print("Phone number already exist")
                        return sign_up_phone_number()
                else:
                    print("Enter a valid number")
                    return sign_up_phone_number()
            except Exception as e:
                print(f"Something went wrong -> {e}") 
        # sign_up_phone_number()


        def sign_up_mail_id():
            try:
                # global mail_id
                mail_pattern =r'^[a-z A-Z 0-9]+[\._]?[a-z A-Z 0-9]+[@]\w+[.]\D{2,3}$'
                # mail_id=str(input("Enter mail id : "))
                if re.search(mail_pattern,mail_id):
                    print("Valid mail id")
                    mail=f"SELECT * from sign_up_page WHERE mail_id = '{mail_id}'"
                    curr.execute(mail)
                    fetch_mail=curr.fetchone()
                    if fetch_mail:
                        print("Mail id already exist")
                        return sign_up_mail_id() 
                else:
                    print("Enter a valid mail id")
                    return sign_up_mail_id()
            except Exception as e:
                print(f"Something went wrong -> {e}")
                
        # sign_up_mail_id()

        def insert_value():
            try:
                insert=f"INSERT INTO sign_up_page (user_name,user_pass,phone_number,mail_id) VALUES ('{username}','{password}','{phone_number}','{mail_id}')"
                curr.execute()
                connection_obj.commit()
                logger.info("Inserted into DB")
            except Exception as e:
                print(f"Something went wrong -> {e}")
        # insert_value()
    

    def reset_password(self):
        db=Connect_db()
        connection_obj=db.check_db_connection()
        curr=connection_obj.cursor()
        # username=str(input("Enter user name : "))
        # mail=str(input("Enter mail id : "))
        details=f"SELECT * FROM sign_up_page WHERE user_name='{username}' AND mail_id='{mail_id}'"
        curr.execute(details)
        fetch=curr.fetchone()
        if fetch:
            # new_pass=str(input("Enter new password : "))
            # confirm_pass=str(input("Confirm new password : "))
            if new_pass==confirm_pass:
                npass=f"UPDATE sign_up_page SET user_pass = '{new_pass}' WHERE mail_id = '{mail_id}'"
                curr.execute(npass)
                connection_obj.commit()
                print("Password changed successfully")
            else:
                print("Password does not match")
                return self.reset_password()
        else:
            print("Enter correct details")
            return self.reset_password()
    # reset_password()


    def update_user_details(self):
        db=Connect_db()
        connection_obj=db.check_db_connection()
        curr=connection_obj.cursor()
        # username=str(input("Enter user name : "))
        # password=str(input("Enter password : "))
        details=f"SELECT * FROM sign_up_page WHERE user_name='{username}' AND user_pass='{password}'"
        curr.execute(details)
        fetch=curr.fetchone()
        if fetch:
            print("Login successful")
            # new_detail=str(input("Which detail has to be updated  \nPress 1 for username\nPress 2 for password\nPress 3 for phone number\nPress 4 for mail id\n:"))
            if new_detail == "1":
                # update_name=str(input("Enter new user name : "))
                updated_name=f"UPDATE sign_up_page SET user_name = '{update_name}' WHERE user_pass = '{password}'"
                curr.execute(updated_name)
                connection_obj.commit()
                print("User name updated")
                return
            if new_detail == "2":
                # update_password=str(input("Enter new password : "))
                updated_password=f"UPDATE sign_up_page SET user_pass = '{update_password}' WHERE user_name = '{username}'"
                curr.execute(updated_password)
                connection_obj.commit()
                print("Password updated")
                return
            if new_detail == "3":
                # update_phone_number=str(input("Enter new phone number : "))
                updated_phone_number=f"UPDATE sign_up_page SET phone_number = '{update_phone_number}' WHERE user_name = '{username}'"
                curr.execute(updated_phone_number)
                connection_obj.commit()
                print("Phone number updated")
                return
            if new_detail == "4":
                # update_mail_id=str(input("Enter new mail id : "))
                updated_mail_id=f"UPDATE sign_up_page SET mail_id = '{update_mail_id}' WHERE user_name = '{username}'"
                curr.execute(updated_mail_id)
                connection_obj.commit()
                print("Mail id updated")
                return
        else:
            print("Enter correct details")
            return self.update_user_details()

    # update_user_details()

class User_input:
    global username, password, phone_number, mail_id
    username=str(input("Enter user name : "))
    password =str(input("Enter password : "))
    phone_number=str(input("Enter phone number : "))
    mail_id =str(input("Enter mail id : "))





