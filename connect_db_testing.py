import psycopg2
import re
import smtplib
import logging
from logging.handlers import TimedRotatingFileHandler

# logger=logging.getLogger()
# logger.setLevel(logging.INFO)
# handler=TimedRotatingFileHandler(filename = "logs/daily_logs.log",when = "midnight", interval = 1 , backupCount = 7)
# handler.setLevel(logging.INFO)
# formatter=logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
# handler.setFormatter(formatter)
# logger.addHandler(handler)

class Sql_database:
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

        def print_user_details(self):
            connection_obj = self.check_db_connection()
            if not connection_obj:
                # print("Printing user details Failed")
                return False

            curr = connection_obj.cursor()
            print(curr)
            curr.execute("SELECT * FROM user_details;")
            data = curr.fetchall()

            # PRINT THE RECORDS
            for row in data:
                print(row)
                print(data)
    # print_user_details()

    def get_user_detail(self):
        user_name=str(input("Enter user name : "))
        password=str(input("Enter password : "))
        phone_number=str(input("Enter phone number : "))
        mail_id=str(input("Enter mail id : "))
        return [user_name,password,phone_number,mail_id]

    def insert_details(self):
        connection_obj=self.check_db_connection()
        values=get_user_detail()
        user_name=values[0]
        password=values[1]
        phone_number=values[2]
        mail_id=values[3]
        curr=connection_obj.cursor()
        insert =f"INSERT INTO user_details (user_name,user_password,phn_number,mail_id) VALUES ('{user_name}','{password}','{phone_number}','{mail_id}')"
        curr.execute(insert)
        connection_obj.commit()
        logger.info(insert)
    # insert_details()

    def login_details(self):
        connection_obj=self.check_db_connection()
        username=str(input("Enter user name : "))
        password=str(input("Enter password : "))
        curr=connection_obj.cursor()
        details=f"SELECT * FROM user_details WHERE user_name= '{username}' AND user_password= '{password}'"
        curr.execute(details)
        fetch=curr.fetchone()
        # print(fetch)
        if fetch:
            logger.info("Login successful")
        else:
            logger.info("Enter correct details")
        # fetch=curr.fetchall()
        for value in fetch:
            if username and password in value:
                logger.info("Login success")
                return
        else:
            logger.info("Enter correct details")
    # login_details()

    def reset_password(self):
        connection_obj=self.check_db_connection()
        username=str(input("Enter user name : "))
        mail=str(input("Enter mail id : "))
        curr=connection_obj.cursor()
        details=f"SELECT * FROM users WHERE user_name='{username}' AND mail_id='{mail}'"
        curr.execute(details)
        fetch=curr.fetchone()
        if fetch:
            new_pass=str(input("Enter new password : "))
            confirm_pass=str(input("Confirm new password : "))
            if new_pass==confirm_pass:
                npass=f"UPDATE users SET user_pass = '{new_pass}' WHERE mail_id = '{mail}'"
                curr.execute(npass)
                connection_obj.commit()
                logger.info("Password changed successfully")
            else:
                logger.info("Password does not match")
    #     else:
    #         print("Enter correct details")
    #     # fetch=curr.fetchall()
        # for value in fetch:
        #     if username and mail in value:
        #         new_pass=str(input("Enter new password : "))
        #         confirm_pass=str(input("Confirm new password : "))
        #         if new_pass==confirm_pass:
        #             npass=f"UPDATE user_details SET user_password = '{new_pass}' WHERE mail_id = '{mail}'"
        #             curr.execute(npass)
        #             connection_obj.commit()
        #             print("Password changed successfully")
        #         else:
        #             print("Password does not match")
        #             return
        #         return
        # else:
        #     print("Enter correct details")
    # reset_password()

    def update_user_details(self):
        connection_obj=self.check_db_connection()
        username=str(input("Enter user name : "))
        password=str(input("Enter password : "))
        curr=connection_obj.cursor()
        details=f"SELECT * FROM user_details WHERE user_name='{username}' AND user_password='{password}'"
        curr.execute(details)
        fetch=curr.fetchone()
        if fetch:
            logger.info("Login successful")
            new_detail=str(input("Which detail has to be updated  \nPress 1 for username\nPress 2 for password\nPress 3 for phone number\nPress 4 for mail id\n:"))
            if new_detail == "1":
                update_name=str(input("Enter new user name : "))
                updated_name=f"UPDATE user_details SET user_name = '{update_name}' WHERE user_password = '{password}'"
                curr.execute(updated_name)
                connection_obj.commit()
                logger.info("User name updated")
                return
            if new_detail == "2":
                update_password=str(input("Enter new password : "))
                updated_password=f"UPDATE user_details SET user_password = '{update_password}' WHERE user_name = '{username}'"
                curr.execute(updated_password)
                connection_obj.commit()
                logger.info("Password updated")
                return
            if new_detail == "3":
                update_phone_number=str(input("Enter new phone number : "))
                updated_phone_number=f"UPDATE user_details SET phn_number = '{update_phone_number}' WHERE user_name = '{username}'"
                curr.execute(updated_phone_number)
                connection_obj.commit()
                logger.info("Phone number updated")
                return
            if new_detail == "4":
                update_mail_id=str(input("Enter new mail id : "))
                updated_mail_id=f"UPDATE user_details SET mail_id = '{update_mail_id}' WHERE user_name = '{username}'"
                curr.execute(updated_mail_id)
                connection_obj.commit()
                logger.info("Mail id updated")
                return
            return
        else:
            logger.info("Enter correct details")

        # for values in fetch:
        #     if username and password in values:
        #         print("Login successful")
        #         new_detail=str(input("Which detail has to be updated  \nPress 1 for username\nPress 2 for password\nPress 3 for phone number\nPress 4 for mail id\n:"))
        #         if new_detail == "1":
        #             update_name=str(input("Enter new user name : "))
        #             updated_name=f"UPDATE user_details SET user_name = '{update_name}' WHERE user_password = '{password}'"
        #             curr.execute(updated_name)
        #             connection_obj.commit()
        #             print("User name updated")
        #             return
        #         if new_detail == "2":
        #             update_password=str(input("Enter new password : "))
        #             updated_password=f"UPDATE user_details SET user_password = '{update_password}' WHERE user_name = '{username}'"
        #             curr.execute(updated_password)
        #             connection_obj.commit()
        #             print("Password updated")
        #             return
        #         if new_detail == "3":
        #             update_phone_number=str(input("Enter new phone number : "))
        #             updated_phone_number=f"UPDATE user_details SET phn_number = '{update_phone_number}' WHERE user_name = '{username}'"
        #             curr.execute(updated_phone_number)
        #             connection_obj.commit()
        #             print("Phone number updated")
        #             return
        #         if new_detail == "4":
        #             update_mail_id=str(input("Enter new mail id : "))
        #             updated_mail_id=f"UPDATE user_details SET mail_id = '{update_mail_id}' WHERE user_name = '{username}'"
        #             curr.execute(updated_mail_id)
        #             connection_obj.commit()
        #             print("Mail id updated")
        #             return
        #         return
        # else:
        #     print("Enter correct details")
    # # update_user_details()
    
    def sign_up_page(self):
        logger=logging.getLogger()
        logger.setLevel(logging.INFO)
        handler=TimedRotatingFileHandler(filename = "logs/daily_logs",when = "midnight", interval = 1 , backupCount = 7)
        handler.setLevel(logging.INFO)
        formatter=logging.Formatter('%(asctime)s - %(levelname)s - %(message)s - %(funcName)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger2=logging.getLogger()
        logger2.setLevel(logging.WARNING)
        handler2=TimedRotatingFileHandler(filename = "logs/daily_logs",when = "midnight", interval = 1 , backupCount = 7)
        handler2.setLevel(logging.WARNING)
        formatter2=logging.Formatter('%(asctime)s - %(levelname)s - %(message)s - %(funcName)s')
        handler2.setFormatter(formatter2)
        logger2.addHandler(handler2)
        
        connection_obj=self.check_db_connection()
        curr=connection_obj.cursor()
        def sign_up_user_name():
            try:
                global username
                username=str(input("Enter user name : "))
                u_name=f"SELECT * FROM sign_up_page WHERE user_name = '{username}'"
                curr.execute(u_name)
                fetch_name=curr.fetchone()
                if fetch_name:
                    logger2.warning("User name already exist")
                    return sign_up_user_name()
            except Exception as e:
                logger.info(f"Something went wrong -> {e} ")
        sign_up_user_name()


        def sign_up_password():
            try:
                global password
                pass_pattern = r'\w{10,100}$'
                logger.info("Password should have at least 10 characters Can be  mix of alphabets and numbers")
                password=str(input("Enter password : "))
                confirm_pass=str(input("Confirm  password again : "))
                if password==confirm_pass:
                    if re.search(pass_pattern,password):
                        logger.info("Valid password")
                    else:
                        logger2.warning("Enter a valid password")
                        return sign_up_password()
                else:
                    logger2.warning("Password does not match")
                    return sign_up_password()
            except Exception as e:
                logger.info(f"Something went wrong -> {e}")
        sign_up_password()


        def sign_up_phone_number():
            try:
                global phone_number
                phn_pattern =r'^\d{10}$'
                phone_number=str(input("Enter phone number : "))
                if re.search(phn_pattern,phone_number):
                    logger.info("Valid number")
                    num=f"SELECT * FROM sign_up_page WHERE phone_number = '{phone_number}'"
                    curr.execute(num)
                    fetch_num=curr.fetchone()
                    if fetch_num:
                        logger2.warning("Phone number already exist")
                        return sign_up_phone_number()
                else:
                    logger2.warning("Enter a valid number")
                    return sign_up_phone_number()
            except Exception as e:
                logger.info(f"Something went wrong -> {e}")  
        sign_up_phone_number()


        def sign_up_mail_id():
            try:
                global mail_id
                mail_pattern =r'^[a-z A-Z 0-9]+[\._]?[a-z A-Z 0-9]+[@]\w+[.]\D{2,3}$'
                mail_id=str(input("Enter mail id : "))
                if re.search(mail_pattern,mail_id):
                    logger.info("Valid mail id")
                    mail=f"SELECT * from sign_up_page WHERE mail_id = '{mail_id}'"
                    curr.execute(mail)
                    fetch_mail=curr.fetchone()
                    if fetch_mail:
                        logger2.warning("Mail id already exist")
                        return sign_up_mail_id() 
                else:
                    logger2.warning("Enter a valid mail id")
                    return sign_up_mail_id()
                
                # sender="niranjanrox56@gmail.com"
                # receiver=(mail_id)
                # message=f"Hello {username}\n Welcome to our website"
                # server=smtplib.SMTP("smtp.gmail.com",587)
                # server.starttls()
                # server.login(sender,'jaxa cqze rzza hvyj')
                # server.sendmail(sender,receiver,message)
                # logger.info(f"Email has been sent to {mail_id}")
            except Exception as e:
                logger.info(f"Something went wrong -> {e}")  
        sign_up_mail_id()

        def insert_value():
            try:
                insert=f"INSERT INTO sign_up_page (user_name,user_pass,phone_number,mail_id) VALUES ('{username}','{password}','{phone_number}','{mail_id}')"
                curr.execute(insert)
                connection_obj.commit()
                logger.info("Inserted into DB")
            except Exception as e:
                logger2.warning(f"Something went wrong -> {e}")
        insert_value()

database=Sql_database()
database.sign_up_page()

