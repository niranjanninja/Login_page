from libs.UserDb import UserDb
import re
import bcrypt
 
 
class Login:
    def __init__(self):
        self.user_db_obj = UserDb() 

    def reset_password_details(self,name,mail,password,confirm_pass):
        mail_pattern =r'^[a-z A-Z 0-9]+[\._]?[a-z A-Z 0-9]+[@]\w+[.]\D{2,3}$'
        pass_pattern = r'\w{10,100}$'
        if re.search(mail_pattern,mail):
            result = self.user_db_obj.get_user_by_name_email(name, mail)
            if result:
                if re.search(pass_pattern,password):
                    if password == confirm_pass:
                        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                        self.user_db_obj.update_user_by_name_email(hashed,name,mail)
                        return f"Updated"
                        # print("Updated")
                    else:
                        return f"Password does not match"
                        # print("No match")
                else:
                    return "Enter correct details"
                    # print("ente rcorect dtaisl")
            else:
                return f"User does not exist"
                # print("NO exist")
            # print(result)


    # def reset_password(self,password,confirm_pass):
    #     pass_pattern= r'\w{10,100}$'
    #     detail=obj.reset_password_details.result
    #     print(detail)
        
        # if re.search(pass_pattern,password):
        #     if password == confirm_pass:



    def get_all_details(self,name,password,confirm_password,number,mail):
        pass_pattern = r'\w{10,100}$'
        phn_pattern =r'^\d{10}$'
        mail_pattern =r'^[a-z A-Z 0-9]+[\._]?[a-z A-Z 0-9]+[@]\w+[.]\D{2,3}$'
        
        if self.user_db_obj.get_user_by_name(name):
            return f"User exist"
            # print("User exist")
        else:
            return f"User does not exist"
            # print("User no exist")
        
        if password==confirm_password:
            if re.search(pass_pattern,password):
                hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            else:
                return f"Enter valid password"
                # print("Enter vlid pass")
        else:
            return "Password does not match"
            # print("Pass no match")

        if re.search(phn_pattern,number):
            if self.user_db_obj.check_user_by_number(number):
                return f"Number Exist"
                # print("Number exist")
            else: 
                return f"Number does not exist"
                # print("Number no exist")
        else:
            return "Enter valid number"
            # print("Enter valid no")

        if re.search(mail_pattern,mail):
            if self.user_db_obj.check_user_by_mail(mail):
                return f"Mail Exist"
                # print("Mail exist")
            else:
                return f"Mail does not exist"
                # print("Mail do not exist")
        else:
            return "Enter valid mail"
            # print("Enter valid mail")
        
        user_details=self.user_db_obj.insert_value_into_table(name,hashed,number,mail) 




# obj=Login()
# obj.reset_password_details("Nirnjan","ninja@gmail.com","niranjanninja","niranjanninja")
# obj=Login()
# obj.get_all_details("jack","ninjaninja","ninjaninja","8757826710","jack@gmail.com")
