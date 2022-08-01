from password_strength import PasswordPolicy
import hashlib

class Account:
    def __init__(self, username, password, user_id, phone, email) -> None:

        self.checkUsername(username)
        self.checkPassword(password)
        self.checkUserId(user_id)
        self.checkPhoneNumber(phone)
        self.checkEmail(email)
    
    def checkUsername(self, username):
            countOfUnderline = 0
            for i in username:
                if (i == "_"):
                    countOfUnderline += 1
                if (ord(i) < 67 or ord(i) > 122):
                    raise Exception("invalid username")
            if (countOfUnderline > 1):
                    raise Exception("invalid username")
            else:
                self.username = username

    def checkPassword(self, password):
        policy = PasswordPolicy.from_names(
            length=8,
            uppercase=1,
            numbers=1,
            )
        errorsOfPassword = len(policy.test(password))

        countOfLowercase = 0
        for i in password:
            if (ord(i) >= 97 and ord(i) <= 122):
                countOfLowercase += 1
            
        if (errorsOfPassword != 0 or countOfLowercase <= 1):
            raise Exception("invalid password")
        else:
            hashedString = hashlib.sha256(password.encode('utf-8')).hexdigest()
            self.password = hashedString
    
    def checkUserId(self, userId):
        lengthOfUserId = len(userId)
        if (lengthOfUserId != 10):
            raise Exception("invalid code melli")

        positionMultValue = 0
        for i in range(0, lengthOfUserId - 1):
            positionMultValue += int(userId[i]) * (lengthOfUserId - i)
            
        divToEleven = positionMultValue % 11
        if (divToEleven >= 2):
            controlNum = 11 - divToEleven
        else:
            controlNum = 1
            
        if (int(userId[lengthOfUserId - 1]) != controlNum):
            raise Exception("invalid code melli")
        else:
            self.userId = userId

    def setNewPassword(self, newPassword):
        policy = PasswordPolicy.from_names(
            length=8,
            uppercase=1,
            numbers=1,
            )

        errorsOfPassword = len(policy.test(newPassword))

        countOfLowercase = 0
        for i in newPassword:
            if (ord(i) >= 97 and ord(i) <= 122):
                countOfLowercase += 1
            
        if (errorsOfPassword != 0 and countOfLowercase <= 1):
            raise Exception("invalid password")
        else:
            hashedString = hashlib.sha256(newPassword.encode('utf-8')).hexdigest()
            self.password = hashedString

    def checkPhoneNumber(self, phone):
        if (phone[0] == "+"):
            if (len(phone) != 13):
                raise Exception("invalid phone number")
            s = slice(0, 4)
            formatPhoneNumber = phone[s]
            if (formatPhoneNumber != "+989"):
                raise Exception("invalid phone number")
            else:
                self.phone = phone
        elif (phone[0] == "0"):
            if (len(phone) != 11):
                raise Exception("invalid phone number")
            s = slice(0, 2)
            formatPhoneNumber = phone[s]
            if (formatPhoneNumber != "09"):
                raise Exception("invalid phone number")
            else:
                self.phone = phone
        else:
            raise Exception("invalid phone number")

    def checkEmail(self, email):
        indexOfFirstPart = email.index("@")
        sliceOfFirstPart = slice(0, indexOfFirstPart)
        firstPart = email[sliceOfFirstPart]

        indexOfSecondPart = email.index(".", indexOfFirstPart)
        sliceOfSecondPart = slice(indexOfFirstPart + 1, indexOfSecondPart)
        secondePart = email[sliceOfSecondPart]

        thirdPart = email[indexOfSecondPart + 1:]

        statusParts = {"firstPart": 0,
                      "secondPart": 0,
                      "thirdPart": 0}
        for i in firstPart:
            if ((ord(i) >= 65 and ord(i) <= 90) or 
                (ord(i) >= 97 and ord(i) <= 122) or
                (ord(i) == 45 or ord(i) == 46 or ord(i) == 95) or
                (ord(i) >= 48 and ord(i) <= 57)):
                statusParts.update({"firstPart": 1})
            else:
                raise Exception("invalid email") 

        for i in secondePart:
            if ((ord(i) >= 65 and ord(i) <= 90) or 
                (ord(i) >= 97 and ord(i) <= 122) or
                (ord(i) == 45 or ord(i) == 46 or ord(i) == 95) or
                (ord(i) >= 48 and ord(i) <= 57)):
                statusParts.update({"secondPart": 1})
            else:
                raise Exception("invalid email")
            
        for i in thirdPart:
            if ((ord(i) >= 65 and ord(i) <= 90) or 
                (ord(i) >= 97 and ord(i) <= 122)):
                if (len(thirdPart) >= 2 and len(thirdPart) <= 5):
                    statusParts.update({"thirdPart": 1})
            else:
                raise Exception("invalid email")
            
        flag = 1
        for i in statusParts.values():
            if (i == 0):
                flag = 0
        if (flag == 1):
            self.email = email

class Site:
    def __init__(self, url) -> None:
        self.url = url
        self.registerUsers = []
        self.activeUsers = []
    
    def register(self, user):
        if (self.registerUsers.count(user) == 0):
            self.registerUsers.append(user)
            print("register successful")
        else:
            raise Exception("user already registered")

    def login(self, email = "", username = "", password = ""):
        checkEmail = len(email)
        checkUsername = len(username)
        checkPassword = len(password)

        hashedString = hashlib.sha256(password.encode('utf-8')).hexdigest()

        stateOfUser = 0
        if (checkEmail != 0 
            and checkUsername != 0 
            and checkPassword != 0):
            for user in self.registerUsers:
                if (self.activeUsers.count(user) != 0):
                    print("user already logged in")
                    stateOfUser = 1
                    break
                print(user.username == username)
                print(user.email == email)
                print(user.password == hashedString)
                if (user.username == username
                    and user.email == email
                    and user.password == hashedString):
                    self.activeUsers.append(user)
                    print("login successful")
                    stateOfUser = 1
                    break
            if (stateOfUser == 0):
                print("invalid login")

    def logout(self, user):
        if (self.activeUsers.count(user) != 0):
            self.activeUsers.remove(user)
            print("logout successful")
        else:
            print("user is not logged in")

def welcome(user):
    indexOfUnderline = user.username.index("_")
    t = user.username.replace("_", " ")
    userName = t[0].upper() + t[1:indexOfUnderline + 1] + t[indexOfUnderline + 1].upper() + t[indexOfUnderline + 2:]

    if (len(userName) > 15):
        userName = userName[:15] + "..."
    
    print("welcome to our site", userName)

def changePassword(user, oldPassword, newPassword):
    hashedString = hashlib.sha256(oldPassword.encode('utf-8')).hexdigest()

    if (user.password == hashedString):
        user.setNewPassword(newPassword)
        print("change password successfully.")
    else:
        raise Exception("old password incorrect.")

person = Account("ali_akbari",
                 "ali.Akbari0",
                 "0024848484", 
                 "+989121212121", 
                 "ali.AA7731@gmail.com")

r = Site("https://example.com")
r.register(person)
r.login("ali.AA7731@gmail.com", "ali_akbari", "ali.Akbari0")
r.logout(person)