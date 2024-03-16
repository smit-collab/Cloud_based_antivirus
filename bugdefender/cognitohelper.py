import boto3
import bugdefender.configure as cfg
import bugdefender.util as util
import os


class CognitoHelper():

    def __init__(self):
        self.clientid = cfg.client['client_id']
        self.region = cfg.client['aws-region']
        self.client = boto3.client('cognito-idp', self.region)
        self.client_ci = boto3.client(
            'cognito-identity', region_name=self.region)
        self.identity_pool_id = cfg.client['identity_pool_id']
        self.provider_name = cfg.client['provider_name']

    def signup(self, username, password):
        try:
            self.client.sign_up(
                ClientId=self.clientid,
                Username=username,
                Password=password
            )

        except self.client.exceptions.UsernameExistsException as e:
            return "This username already exists"

        except self.client.exceptions.InvalidPasswordException as e:
            return "Password should have Caps, Special chars, Numbers"

        except Exception as e:
            return str(e)

        return True

    def confirm_signup(self, username, code):
        try:
            self.client.confirm_sign_up(
                ClientId=self.clientid,
                Username=username,
                ConfirmationCode=code,
                ForceAliasCreation=False,
            )
        except self.client.exceptions.UserNotFoundException:
            return "Username doesnt exists"

        except self.client.exceptions.ExpiredCodeException:
            return "Expired code provided"

        except self.client.exceptions.CodeMismatchException:
            return "Invalid Verification code"

        except self.client.exceptions.NotAuthorizedException:
            return "User is already confirmed"

        except Exception as e:
            return str(e)

        return True

    def resend_otp(self, username):
        try:
            self.client.resend_confirmation_code(
                ClientId=self.clientid,
                Username=username
            )
        except Exception as e:
            return str(e)
        return True

    def signin(self, username, password):
        try:
            response = self.client.initiate_auth(
                AuthFlow='USER_PASSWORD_AUTH',
                AuthParameters={
                    'USERNAME': username,
                    'PASSWORD': password
                },
                ClientId=self.clientid
            )

            id_token = response['AuthenticationResult']['IdToken']
            os.environ["AWS_ACCESS_TOKEN"] = response['AuthenticationResult']['AccessToken']
            ids = self.client_ci.get_id(
                IdentityPoolId=self.identity_pool_id,
                Logins={self.provider_name: id_token}
            )

            identity = ids['IdentityId']
            os.environ["AWS_IDENTITY_ID"] = identity
            creds = self.client_ci.get_credentials_for_identity(
                IdentityId=identity,
                Logins={self.provider_name: id_token}
            )

            os.environ["AWS_ACCESS_KEY_ID"] = creds['Credentials']['AccessKeyId']
            os.environ["AWS_SECRET_ACCESS_KEY"] = creds['Credentials']['SecretKey']
            os.environ["AWS_SESSION_TOKEN"] = creds['Credentials']['SessionToken']

            # util.save_credentials(username, identity,
            #                      self.akid, self.sk, self.st)
            util.save_user(username, password)

        except self.client.exceptions.NotAuthorizedException:
            return "The username or password is incorrect"

        except self.client.exceptions.UserNotConfirmedException:
            return "notconfirmed"

        except Exception as e:
            return str(e)

        return True

    def forgot_password(self, username):
        try:
            self.client.forgot_password(
                ClientId=self.clientid,
                Username=username,
            )
        except self.client.exceptions.UserNotFoundException:
            return "Username doesnt exists"

        except self.client.exceptions.InvalidParameterException:
            return "User <{}> is not confirmed yet".format(username)

        except Exception as e:
            return str(e)

        return True

    def confirm_forgot_password(self, username, new_password, code):
        try:
            self.client.confirm_forgot_password(
                ClientId=self.clientid,
                Username=username,
                Password=new_password,
                ConfirmationCode=code,
            )

            util.logout_user(username)

        except self.client.exceptions.UserNotFoundException as e:
            return "Username doesnt exists"

        except self.client.exceptions.CodeMismatchException as e:
            return "Invalid Verification code"

        except self.client.exceptions.NotAuthorizedException as e:
            return "User is already confirmed"

        except Exception as e:
            return str(e)

        return True

    def change_password(self, username, oldpassword, newpassword):
        try:
            self.client.change_password(
                PreviousPassword=oldpassword,
                ProposedPassword=newpassword,
                AccessToken=os.environ["AWS_ACCESS_TOKEN"]
            )

            util.update_password(username, newpassword)

        except self.client.exceptions.InvalidPasswordException as e:
            return "Invalid Password"

        except self.client.exceptions.NotAuthorizedException as e:
            return "Incorrect username or password"

        except Exception as e:
            return str(e)

        return True
