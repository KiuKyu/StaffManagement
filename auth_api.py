import jwt
import hashlib

from initiate import mongo_account_col, mongo_staff_col, redis_client, mongo_salary_col, mongo_key_col, mongo_role_col
from datetime import datetime, date
from flask import Blueprint, request
from uuid import uuid1
from util import exec_find_staff, check_role, exec_find_account, check_none, find_username_request

auth = Blueprint('auth', __name__)


# Logging : Login
@auth.route('/login', methods=['POST'])
def login():
    if request.method == 'POST':
        input_username = request.json.get('username')
        input_password = request.json.get('password')

        mongo_find_account = mongo_account_col.find_one({'username': input_username})
        try:
            check_none(mongo_find_account)
        except AttributeError:
            http_response = {
                'code': 400,
                'message': 'Account doesnt exist'
            }
            return http_response, 400
        encoded_password = hashlib.md5(input_password.encode()).hexdigest()
        if mongo_find_account.get('username') == input_username and mongo_find_account.get(
                'password') == encoded_password:
            jwt_key_mongo = mongo_key_col.find_one({'name': 'jwt'})
            secret_key = jwt_key_mongo.get('key')
            payload_data = {
                'username': mongo_find_account.get('username'),
                'email': mongo_find_account.get('email'),
                'role': mongo_find_account.get('role')
            }
            encoded_jwt = jwt.encode(payload=payload_data, key=secret_key, algorithm="HS256")
            redis_client.set(encoded_jwt, input_username, ex=3600)
            http_response = {
                'code': 200,
                'message': 'Welcome ' + input_username,
                'data': {
                    'jwt': encoded_jwt
                }
            }
            return http_response, 200
        else:
            http_response = {
                'code': 401,
                'message': 'Incorrect email or password'
            }
            return http_response, 401


# Logging : Logout
@auth.route('/logout', methods=['GET'])
def logout():
    request_header = request.headers.get('Authorization')
    jwt_from_header = request_header[7:]

    user_request = check_role()
    if user_request is not None:
        redis_client.delete(jwt_from_header)
        http_response = {
            'code': 200,
            'message': 'Successfully logged out'
        }
        return http_response, 200
    else:
        http_response = {
            'code': 400,
            'message': 'Bad Request'
        }
        return http_response, 400


@auth.route('/forgot-password', methods=['POST'])
def forgot_password():
    username = request.json.get('username')
    email = request.json.get('email')
    user_from_query = mongo_account_col.find_one({"$and": [{"username": username}, {"email": email}]})
    print(user_from_query)
    # user_from_query = mongo_account_col.find_one({'username': username})
    user_list = list(mongo_account_col.find({}, {'_id': False}))
    username_list = []
    email_list = []
    for user in user_list:
        username_list.append(user.get('username'))
        email_list.append(user.get('email'))
    if user_from_query is None:
        http_response = {
            'code': 400,
            'message': 'Account doesnt exist'
        }
        return http_response, 400
    elif username not in username_list and email not in email_list:
        http_response = {
            'code': 400,
            'message': 'Username or Email is not corrected'
        }
        return http_response, 400
    else:
        new_password = request.json.get('new_password')
        confirm_password = request.json.get('confirm_password')
        if new_password != confirm_password:
            http_response = {
                'code': 400,
                'message': 'Passwords dont match'
            }
            return http_response, 400
        else:
            encoded_password = hashlib.md5(new_password.encode())
            new_value = {"$set": {"password": encoded_password.hexdigest()}}
            new_value["$set"]["update_at"] = str(datetime.now())
            new_value["$set"]["update_by"] = username
            update_filter = {'username': username}
            mongo_account_col.update_one(update_filter, new_value)

            http_response = {
                'code': 200,
                'message': 'Success'
            }
            return http_response, 200


# ---------------------------------------------------------------------------------------------------------------------


# Account management : Show list accounts (R)
@auth.route('/accounts', methods=['GET'])
def list_account():
    request_role = check_role()
    if request_role == 'none':
        http_response = {
            'code': 401,
            'message': 'Unauthorized'
        }
        return http_response, 401
    elif request_role == 'admin':
        accounts_from_query = list(mongo_account_col.find({}, {'_id': 0}))
        http_response = {
            'code': 200,
            'message': 'Success',
            'data': accounts_from_query
        }
        return http_response, 200
    else:
        http_response = {
            'code': 403,
            'message': 'You dont have permission for this action'
        }
        return http_response, 403


# Account management : Find an account (R)
@auth.route('accounts/details', methods=['GET'])
def find_account():
    user_request = check_role()
    if user_request == 'admin':
        id_param = request.args.get('id')
        # account = mongo_account_col.find_one({'username': username_param})
        account = exec_find_account(id_param)
        if account is not None:
            http_response = {
                'code': 200,
                'message': 'Success',
                'data': {
                    'id': account.get('id'),
                    'username': account.get('username'),
                    'email': account.get('email'),
                    'password': account.get('password'),
                    'status': account.get('status'),
                    'create_at': account.get('create_at'),
                    'create_by': account.get('create_by'),
                    'update_at': account.get('update_at'),
                    'update_by': account.get('update_by')
                }
            }
            return http_response, 200
        else:
            http_response = {
                'code': 404,
                'message': 'Not found'
            }
            return http_response, 404
    elif user_request == 'none':
        http_response = {
            'code': 401,
            'message': 'Unauthorized'
        }
        return http_response, 401
    else:
        http_response = {
            'code': 403,
            'message': 'You dont have permission for this action'
        }
        return http_response, 403


# Account management : Create account (C)
@auth.route('/accounts', methods=['POST'])
def create_account():
    if request.method == 'POST':
        user_request = check_role()
        if user_request == 'admin':
            email = request.json.get('email')
            username = request.json.get('username')
            role = request.json.get('role')
            password = request.json.get('password')
            status = request.json.get('status')
            confirm_password = request.json.get('confirm_password')

            if status is None:
                status = True

            mongo_accounts_query = list(mongo_account_col.find({}, {'_id': 0}))
            mongo_roles_query = list(mongo_role_col.find({}, {'_id': 0}))
            # role_list = []
            # for role_item in mongo_roles_query:
            #     role_list.append(role_item.get('name'))
            email_list = []
            username_list = []
            for account_item in mongo_accounts_query:
                email_list.append(account_item.get('email'))
                username_list.append(account_item.get('username'))

            if email in email_list or username in username_list:
                http_response = {
                    'code': 400,
                    'message': "Account already exists"
                }
                return http_response, 400
            elif password is None or password != confirm_password:
                http_response = {
                    'code': 400,
                    'message': "Password must exist and match with confirm_password"
                }
                return http_response, 400
            # elif role not in role_list:
            elif not any(role_item['name'] == role for role_item in mongo_roles_query):
                http_response = {
                    'code': 400,
                    'message': "Not corrected role"
                }
                return http_response, 400
            else:
                encoded_password = hashlib.md5(password.encode())
                new_user = {
                    'id': str(uuid1()),
                    'email': email,
                    'role': role,
                    'status': status,
                    'username': username,
                    'password': encoded_password.hexdigest(),
                    'create_at': str(datetime.now()),
                    'create_by': find_username_request(),
                }
                mongo_account_col.insert_one(new_user)
                http_response = {
                    'code': 200,
                    'message': "Success"
                }
                return http_response, 200
        elif user_request == 'none':
            http_response = {
                'code': 401,
                'message': 'Unauthorized'
            }
            return http_response, 401
        else:
            http_response = {
                'code': 403,
                'message': 'You dont have permission for this action'
            }
            return http_response, 403


# Account management : Update account (U)
@auth.route('/accounts/update', methods=['PUT'])
def update_account():
    user_request = check_role()
    if user_request == 'admin':
        id_param = request.args.get('id')
        account_from_query = exec_find_account(id_param)
        if account_from_query is not None:
            updated_info = request.get_json(force=True)

            # if replaceOne is used
            # for key in updated_info:
            #     account_from_query[key] = updated_info.get(key)
            # -> use replaceOne to replace existing account

            # if updateOne is used
            update_filter = {"id": id_param}
            new_value = {"$set": {}}
            for key in updated_info:
                new_value["$set"][key] = updated_info.get(key)

            new_value["$set"]["update_at"] = str(datetime.now())
            new_value["$set"]["update_by"] = find_username_request()
            mongo_account_col.update_one(update_filter, new_value)
            updated_account = exec_find_account(id_param)
            http_response = {
                'code': 200,
                'message': 'Success',
                'data': {
                    'id': updated_account.get('id'),
                    'username': updated_account.get('username'),
                    'email': updated_account.get('email'),
                    'password': updated_account.get('password'),
                    'status': updated_account.get('status'),
                    'create_at': updated_account.get('create_at'),
                    'create_by': updated_account.get('create_by'),
                    'update_at': updated_account.get('update_at'),
                    'update_by': updated_account.get('update_by')
                }
            }
            return http_response, 200
        else:
            http_response = {
                'code': 404,
                'message': 'Not found'
            }
            return http_response, 404
    elif user_request == 'none':
        http_response = {
            'code': 401,
            'message': "Unauthorized"
        }
        return http_response, 401
    else:
        http_response = {
            'code': 403,
            'message': "You dont have permission for this action"
        }
        return http_response, 403


# Staff management : Create staff (C)
@auth.route('/staffs', methods=['POST'])
def create_staff():
    user_request = check_role()
    if user_request == 'manager' or user_request == 'admin':
        name = request.json.get('name')
        phone = request.json.get('phone')
        status = request.json.get('status')
        email = request.json.get('email')

        if status is None:
            status = True

        mongo_list_account = list(mongo_staff_col.find({}, {'_id': 0}))
        print(mongo_list_account)
        email_list = []
        for acc in mongo_list_account:
            email_list.append(acc.get('email'))

        print(email_list)
        if email in email_list:
            http_response = {
                'code': 400,
                'message': "Email has already been used"
            }
            return http_response, 400
        else:
            create_at = str(datetime.now())
            create_by = find_username_request()

            new_staff = {
                'id': str(uuid1()),
                'name': name,
                'phone': phone,
                'email': email,
                'status': status,
                'create_at': create_at,
                'create_by': create_by
            }
            mongo_staff_col.insert_one(new_staff)
            http_response = {
                'code': 200,
                'message': 'Success'
            }
            return http_response, 200
    elif user_request == 'none':
        http_response = {
            'code': 401,
            'message': "Unauthorized"
        }
        return http_response, 401
    else:
        http_response = {
            'code': 403,
            'message': "You dont have permission for this action"
        }
        return http_response, 403


# Staff management : Update staff (U)
@auth.route('/staffs', methods=['PUT'])
def update_staff():
    user_request = check_role()
    if user_request == 'admin' or user_request == 'manager':
        id_param = request.args.get('id')
        staff = exec_find_staff(id_param)
        if staff is not None:
            updated_info = request.get_json(force=True)
            update_filter = {"id": id_param}
            new_value = {"$set": {}}
            for key in updated_info:
                new_value["$set"][key] = updated_info.get(key)

            new_value["$set"]["update_at"] = str(datetime.now())
            new_value["$set"]["update_by"] = find_username_request()
            mongo_staff_col.update_one(update_filter, new_value)
            http_response = {
                'code': 200,
                'message': 'Success'
            }
            return http_response, 200
        else:
            http_response = {
                'code': 404,
                'message': 'Not found'
            }
            return http_response, 404
    elif user_request == 'none':
        http_response = {
            'code': 401,
            'message': "Unauthorized"
        }
        return http_response, 401
    else:
        http_response = {
            'code': 403,
            'message': "You dont have permission for this action"
        }
        return http_response, 403


# Salary management : Pay
@auth.route('/salary', methods=['POST'])
def pay_salary():
    user_request = check_role()
    if user_request == 'admin' or user_request == 'manager':
        id_param = request.args.get('id')
        staff = exec_find_staff(id_param)
        if staff is not None:
            payment_month = request.json.get('payment_month')
            payment_year = date.today().year
            payment_amount = request.json.get('payment_amount')
            salary = {
                'staff_id': id_param,
                'payment_id': str(uuid1()),
                'payment_month': payment_month,
                'payment_year': payment_year,
                'payment_amount': payment_amount,
                'create_at': str(datetime.now()),
                'create_by': find_username_request()
            }
            mongo_salary_col.insert_one(salary)
            # salary_check = mongo_salary_col.find_one({'staff_id': staff.get('_id')})
            http_response = {
                'code': 200,
                'message': 'Success'
            }
            return http_response, 200
        else:
            http_response = {
                'code': 404,
                'message': 'Not found'
            }
            return http_response, 404
    elif user_request == 'none':
        http_response = {
            'code': 401,
            'message': 'Unauthorized'
        }
        return http_response, 401
    else:
        http_response = {
            'code': 403,
            'message': 'You dont have permission for this action'
        }
        return http_response, 403


# Salary management : Salary list
@auth.route('/salary', methods=['GET'])
def manager_salary_list():
    user_request = check_role()
    if user_request == 'none':
        http_response = {
            'code': 401,
            'message': 'Unauthorized'
        }
        return http_response, 401
    else:
        from_month = request.args.get('from_month')
        to_month = request.args.get('to_month')
        year_to_find = request.args.get('year')

        if year_to_find is None:
            year_to_find = date.today().year
        else:
            year_to_find = int(year_to_find)

        # Find all salary payment in 1 month
        month_to_find = request.args.get('month')

        if month_to_find is not None:
            month_to_find = int(month_to_find)
            salary_month_list = list(
                mongo_salary_col.find({"$and": [{'payment_month': month_to_find}, {'payment_year': year_to_find}]},
                                      {'_id': 0}))
            print(salary_month_list)

            http_response = {
                'code': 200,
                'message': 'Success',
                'data': salary_month_list
            }
            return http_response, 200
        # Find all salary payment in a range of months
        elif from_month is not None and to_month is not None:
            from_month = int(from_month)
            to_month = int(to_month)
            salary_range_list = list(
                mongo_salary_col.find({"$and": [{'payment_month': {"$gte": from_month, "$lte": to_month}},
                                                {'payment_year': year_to_find}]}, {'_id': 0})
            )
            data_response = []
            for item in salary_range_list:
                data_response.append({
                    'staff_id': item.get('staff_id'),
                    'salary': [

                    ]
                })

            http_response = {
                'code': 200,
                'message': 'Success',
                'data': salary_range_list
            }
            return http_response, 200
