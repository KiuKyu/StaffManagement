# Execute finding 1 staff
from initiate import mongo_staff_col, redis_client, mongo_account_col
from flask import request


# Execute finding 1 staff
def exec_find_staff(id_param):
    staff = mongo_staff_col.find_one({'id': id_param})
    return staff


# execute finding an account
def exec_find_account(id_param):
    account = mongo_account_col.find_one({'id': id_param})
    return account


# Check role
def check_role():
    try:
        request_header = request.headers.get('Authorization')
        jwt_from_header = request_header[7:]
        user_redis_query = redis_client.get(jwt_from_header)
        user_mongo_query = mongo_account_col.find_one({'username': user_redis_query})
        if user_mongo_query.get('role') == 'admin':
            return 'admin'
        elif user_mongo_query.get('role') == 'manager':
            return 'manager'
        else:
            return 'member'
    except (TypeError, AttributeError):
        return 'none'


# AttributeError: NoneType handling
def check_none(param):
    if param is not None:
        pass
    else:
        raise AttributeError('Cant find existing value from param')


# Get username of request author
def find_username_request():
    request_header = request.headers.get('Authorization')
    jwt_from_header = request_header[7:]
    user_redis_query = redis_client.get(jwt_from_header)
    return user_redis_query


# Decorator exception handling
def exception_handling(arg_function):
    try:
        arg_function()
    except:
        print(Exception)
