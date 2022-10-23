from flask import Flask
import redis
import pymongo

# mongo
mongo_host = 'localhost'
mongo_port = 27017
mongo_client = pymongo.MongoClient(host=mongo_host, port=mongo_port)
mongo_db = mongo_client['staff_management']
mongo_account_col = mongo_db['account']
mongo_staff_col = mongo_db['staff']
mongo_salary_col = mongo_db['salary']
mongo_key_col = mongo_db['secret_key']
mongo_role_col = mongo_db['role']

# redis
redis_host = 'localhost'
redis_port = 6379
db_index = 0
redis_client = redis.Redis(host=redis_host, port=redis_port, db=db_index, charset="utf-8", decode_responses=True)


def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = '3f_C04Bh5kp67qR_'
    app.config['JSON_SORT_KEY'] = False

    from public_api import public
    from auth_api import auth

    app.register_blueprint(public, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/')

    return app
