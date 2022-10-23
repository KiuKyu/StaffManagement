from flask import Blueprint, request
from initiate import mongo_staff_col
from datetime import datetime

from util import exec_find_staff

public = Blueprint('public', __name__)


# Staff management : List staff (R)
@public.route('/staffs', methods=['GET'])
def show_list_staff():
    staffs = list(mongo_staff_col.find({}, {'_id': False}))
    http_response = {
        'code': 200,
        'message': 'Success',
        'data': staffs
    }
    return http_response, 200


# Staff management : Find 1 staff (R)
@public.route('/staffs/details', methods=['GET'])
def find_staff():
    id_param = request.args.get('id')
    staff = exec_find_staff(id_param)
    if staff is not None:
        http_response = {
            'code': 200,
            'message': 'Success',
            'data': {
                'id': staff.get('id'),
                'name': staff.get('name'),
                'phone': staff.get('phone'),
                'email': staff.get('email'),
                'status': staff.get('status'),
                'create_at': staff.get('create_at'),
                'create_by': staff.get('create_by'),
                'update_at': staff.get('update_at'),
                'update_by': staff.get('update_by')
            }
        }
        return http_response, 200
    else:
        http_response = {
            'code': 404,
            'message': 'Not found'
        }
        return http_response, 404


