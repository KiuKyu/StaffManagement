from util import exec_find_staff
from initiate import create_app

app = create_app()

if __name__ == '__main__':
    app.run(debug=True)
