from flask import Flask, request
import sqlite3
app = Flask(__name__)

@app.route('/Api/Users/<id>', methods=['GET'])
def user(id):
    connection = sqlite3.connect('users.db')
    cursor = connection.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ' + request.args.get('id'))
    return str(cursor.fetchall())
