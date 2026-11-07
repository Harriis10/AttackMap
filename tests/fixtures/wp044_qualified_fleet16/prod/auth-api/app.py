from flask import Flask
app = Flask(__name__)
@app.route('/Items/<id>', methods=['GET'])
def item(id):
    return id
