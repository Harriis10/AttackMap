from flask import Flask
app = Flask(__name__)
@app.route('/beta', methods=['GET'])
def index():
    return 'beta'
