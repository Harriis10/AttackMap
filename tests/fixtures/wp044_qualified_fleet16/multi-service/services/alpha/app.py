from flask import Flask
app = Flask(__name__)
@app.route('/alpha', methods=['GET'])
def index():
    return 'alpha'
