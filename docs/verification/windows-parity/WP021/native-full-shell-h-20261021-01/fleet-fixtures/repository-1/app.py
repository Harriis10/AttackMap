from flask import Flask, request
app = Flask(__name__)
@app.route('/status')
def status():
    return {'status': 'ok'}

# removed root must remain silent
