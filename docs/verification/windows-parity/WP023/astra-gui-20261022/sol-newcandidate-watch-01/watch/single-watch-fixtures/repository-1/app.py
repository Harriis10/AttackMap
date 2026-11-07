from flask import Flask
app = Flask(__name__)
@app.route('/status')
def status():
    return {'status': 'ok'}

# edited during first scan

# stopped watch remains silent

# next actual worker is cancelled

# old selection remains silent
