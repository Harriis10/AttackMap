from flask import Flask, request
app = Flask(__name__)
@app.route('/records')
def records():
    return {'query': request.args.get('q', '')}
if __name__ == '__main__':
    app.run(debug=True)
