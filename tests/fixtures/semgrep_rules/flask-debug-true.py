from flask import Flask
app = Flask(__name__)
# ruleid: flask-debug-true
app.run(debug=True)
# ruleid: flask-debug-true
app.run(host="0.0.0.0", port=5000, debug=True)
# ok: flask-debug-true
app.run(debug=False)
# ok: flask-debug-true
app.run()
