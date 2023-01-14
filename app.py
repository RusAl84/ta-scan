from flask import Flask, jsonify, render_template, request, send_from_directory
from flask_cors import CORS, cross_origin
import os
import time
import config as cfg

app = Flask(__name__)
CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'


@app.route('/')
def dafault_route():
    return 'API'


@app.route('/uploadsa', methods=['POST'])
@cross_origin()
def uploadsa():
    str1=""
    if request.method == 'POST':
        for fname in request.files:
            f = request.files.get(fname)
            milliseconds = int(time.time() * 1000)
            filename = f"./uploads/{milliseconds}.pcap"
            f.save(filename)
            from scan_detector import all_check
            str1 = all_check(filename)
            print(str1)
    d={}
    d['text']=str1
    return d        


if __name__ == '__main__':
    app.run(host="0.0.0.0", port="5001")
# app.run(host="0.0.0.0")
