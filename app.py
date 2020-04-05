#!/usr/bin/env python 
# -*- coding: utf-8 -*-
import os
from flask import Flask,render_template,request
from utils.Checker import Checker
from utils.Helper import Helper
from model.functions import Functions
import threading
import requests
app = Flask(__name__)
feature_count = 30
port = os.environ.get('port', '8080')

# NOTES:
# THE API WILL RETURN -1/2/1 -> normal / undetectable / phishing

@app.route("/",methods=["GET"])
def main():
    return render_template("index.html")

@app.route("/api/check",methods=["GET"])
# Params only include url of websites we need to check
def check():    
    # return -1/2/1 -> normal / undetectable / phishing

    submit_url = request.args["url"]
    submit_url = submit_url.replace(" ","")
    if not Checker.check_connection(submit_url):
        print("Connection unavailable")
        return {
            "status": "unknown", # unable to detect
            "message": "Unreachable"
        }
        
    if(Checker.Statistical_report(submit_url) == 1):
        return {
            "status": "phishing",
            "message": "Found in our database"
        }
    try:
        print("Getting info for",submit_url)
        
        embed_info = Helper.embed_url(submit_url)
        input_array = embed_info[0]
        info_obj = embed_info[1]

        print("Checking vector")
        result = Functions.check_vector(input_array)
        status = "unknown"
        if (result == 1):
            status = "phishing"
        elif (result == -1):
            status = "normal"

        return {
            "status": status,
            "message": "detect by model",
            "info": info_obj
        }
        # this code is used to logged into the database file. Uncomment when needed
        # if (result == 1):
        #     f = open("model/data/urls.csv","a",encoding="UTF-8")
        #     f.write(submit_url+"\n")
        
        return str(result)
    except:
        return {
            "status": "unknown",
            "message": "Internal error"
        }

# remove cache for development purpose
@app.after_request
def add_header(r):
    """
    Add headers to both force latest IE rendering engine or Chrome Frame,
    and also to cache the rendered page for 10 minutes.
    """
    r.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    r.headers["Pragma"] = "no-cache"
    r.headers["Expires"] = "0"
    r.headers['Cache-Control'] = 'public, max-age=0'
    return r

if __name__ == "__main__":
    app.run(host='0.0.0.0',threaded=True,debug=True,port=port)
