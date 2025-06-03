# Test Flask server to server API for IOC's
# ONLY for test


import os
import psycopg2
import json
from flask import Flask, request

app = Flask(__name__)

def get_db_connection():
    conn = psycopg2.connect(host='localhost',
                            database='bazaar',
                            user='bazaar',
                            password='bazaar')
    return conn

def parse_malware(malware):
    keys = ["first_seen_utc","sha256_hash","md5_hash","sha1_hash","reporter","file_name","file_type_guess","mime_type","signature","clamav","vtpercent","imphash","ssdeep","tlsh"]
    result_dict = {}
    x = 0
    for key in keys:
        result_dict[key] = malware[0][x]
        x += 1
    return result_dict

def get_malware(sha256sum):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(f"SELECT * FROM malware WHERE sha256hash = '{sha256sum}';")
        malware = cur.fetchall()
        cur.close()
        if len(malware) == 0:
            return "{'null'}"
        else:
            return parse_malware(malware)

    except psycopg2.DatabaseError as e:
        print(f'Error {e}')
        return "{'error'}"

    finally:
        if conn:
            conn.close()

@app.route('/api/malware/<sha256sum>', methods = ['GET'])
def malware(sha256sum):
    result = get_malware(sha256sum)
    return result
    

if __name__ == '__main__':
    app.run(debug=True, port=8081, host='0.0.0.0')
