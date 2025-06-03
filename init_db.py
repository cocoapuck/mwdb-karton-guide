
# Test file for postgres IOC db

import os
import psycopg2
import csv
import re

conn = psycopg2.connect(
        host="localhost",
        database="bazaar",
        user="bazaar",
        password="bazaar")

cur = conn.cursor()

# "first_seen_utc","sha256_hash","md5_hash","sha1_hash","reporter","file_name","file_type_guess","mime_type","signature","clamav","vtpercent","imphash","ssdeep","tlsh"

cur.execute('DROP TABLE IF EXISTS malware;')
cur.execute('CREATE TABLE malware (id serial PRIMARY KEY,'
                                 'first_seen_utc date,'
                                 'sha256hash varchar (250),'
                                 'md5hash varchar (250),'
                                 'sha1hash varchar (250),'
                                 'reporter varchar (200),'
                                 'file_name varchar (250),'
                                 'file_type_guess varchar (250),'
                                 'mime_type varchar (250),'
                                 'signature varchar (250),'
                                 'clamav varchar (250),'
                                 'vtpercent varchar(250),'
                                 'imphash varchar(250),'
                                 'ssdeep varchar (250),'
                                 'tlsh varchar (250),'
                                 'date_added date DEFAULT CURRENT_TIMESTAMP);'
                                 )


x = 0

with open("full.csv") as fp:
    reader = csv.reader(fp, delimiter=",", quotechar='"')
    query_start = "INSERT INTO malware (first_seen_utc, sha256hash, md5hash, sha1hash, reporter, file_name, file_type_guess, mime_type, signature, clamav, vtpercent, imphash, ssdeep, tlsh)"

    pattern = r"\"(.*?)\""

    error_rows = []


    for row in reader:
        query_data = " VALUES ("
        
        #if x > 20:
        #    break

        if x < 9:
            x += 1
            continue
        
        if len(row) != 14:
            error_rows.append(row)
            x += 1
            continue

        for n in range(14):
            
            if n == 0:
                query_data += f"'{row[n]}', "
                continue
            
            match = re.search(pattern, row[n])
            if match:
                result = match.group(1)
                query_data += f"'{result.replace("'", "")}', "
            else:
                query_data += f"'', "

        query_data = query_data[:-2]
        query_data += ")"
        query_full = query_start + query_data

        print("Processing:" + str(x))
        cur.execute(query_full)

        x += 1

print("Inserted : " + str(x))
print("Error : " + str(len(error_rows)))
#print(error_rows)

conn.commit()

cur.close()
conn.close()
