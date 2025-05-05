import mysql.connector

def get_db():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="<your_password>",
        database="project"
    )

def insert_prediction(prediction):
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("""
            INSERT INTO predictions (
                timestamp, source_ip, destination_ip, protocol, packet_size,
                src_port, dst_port, tcp_flags, ttl,
                http_host, http_uri, tls_sni, full_url, prediction
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            prediction["timestamp"],
            prediction["source_ip_raw"],
            prediction["destination_ip_raw"],
            prediction["protocol"],
            prediction["packet_size"],
            prediction["src_port"],
            prediction["dst_port"],
            prediction["tcp_flags"],
            prediction["ttl"],
            prediction.get("http_host", ""),
            prediction.get("http_uri", "*"),
            prediction.get("tls_sni", ""),
            prediction.get("full_url", ""),
            prediction["Prediction"]
        ))
        db.commit()
        cursor.close()
        db.close()
    except Exception as e:
        print("⚠️ DB Insert Error:", e)
