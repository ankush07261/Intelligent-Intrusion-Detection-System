import pandas as pd
import joblib
import time
import os
import sys
import mysql.connector

sys.stdout.reconfigure(encoding='utf-8')

# Paths
INPUT_CSV = 'capture_data.csv'
OUTPUT_CSV = 'output_predictions.csv'

# Load models and encoders
model = joblib.load('attack_detector_model.pkl')
label_encoder = joblib.load('label_encoder.pkl')
ip_encoder = joblib.load('ip_encoder.pkl')
flags_encoder = joblib.load('flags_encoder.pkl')

# Essential features used for prediction
features = ['source_ip', 'destination_ip', 'protocol', 'packet_size',
            'src_port', 'dst_port', 'tcp_flags', 'ttl']
essential_cols = ['timestamp', 'source_ip', 'destination_ip', 'protocol',
                  'packet_size', 'src_port', 'dst_port', 'ttl']

# Safe domains (for extra security labeling)
safe_domains = ['youtube.com', 'instagram.com', 'facebook.com', 'x.com', 'twitter.com']

# Output CSV header setup
if not os.path.exists(OUTPUT_CSV):
    pd.DataFrame(columns=['timestamp', 'source_ip_raw', 'destination_ip_raw', 'http_host', 'tls_sni', 'full_url'] + features + ['Prediction'])\
      .to_csv(OUTPUT_CSV, index=False)

# MySQL Database connection
def get_db():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="hallo",
        database="project"
    )

# Safely convert to int
def safe_int(col, df):
    return df[col].astype(str).str.split('#').str[0].str.strip().replace('', '0').astype(float).fillna(0).astype(int)

def insert_into_db(data):
    try:
        db = get_db()
        cursor = db.cursor()

        for _, row in data.iterrows():
            # Replace NaN with empty strings in the row before inserting
            row = row.fillna('')
            sql = """INSERT INTO predictions (timestamp, source_ip, destination_ip, protocol, packet_size, 
                     src_port, dst_port, tcp_flags, ttl, http_host, http_uri, tls_sni, full_url, prediction) 
                     VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
            cursor.execute(sql, (
                row['timestamp'], row['source_ip_raw'], row['destination_ip_raw'], row['protocol'], row['packet_size'],
                row['src_port'], row['dst_port'], row['tcp_flags'], row['ttl'], row['http_host'], row.get('http_uri', ''),
                row['tls_sni'], row['full_url'], row['Prediction']
            ))

        db.commit()
        cursor.close()
        db.close()
    except Exception as e:
        print("⚠️ Error in DB insertion:", e)


def process_new_data():
    try:
        processed_rows = pd.read_csv(OUTPUT_CSV, low_memory=False).shape[0]

        data = pd.read_csv(INPUT_CSV, low_memory=False)
        
        if data.shape[0] <= processed_rows:
            return

        new_data = data.iloc[processed_rows:]
        new_data = new_data.dropna(subset=essential_cols)
        if new_data.empty:
            return

        # Safe integer conversion
        for col in ['packet_size', 'src_port', 'dst_port', 'ttl', 'protocol']:
            new_data[col] = safe_int(col, new_data)

        # Save original IPs
        new_data['source_ip_raw'] = new_data['source_ip']
        new_data['destination_ip_raw'] = new_data['destination_ip']

        # Encode IPs
        new_data['source_ip'] = new_data['source_ip'].apply(
            lambda ip: ip_encoder.transform([ip])[0] if ip in ip_encoder.classes_ else 0)
        new_data['destination_ip'] = new_data['destination_ip'].apply(
            lambda ip: ip_encoder.transform([ip])[0] if ip in ip_encoder.classes_ else 0)

        # Encode TCP flags
        if 'tcp_flags' in new_data.columns:
            new_data['tcp_flags'] = new_data['tcp_flags'].fillna('0').astype(str).apply(
                lambda flag: flags_encoder.transform([flag])[0] if flag in flags_encoder.classes_ else 0)
        else:
            new_data['tcp_flags'] = 0

        # Safe traffic marking
        new_data['safe_traffic'] = new_data.apply(
            lambda row: any(domain in str(row.get('http_host', '')).lower() or
                            domain in str(row.get('tls_sni', '')).lower() or
                            domain in str(row.get('full_url', '')).lower()
                            for domain in safe_domains),
            axis=1
        )

        # Predict
        X_test = new_data[features]
        predictions = model.predict(X_test)
        predicted_labels = label_encoder.inverse_transform(predictions)
        new_data['Prediction'] = predicted_labels

        # Override with BENIGN if safe domain detected
        new_data.loc[new_data['safe_traffic'], 'Prediction'] = 'BENIGN'

        # Save to output CSV
        new_data[['timestamp', 'source_ip_raw', 'destination_ip_raw', 'http_host', 'tls_sni', 'full_url'] +
                 features + ['Prediction']].to_csv(OUTPUT_CSV, mode='a', header=False, index=False)

        # Insert into MySQL DB
        insert_into_db(new_data)

    except Exception as e:
        print("⚠️ Error in processing:", e)

# 🔄 Loop for real-time processing
print("🔄 Real-time prediction started...")
while True:
    process_new_data()
    time.sleep(2)
