import csv
import json
import re
import sys
import os



def detect_and_redact_pii(record):
    
    is_pii_detected = False
    combinatorial_pii_count = 0
    redacted_record = record.copy()


    phone_pattern = re.compile(r'^\d{10}$')
    aadhar_pattern = re.compile(r'^\d{12}$')
    passport_pattern = re.compile(r'^[A-Z]\d{7}$')
    upi_id_pattern = re.compile(r'^[a-zA-Z0-9._]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$')
    

    if 'phone' in record and isinstance(record['phone'], str) and phone_pattern.match(record['phone']):
        is_pii_detected = True
        redacted_record['phone'] = record['phone'][:2] + 'XXXXXX' + record['phone'][-2:]
    
    if 'aadhar' in record and isinstance(record['aadhar'], str) and aadhar_pattern.match(record['aadhar']):
        is_pii_detected = True
        redacted_record['aadhar'] = 'XXXX XXXX XXXX'

    if 'passport' in record and isinstance(record['passport'], str) and passport_pattern.match(record['passport']):
        is_pii_detected = True
        redacted_record['passport'] = '[REDACTED_PII]'

    if 'upi_id' in record and isinstance(record['upi_id'], str) and upi_id_pattern.match(record['upi_id']):
        is_pii_detected = True
        redacted_record['upi_id'] = '[REDACTED_PII]'
        

    combinatorial_keys = []
    
    if 'name' in record and isinstance(record['name'], str) and len(record['name'].split()) >= 2:
        combinatorial_keys.append('name')
    
    if 'email' in record and isinstance(record['email'], str) and '@' in record['email']:
        combinatorial_keys.append('email')

    if 'address' in record and isinstance(record['address'], str):
        combinatorial_keys.append('address')

    if ('ip_address' in record and isinstance(record['ip_address'], str)) or ('device_id' in record and isinstance(record['device_id'], str)):
        if 'ip_address' in record:
            combinatorial_keys.append('ip_address')
        if 'device_id' in record:
            combinatorial_keys.append('device_id')
    

    if len(combinatorial_keys) >= 2:
        is_pii_detected = True
        # Redact the combinatorial PII fields
        if 'name' in combinatorial_keys and 'name' in redacted_record:
            redacted_record['name'] = '[REDACTED_PII]'
        if 'email' in combinatorial_keys and 'email' in redacted_record:
            redacted_record['email'] = '[REDACTED_PII]'
        if 'address' in combinatorial_keys and 'address' in redacted_record:
            redacted_record['address'] = '[REDACTED_PII]'
        if 'ip_address' in combinatorial_keys and 'ip_address' in redacted_record:
            redacted_record['ip_address'] = '[REDACTED_PII]'
        if 'device_id' in combinatorial_keys and 'device_id' in redacted_record:
            redacted_record['device_id'] = '[REDACTED_PII]'

    return is_pii_detected, redacted_record


def process_csv(input_path, output_path):
    
    try:
        with open(input_path, mode='r', encoding='utf-8') as infile:
            reader = csv.DictReader(infile)
            
            with open(output_path, mode='w', newline='', encoding='utf-8') as outfile:
                fieldnames = ['record_id', 'redacted_data_json', 'is_pii']
                writer = csv.DictWriter(outfile, fieldnames=fieldnames)
                writer.writeheader()

                for row in reader:
                    record_id = row['record_id']
                    data_json_str = row['data_json']
                    
                    try:

                        record_data = json.loads(data_json_str)
                        is_pii, redacted_data = detect_and_redact_pii(record_data)
                        
                        writer.writerow({
                            'record_id': record_id,
                            'redacted_data_json': json.dumps(redacted_data),
                            'is_pii': is_pii
                        })
                    except json.JSONDecodeError as e:
                        print(f"Skipping record_id {record_id} due to JSON decoding error: {e}")
                        continue
    except FileNotFoundError:
        print(f"Error: The file {input_path} was not found.")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)


# --- Main Execution Block ---
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 detector_full_candidate_name.py <input_csv_file>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = "redacted_output_full_candidate_name.csv"

    print(f"Processing {input_file}...")
    process_csv(input_file, output_file)
    print(f"Processing complete. Output written to {output_file}.")
