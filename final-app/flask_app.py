import os
import logging

from io import BytesIO
from flask import Flask, render_template, request, send_file, jsonify

# STEP 1 CHANGE (F-03 / F-04, ASD STIG V-222604, V-222511):
# Removed the hard-coded Fernet "API_LICENCE_KEY" and the start-up code that
# ran `source ~/.bashrc && echo $API_CHECK`, decrypted the value and executed
# it with subprocess(shell=True). That payload read encryption keys out of the
# log file and sent them to an external canarytokens URL (data exfiltration).
# The `subprocess` import is no longer needed and has been removed.

app = Flask(__name__)


# NOTE: still the original weak XOR scheme - replaced in Step 2.
def xor_encrypt_decrypt(data, key):
    return bytes([b ^ key for b in data])


def encrypt_file(file):
    key = os.urandom(1)[0]  # Generate a random 1-byte key
    file_data = file.read()
    encrypted_data = xor_encrypt_decrypt(file_data, key)

    encrypted_file_path = os.path.join('/tmp', f"{file.filename}.enc")
    with open(encrypted_file_path, 'wb') as f_enc:
        f_enc.write(encrypted_data)

    app.logger.info(f'File {file.filename} encrypted and saved to {encrypted_file_path} with key {key}')

    return encrypted_file_path, key


def decrypt_file(filepath, key):
    with open(filepath, 'rb') as f_enc:
        encrypted_data = f_enc.read()

    decrypted_data = xor_encrypt_decrypt(encrypted_data, key)

    decrypted_file = BytesIO()
    decrypted_file.write(decrypted_data)
    decrypted_file.seek(0)

    return decrypted_file


# NOTE: logging is replaced in Step 5.
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s',
                    handlers=[
                        logging.FileHandler("/app/logs/flask_app.log"),
                        logging.StreamHandler()
                    ])


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files['file']
    encrypted_file_path, encryption_key = encrypt_file(file)

    return jsonify({
        "message": f"File saved to {encrypted_file_path}",
        "encryption_key": encryption_key
    }), 200


if __name__ == "__main__":
    app.run(host='0.0.0.0')
