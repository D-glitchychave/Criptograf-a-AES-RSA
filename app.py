from flask import Flask, render_template, request
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import base64

app = Flask(__name__)

# Generar claves RSA
key = RSA.generate(2048)
private_key = key
public_key = key.publickey()

# Almacenamiento temporal
stored_data = {}

# RUTA PRINCIPAL
@app.route("/", methods=["GET", "POST"])
def index():
    global stored_data

    if request.method == "POST":
        message = request.form["message"]

        # Generar clave AES
        aes_key = get_random_bytes(16)

        # Cifrar mensaje con AES
        cipher_aes = AES.new(aes_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode())

        # Cifrar clave AES con RSA
        cipher_rsa = PKCS1_OAEP.new(public_key)
        encrypted_key = cipher_rsa.encrypt(aes_key)

        # Guardar datos
        stored_data = {
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "nonce": base64.b64encode(cipher_aes.nonce).decode(),
            "tag": base64.b64encode(tag).decode(),
            "encrypted_key": base64.b64encode(encrypted_key).decode()
        }

    return render_template("index.html", data=stored_data)


# RUTA DE DESCIFRADO
@app.route("/decrypt")
def decrypt():
    global stored_data

    if not stored_data:
        return "No hay datos para descifrar. Primero cifra un mensaje."

    try:
        # Descifrar clave AES con RSA
        cipher_rsa = PKCS1_OAEP.new(private_key)
        aes_key = cipher_rsa.decrypt(base64.b64decode(stored_data["encrypted_key"]))

        # Descifrar mensaje con AES
        cipher_aes = AES.new(
            aes_key,
            AES.MODE_EAX,
            nonce=base64.b64decode(stored_data["nonce"])
        )

        decrypted = cipher_aes.decrypt_and_verify(
            base64.b64decode(stored_data["ciphertext"]),
            base64.b64decode(stored_data["tag"])
        )

        return render_template("decrypt.html", message=decrypted.decode())

    except Exception as e:
        return f"Error al descifrar: {str(e)}"


# Ejecutar aplicación
if __name__ == "__main__":
    app.run()