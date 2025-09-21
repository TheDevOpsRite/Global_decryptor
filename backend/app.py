#!/usr/bin/env python3
"""
Flask backend to decrypt encrypted .sa/.sav (or other) files
using a provided hex key. Supports AES ECB and CBC (auto-detect).
"""

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import unpad
import binascii
import tempfile
import filetype
import os
import io

app = Flask(__name__)
# Allow only the production frontend origin
CORS(app, origins=["https://global-decryptor.vercel.app"])

# limit uploads to ~50 MB (adjusted as per your request)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024


def try_decrypt(ciphertext: bytes, key: bytes):
    """Try decrypting with AES (ECB, CBC, CFB, OFB), DES (ECB, CBC), and XOR."""
    results = []

    # AES (key must be 16, 24, 32 bytes)
    if len(key) in (16, 24, 32):
        # AES ECB
        try:
            cipher = AES.new(key, AES.MODE_ECB)
            pt = unpad(cipher.decrypt(ciphertext), AES.block_size)
            results.append(("AES-ECB", pt))
        except Exception:
            pass
        # AES CBC (IV = first 16 bytes)
        if len(ciphertext) > 16:
            try:
                iv = ciphertext[:16]
                data = ciphertext[16:]
                cipher = AES.new(key, AES.MODE_CBC, iv)
                pt = unpad(cipher.decrypt(data), AES.block_size)
                results.append(("AES-CBC", pt))
            except Exception:
                pass
        # AES CFB (IV = first 16 bytes)
        if len(ciphertext) > 16:
            try:
                iv = ciphertext[:16]
                data = ciphertext[16:]
                cipher = AES.new(key, AES.MODE_CFB, iv)
                pt = cipher.decrypt(data)
                results.append(("AES-CFB", pt))
            except Exception:
                pass
        # AES OFB (IV = first 16 bytes)
        if len(ciphertext) > 16:
            try:
                iv = ciphertext[:16]
                data = ciphertext[16:]
                cipher = AES.new(key, AES.MODE_OFB, iv)
                pt = cipher.decrypt(data)
                results.append(("AES-OFB", pt))
            except Exception:
                pass

    # DES (key must be 8 bytes)
    if len(key) == 8:
        # DES ECB
        try:
            cipher = DES.new(key, DES.MODE_ECB)
            pt = unpad(cipher.decrypt(ciphertext), DES.block_size)
            results.append(("DES-ECB", pt))
        except Exception:
            pass
        # DES CBC (IV = first 8 bytes)
        if len(ciphertext) > 8:
            try:
                iv = ciphertext[:8]
                data = ciphertext[8:]
                cipher = DES.new(key, DES.MODE_CBC, iv)
                pt = unpad(cipher.decrypt(data), DES.block_size)
                results.append(("DES-CBC", pt))
            except Exception:
                pass

    # XOR (any key length)
    try:
        pt = xor_decrypt(ciphertext, key)
        results.append(("XOR", pt))
    except Exception:
        pass

    return results


def xor_decrypt(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("Empty key")
    out = bytearray(len(data))
    klen = len(key)
    for i, b in enumerate(data):
        out[i] = b ^ key[i % klen]
    return bytes(out)


@app.route("/decrypt", methods=["POST"])
def decrypt_file():
    """
    POST /decrypt
    Form fields:
      - file: encrypted file (.sa, .sav, etc. or any type)
      - hex_key: hex string (AES/DES/XOR key) [required]
    Tries all supported algorithms (AES, DES, XOR) with the provided hex key.
    Returns the first successful decryption as a properly typed file.
    """
    uploaded = request.files.get('file')
    hex_key = request.form.get('hex_key') or request.form.get('hexKey')

    if uploaded is None or not hex_key:
        return jsonify({"error": "Missing 'file' or 'hex_key'"}), 400

    try:
        if hex_key.startswith("0x") or hex_key.startswith("0X"):
            hex_key = hex_key[2:]
        key = binascii.unhexlify(hex_key)
    except Exception as e:
        return jsonify({"error": f"Invalid hex key: {str(e)}. Please provide a valid hex string."}), 400

    ciphertext = uploaded.read()
    if not ciphertext:
        return jsonify({"error": "Uploaded file is empty."}), 400

    # Try all supported algorithms with the provided hex key
    try:
        results = try_decrypt(ciphertext, key)
        if not results:
            return jsonify({"error": "Decryption failed: could not decrypt with AES, DES, or XOR. "
                                     "Check your key and file. Supported key lengths: "
                                     "AES (16/24/32 bytes), DES (8 bytes), XOR (any length)."}), 400
        mode, plaintext = results[0]
    except Exception as e:
        return jsonify({"error": "Decryption failed", "details": str(e)}), 500

    kind = filetype.guess(plaintext)
    orig_ext = (uploaded.filename or "bin").split('.')[-1].lower() if '.' in (uploaded.filename or "") else "bin"
    ext = None
    mime = None

    # Map encrypted extensions to real output types (priority over filetype.guess)
    encrypted_ext_map = {
        "lsav": ("mp4", "video/mp4"),
        "esav": ("mp4", "video/mp4"),
        "sav": ("mp4", "video/mp4"),
        "limg": ("jpg", "image/jpeg"),
        "eimg": ("jpg", "image/jpeg"),
        "img": ("jpg", "image/jpeg"),
        "lpdf": ("pdf", "application/pdf"),
        "epdf": ("pdf", "application/pdf"),
        "lpng": ("png", "image/png"),
        "epng": ("png", "image/png"),
        # add more as needed
    }
    mapped = encrypted_ext_map.get(orig_ext)
    if mapped:
        ext, mime = mapped
    elif kind:
        ext = kind.extension
        mime = kind.mime
    else:
        ext = orig_ext if orig_ext != "bin" else "bin"
        mime = "application/octet-stream"

    # If still bin, try to guess from magic bytes for common types
    if ext == "bin":
        if plaintext.startswith(b"\xFF\xD8\xFF"):
            ext, mime = "jpg", "image/jpeg"
        elif plaintext.startswith(b"\x89PNG\r\n\x1a\n"):
            ext, mime = "png", "image/png"
        elif plaintext.startswith(b"%PDF"):
            ext, mime = "pdf", "application/pdf"
        elif plaintext[4:8] == b"ftyp":
            ext, mime = "mp4", "video/mp4"
        elif plaintext.startswith(b"PK\x03\x04"):
            ext, mime = "zip", "application/zip"
        # add more as needed

    out_name = "decrypted_" + secure_filename(os.path.splitext(uploaded.filename or f"file.{ext}")[0]) + f".{ext}"
    bio = io.BytesIO(plaintext)
    bio.seek(0)
    return send_file(
        bio,
        mimetype=mime,
        as_attachment=True,
        download_name=out_name
    )


@app.route("/", methods=["GET"])
def index():
    return jsonify({"info": "Upload encrypted file + hex_key to /decrypt"}), 200


if __name__ == "__main__":
    # Only run the server ONCE, and disable the reloader to avoid socket errors on Windows
    app.run(host="0.0.0.0", port=5001, debug=True, use_reloader=False)
