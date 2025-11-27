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
import argparse
import sys

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


def try_detect_type_and_name(original_filename: str, plaintext: bytes):
    # reuse same mapping/detection as endpoint
    orig_ext = (original_filename or "bin").split('.')[-1].lower() if '.' in (original_filename or "") else "bin"
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
    }
    mapped = encrypted_ext_map.get(orig_ext)
    if mapped:
        return mapped

    kind = filetype.guess(plaintext)
    if kind:
        return (kind.extension, kind.mime)

    # fallback magic-bytes
    if plaintext.startswith(b"\xFF\xD8\xFF"):
        return ("jpg", "image/jpeg")
    if plaintext.startswith(b"\x89PNG\r\n\x1a\n"):
        return ("png", "image/png")
    if plaintext.startswith(b"%PDF"):
        return ("pdf", "application/pdf")
    if len(plaintext) >= 12 and plaintext[4:8] == b"ftyp":
        return ("mp4", "video/mp4")
    if plaintext.startswith(b"PK\x03\x04"):
        return ("zip", "application/zip")
    return ("bin", "application/octet-stream")


def cli_decrypt_file(input_path: str, hex_key: str, output_path: str = None, show_attempts: bool = True):
    # Read file
    with open(input_path, "rb") as f:
        ciphertext = f.read()
    if not ciphertext:
        raise ValueError("Input file is empty")

    # normalize hex
    if hex_key.startswith("0x") or hex_key.startswith("0X"):
        hex_key = hex_key[2:]
    try:
        key = binascii.unhexlify(hex_key)
    except Exception as e:
        raise ValueError(f"Invalid hex key: {e}")

    # Try decryption algorithms
    results = try_decrypt(ciphertext, key)
    if not results:
        raise RuntimeError("Decryption failed with all attempted algorithms (AES/DES/XOR)")

    # Choose first successful result
    mode, plaintext = results[0]
    if show_attempts:
        print(f"[+] Decryption succeeded with mode: {mode}")

    # Detect output extension/mime
    ext, mime = try_detect_type_and_name(input_path, plaintext)

    # Output filename
    if output_path:
        out_file = output_path
    else:
        base = os.path.splitext(os.path.basename(input_path))[0]
        out_file = os.path.join(os.path.dirname(input_path) or ".", f"decrypted_{base}.{ext}")

    # Write plaintext
    with open(out_file, "wb") as outfh:
        outfh.write(plaintext)

    return out_file, mode, mime


# Add CLI helpers and main entry (keeps Flask server when no CLI used)
def _detect_type_from_plaintext(original_filename: str, plaintext: bytes):
    orig_ext = (original_filename or "bin").split('.')[-1].lower() if '.' in (original_filename or "") else "bin"
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
    }
    if orig_ext in encrypted_ext_map:
        return encrypted_ext_map[orig_ext]
    kind = filetype.guess(plaintext)
    if kind:
        return (kind.extension, kind.mime)
    # magic bytes fallback
    if plaintext.startswith(b"\xFF\xD8\xFF"):
        return ("jpg","image/jpeg")
    if plaintext.startswith(b"\x89PNG\r\n\x1a\n"):
        return ("png","image/png")
    if plaintext.startswith(b"%PDF"):
        return ("pdf","application/pdf")
    if len(plaintext) >= 12 and plaintext[4:8] == b"ftyp":
        return ("mp4","video/mp4")
    if plaintext.startswith(b"PK\x03\x04"):
        return ("zip","application/zip")
    return ("bin","application/octet-stream")

def cli_decrypt(input_path: str, hex_key: str, output_path: str = None, verbose: bool = True):
    if not os.path.isfile(input_path):
        raise FileNotFoundError(input_path)
    with open(input_path, "rb") as f:
        ciphertext = f.read()
    if not ciphertext:
        raise ValueError("Input file is empty")
    if hex_key.startswith("0x") or hex_key.startswith("0X"):
        hex_key = hex_key[2:]
    try:
        key = binascii.unhexlify(hex_key)
    except Exception as e:
        raise ValueError(f"Invalid hex key: {e}")
    results = try_decrypt(ciphertext, key)
    if not results:
        raise RuntimeError("Decryption failed with AES/DES/XOR using provided key")
    mode, plaintext = results[0]
    if verbose:
        print(f"[+] Decrypted with mode: {mode}")
    ext, mime = _detect_type_from_plaintext(os.path.basename(input_path), plaintext)
    if output_path:
        out_file = output_path
    else:
        base = os.path.splitext(os.path.basename(input_path))[0]
        out_file = os.path.join(os.path.dirname(input_path) or ".", f"decrypted_{base}.{ext}")
    with open(out_file, "wb") as outfh:
        outfh.write(plaintext)
    if verbose:
        print(f"[+] Wrote decrypted file: {out_file} (mime={mime})")
    return out_file


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run server or decrypt local file")
    sub = parser.add_subparsers(dest="cmd")

    run_parser = sub.add_parser("runserver", help="Run Flask server")
    run_parser.add_argument("--host", default="0.0.0.0")
    run_parser.add_argument("--port", type=int, default=5001)
    run_parser.add_argument("--no-reload", action="store_true", help="Disable reloader")

    dec_parser = sub.add_parser("decrypt", help="Decrypt a local file with a hex key")
    dec_parser.add_argument("input", help="Path to encrypted file (e.g. video.sav)")
    dec_parser.add_argument("hex", help="Hex key (with or without 0x prefix)")
    dec_parser.add_argument("-o", "--output", help="Optional output filepath")
    dec_parser.add_argument("-q", "--quiet", action="store_true", help="Quiet output")

    args = parser.parse_args()

    if args.cmd == "decrypt":
        try:
            cli_decrypt(args.input, args.hex, args.output, verbose=not args.quiet)
            sys.exit(0)
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(2)

    # default behavior: run server
    use_reloader = False
    if args.cmd == "runserver":
        use_reloader = not args.no_reload
        app.run(host=args.host, port=args.port, debug=True, use_reloader=use_reloader)
    else:
        app.run(host="0.0.0.0", port=5001, debug=True, use_reloader=False)
