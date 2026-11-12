# ---------------------------------------------------------
# Videozen Pro - Single File Version (NO MODULES REQUIRED)
# ---------------------------------------------------------

import os
import shutil
import cv2
from datetime import datetime

from flask import (
    Flask, request, redirect, url_for, flash,
    render_template, send_from_directory
)
from werkzeug.utils import secure_filename

# Crypto
from Crypto.Cipher import AES, Blowfish
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# MoviePy (audio + video merge)
from moviepy.editor import VideoFileClip, AudioFileClip


# ---------------------------------------------------------
# CONFIG
# ---------------------------------------------------------
BASE_STORAGE = "storage"
DEFAULT_FPS = 24.0
ALLOWED_EXTENSIONS = {"mp4", "avi", "mov", "mkv", "webm"}

app = Flask(__name__)
app.config["SECRET_KEY"] = "super-secure-key"


# ---------------------------------------------------------
# DIRECTORIES / HELPERS
# ---------------------------------------------------------
def allowed_file(fname):
    return "." in fname and fname.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def safe_base_name(filename):
    base = secure_filename(os.path.splitext(filename)[0])
    timecode = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    return f"{base}_{timecode}"


def get_paths(base):
    root = os.path.join(BASE_STORAGE, base)
    return {
        "root": root,
        "original": os.path.join(root, "original"),
        "frames": os.path.join(root, "frames"),
        "encrypted": os.path.join(root, "encrypted"),
        "decrypted": os.path.join(root, "decrypted"),
        "keys": os.path.join(root, "keys"),
        "audio": os.path.join(root, "audio.mp3"),
        "output": os.path.join(root, "output.mp4"),
    }


def setup_dirs(base):
    paths = get_paths(base)
    for k in ["root", "original", "frames", "encrypted", "decrypted", "keys"]:
        os.makedirs(paths[k], exist_ok=True)
    return paths


# ---------------------------------------------------------
# VIDEO PROCESSING FUNCTIONS
# ---------------------------------------------------------
def split_video(video_path, frames_folder):
    try:
        cap = cv2.VideoCapture(video_path)
        if not cap.isOpened():
            return False, "[ERROR] Cannot open video.", None

        fps = cap.get(cv2.CAP_PROP_FPS) or DEFAULT_FPS
        count = 0

        ok, frame = cap.read()
        while ok:
            cv2.imwrite(os.path.join(frames_folder, f"frame_{count:06d}.jpg"), frame)
            count += 1
            ok, frame = cap.read()

        cap.release()
        return True, f"[OK] Extracted {count} frames.", fps

    except Exception as e:
        return False, f"[ERROR] Frame extraction failed: {e}", None


def extract_audio(video_path, audio_path):
    try:
        clip = VideoFileClip(video_path)
        if clip.audio:
            clip.audio.write_audiofile(audio_path)
        clip.reader.close()
        if clip.audio:
            clip.audio.reader.close_proc()
        return True, "[OK] Audio extracted."
    except Exception as e:
        return False, f"[ERROR] Audio extraction failed: {e}"


def rebuild_video_with_audio(frames_folder, audio_path, output_path, fps):
    try:
        frames = sorted([f for f in os.listdir(frames_folder) if f.endswith(".jpg")])

        if not frames:
            return False, "[ERROR] No frames available to build video."

        # Read first frame dimensions
        first_frame = cv2.imread(os.path.join(frames_folder, frames[0]))
        h, w = first_frame.shape[:2]

        temp_video = output_path.replace(".mp4", "_temp.mp4")

        writer = cv2.VideoWriter(
            temp_video, cv2.VideoWriter_fourcc(*"mp4v"), fps, (w, h)
        )

        for f in frames:
            img = cv2.imread(os.path.join(frames_folder, f))
            writer.write(img)

        writer.release()

        # Merge audio
        final_clip = VideoFileClip(temp_video)
        if os.path.exists(audio_path):
            audio_clip = AudioFileClip(audio_path)
            final = final_clip.set_audio(audio_clip)
            final.write_videofile(output_path)
        else:
            final_clip.write_videofile(output_path)

        return True, "[OK] Final video rebuilt successfully."

    except Exception as e:
        return False, f"[ERROR] Video rebuild failed: {e}"


# ---------------------------------------------------------
# ENCRYPTION / DECRYPTION
# ---------------------------------------------------------
def create_random_keys(path):
    bf_key = get_random_bytes(16)
    aes_key = get_random_bytes(16)

    open(os.path.join(path, "bf.key"), "wb").write(bf_key)
    open(os.path.join(path, "aes.key"), "wb").write(aes_key)

    return bf_key, aes_key


def encrypt_frames(folder_in, folder_out, bf_key, aes_key):
    try:
        for f in sorted(os.listdir(folder_in)):
            if not f.endswith(".jpg"):
                continue

            raw = open(os.path.join(folder_in, f), "rb").read()

            bf_iv = get_random_bytes(8)
            aes_iv = get_random_bytes(16)

            bf = Blowfish.new(bf_key, Blowfish.MODE_CBC, bf_iv)
            x = bf.encrypt(pad(raw, Blowfish.block_size))

            aes = AES.new(aes_key, AES.MODE_CBC, aes_iv)
            enc = aes.encrypt(pad(x, AES.block_size))

            open(os.path.join(folder_out, f + ".enc"), "wb").write(aes_iv + bf_iv + enc)

        return True, "[OK] Encryption successful."

    except Exception as e:
        return False, f"[ERROR] Encryption failed: {e}"


def decrypt_frames(folder_in, folder_out, bf_key, aes_key):
    try:
        for f in sorted(os.listdir(folder_in)):
            if not f.endswith(".enc"):
                continue

            raw = open(os.path.join(folder_in, f), "rb").read()
            aes_iv = raw[:16]
            bf_iv = raw[16:24]
            data = raw[24:]

            aes = AES.new(aes_key, AES.MODE_CBC, aes_iv)
            x = unpad(aes.decrypt(data), AES.block_size)

            bf = Blowfish.new(bf_key, Blowfish.MODE_CBC, bf_iv)
            dec = unpad(bf.decrypt(x), Blowfish.block_size)

            outname = f.replace(".enc", "")
            open(os.path.join(folder_out, outname), "wb").write(dec)

        return True, "[OK] Decryption successful."

    except Exception as e:
        return False, f"[ERROR] Decryption failed: {e}"


# ---------------------------------------------------------
# ROUTES
# ---------------------------------------------------------
@app.route("/")
def index():
    os.makedirs(BASE_STORAGE, exist_ok=True)
    uploads = sorted(os.listdir(BASE_STORAGE))
    return render_template("index.html", uploads=uploads)


@app.route("/upload", methods=["POST"])
def upload():
    try:
        file = request.files.get("file")
        if not file or not allowed_file(file.filename):
            flash("❌ ERROR: Invalid video.")
            return redirect("/")

        filename = secure_filename(file.filename)
        base = safe_base_name(filename)
        paths = setup_dirs(base)

        file_path = os.path.join(paths["original"], filename)
        file.save(file_path)

        ok, msg = extract_audio(file_path, paths["audio"])
        flash(msg)
        print(msg)

        return redirect(f"/uploads/{base}")

    except Exception as e:
        flash(f"❌ Upload failed: {e}")
        return redirect("/")


@app.route("/uploads/<base>")
def view_upload(base):
    p = get_paths(base)
    if not os.path.exists(p["root"]):
        flash("❌ Upload does not exist.")
        return redirect("/")

    original_files = os.listdir(p["original"])
    original = original_files[0] if original_files else None

    counts = {
        "frames": len(os.listdir(p["frames"])),
        "encrypted": len(os.listdir(p["encrypted"])),
        "decrypted": len(os.listdir(p["decrypted"])),
    }

    output_ready = os.path.exists(p["output"])

    return render_template(
        "view_upload.html",
        base=base,
        original=original,
        counts=counts,
        output_ready=output_ready
    )


@app.route("/operate/<base>", methods=["POST"])
def operate(base):
    action = request.form.get("action")
    p = get_paths(base)

    try:
        if action == "split":
            video_file = os.listdir(p["original"])[0]
            ok, msg, fps = split_video(os.path.join(p["original"], video_file), p["frames"])
            flash(msg)

        elif action == "keys":
            create_random_keys(p["keys"])
            flash("🔑 Keys generated.")

        elif action == "encrypt":
            bf = open(os.path.join(p["keys"], "bf.key"), "rb").read()
            aes = open(os.path.join(p["keys"], "aes.key"), "rb").read()
            ok, msg = encrypt_frames(p["frames"], p["encrypted"], bf, aes)
            flash(msg)

        elif action == "decrypt":
            bf = open(os.path.join(p["keys"], "bf.key"), "rb").read()
            aes = open(os.path.join(p["keys"], "aes.key"), "rb").read()
            ok, msg = decrypt_frames(p["encrypted"], p["decrypted"], bf, aes)
            flash(msg)

        elif action == "rebuild":
            ok, msg = rebuild_video_with_audio(p["decrypted"], p["audio"], p["output"], DEFAULT_FPS)
            flash(msg)

        else:
            flash("❌ Invalid action.")

    except Exception as e:
        flash(f"❌ ERROR: {e}")

    return redirect(f"/uploads/{base}")


@app.route("/output/<base>")
def output_file(base):
    p = get_paths(base)
    if not os.path.exists(p["output"]):
        flash("❌ No output video found.")
        return redirect(f"/uploads/{base}")

    return send_from_directory(os.path.dirname(p["output"]), "output.mp4")


@app.route("/delete/<base>")
def delete_upload(base):
    p = get_paths(base)

    try:
        shutil.rmtree(p["root"])
        flash("🗑 Upload deleted successfully.")

    except Exception as e:
        flash(f"❌ Delete failed: {e}")

    return redirect("/")

@app.route("/original/<base>/<filename>")
def serve_original(base, filename):
    p = get_paths(base)
    return send_from_directory(p["original"], filename, mimetype="video/mp4")

# ---------------------------------------------------------
# RUN
# ---------------------------------------------------------
if __name__ == "__main__":
    os.makedirs(BASE_STORAGE, exist_ok=True)
    app.run(debug=True, port=5000)
