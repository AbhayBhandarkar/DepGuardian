import os
import json
from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.utils import secure_filename
import logging
from datetime import datetime
import tempfile
import subprocess
import uuid
import sys
import zipfile

# Conditional import for httpx (for Ollama, if kept as an option, and for the check)
try:
    import httpx
except ImportError:
    httpx = None
    logging.info(
        "httpx library not found. Ollama-specific LLM features might be unavailable if re-enabled."
    )

# Import for Gemini
try:
    import google.generativeai as genai
except ImportError:
    genai = None
    logging.warning(
        "google-generativeai library not found. Gemini features will be unavailable. Please install 'pip install google-generativeai'"
    )

# Logger setup
logger = logging.getLogger("depg.gui")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(funcName)s() - %(message)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

# Base directory settings
_basedir = os.path.abspath(os.path.dirname(__file__))
template_dir = os.path.join(_basedir, "templates")
app = Flask(__name__, template_folder=template_dir)
app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY", "a_very_secure_secret_key_for_depg_v8_gemini_agent"
)

# Temp processing dir
TEMP_PROCESSING_DIR_BASE = os.path.join(
    tempfile.gettempdir(), "depguardian_processing_sessions"
)
if not os.path.exists(TEMP_PROCESSING_DIR_BASE):
    os.makedirs(TEMP_PROCESSING_DIR_BASE, exist_ok=True)
logger.info(f"Base directory for temporary processing: {TEMP_PROCESSING_DIR_BASE}")

ALLOWED_EXTENSIONS = {"json", "zip"}
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB max upload size


def get_session_processing_folder():
    session_folder_name = str(uuid.uuid4())
    session_path = os.path.join(TEMP_PROCESSING_DIR_BASE, session_folder_name)
    try:
        os.makedirs(session_path, exist_ok=True)
        logger.info(f"Created session processing folder: {session_path}")
    except OSError as e:
        logger.error(
            f"Could not create session processing folder '{session_path}': {e}"
        )
        session_path = tempfile.mkdtemp(
            prefix="depg_fallback_", dir=TEMP_PROCESSING_DIR_BASE
        )
        logger.warning(f"Using fallback session processing folder: {session_path}")
    return session_path


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def find_project_root(base_path):
    """
    Walk the extracted directory tree and return the first path containing package.json.
    """
    for root, dirs, files in os.walk(base_path):
        if "package.json" in files:
            return root
    return base_path


@app.route("/", methods=["GET"])
def index():
    context_to_pass = {"SCRIPT_LOAD_TIME": datetime.utcnow()}
    return render_template("index.html", **context_to_pass)


@app.route("/upload_existing_report", methods=["POST"])
def upload_existing_report_route():
    session_folder = get_session_processing_folder()
    if "report_file" not in request.files:
        flash("No file part in the request. Please select a file.", "error")
        return redirect(url_for("index"))
    file = request.files["report_file"]
    if file.filename == "":
        flash("No file selected. Please choose a JSON report file.", "error")
        return redirect(url_for("index"))

    if file and allowed_file(file.filename) and file.filename.endswith(".json"):
        original_filename = secure_filename(file.filename)
        unique_filename = f"uploaded_{uuid.uuid4().hex}_{original_filename}"
        filepath = os.path.join(session_folder, unique_filename)
        try:
            file.save(filepath)
            logger.info(
                f"File '{original_filename}' uploaded as '{unique_filename}' to '{filepath}'."
            )
            return redirect(
                url_for(
                    "display_report",
                    session_id=os.path.basename(session_folder),
                    filename=unique_filename,
                )
            )
        except Exception as e:
            logger.error(
                f"Error saving uploaded file '{original_filename}': {e}", exc_info=True
            )
            flash(f"Error saving file: {e}", "error")
            return redirect(url_for("index"))
    else:
        flash("Invalid file type. Please upload a JSON file for this option.", "error")
        return redirect(url_for("index"))


@app.route("/agent_analyze_project", methods=["POST"])
def agent_analyze_project_route():
    session_folder = get_session_processing_folder()

    gemini_api_key = request.form.get("gemini_api_key")
    if not genai:
        flash(
            "Gemini AI library (google-generativeai) is not installed on the server. This feature is unavailable.",
            "error",
        )
        return redirect(url_for("index"))
    if not gemini_api_key or not gemini_api_key.strip():
        flash("Gemini API Key is required.", "error")
        return redirect(url_for("index"))

    if "project_zip" not in request.files:
        flash("No project ZIP file part in the request.", "error")
        return redirect(url_for("index"))

    file = request.files["project_zip"]
    if file.filename == "":
        flash("No project ZIP file selected.", "error")
        return redirect(url_for("index"))

    if file and file.filename.endswith(".zip"):
        original_zip_filename = secure_filename(file.filename)
        zip_filepath = os.path.join(session_folder, original_zip_filename)
        extracted_folder_path = os.path.join(session_folder, "project_content")
        try:
            file.save(zip_filepath)
            logger.info(
                f"Project ZIP '{original_zip_filename}' uploaded to '{zip_filepath}'."
            )
            os.makedirs(extracted_folder_path, exist_ok=True)
            with zipfile.ZipFile(zip_filepath, "r") as zip_ref:
                zip_ref.extractall(extracted_folder_path)

            # Find actual project root containing package.json
            project_root = find_project_root(extracted_folder_path)
            logger.info(f"Using project root for scan: {project_root}")

            agent_output_report_name = f"agent_analysis_gemini_{uuid.uuid4().hex}.json"
            agent_output_report_path = os.path.join(
                session_folder, agent_output_report_name
            )

            command = [
                sys.executable,
                "-m",
                "dep_guardian.cli",
                "agent",
                "analyze-project",
                "--project-path",
                project_root,
                "--gemini-api-key",
                gemini_api_key,
                "--output-json",
                agent_output_report_path,
                "--verbose",
            ]
            logger.info(f"Executing agent command: {' '.join(command)}")
            flash(
                f"Processing project '{original_zip_filename}' with Gemini AI. This may take several minutes...",
                "info",
            )

            process = subprocess.run(
                command, capture_output=True, text=True, check=False, timeout=600
            )

            if process.stdout:
                logger.debug(f"Agent CLI STDOUT:\n{process.stdout}")
            if process.stderr:
                logger.debug(f"Agent CLI STDERR:\n{process.stderr}")

            if process.returncode != 0:
                stderr_to_flash = process.stderr[:200]
                if "RuntimeWarning" in stderr_to_flash and len(process.stderr) > 200:
                    stderr_to_flash = process.stderr
                flash(
                    f"Error during AI analysis (CLI execution failed): {stderr_to_flash}...",
                    "error",
                )
                return redirect(url_for("index"))

            if not os.path.exists(agent_output_report_path):
                flash(
                    "AI analysis completed, but the output report was not found. Check server logs for CLI errors.",
                    "error",
                )
                return redirect(url_for("index"))

            flash(
                f"AI analysis for '{original_zip_filename}' complete! Report generated.",
                "success",
            )
            return redirect(
                url_for(
                    "display_report",
                    session_id=os.path.basename(session_folder),
                    filename=agent_output_report_name,
                )
            )

        except zipfile.BadZipFile:
            flash("Invalid ZIP file uploaded.", "error")
            return redirect(url_for("index"))
        except FileNotFoundError:
            flash(
                "Error: DepGuardian CLI agent command not found. Ensure it's installed correctly in the environment Flask is using.",
                "error",
            )
            return redirect(url_for("index"))
        except subprocess.TimeoutExpired:
            flash(
                "AI analysis timed out. The project might be too large or the AI is taking too long.",
                "error",
            )
            return redirect(url_for("index"))
        except Exception as e:
            logger.error(
                f"Error processing project ZIP '{original_zip_filename}': {e}",
                exc_info=True,
            )
            flash(f"Error processing project: {e}", "error")
            return redirect(url_for("index"))
    else:
        flash("Invalid file type. Please upload a ZIP file for AI analysis.", "error")
        return redirect(url_for("index"))


@app.route("/report/<session_id>/<filename>")
def display_report(session_id, filename):
    secured_filename = secure_filename(filename)
    filepath = os.path.join(
        TEMP_PROCESSING_DIR_BASE, secure_filename(session_id), secured_filename
    )

    context_for_report_display = {
        "report_data": None,
        "error_message": None,
        "filename": secured_filename,
        "session_id": session_id,
        "SCRIPT_LOAD_TIME": datetime.utcnow(),
        "gemini_available": genai is not None,
    }

    if not os.path.exists(filepath):
        flash(
            f"Report file '{secured_filename}' (session: {session_id}) not found. Please analyze or upload again.",
            "error",
        )
        return render_template("report_display.html", **context_for_report_display)

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            context_for_report_display["report_data"] = json.load(f)
        logger.info(f"Loaded report for display: {secured_filename} from {filepath}")
    except Exception as e:
        context_for_report_display[
            "error_message"
        ] = f"Error processing report '{secured_filename}': {e}"
        flash(context_for_report_display["error_message"], "error")

    return render_template("report_display.html", **context_for_report_display)


def run_server(host="127.0.0.1", port=5001, debug=False):
    logger.info(f"Starting DepGuardian GUI server on http://{host}:{port}")
    app.run(debug=debug, host=host, port=port, use_reloader=debug)


if __name__ == "__main__":
    run_server(debug=True)
