
from pathlib import Path
import sys

from flask import (
    Flask,
    request,
    render_template_string,
    send_file,
    abort,
    redirect,
    url_for
)

# ==========================================
# 1. PROJECT CONFIGURATION
# ==========================================

BASE_DIR = Path(__file__).resolve().parent
SRC_DIR = BASE_DIR / "src"
REPORT_DIR = BASE_DIR / "reports" / "generated"

sys.path.insert(0, str(SRC_DIR))

# ==========================================
# 2. IMPORT PROJECT MODULES
# ==========================================

from live_predict import (
    predict_url,
    create_security_report
)

from database import (
    save_scan,
    get_all_scans,
    get_scan_statistics,
    get_scan_by_id
)

# ==========================================
# 3. FLASK CONFIGURATION
# ==========================================

app = Flask(__name__)

app.config["MAX_CONTENT_LENGTH"] = 16 * 1024


# ==========================================
# 4. MAIN WEBSITE HTML
# ==========================================

HTML = """
<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<title>HACKTVIS PhishGuard</title>

<style>

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    background: #071315;
    color: #e9f5f3;
    font-family: Inter, Arial, sans-serif;
    min-height: 100vh;
}

nav {
    min-height: 75px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 15px 8%;
    border-bottom: 1px solid #183638;
}

.logo {
    font-size: 21px;
    font-weight: 800;
    color: #35ddc2;
}

.nav-links {
    display: flex;
    gap: 22px;
}

.nav-links a {
    color: #9ab2af;
    text-decoration: none;
    font-size: 14px;
}

.nav-links a:hover {
    color: #35ddc2;
}

.container {
    width: 90%;
    max-width: 1050px;
    margin: 75px auto;
}

.hero {
    text-align: center;
    margin-bottom: 45px;
}

.tag {
    display: inline-block;
    color: #35ddc2;
    border: 1px solid #17645b;
    padding: 8px 15px;
    border-radius: 30px;
    font-size: 12px;
    margin-bottom: 20px;
}

h1 {
    font-size: clamp(32px, 5vw, 53px);
    margin-bottom: 18px;
}

h1 span {
    color: #35ddc2;
}

.subtitle {
    color: #9ab2af;
    line-height: 1.7;
}

.scan-box {
    background: #102326;
    border: 1px solid #204447;
    padding: 30px;
    border-radius: 16px;
    max-width: 750px;
    margin: auto;
}

label {
    display: block;
    color: #b4ceca;
    font-size: 13px;
    margin-bottom: 12px;
}

input {
    width: 100%;
    padding: 17px;
    background: #071719;
    color: white;
    border: 1px solid #285153;
    border-radius: 9px;
    outline: none;
    font-size: 15px;
}

input:focus {
    border-color: #35ddc2;
}

button {
    width: 100%;
    padding: 16px;
    margin-top: 15px;
    background: #13a995;
    color: white;
    border: none;
    border-radius: 9px;
    font-size: 15px;
    font-weight: bold;
    cursor: pointer;
}

button:hover {
    background: #0d897b;
}

.error {
    color: #ff8989;
    background: #321b20;
    border: 1px solid #74343b;
    padding: 15px;
    margin-top: 20px;
    border-radius: 9px;
}

.results {
    margin-top: 35px;
    background: #102326;
    border: 1px solid #204447;
    padding: 25px;
    border-radius: 15px;
}

.results h2 {
    margin-bottom: 20px;
    color: #35ddc2;
}

.result-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 15px;
}

.result-card {
    background: #091a1c;
    border: 1px solid #204447;
    border-radius: 10px;
    padding: 18px;
    overflow-wrap: anywhere;
}

.result-card small {
    display: block;
    color: #8da9a5;
    margin-bottom: 9px;
}

.result-card strong {
    font-size: 20px;
}

.report-link {
    display: block;
    text-decoration: none;
    text-align: center;
    margin-top: 22px;
    padding: 15px;
    color: white;
    background: #087f8c;
    border-radius: 9px;
}

.notice {
    color: #a9bfbb;
    font-size: 12px;
    line-height: 1.6;
    margin-top: 18px;
}

.features {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 15px;
    margin-top: 55px;
}

.feature {
    padding: 22px 15px;
    background: #102326;
    border: 1px solid #204447;
    border-radius: 12px;
    text-align: center;
}

.feature h3 {
    color: #35ddc2;
    font-size: 15px;
    margin-bottom: 8px;
}

.feature p {
    color: #91aaa6;
    font-size: 12px;
    line-height: 1.6;
}

footer {
    text-align: center;
    color: #76918d;
    padding: 30px;
    border-top: 1px solid #183638;
    font-size: 12px;
}

@media(max-width: 650px) {

    .result-grid {
        grid-template-columns: 1fr;
    }

    .features {
        grid-template-columns: repeat(2, 1fr);
    }

    nav {
        padding: 15px 5%;
    }

    .container {
        margin: 45px auto;
    }

    .scan-box {
        padding: 20px;
    }

    .nav-links {
        gap: 12px;
    }
}

</style>

</head>

<body>

<nav>

    <div class="logo">
        🛡 HACKTVIS PhishGuard
    </div>

    <div class="nav-links">
        <a href="/">Home</a>
        <a href="/history">Scan History</a>
    </div>

</nav>

<div class="container">

    <section class="hero">

        <div class="tag">
            AI-POWERED PHISHING DETECTION
        </div>

        <h1>
            Detect Phishing.<br>
            <span>Browse Safer.</span>
        </h1>

        <p class="subtitle">
            Analyze website URLs using machine learning,
            website inspection and security indicators.
        </p>

    </section>

    <section class="scan-box">

        <form method="POST">

            <label for="url">
                ENTER WEBSITE URL
            </label>

            <input
                type="url"
                id="url"
                name="url"
                placeholder="https://example.com"
                maxlength="2048"
                value="{{ submitted_url }}"
                required
            >

            <button type="submit">
                🔍 Scan Website
            </button>

        </form>

        {% if error %}

            <div class="error">
                {{ error }}
            </div>

        {% endif %}

    </section>

    {% if result %}

    <section class="results">

        <h2>Scan Results</h2>

        <div class="result-grid">

            <div class="result-card">
                <small>ML Prediction</small>
                <strong>{{ result.verdict }}</strong>
            </div>

            <div class="result-card">
                <small>Risk Level</small>
                <strong>{{ result.risk.level }}</strong>
            </div>

            <div class="result-card">
                <small>Risk Score</small>
                <strong>{{ result.risk.score }}/100</strong>
            </div>

            <div class="result-card">
                <small>Phishing Probability</small>
                <strong>
                    {{ "%.2f"|format(
                    result.phishing_probability * 100
                    ) }}%
                </strong>
            </div>

            <div class="result-card">
                <small>Legitimate Probability</small>
                <strong>
                    {{ "%.2f"|format(
                    result.legitimate_probability * 100
                    ) }}%
                </strong>
            </div>

            <div class="result-card">
                <small>Reputation</small>
                <strong>{{ result.reputation.status }}</strong>
            </div>

            <div class="result-card">
                <small>HTTP Status</small>
                <strong>
                    {{ result.metadata.get("status_code", "Unknown") }}
                </strong>
            </div>

            <div class="result-card">
                <small>ML Features</small>
                <strong>{{ result.features|length }}</strong>
            </div>

        </div>

        <h3 style="margin-top:25px; color:#35ddc2;">
            Risk Indicators
        </h3>

        <ul style="margin:15px 0 0 20px; line-height:2;">

            {% for reason in result.risk.reasons %}
                <li>{{ reason }}</li>
            {% endfor %}

        </ul>

        {% if report_filename %}

            <a class="report-link"
               href="{{ url_for(
                    'download_report',
                    filename=report_filename
               ) }}">

                📄 Download PDF Security Report

            </a>

        {% endif %}

        <p class="notice">
            ML predictions and risk scores are experimental
            indicators, not confirmed security verdicts.
            The model has not yet been independently validated
            on live websites.
        </p>

    </section>

    {% endif %}

    <section class="features">

        <div class="feature">
            <h3>AI Detection</h3>
            <p>Machine learning phishing classification.</p>
        </div>

        <div class="feature">
            <h3>URL Analysis</h3>
            <p>URL structure and domain indicators.</p>
        </div>

        <div class="feature">
            <h3>Website Analysis</h3>
            <p>Static HTML security feature inspection.</p>
        </div>

        <div class="feature">
            <h3>PDF Reports</h3>
            <p>Downloadable scan summaries.</p>
        </div>

    </section>

</div>

<footer>

    HACKTVIS PhishGuard · AI-Powered Website Protection

    <br><br>

    Defensive security research and education.

</footer>

</body>
</html>
"""


# ==========================================
# 5. HOME AND SCANNER ROUTE
# ==========================================

@app.route("/", methods=["GET", "POST"])
def home():

    result = None
    error = None
    report_filename = None
    submitted_url = ""

    if request.method == "POST":

        submitted_url = request.form.get(
            "url", ""
        ).strip()

        if not submitted_url:

            error = "Please enter a website URL."

        elif len(submitted_url) > 2048:

            error = "URL is too long."

        else:

            try:

                # Run ML scanner
                result = predict_url(submitted_url)

                # Generate PDF
                report_path = create_security_report(
                    submitted_url,
                    result
                )

                report_filename = Path(
                    report_path
                ).name

                # Save scan to SQLite
                save_scan(
                    submitted_url,
                    result,
                    report_filename
                )

            except Exception as exception:

                result = None

                error = (
                    "Scan failed. Please check the URL "
                    "and try again."
                )

                app.logger.exception(
                    "PhishGuard scan failed: %s",
                    exception
                )

    return render_template_string(
        HTML,
        result=result,
        error=error,
        report_filename=report_filename,
        submitted_url=submitted_url
    )


# ==========================================
# 6. SCAN HISTORY DASHBOARD
# ==========================================

@app.route("/history")
def history():

    scans = get_all_scans()

    stats = get_scan_statistics()

    return render_template_string("""

    <!DOCTYPE html>
    <html lang="en">

    <head>

        <meta charset="UTF-8">

        <meta name="viewport"
              content="width=device-width, initial-scale=1">

        <title>PhishGuard Scan History</title>

        <style>

        * {
            box-sizing: border-box;
        }

        body {
            background: #071315;
            color: #e9f5f3;
            font-family: Arial, sans-serif;
            padding: 30px;
            margin: 0;
        }

        a {
            color: #35ddc2;
            text-decoration: none;
        }

        h1, h2 {
            color: #35ddc2;
        }

        .stats {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 15px;
            margin: 25px 0;
        }

        .card {
            background: #102326;
            padding: 22px;
            border: 1px solid #204447;
            border-radius: 10px;
            overflow-wrap: anywhere;
        }

        .card h2 {
            font-size: 30px;
        }

        .table-wrap {
            overflow-x: auto;
            margin-top: 20px;
        }

        table {
            width: 100%;
            min-width: 850px;
            border-collapse: collapse;
            background: #102326;
        }

        th, td {
            padding: 14px;
            border-bottom: 1px solid #204447;
            text-align: left;
        }

        th {
            color: #35ddc2;
        }

        tr:hover {
            background: #173235;
        }

        @media(max-width: 650px) {

            body {
                padding: 18px;
            }

            .stats {
                grid-template-columns: 1fr;
            }

        }

        </style>

    </head>

    <body>

        <h1>PhishGuard Scan History</h1>

        <p>
            <a href="/">← Back to Scanner</a>
        </p>

        <div class="stats">

            <div class="card">

                <h2>{{ stats.total_scans }}</h2>

                <p>Total Scans</p>

            </div>

            <div class="card">

                <h2>{{ stats.phishing_scans }}</h2>

                <p>Phishing Predictions</p>

            </div>

            <div class="card">

                <h2>{{ stats.legitimate_scans }}</h2>

                <p>Legitimate Predictions</p>

            </div>

        </div>

        <h2>Previous Scans</h2>

        <div class="table-wrap">

        <table>

            <tr>

                <th>ID</th>
                <th>URL</th>
                <th>Prediction</th>
                <th>Risk</th>
                <th>Date</th>
                <th>Report</th>

            </tr>

            {% for scan in scans %}

            <tr>

                <td>{{ scan.id }}</td>

                <td>{{ scan.url }}</td>

                <td>{{ scan.verdict }}</td>

                <td>
                    {{ scan.risk_score }}/100
                    ({{ scan.risk_level }})
                </td>

                <td>{{ scan.scanned_at }}</td>

                <td>

                    {% if scan.report_filename %}

                        <a href="{{ url_for(
                            'download_report',
                            filename=scan.report_filename
                        ) }}">
                            PDF
                        </a>

                    {% else %}

                        Not available

                    {% endif %}

                </td>

            </tr>

            {% else %}

            <tr>

                <td colspan="6">
                    No scans found.
                </td>

            </tr>

            {% endfor %}

        </table>

        </div>

    </body>

    </html>

    """, scans=scans, stats=stats)


# ==========================================
# 7. INDIVIDUAL SCAN DETAILS
# ==========================================

@app.route("/history/<int:scan_id>")
def scan_details(scan_id):

    scan = get_scan_by_id(scan_id)

    if not scan:
        abort(404)

    return render_template_string("""

    <!DOCTYPE html>
    <html>

    <head>

        <title>Scan Details</title>

        <meta name="viewport"
              content="width=device-width, initial-scale=1">

        <style>

        body {
            background: #071315;
            color: #e9f5f3;
            font-family: Arial, sans-serif;
            padding: 30px;
        }

        h1 {
            color: #35ddc2;
        }

        .card {
            max-width: 750px;
            background: #102326;
            border: 1px solid #204447;
            padding: 25px;
            border-radius: 12px;
            overflow-wrap: anywhere;
        }

        p {
            padding: 10px 0;
            border-bottom: 1px solid #204447;
        }

        a {
            color: #35ddc2;
            text-decoration: none;
        }

        </style>

    </head>

    <body>

        <h1>Scan Details #{{ scan.id }}</h1>

        <p><a href="/history">← Back to History</a></p>

        <div class="card">

            <p><b>URL:</b> {{ scan.url }}</p>

            <p><b>Prediction:</b> {{ scan.verdict }}</p>

            <p>
                <b>Phishing Probability:</b>
                {{ "%.2f"|format(
                    scan.phishing_probability * 100
                ) }}%
            </p>

            <p>
                <b>Legitimate Probability:</b>
                {{ "%.2f"|format(
                    scan.legitimate_probability * 100
                ) }}%
            </p>

            <p>
                <b>Risk Score:</b>
                {{ scan.risk_score }}/100
            </p>

            <p><b>Risk Level:</b> {{ scan.risk_level }}</p>

            <p>
                <b>Reputation:</b>
                {{ scan.reputation_status }}
            </p>

            <p><b>Scan Date:</b> {{ scan.scanned_at }}</p>

            {% if scan.report_filename %}

                <a href="{{ url_for(
                    'download_report',
                    filename=scan.report_filename
                ) }}">
                    Download PDF Report
                </a>

            {% endif %}

        </div>

    </body>

    </html>

    """, scan=scan)


# ==========================================
# 8. PDF DOWNLOAD ROUTE
# ==========================================

@app.route("/download/<filename>")
def download_report(filename):

    # Prevent directory traversal
    if (
        Path(filename).name != filename
        or not filename.endswith(".pdf")
    ):
        abort(404)

    report_dir = REPORT_DIR.resolve()

    report_path = (
        REPORT_DIR / filename
    ).resolve()

    if report_path.parent != report_dir:
        abort(404)

    if not report_path.is_file():
        abort(404)

    return send_file(
        report_path,
        as_attachment=True,
        download_name=filename,
        mimetype="application/pdf"
    )


# ==========================================
# 9. ERROR HANDLERS
# ==========================================

@app.errorhandler(404)
def not_found(error):

    return "Requested page or report was not found.", 404


@app.errorhandler(413)
def file_too_large(error):

    return "Request is too large.", 413


# ==========================================
# 10. START WEBSITE
# ==========================================

if __name__ == "__main__":

    print("\n" + "=" * 45)
    print("       HACKTVIS PhishGuard")
    print("       AI WEBSITE SECURITY")
    print("=" * 45)

    print("\nScanner: http://127.0.0.1:5000")
    print("History: http://127.0.0.1:5000/history")

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
