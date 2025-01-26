from flask import Flask, request, jsonify
from flask_cors import CORS
from androguard.core.bytecodes.apk import APK
import requests
import os

app = Flask(__name__)
CORS(app)  # CORSを全て許可

@app.route('/analyze', methods=['GET', 'POST'])
def analyze_apk():
    if request.method == 'GET':
        return jsonify({"message": "Use POST or GET with 'url' parameter to analyze an APK."}), 200

    # GETリクエストでの処理
    apk_url = request.args.get('url') if request.method == 'GET' else None
    if request.method == 'POST':
        data = request.get_json()
        apk_url = data.get('url') if data else None

    if not apk_url:
        return jsonify({"error": "No URL provided"}), 400

    apk_path = "./downloaded_apk.apk"

    try:
        # ファイルをダウンロード
        response = requests.get(apk_url, stream=True)
        if response.status_code != 200:
            return jsonify({"error": "Failed to download the APK file"}), 400
        
        with open(apk_path, 'wb') as apk_file:
            for chunk in response.iter_content(chunk_size=8192):
                apk_file.write(chunk)

        # APKを解析
        apk = APK(apk_path)
        result = {
            "App Name": apk.get_app_name(),
            "Package Name": apk.get_package(),
            "Version Code": apk.get_androidversion_code(),
            "Version Name": apk.get_androidversion_name(),
        }

        # 一時ファイルを削除
        os.remove(apk_path)
        return jsonify(result), 200

    except Exception as e:
        if os.path.exists(apk_path):
            os.remove(apk_path)
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)
