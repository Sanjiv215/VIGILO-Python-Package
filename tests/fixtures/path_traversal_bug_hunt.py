filename = request.args.get("name", "").strip()
file_path = os.path.join(UPLOAD_DIR, filename)
if not os.path.exists(file_path):
    return jsonify({"error": "File not found"}), 404
return send_file(file_path, as_attachment=True)
