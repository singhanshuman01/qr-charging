, methods=["POST"])
# def stop_charging():
#     if nodeMCU_IP:
#         try:
#             requests.get(f"http://{nodeMCU_IP}/relay_off")
#             return jsonify({"status": "Charging stopped"})
#         except Exception as e:
#             return jsonify({"error": str(e)})

#     return jsonify({"error": "NodeMCU IP not registered"})