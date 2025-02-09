from flask import Flask, request, jsonify, render_template, redirect, url_for
import requests
import mysql.connector
from datetime import datetime

app = Flask(__name__)

# Global variable to store NodeMCU IP
nodeMCU_IP = None

# MySQL Database Connection
db_config = {
    "host": "localhost",
    "user": "root",
    "password": "anshuMan0098@",
    "database": "rfid_charging",
    "use_pure": True,
    "ssl_disabled": True
}

# Function to log data into MySQL
def log_charging(user_id, start_time=None, stop_time=None):
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()

        if start_time and not stop_time:  # Log start time
            query = "INSERT INTO charging_logs (user_id, start_time) VALUES (%s, %s)"
            cursor.execute(query, (user_id, start_time))
        elif stop_time:  # Update stop time
            query = "UPDATE charging_logs SET stop_time = %s WHERE user_id = %s AND stop_time IS NULL"
            cursor.execute(query, (stop_time, user_id))

        conn.commit()
        cursor.close()
        conn.close()
    except mysql.connector.Error as err:
        print(f"Error: {err}")


@app.route("/register_ip", methods=["POST"])
def register_ip():
    global nodeMCU_IP
    data = request.get_json()
    if "ip" in data:
        nodeMCU_IP = data["ip"]
        print(f"NodeMCU IP registered: {nodeMCU_IP}")
        return jsonify({"status": "IP registered successfully"}), 200
    return jsonify({"error": "Invalid request"}), 400


@app.route("/login", methods=["POST", "GET"])
def login():
    if request.method == "POST":
        user_id = request.form["user_id"]
        password = request.form["password"]

        # Verify user credentials from the MySQL database
        try:
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor(dictionary=True)

            query = "SELECT * FROM users WHERE user_id = %s AND password = %s"
            cursor.execute(query, (user_id, password))
            user = cursor.fetchone()

            cursor.close()
            conn.close()

            if user:
                # Log start time
                log_charging(user_id, start_time=datetime.now())
                # Redirect to success page
                return redirect(url_for("success", user_id=user_id))
            else:
                return render_template("login.html", error="Invalid credentials")

        except mysql.connector.Error as err:
            print(f"Error: {err}")
            return render_template("login.html", error="Database connection error")

    return render_template("login.html")


@app.route("/success/<user_id>", methods=["GET", "POST"])
def success(user_id):
    if request.method == "POST":  # Stop charging manually
        stop_charging()
        # Log stop time
        log_charging(user_id, stop_time=datetime.now())
        return redirect(url_for("login"))

    # Start charging via NodeMCU
    if nodeMCU_IP:
        try:
            requests.get(f"http://{nodeMCU_IP}/relay_on")
        except Exception as e:
            print(f"Error communicating with NodeMCU: {e}")
            return render_template("success.html", user_id=user_id, error="Unable to start charging")

    return render_template("success.html", user_id=user_id)


@app.route("/status", methods=["GET"])
def status():
    charging_status = "Unknown"
    if nodeMCU_IP:
        try:
            response = requests.get(f"http://{nodeMCU_IP}/status")
            charging_status = response.json().get("status", "Unknown")
        except Exception as e:
            print(f"Error fetching status: {e}")

    # Fetch logs from MySQL
    logs = []
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)

        query = "SELECT * FROM charging_logs ORDER BY start_time DESC"
        cursor.execute(query)
        logs = cursor.fetchall()
        for log in logs:
            print(log)

        cursor.close()
        conn.close()
        return render_template("status.html", logs=logs, status=charging_status)
    except mysql.connector.Error as err:
        print(f"Error: {err}")


@app.route('/stop_charging/<user_id>')
def stop_charging(user_id):
    stop_time = datetime.now()

    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)
    cursor.execute("UPDATE charging_logs SET stop_time = %s WHERE user_id = %s AND stop_time IS NULL",
                    (stop_time, user_id))
    conn.commit()
    cursor.close()
    conn.close()

    # Send request to NodeMCU to turn off the relay
    try:
        requests.get(f"http://{nodeMCU_IP}/relay_off")
        return redirect(url_for('login'))
    except requests.exceptions.RequestException as e:
        print("Error communicating with NodeMCU:", e)

    # flash('Charging Stopped', 'info')
    return redirect(url_for('login'))

# @app.route("/relay_off", methods=["POST"])
# def stop_charging():
#     if nodeMCU_IP:
#         try:
#             requests.get(f"http://{nodeMCU_IP}/relay_off")
#             return jsonify({"status": "Charging stopped"})
#         except Exception as e:
#             return jsonify({"error": str(e)})

#     return jsonify({"error": "NodeMCU IP not registered"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
