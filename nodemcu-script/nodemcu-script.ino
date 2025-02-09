#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>
#include <ESP8266WebServer.h>

const int relayPin = D1;
const char* ssid = "realme8i";
const char* password = "ansh0098";
const char* flaskServerURL = "http://192.168.149.21:5000/register_ip";

ESP8266WebServer server(80);

void announceIP() {
  if (WiFi.status() == WL_CONNECTED) {
    WiFiClient client;
    HTTPClient http;
    String nodeMCU_IP = WiFi.localIP().toString();
    http.begin(client,flaskServerURL);
    http.addHeader("Content-Type", "application/json");

    String requestBody = "{\"ip\": \"" + nodeMCU_IP + "\"}";
    int httpResponseCode = http.POST(requestBody);

    if (httpResponseCode > 0) {
      Serial.print("IP announced successfully: ");
      Serial.println(nodeMCU_IP);
    } else {
      Serial.print("Failed to announce IP: ");
      Serial.println(httpResponseCode);
    }
    http.end();
  }
}

void setup() {
  Serial.begin(115200);
  pinMode(relayPin, OUTPUT);
  digitalWrite(relayPin, LOW);

  // Connect to Wi-Fi
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nConnected to Wi-Fi!");
  Serial.print("ESP IP Address: ");
  Serial.println(WiFi.localIP());

  // Announce IP to Flask server
  announceIP();

  // Define routes
  server.on("/relay_on", []() {
    digitalWrite(relayPin, HIGH);
    server.send(200, "application/json", "{\"status\": \"Charging\"}");
  });

  server.on("/relay_off", []() {
    digitalWrite(relayPin, LOW);
    server.send(200, "application/json", "{\"status\": \"Idle\"}");
  });

  server.on("/status", []() {
    String status = digitalRead(relayPin) == HIGH ? "Charging" : "Idle";
    server.send(200, "application/json", "{\"status\": \"" + status + "\"}");
  });

  server.begin();
  Serial.println("Server started");
}

void loop() {
  server.handleClient();
}
