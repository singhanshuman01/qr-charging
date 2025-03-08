#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>
#include <ESP8266WebServer.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>

#define SCREEN_WIDTH 128 // OLED display width, in pixels
#define SCREEN_HEIGHT 64 // OLED display height, in pixels

// Declaration for an SSD1306 display connected to I2C (SDA, SCL pins)
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, -1);

const int relayPin = D3;
const char* ssid = "realme8i";
const char* password = "ansh0098";
const char* flaskServerURL = "http://192.168.150.21:5000/register_ip";

ESP8266WebServer server(80);

void printOled(const char* s){
  Serial.println(s);
  display.clearDisplay();

  display.setTextSize(1);
  display.setTextColor(WHITE);
  display.setCursor(0, 10);
  // Display static text
  display.println(s);
  display.display(); 
}

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
  if(!display.begin(SSD1306_SWITCHCAPVCC, 0x3D)) { // Address 0x3D for 128x64
    Serial.println(F("SSD1306 allocation failed"));
    for(;;);
  }
  delay(2000);
  printOled("Idle...");

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
    printOled("Charging...");
    server.send(200, "application/json", "{\"status\": \"Charging\"}");
  });

  server.on("/relay_off", []() {
    digitalWrite(relayPin, LOW);
    printOled("Idle...");
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
