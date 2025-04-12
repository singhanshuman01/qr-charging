#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>
#include <ESP8266WebServer.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>

#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_RESET    -1
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);

const int relayPin = D4;  // Changed from D1 to D4
const char* ssid = "realme8i";
const char* password = "ansh0098";
const char* flaskServerURL = "http://192.168.33.21:5000/register_ip";

ESP8266WebServer server(80);

String relayStatus = "Idle";  // Track relay state

void updateDisplay() {
    display.clearDisplay();
    display.setTextSize(2);
    display.setTextColor(WHITE);
    display.setCursor(20, 25);
    display.println(relayStatus);
    display.display();
}

void announceIP() {
    if (WiFi.status() == WL_CONNECTED) {
        WiFiClient client;
        HTTPClient http;
        String nodeMCU_IP = WiFi.localIP().toString();
        http.begin(client, flaskServerURL);
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
    Serial.begin(9600);
    pinMode(relayPin, OUTPUT);
    digitalWrite(relayPin, LOW);

    // Initialize OLED display
    if (!display.begin(SSD1306_SWITCHCAPVCC, 0x3C)) {
        Serial.println(F("SSD1306 allocation failed"));
        for (;;);
    }
    display.clearDisplay();
    display.setTextSize(1);
    display.setTextColor(WHITE);
    display.setCursor(0, 0);
    display.println("Starting...");
    display.display();
    delay(1000);

    // Connect to Wi-Fi
    WiFi.begin(ssid, password);
    unsigned long startAttemptTime = millis();
    while (WiFi.status() != WL_CONNECTED && millis() - startAttemptTime < 20000) {  // 20-second timeout
        delay(500);
        Serial.print(".");
    }
    if (WiFi.status() == WL_CONNECTED) {
        Serial.println("\nConnected to Wi-Fi!");
        Serial.print("ESP IP Address: ");
        Serial.println(WiFi.localIP());
        announceIP();
    } else {
        Serial.println("\nFailed to connect to Wi-Fi!");
    }

    // Initial Display Update
    updateDisplay();

    // Define routes
    server.on("/relay_on", []() {
        digitalWrite(relayPin, HIGH);
        relayStatus = "Charging";
        updateDisplay();
        server.send(200, "application/json", "{\"status\": \"Charging\"}");
    });

    server.on("/relay_off", []() {
        digitalWrite(relayPin, LOW);
        relayStatus = "Idle";
        updateDisplay();
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
