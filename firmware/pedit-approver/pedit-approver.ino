// pedit-approver: the ESP32-S3 side of internal/approve/serial.go.
//
// Talks plain Serial (UART0, wired to this board's CH340 USB-serial bridge
// -- the "uart" port, not the SoC's native USB port; see this firmware's
// README for why). No special USBMode build flag is needed for that, unlike
// sketches that want a console on the native port.
//
// Line protocol (newline-terminated ASCII, matches serial.go exactly):
//   host -> board: "HELLO"
//   board -> host: "PEDIT-APPROVER v1"
//   host -> board: "REQ <opaque display text>"
//   board -> host: "YES"  (BOOT button pressed before the timeout)
//   board -> host: "NO"   (timeout elapsed with no press)
//
// The request body isn't parsed, only displayed -- peditagentd already
// decides everything that matters (profile allowlist, size limits); this
// board's only job is "did a human standing at it press the button."

#include <Adafruit_NeoPixel.h>

#define BUTTON_PIN 0     // BOOT button, active-low (standard on ESP32-S3 devkits)
#define USE_LED 1
#define REQUEST_TIMEOUT_MS 120000
#define DEBOUNCE_MS 30

// Official Espressif ESP32-S3-DevKitC-1: the onboard addressable RGB LED
// moved from GPIO48 (original) to GPIO38 (v1.1, after a PSRAM 1.8V supply
// fix on GPIO47/48) -- see docs.espressif.com's v1.1 user guide changelog.
// Rather than guess the revision, drive both; whichever one is actually
// wired lights up; the other GPIO does nothing.
#if USE_LED
Adafruit_NeoPixel led48(1, 48, NEO_GRB + NEO_KHZ800);
Adafruit_NeoPixel led38(1, 38, NEO_GRB + NEO_KHZ800);
#endif

void setColor(uint8_t r, uint8_t g, uint8_t b) {
#if USE_LED
  led48.setPixelColor(0, led48.Color(r, g, b));
  led48.show();
  led38.setPixelColor(0, led38.Color(r, g, b));
  led38.show();
#endif
}

void setup() {
  Serial.begin(115200);
  pinMode(BUTTON_PIN, INPUT_PULLUP);
#if USE_LED
  led48.begin();
  led38.begin();
#endif
  setColor(0, 0, 0);
}

String readLine() {
  static String buf;
  while (true) {
    while (Serial.available()) {
      char c = (char)Serial.read();
      if (c == '\n') {
        String line = buf;
        buf = "";
        line.trim();
        return line;
      }
      if (c != '\r') buf += c;
    }
  }
}

// Blocks until the button is pressed or REQUEST_TIMEOUT_MS elapses. Returns
// true on press. A plain edge check (not just "is it low") so a button
// already held down from a previous press doesn't auto-approve the next
// request.
bool waitForButton() {
  unsigned long start = millis();
  int lastState = digitalRead(BUTTON_PIN);
  while (millis() - start < REQUEST_TIMEOUT_MS) {
    int state = digitalRead(BUTTON_PIN);
    if (lastState == HIGH && state == LOW) {
      delay(DEBOUNCE_MS);
      if (digitalRead(BUTTON_PIN) == LOW) return true;
    }
    lastState = state;
    delay(5);
  }
  return false;
}

void handleRequest(const String &body) {
  Serial.print("# pending: ");
  Serial.println(body);
  setColor(40, 25, 0); // amber: awaiting the button

  bool approved = waitForButton();

  if (approved) {
    setColor(0, 40, 0); // green
    Serial.println("YES");
  } else {
    setColor(40, 0, 0); // red
    Serial.println("NO");
  }
  delay(400);
  setColor(0, 0, 0);
}

void loop() {
  String line = readLine();
  if (line == "HELLO") {
    Serial.println("PEDIT-APPROVER v1");
  } else if (line.startsWith("REQ ")) {
    handleRequest(line.substring(4));
  }
  // anything else: ignore
}
