/**************************************************************
   AsyncWiFiManager is a library for the ESP8266/Arduino platform
   (https://github.com/esp8266/Arduino) to enable easy
   configuration and reconfiguration of WiFi credentials using a Captive Portal
   inspired by:
   http://www.esp8266.com/viewtopic.php?f=29&t=2520
   https://github.com/chriscook8/esp-arduino-apboot
   https://github.com/esp8266/Arduino/tree/esp8266/hardware/esp8266com/esp8266/libraries/DNSServer/examples/CaptivePortalAdvanced
   Built by AlexT https://github.com/tzapu
   Ported to Async Web Server by https://github.com/alanswx
   Licensed under MIT license
 **************************************************************/

#include "ESPAsyncWiFiManager.h"

AsyncWiFiManagerParameter::AsyncWiFiManagerParameter(const char *custom)
{
  _id = NULL;
  _placeholder = NULL;
  _length = 0;
  _value = NULL;

  _customHTML = custom;
}

AsyncWiFiManagerParameter::AsyncWiFiManagerParameter(const char *id,
                                                     const char *placeholder,
                                                     const char *defaultValue,
                                                     unsigned int length)
{
  init(id, placeholder, defaultValue, length, "");
}

AsyncWiFiManagerParameter::AsyncWiFiManagerParameter(const char *id,
                                                     const char *placeholder,
                                                     const char *defaultValue,
                                                     unsigned int length,
                                                     const char *custom)
{
  init(id, placeholder, defaultValue, length, custom);
}

void AsyncWiFiManagerParameter::init(const char *id,
                                     const char *placeholder,
                                     const char *defaultValue,
                                     unsigned int length,
                                     const char *custom)
{
  _id = id;
  _placeholder = placeholder;
  _length = length;
  _value = new char[length + 1];

  for (unsigned int i = 0; i < length; i++)
  {
    _value[i] = 0;
  }
  if (defaultValue != NULL)
  {
    strncpy(_value, defaultValue, length);
  }

  _customHTML = custom;
}

const char *AsyncWiFiManagerParameter::getValue()
{
  return _value;
}
const char *AsyncWiFiManagerParameter::getID()
{
  return _id;
}
const char *AsyncWiFiManagerParameter::getPlaceholder()
{
  return _placeholder;
}
unsigned int AsyncWiFiManagerParameter::getValueLength()
{
  return _length;
}
const char *AsyncWiFiManagerParameter::getCustomHTML()
{
  return _customHTML;
}

#ifdef USE_EADNS
AsyncWiFiManager::AsyncWiFiManager(AsyncWebServer *server,
                                   AsyncDNSServer *dns) : server(server), dnsServer(dns)
{
#else
AsyncWiFiManager::AsyncWiFiManager(AsyncWebServer *server,
                                   DNSServer *dns) : server(server), dnsServer(dns)
{
#endif
  wifiSSIDs = NULL;
  wifiSSIDscan = true;
  _modeless = false;
  shouldscan = true;
}

void AsyncWiFiManager::addParameter(AsyncWiFiManagerParameter *p)
{
  _params[_paramsCount] = p;
  _paramsCount++;
  DEBUG_WM(F("Adding parameter"));
  DEBUG_WM(p->getID());
}

void AsyncWiFiManager::setupConfigPortal()
{
  server->reset();

  DEBUG_WM(F(""));
  _configPortalStart = millis();
  _wifiConnectStatus = 0;
  // Scan once, before a phone is connected. Scanning later drops the phone.
  shouldscan = true;
  scanModal();

  DEBUG_WM(F("Configuring access point... "));
  DEBUG_WM(_apName);
  if (_apPassword != NULL)
  {
    if (strlen(_apPassword) < 8 || strlen(_apPassword) > 63)
    {
      // fail passphrase to short or long!
      DEBUG_WM(F("Invalid AccessPoint password. Ignoring"));
      _apPassword = NULL;
    }
    DEBUG_WM(_apPassword);
  }

  // optional soft ip config
  if (_ap_static_ip)
  {
    DEBUG_WM(F("Custom AP IP/GW/Subnet"));
    WiFi.softAPConfig(_ap_static_ip, _ap_static_gw, _ap_static_sn);
  }

  if (_apPassword != NULL)
  {
    WiFi.softAP(_apName, _apPassword); // password option
  }
  else
  {
    WiFi.softAP(_apName);
  }

  delay(500); // without delay I've seen the IP address blank
  DEBUG_WM(F("AP IP address: "));
  DEBUG_WM(WiFi.softAPIP());

// setup the DNS server redirecting all the domains to the apIP
#ifdef USE_EADNS
  dnsServer->setErrorReplyCode(AsyncDNSReplyCode::NoError);
#else
  dnsServer->setErrorReplyCode(DNSReplyCode::NoError);
#endif
  if (!dnsServer->start(DNS_PORT, "*", WiFi.softAPIP()))
  {
    DEBUG_WM(F("Could not start Captive DNS Server!"));
  }
  // setup web pages: root, wifi config pages, SO captive portal detectors and not found
  server->on("/",
             std::bind(&AsyncWiFiManager::handleWifi, this, std::placeholders::_1, true))
      .setFilter(ON_AP_FILTER);
  server->on("/wifi",
             std::bind(&AsyncWiFiManager::handleWifi, this, std::placeholders::_1, true))
      .setFilter(ON_AP_FILTER);
  server->on("/wifisave",
             std::bind(&AsyncWiFiManager::handleWifiSave, this, std::placeholders::_1))
      .setFilter(ON_AP_FILTER);
  server->on("/status", HTTP_GET, [](AsyncWebServerRequest *request)
  {
    if (_wifiConnectStatus == 1)
      request->send(200, "text/plain", "SUCCESS");
    else if (_wifiConnectStatus == 2)
      request->send(200, "text/plain", "FAILED");
    else
      request->send(200, "text/plain", "CONNECTING");
  }).setFilter(ON_AP_FILTER);
  // A 204 or the word Success tells the phone the network is fine, so it
  // shows "no internet" and never opens the setup page. Send it there.
  // DNS is stopped as soon as Wi-Fi connects, so this does not keep
  // hijacking https://lukerobotarm.com afterwards.
  const char *probes[] = {
      "/hotspot-detect.html", "/canonical.html", "/generate_204", "/generate204",
      "/gen_204", "/connecttest.txt", "/ncsi.txt", "/redirect", "/fwlink"};
  for (const char *probe : probes)
  {
    server->on(probe, HTTP_ANY, [](AsyncWebServerRequest *request) {
      const String url = String("http://") + WiFi.softAPIP().toString() + "/";
      AsyncWebServerResponse *response = request->beginResponse(302, "text/plain", "redirect to captive portal");
      response->addHeader("Location", url);
      response->addHeader("Cache-Control", "no-cache, no-store, must-revalidate");
      request->send(response);
    });
  }
  server->onNotFound(std::bind(&AsyncWiFiManager::handleNotFound, this, std::placeholders::_1));
  server->begin(); // web server start
  DEBUG_WM(F("HTTP server started"));
}

static const char HEX_CHAR_ARRAY[17] = "0123456789ABCDEF";

#if !defined(ESP8266)
/**
* convert char array (hex values) to readable string by seperator
* buf:           buffer to convert
* length:        data length
* strSeperator   seperator between each hex value
* return:        formated value as String
*/
static String byteToHexString(uint8_t *buf, uint8_t length, String strSeperator = "-")
{
  String dataString = "";
  for (uint8_t i = 0; i < length; i++)
  {
    byte v = buf[i] / 16;
    byte w = buf[i] % 16;
    if (i > 0)
    {
      dataString += strSeperator;
    }
    dataString += String(HEX_CHAR_ARRAY[v]);
    dataString += String(HEX_CHAR_ARRAY[w]);
  }
  dataString.toUpperCase();
  return dataString;
} // byteToHexString

String getESP32ChipID()
{
  uint64_t chipid;
  chipid = ESP.getEfuseMac(); // the chip ID is essentially its MAC address (length: 6 bytes)
  uint8_t chipid_size = 6;
  uint8_t chipid_arr[chipid_size];
  for (uint8_t i = 0; i < chipid_size; i++)
  {
    chipid_arr[i] = (chipid >> (8 * i)) & 0xff;
  }
  return byteToHexString(chipid_arr, chipid_size, "");
}
#endif

boolean AsyncWiFiManager::autoConnect(unsigned long maxConnectRetries,
                                      unsigned long retryDelayMs)
{
  String ssid = "ESP";
#if defined(ESP8266)
  ssid += String(ESP.getChipId());
#else
  ssid += getESP32ChipID();
#endif
  return autoConnect(ssid.c_str(), NULL);
}

boolean AsyncWiFiManager::autoConnect(char const *apName,
                                      char const *apPassword,
                                      unsigned long maxConnectRetries,
                                      unsigned long retryDelayMs)
{
  DEBUG_WM(F(""));

  // attempt to connect; should it fail, fall back to AP
  WiFi.mode(WIFI_STA);

  for (unsigned long tryNumber = 0; tryNumber < maxConnectRetries; tryNumber++)
  {
    DEBUG_WM(F("AutoConnect Try No.:"));
    DEBUG_WM(tryNumber);

    if (connectWifi("", "") == WL_CONNECTED)
    {
      DEBUG_WM(F("IP Address:"));
      DEBUG_WM(WiFi.localIP());
      // connected
      return true;
    }

    if (tryNumber + 1 < maxConnectRetries)
    {
      // we might connect during the delay
      unsigned long restDelayMs = retryDelayMs;
      while (restDelayMs != 0)
      {
        if (WiFi.status() == WL_CONNECTED)
        {
          DEBUG_WM(F("IP Address (connected during delay):"));
          DEBUG_WM(WiFi.localIP());
          return true;
        }
        unsigned long thisDelay = std::min(restDelayMs, 100ul);
        delay(thisDelay);
        restDelayMs -= thisDelay;
      }
    }
  }

  return startConfigPortal(apName, apPassword);
}

String AsyncWiFiManager::networkListAsString()
{
  String pager;
  int shown = 0;
  // Strongest first. Hide our own setup network and keep at most five.
  for (int i = 0; i < wifiSSIDCount && shown < 5; i++)
  {
    if (wifiSSIDs[i].duplicate == true)
    {
      continue; // skip dups
    }
    if (wifiSSIDs[i].SSID.length() == 0 || wifiSSIDs[i].SSID.startsWith("Luke-"))
    {
      continue;
    }
    unsigned int quality = getRSSIasQuality(wifiSSIDs[i].RSSI);

    if (_minimumQuality == 0 || _minimumQuality < quality)
    {
      String item = F("<div><a href='javascript:void(0);' data-ssid='{v}' onclick='c(this); return false;'>{v}</a> <span>{r}%</span></div>");
      String rssiQ;
      rssiQ += quality;
      item.replace("{v}", wifiSSIDs[i].SSID);
      item.replace("{r}", rssiQ);
#if defined(ESP8266)
      if (wifiSSIDs[i].encryptionType != ENC_TYPE_NONE)
      {
#else
      if (wifiSSIDs[i].encryptionType != WIFI_AUTH_OPEN)
      {
#endif
        item.replace("{i}", "l");
      }
      else
      {
        item.replace("{i}", "");
      }
      pager += item;
      shown++;
    }
  }
  return pager;
}

String AsyncWiFiManager::scanModal()
{
  shouldscan = true;
  scan();
  String pager = networkListAsString();
  return pager;
}

void AsyncWiFiManager::scan(boolean async)
{
  if (!shouldscan)
  {
    return;
  }
  // DEBUG_WM(F("About to scan()"));
  if (wifiSSIDscan)
  {
    wifi_ssid_count_t n = WiFi.scanNetworks(async);
    copySSIDInfo(n);
  }
}

void AsyncWiFiManager::copySSIDInfo(wifi_ssid_count_t n)
{
  if (n == WIFI_SCAN_FAILED)
  {
    DEBUG_WM(F("scanNetworks returned: WIFI_SCAN_FAILED!"));
  }
  else if (n == WIFI_SCAN_RUNNING)
  {
    DEBUG_WM(F("scanNetworks returned: WIFI_SCAN_RUNNING!"));
  }
  else if (n < 0)
  {
    DEBUG_WM(F("scanNetworks failed with unknown error code!"));
  }
  else if (n == 0)
  {
    DEBUG_WM(F("No networks found"));
    // page += F("No networks found. Refresh to scan again.");
  }
  else
  {
    // DEBUG_WM(F("Scan done"));
  }

  if (n > 0)
  {
    // WE SHOULD MOVE THIS IN PLACE ATOMICALLY
    if (wifiSSIDs)
    {
      delete[] wifiSSIDs;
    }
    wifiSSIDs = new WiFiResult[n];
    wifiSSIDCount = n;

    if (n > 0)
    {
      shouldscan = false;
    }
    for (wifi_ssid_count_t i = 0; i < n; i++)
    {
      wifiSSIDs[i].duplicate = false;

#if defined(ESP8266)
      WiFi.getNetworkInfo(i,
                          wifiSSIDs[i].SSID,
                          wifiSSIDs[i].encryptionType,
                          wifiSSIDs[i].RSSI,
                          wifiSSIDs[i].BSSID,
                          wifiSSIDs[i].channel,
                          wifiSSIDs[i].isHidden);
#else
      WiFi.getNetworkInfo(i,
                          wifiSSIDs[i].SSID,
                          wifiSSIDs[i].encryptionType,
                          wifiSSIDs[i].RSSI,
                          wifiSSIDs[i].BSSID,
                          wifiSSIDs[i].channel);
#endif
    }

    // RSSI SORT

    // old sort
    for (int i = 0; i < n; i++)
    {
      for (int j = i + 1; j < n; j++)
      {
        if (wifiSSIDs[j].RSSI > wifiSSIDs[i].RSSI)
        {
          std::swap(wifiSSIDs[i], wifiSSIDs[j]);
        }
      }
    }

    // remove duplicates ( must be RSSI sorted )
    if (_removeDuplicateAPs)
    {
      String cssid;
      for (int i = 0; i < n; i++)
      {
        if (wifiSSIDs[i].duplicate == true)
        {
          continue;
        }
        cssid = wifiSSIDs[i].SSID;
        for (int j = i + 1; j < n; j++)
        {
          if (cssid == wifiSSIDs[j].SSID)
          {
            //DEBUG_WM("DUP AP: " + wifiSSIDs[j].SSID);
            wifiSSIDs[j].duplicate = true; // set dup aps to NULL
          }
        }
      }
    }
  }
}

void AsyncWiFiManager::startConfigPortalModeless(char const *apName, char const *apPassword)
{
  _modeless = true;
  _apName = apName;
  _apPassword = apPassword;

  /*
  AJS - do we want this?
  */

  // setup AP
  WiFi.mode(WIFI_AP_STA);
  DEBUG_WM(F("SET AP STA"));

  // try to connect
  if (connectWifi("", "") == WL_CONNECTED)
  {
    DEBUG_WM(F("IP Address:"));
    DEBUG_WM(WiFi.localIP());
    // connected
    // call the callback!
    if (_savecallback != NULL)
    {
      // TODO: check if any custom parameters actually exist, and check if they really changed maybe
      _savecallback();
    }
  }

  // notify we entered AP mode
  if (_apcallback != NULL)
  {
    _apcallback(this);
  }

  connect = false;
  setupConfigPortal();
  scannow = 0;
}

void AsyncWiFiManager::loop()
{
  safeLoop();
  criticalLoop();
}

// anything that accesses WiFi, ESP or EEPROM goes here
void AsyncWiFiManager::criticalLoop()
{
  if (_modeless)
  {
    if (scannow == 0 || millis() - scannow >= 60000)
    {
      scannow = millis();
      scan(true);
    }

    wifi_ssid_count_t n = WiFi.scanComplete();
    if (n >= 0)
    {
      copySSIDInfo(n);
      WiFi.scanDelete();
    }

    if (connect)
    {
      connect = false;
      //delay(2000);
      DEBUG_WM(F("Connecting to new AP"));

      // using user-provided _ssid, _pass in place of system-stored ssid and pass
      if (connectWifi(_ssid, _pass) != WL_CONNECTED)
      {
        DEBUG_WM(F("Failed to connect"));
      }
      else
      {
        // connected
        // alanswx - should we have a config to decide if we should shut down AP?
        // WiFi.mode(WIFI_STA);
        // notify that configuration has changed and any optional parameters should be saved
        if (_savecallback != NULL)
        {
          // TODO: check if any custom parameters actually exist, and check if they really changed maybe
          _savecallback();
        }

        return;
      }

      if (_shouldBreakAfterConfig)
      {
        // flag set to exit after config after trying to connect
        // notify that configuration has changed and any optional parameters should be saved
        if (_savecallback != NULL)
        {
          // TODO: check if any custom parameters actually exist, and check if they really changed maybe
          _savecallback();
        }
      }
    }
  }
}

// anything that doesn't access WiFi, ESP or EEPROM can go here
void AsyncWiFiManager::safeLoop()
{
#ifndef USE_EADNS
  dnsServer->processNextRequest();
#endif
}

boolean AsyncWiFiManager::startConfigPortal(char const *apName, char const *apPassword)
{
  // setup AP
  WiFi.mode(WIFI_AP_STA);
  DEBUG_WM(F("SET AP STA"));

  _apName = apName;
  _apPassword = apPassword;
  bool connectedDuringConfigPortal = false;

  // notify we entered AP mode
  if (_apcallback != NULL)
  {
    _apcallback(this);
  }

  connect = false;
  setupConfigPortal();
  scannow = 0;
  while (_configPortalTimeout == 0 || millis() - _configPortalStart < _configPortalTimeout)
  {
// DNS
#ifndef USE_EADNS
    dnsServer->processNextRequest();
#endif
    // Do not scan or disconnect while a phone is on the setup network.

    // attempts to reconnect were successful
    if (WiFi.status() == WL_CONNECTED)
    {
      // connected
      WiFi.mode(WIFI_STA);
      // notify that configuration has changed and any optional parameters should be saved
      // configuraton should not be saved when just connected using stored ssid and password during config portal
      if (!connectedDuringConfigPortal && _savecallback != NULL)
      {
        // TODO: check if any custom parameters actually exist, and check if they really changed maybe
        _savecallback();
      }
      break;
    }

    if (connect)
    {
      connect = false;
      _wifiConnectStatus = 0; // Reset status to CONNECTING
      delay(1000);
      DEBUG_WM(F("Connecting to new AP"));

      // using user-provided _ssid, _pass in place of system-stored ssid and pass
      WiFi.persistent(true);
      if (connectWifi(_ssid, _pass) == WL_CONNECTED)
      {
        _wifiConnectStatus = 1; // Mark SUCCESS
        WiFi.persistent(false);

        DEBUG_WM(F("Wi-Fi Connected! Holding AP briefly for browser polling..."));
        // Stop name hijacking now. The phone can still reach 4.3.2.1 for
        // /status, and can resolve lukerobotarm.com once it leaves this network.
        dnsServer->stop();
        delay(2500); // Gives browser time to poll /status and receive "SUCCESS"
        WiFi.softAPdisconnect(true);
        WiFi.mode(WIFI_STA);
        if (_savecallback != NULL)
        {
          _savecallback();
        }
        break; // Exit portal loop on success
      }
      else
      {
        _wifiConnectStatus = 2; // Mark FAILED (Wrong Password / Timeout)
        DEBUG_WM(F("Connection Failed! Keeping AP active for retry..."));
        WiFi.persistent(false);
        WiFi.mode(WIFI_AP_STA); // Keep AP active
        scannow = 0;
      }

      if (_shouldBreakAfterConfig)
      {
        if (_savecallback != NULL)
        {
          _savecallback();
        }
        break;
      }
    }
    yield();
  }

  server->reset();
  dnsServer->stop();

  return WiFi.status() == WL_CONNECTED;
}

uint8_t AsyncWiFiManager::connectWifi(String ssid, String pass)
{
  DEBUG_WM(F("Connecting as wifi client..."));

  // check if we've got static_ip settings, if we do, use those
  if (_sta_static_ip)
  {
    DEBUG_WM(F("Custom STA IP/GW/Subnet/DNS"));
    WiFi.config(_sta_static_ip, _sta_static_gw, _sta_static_sn, _sta_static_dns1, _sta_static_dns2);
    DEBUG_WM(WiFi.localIP());
  }
  // fix for auto connect racing issue
  //  if (WiFi.status() == WL_CONNECTED) {
  //    DEBUG_WM("Already connected. Bailing out.");
  //    return WL_CONNECTED;
  //  }
  // check if we have ssid and pass and force those, if not, try with last saved values
  if (ssid != "")
  {
    WiFi.disconnect(false);
    WiFi.begin(ssid.c_str(), pass.c_str());
  }
  else
  {
    if (WiFi.SSID().length() > 0)
    {
      DEBUG_WM(F("Using last saved values, should be faster"));
      WiFi.disconnect(false);
      WiFi.begin();
    }
    else
    {
      DEBUG_WM(F("Try to connect with saved credentials"));
      WiFi.begin();
    }
  }

  uint8_t connRes = waitForConnectResult();
  DEBUG_WM(F("Connection result: "));
  DEBUG_WM(connRes);
  // not connected, WPS enabled, no pass - first attempt
#ifdef NO_EXTRA_4K_HEAP
  if (_tryWPS && connRes != WL_CONNECTED && pass == "")
  {
    startWPS();
    // should be connected at the end of WPS
    connRes = waitForConnectResult();
  }
#endif
  needInfo = true;
  return connRes;
}

uint8_t AsyncWiFiManager::waitForConnectResult()
{
  if (_connectTimeout == 0)
  {
    return WiFi.waitForConnectResult();
  }
  else
  {
    DEBUG_WM(F("Waiting for connection result with time out"));
    unsigned long start = millis();
    boolean keepConnecting = true;
    uint8_t status;
    while (keepConnecting)
    {
      status = WiFi.status();
      if (millis() > start + _connectTimeout)
      {
        keepConnecting = false;
        DEBUG_WM(F("Connection timed out"));
      }
      if (status == WL_CONNECTED || status == WL_CONNECT_FAILED)
      {
        keepConnecting = false;
      }
      delay(100);
    }
    return status;
  }
}
#ifdef NO_EXTRA_4K_HEAP
void AsyncWiFiManager::startWPS()
{
  DEBUG_WM(F("START WPS"));
#if defined(ESP8266)
  WiFi.beginWPSConfig();
#else
  //esp_wps_config_t config = WPS_CONFIG_INIT_DEFAULT(ESP_WPS_MODE);
  esp_wps_config_t config = {};
  config.wps_type = ESP_WPS_MODE;
  config.crypto_funcs = &g_wifi_default_wps_crypto_funcs;
  strcpy(config.factory_info.manufacturer, "ESPRESSIF");
  strcpy(config.factory_info.model_number, "ESP32");
  strcpy(config.factory_info.model_name, "ESPRESSIF IOT");
  strcpy(config.factory_info.device_name, "ESP STATION");

  esp_wifi_wps_enable(&config);
  esp_wifi_wps_start(0);
#endif
  DEBUG_WM(F("END WPS"));
}
#endif
String AsyncWiFiManager::getConfigPortalSSID()
{
  return _apName;
}

void AsyncWiFiManager::setTimeout(unsigned long seconds)
{
  setConfigPortalTimeout(seconds);
}

void AsyncWiFiManager::setConfigPortalTimeout(unsigned long seconds)
{
  _configPortalTimeout = seconds * 1000;
}

void AsyncWiFiManager::setConnectTimeout(unsigned long seconds)
{
  _connectTimeout = seconds * 1000;
}

void AsyncWiFiManager::setTryConnectDuringConfigPortal(boolean v)
{
  _tryConnectDuringConfigPortal = v;
}

void AsyncWiFiManager::setDebugOutput(boolean debug)
{
  _debug = debug;
}

void AsyncWiFiManager::setAPStaticIPConfig(IPAddress ip,
                                           IPAddress gw,
                                           IPAddress sn)
{
  _ap_static_ip = ip;
  _ap_static_gw = gw;
  _ap_static_sn = sn;
}

void AsyncWiFiManager::resetSettings()
{
  DEBUG_WM(F("settings invalidated"));
  DEBUG_WM(F("THIS MAY CAUSE AP NOT TO START UP PROPERLY. YOU NEED TO COMMENT IT OUT AFTER ERASING THE DATA."));

  WiFi.mode(WIFI_AP_STA); // cannot erase if not in STA mode !
  WiFi.persistent(true);
#if defined(ESP8266)
  WiFi.disconnect(true);
#else
  WiFi.disconnect(true, true);
#endif
  WiFi.persistent(false);

  //delay(200);
}

void AsyncWiFiManager::setSTAStaticIPConfig(IPAddress ip,
                                            IPAddress gw,
                                            IPAddress sn,
                                            IPAddress dns1,
                                            IPAddress dns2)
{
  _sta_static_ip = ip;
  _sta_static_gw = gw;
  _sta_static_sn = sn;
  _sta_static_dns1 = dns1;
  _sta_static_dns2 = dns2;
}

void AsyncWiFiManager::setMinimumSignalQuality(unsigned int quality)
{
  _minimumQuality = quality;
}

void AsyncWiFiManager::setBreakAfterConfig(boolean shouldBreak)
{
  _shouldBreakAfterConfig = shouldBreak;
}

// handle root or redirect to captive portal
void AsyncWiFiManager::handleRoot(AsyncWebServerRequest *request)
{
  // AJS - maybe we should set a scan when we get to the root???
  // and only scan on demand? timer + on demand? plus a link to make it happen?

  shouldscan = true;
  scannow = 0;
  DEBUG_WM(F("Handle root"));

  if (captivePortal(request))
  {
    // if captive portal redirect instead of displaying the page
    return;
  }

  DEBUG_WM(F("Sending Captive Portal"));

  String page = FPSTR(WFM_HTTP_HEAD);
  page.replace("{v}", "Options");
  page += FPSTR(HTTP_SCRIPT);
  page += FPSTR(HTTP_STYLE);
  page += _customHeadElement;
  page += FPSTR(HTTP_HEAD_END);
  page += "<h1>";
  page += _apName;
  page += "</h1>";
  page += F("<h3>AsyncWiFiManager</h3>");
  page += FPSTR(HTTP_PORTAL_OPTIONS);
  page += _customOptionsElement;
  page += FPSTR(HTTP_END);

  request->send(200, "text/html", page);
  DEBUG_WM(F("Sent..."));
}

// wifi config page handler
void AsyncWiFiManager::handleWifi(AsyncWebServerRequest *request, boolean scan)
{
  shouldscan = true;

  DEBUG_WM(F("Handle wifi"));
  if (strcmp(request->url().c_str(), "/wifi") == 0)
  {
    shouldscan = true;
    scanModal();
  }
  String page = getPageHeader("Setup your Luke Wi-Fi");
  page.replace("{v}", "Setup your Luke Wi-Fi");
  page += F("<p style='text-align:left;font-size:15px;color:#ddd;margin:0 0 8px;'>Tap your Wi-Fi and enter the password. After setup, rejoin your home Wi-Fi and return to the assembly browser tab to continue to Control.</p>");

  if (scan)
  {
    wifiSSIDscan = false;

    DEBUG_WM(F("Scan done"));
    if (wifiSSIDCount == 0)
    {
      DEBUG_WM(F("No networks found"));
      page += F("<div class='c'>No networks found. Tap 'Rescan' below.</div>");
    }
    else
    {
      // display scanned networks list at the top
      String pager = networkListAsString();
      page += pager;
      page += "<br/><br/>";
    }
  }
  wifiSSIDscan = true;

  page += FPSTR(HTTP_FORM_START);
  char parLength[2];

  // Add custom parameters (if any)
  for (unsigned int i = 0; i < _paramsCount; i++)
  {
    if (_params[i] == NULL)
    {
      break;
    }

    String pitem = FPSTR(HTTP_FORM_PARAM);
    if (_params[i]->getID() != NULL)
    {
      pitem.replace("{i}", _params[i]->getID());
      pitem.replace("{n}", _params[i]->getID());
      pitem.replace("{p}", _params[i]->getPlaceholder());
      snprintf(parLength, 2, "%d", _params[i]->getValueLength());
      pitem.replace("{l}", parLength);
      pitem.replace("{v}", _params[i]->getValue());
      pitem.replace("{c}", _params[i]->getCustomHTML());
    }
    else
    {
      pitem = _params[i]->getCustomHTML();
    }

    page += pitem;
  }
  if (_params[0] != NULL)
  {
    page += "<br/>";
  }

  // Static IP fields (if enabled)
  if (_sta_static_ip)
  {
    String item = FPSTR(HTTP_FORM_PARAM);
    item.replace("{i}", "ip");
    item.replace("{n}", "ip");
    item.replace("{p}", "Static IP");
    item.replace("{l}", "15");
    item.replace("{v}", _sta_static_ip.toString());

    page += item;

    item = FPSTR(HTTP_FORM_PARAM);
    item.replace("{i}", "gw");
    item.replace("{n}", "gw");
    item.replace("{p}", "Static Gateway");
    item.replace("{l}", "15");
    item.replace("{v}", _sta_static_gw.toString());

    page += item;

    item = FPSTR(HTTP_FORM_PARAM);
    item.replace("{i}", "sn");
    item.replace("{n}", "sn");
    item.replace("{p}", "Subnet");
    item.replace("{l}", "15");
    item.replace("{v}", _sta_static_sn.toString());

    page += item;

    item = FPSTR(HTTP_FORM_PARAM);
    item.replace("{i}", "dns1");
    item.replace("{n}", "dns1");
    item.replace("{p}", "DNS1");
    item.replace("{l}", "15");
    item.replace("{v}", _sta_static_dns1.toString());

    page += item;

    item = FPSTR(HTTP_FORM_PARAM);
    item.replace("{i}", "dns2");
    item.replace("{n}", "dns2");
    item.replace("{p}", "DNS2");
    item.replace("{l}", "15");
    item.replace("{v}", _sta_static_dns2.toString());

    page += item;
    page += "<br/>";
  }

  // Close the main connection form
  page += FPSTR(HTTP_FORM_END);

  // --- SECONDARY ACTION BUTTONS / FOOTER LINKS ---
  // Replaces the single HTTP_SCAN_LINK with a neat utility footer
  page += F("<div class='links'>");
  page += F("<a href='/wifi'>Rescan</a>");
  page += F("</div>");

  page += FPSTR(HTTP_END);

  request->send(200, "text/html", page);

  DEBUG_WM(F("Sent config page"));
}

// handle the WLAN save form and redirect to WLAN config page again
void AsyncWiFiManager::handleWifiSave(AsyncWebServerRequest *request)
{
  needInfo = true;
  _wifiConnectStatus = 0; // Reset status to CONNECTING on form submit
  _ssid = request->arg("s").c_str();
  _pass = request->arg("p").c_str();
  const char* redirectUrl = "https://lukerobotarm.com/#control";

  // Process custom parameters
  for (unsigned int i = 0; i < _paramsCount; i++)
  {
    if (_params[i] == NULL) break;
    String value = request->arg(_params[i]->getID()).c_str();
    value.toCharArray(_params[i]->_value, _params[i]->_length);
  }

  // Process static IP settings
  if (request->hasArg("ip")) optionalIPFromString(&_sta_static_ip, request->arg("ip").c_str());
  if (request->hasArg("gw")) optionalIPFromString(&_sta_static_gw, request->arg("gw").c_str());
  if (request->hasArg("sn")) optionalIPFromString(&_sta_static_sn, request->arg("sn").c_str());
  if (request->hasArg("dns1")) optionalIPFromString(&_sta_static_dns1, request->arg("dns1").c_str());
  if (request->hasArg("dns2")) optionalIPFromString(&_sta_static_dns2, request->arg("dns2").c_str());

  String page = getPageHeader("Connecting Luke...");

  page += F("<div class='c'>");
  page += F("<h2>Connecting Luke...</h2>");
  page += F("<p>Attempting to join <b>");
  String escapedSSID = _ssid;
  escapedSSID.replace("&", "&amp;");
  escapedSSID.replace("<", "&lt;");
  escapedSSID.replace(">", "&gt;");
  page += escapedSSID;
  page += F("</b></p><p>If this window closes, rejoin your home Wi-Fi and return to your assembly browser tab.</p>");

  page += F("<div id='spinner'></div>");
  page += F("<div id='timer'>15</div>");
  page += F("<p id='status'>Testing connection...</p>");

  page += F("<div id='fallback'>");
  page += F("<p id='fallback-title'></p>");
  page += F("<p id='fallback-desc'></p>");
  page += F("<a id='btn-retry' class='btn btn-secondary' href='/wifi'>Re-enter Password</a>");

  page += F("<div id='controller-section' style='display:none;'>");
  page += F("<hr style='border:none; border-top:1px solid #444; margin:12px 0;'>");
  page += F("<p style='margin:0 0 8px; font-size:13px; color:#ccc;'>If Luke connected successfully, make sure your phone is on your Wi-Fi network, then open the controller:</p>");
  page += F("<a class='btn btn-primary' href='");
  page += redirectUrl;
  page += F("' target='_blank'>Open Luke Controller</a>");
  page += F("</div>");

  page += F("</div>");
  page += F("</div>");

  // JavaScript Logic
  page += F("<script>");
  page += F("let statusPoll, checkInterval, timerInterval;");
  page += F("let timeLeft = 15;");
  page += String((_connectTimeout ? _connectTimeout / 1000 : 30) + 10);
  page += F(";let connected = false;");
  page += F("const targetUrl = '");
  page += redirectUrl;
  page += F("';");
  page += F("const timerEl = document.getElementById('timer');");
  page += F("const statusEl = document.getElementById('status');");
  page += F("const spinnerEl = document.getElementById('spinner');");
  page += F("const fallbackEl = document.getElementById('fallback');");
  page += F("const titleEl = document.getElementById('fallback-title');");
  page += F("const descEl = document.getElementById('fallback-desc');");
  page += F("const controllerSec = document.getElementById('controller-section');");

  // 1. Status Polling for Instant Error Catching
  page += F("statusPoll = setInterval(() => {");
  page += F("  fetch('/status', {cache: 'no-store'})");
  page += F("    .then(res => res.text())");
  page += F("    .then(data => {");
  page += F("      if (data === 'FAILED') {");
  page += F("        clearInterval(statusPoll);");
  page += F("        clearInterval(timerInterval);");
  page += F("        clearInterval(checkInterval);");
  page += F("        if (spinnerEl) spinnerEl.style.display = 'none';");
  page += F("        if (timerEl) timerEl.style.display = 'none';");
  page += F("        statusEl.innerHTML = \"<span class='err'>Wi-Fi connection failed.</span>\";");
  page += F("        titleEl.innerText = 'Connection failed';");
  page += F("        descEl.innerText = 'Check the network name, password and signal, then try again.';");
  page += F("        controllerSec.style.display = 'none';"); // Hide Controller Option on Wrong Password
  page += F("        fallbackEl.style.display = 'block';");
  page += F("      } else if (data === 'SUCCESS') {");
  page += F("        clearInterval(statusPoll);");
  page += F("        connected = true; timeLeft = 15;");
  page += F("        statusEl.innerText = 'Luke connected. Rejoin your home Wi-Fi. If this window closes, return to the assembly tab.';");
  page += F("      }");
  page += F("    }).catch(() => {});");
  page += F("}, 1000);");

  // 2. Backup WAN Connection Polling
  page += F("checkInterval = setInterval(() => {");
  page += F("  if (!connected) return;");
  page += F("  fetch(targetUrl, { mode: 'no-cors', cache: 'no-cache' })");
  page += F("    .then(() => {");
  page += F("      clearInterval(checkInterval);");
  page += F("      clearInterval(timerInterval);");
  page += F("      clearInterval(statusPoll);");
  page += F("      statusEl.innerText = 'Connected! Redirecting...';");
  page += F("      window.location.href = targetUrl;");
  page += F("    }).catch(() => {});");
  page += F("}, 2000);");

  // 3. Wait for the connection result; start the handoff countdown only after SUCCESS.
  page += F("timerInterval = setInterval(() => {");
  page += F("  timeLeft--;");
  page += F("  if (timerEl) timerEl.innerText = timeLeft;");
  page += F("  if (timeLeft <= 0) {");
  page += F("    clearInterval(timerInterval);");
  page += F("    clearInterval(checkInterval);");
  page += F("    clearInterval(statusPoll);");
  page += F("    if (connected) { window.location.replace(targetUrl); return; }");
  page += F("    if (spinnerEl) spinnerEl.style.display = 'none';");
  page += F("    if (timerEl) timerEl.style.display = 'none';");
  page += F("    statusEl.innerText = 'Connection status unconfirmed.';");
  page += F("    titleEl.innerText = 'Timed Out';");
  page += F("    descEl.innerText = 'If Luke could not connect, re-enter your Wi-Fi credentials:';");
  page += F("    controllerSec.style.display = 'block';"); // Show Controller Option on 20s Timeout
  page += F("    fallbackEl.style.display = 'block';");
  page += F("  }");
  page += F("}, 1000);");
  page += F("</script>");

  page += FPSTR(HTTP_END);

  request->send(200, "text/html", page);
  connect = true;
}


void AsyncWiFiManager::handleNotFound(AsyncWebServerRequest *request)
{
  DEBUG_WM(F("Handle not found"));
  if (captivePortal(request))
  {
    // if captive portal redirect instead of displaying the error page
    return;
  }

  String message = "File Not Found\n\n";
  message += "URI: ";
  message += request->url();
  message += "\nMethod: ";
  message += (request->method() == HTTP_GET) ? "GET" : "POST";
  message += "\nArguments: ";
  message += request->args();
  message += "\n";

  for (unsigned int i = 0; i < request->args(); i++)
  {
    message += " " + request->argName(i) + ": " + request->arg(i) + "\n";
  }
  AsyncWebServerResponse *response = request->beginResponse(404, "text/plain", message);
  response->addHeader("Cache-Control", "no-cache, no-store, must-revalidate");
  response->addHeader("Pragma", "no-cache");
  response->addHeader("Expires", "-1");
  request->send(response);
}

/** Redirect to captive portal if we got a request for another domain.
 * Return true in that case so the page handler do not try to handle the request again. */
boolean AsyncWiFiManager::captivePortal(AsyncWebServerRequest *request)
{
  if (!isIp(request->host()))
  {
    DEBUG_WM(F("Request redirected to captive portal"));
    AsyncWebServerResponse *response = request->beginResponse(302, "text/plain", "");
    response->addHeader("Location", String("http://") + WiFi.softAPIP().toString() + "/");
    response->addHeader("Cache-Control", "no-cache, no-store, must-revalidate");
    response->addHeader("Pragma", "no-cache");
    response->addHeader("Expires", "-1");
    request->send(response);
    return true;
  }
  return false;
}

// start up config portal callback
void AsyncWiFiManager::setAPCallback(std::function<void(AsyncWiFiManager *)> func)
{
  _apcallback = func;
}

// start up save config callback
void AsyncWiFiManager::setSaveConfigCallback(std::function<void()> func)
{
  _savecallback = func;
}

// sets a custom element to add to head, like a new style tag
void AsyncWiFiManager::setCustomHeadElement(const char *element)
{
  _customHeadElement = element;
}

// sets a custom element to add to options page
void AsyncWiFiManager::setCustomOptionsElement(const char *element)
{
  _customOptionsElement = element;
}

// if this is true, remove duplicated Access Points - defaut true
void AsyncWiFiManager::setRemoveDuplicateAPs(boolean removeDuplicates)
{
  _removeDuplicateAPs = removeDuplicates;
}

template <typename Generic>
void AsyncWiFiManager::DEBUG_WM(Generic text)
{
  if (_debug)
  {
    Serial.print(F("*WM: "));
    Serial.println(text);
  }
}

unsigned int AsyncWiFiManager::getRSSIasQuality(int RSSI)
{
  unsigned int quality = 0;

  if (RSSI <= -100)
  {
    quality = 0;
  }
  else if (RSSI >= -50)
  {
    quality = 100;
  }
  else
  {
    quality = 2 * (RSSI + 100);
  }
  return quality;
}

// is this an IP?
boolean AsyncWiFiManager::isIp(String str)
{
  for (unsigned int i = 0; i < str.length(); i++)
  {
    int c = str.charAt(i);
    if (c != '.' && (c < '0' || c > '9'))
    {
      return false;
    }
  }
  return true;
}

// IP to String?
String AsyncWiFiManager::toStringIp(IPAddress ip)
{
  String res = "";
  for (int i = 0; i < 3; i++)
  {
    res += String((ip >> (8 * i)) & 0xFF) + ".";
  }
  res += String(((ip >> 8 * 3)) & 0xFF);
  return res;
}

String AsyncWiFiManager::getPageHeader(const String& pageTitle)
{
  String page = FPSTR(WFM_HTTP_HEAD);
  page.replace("{v}", pageTitle);
  page += FPSTR(HTTP_SCRIPT);
  page += FPSTR(HTTP_STYLE);
  page += _customHeadElement;
  page += FPSTR(HTTP_HEAD_END);

  // Top Title Bar displaying Luke Wi-Fi and Unique Device ID
  page += F("<div class='c' style='margin-bottom:12px;'>");
  page += F("<h1 style='font-size:1.2rem;margin:0 0 8px;'>Setup your Luke Wi-Fi</h1>");
  page += F("<div style='font-size:14px; opacity:.75; font-weight:600; color:#ccc;'>ID: ");
  page += (_apName != NULL) ? _apName : "Luke-Device";
  page += F("</div></div>");

  return page;
}