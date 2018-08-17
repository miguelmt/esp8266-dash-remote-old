extern "C"
{
#include <user_interface.h>
}

#define DATA_LENGTH 112
#define L3_DATA_LENGTH 88

#define TYPE_MANAGEMENT 0x00
#define TYPE_CONTROL 0x01
#define TYPE_DATA 0x02
#define SUBTYPE_PROBE_REQUEST 0x04

struct RxControl
{ // 12-byte header (L1?)
  // Byte 0
  signed rssi : 8; // signal intensity of packet
  // Byte 1
  unsigned rate : 4;
  unsigned is_group : 1;
  unsigned : 1;
  unsigned sig_mode : 2; // 0:is 11n packet; 1:is not 11n packet;
  // Bytes 2 & 3
  unsigned legacy_length : 12; // if not 11n packet, shows length of packet.
  unsigned damatch0 : 1;
  unsigned damatch1 : 1;
  unsigned bssidmatch0 : 1;
  unsigned bssidmatch1 : 1;
  // Byte 4
  unsigned MCS : 7; // if is 11n packet, shows the modulation and code used (range from 0 to 76)
  unsigned CWB : 1; // if is 11n packet, shows if is HT40 packet or not
  // Bytes 5 & 6
  unsigned HT_length : 16; // if is 11n packet, shows length of packet.
  // Byte 7
  unsigned Smoothing : 1;
  unsigned Not_Sounding : 1;
  unsigned : 1;
  unsigned Aggregation : 1;
  unsigned STBC : 2;
  unsigned FEC_CODING : 1; // if is 11n packet, shows if is LDPC packet or not.
  unsigned SGI : 1;
  // Byte 8
  unsigned rxend_state : 8;
  // Byte 9
  unsigned ampdu_cnt : 8;
  // Byte 10
  unsigned channel : 4; //which channel this packet in.
  // Byte 11
  unsigned : 12;
};

struct MacHeader
{ // 24-byte MAC (L2) header
	// 2-byte frame control
	unsigned version : 2;
	unsigned frameType : 2;
	unsigned frameSubType : 4;
	unsigned toDS : 1;
	unsigned fromDS : 1;
	unsigned : 6;
	// Rest of the stuff, in which we are not really interested (now)
	unsigned duration : 16;
	unsigned destinationAddress : 48;
	unsigned sourceAddress : 48;
	unsigned bssid : 48;
	unsigned seqControl : 16;
};

struct MiguelPacket
{
  // Bytes 0 to 11
  struct RxControl rx_ctrl;
  // Bytes 12 to 35 (i.e. 24 additional bytes)
  struct MacHeader mac_header;
  // Bytes 36 to 123 (i.e. 88 more bytes)
  uint8_t data[L3_DATA_LENGTH];
  // Bytes 124 & 125
  uint16_t cnt;
  // Bytes 126 & 127, for a grand total of 128 bytes
  uint16_t len;
};


struct SnifferPacket
{
  // Bytes 0 to 11
  struct RxControl rx_ctrl;
  // Bytes 12 to 123 (i.e. 112 more bytes)
  uint8_t data[DATA_LENGTH];
  // Bytes 124 & 125
  uint16_t cnt;
  // Bytes 126 & 127, for a grand total of 128 bytes
  uint16_t len;
};

static void showMetadata(SnifferPacket *snifferPacket)
{

  unsigned int frameControl = ((unsigned int)snifferPacket->data[1] << 8) + snifferPacket->data[0];

  uint8_t version = (frameControl & 0b0000000000000011) >> 0;
  uint8_t frameType = (frameControl & 0b0000000000001100) >> 2;
  uint8_t frameSubType = (frameControl & 0b0000000011110000) >> 4;
  uint8_t toDS = (frameControl & 0b0000000100000000) >> 8;
  uint8_t fromDS = (frameControl & 0b0000001000000000) >> 9;

  // Only look for probe request packets
  if (frameType != TYPE_MANAGEMENT ||
      frameSubType != SUBTYPE_PROBE_REQUEST)
    return;

  Serial.print("RSSI: ");
  Serial.print(snifferPacket->rx_ctrl.rssi, DEC);

  Serial.print(" Ch: ");
  Serial.print(wifi_get_channel());

  char addr[] = "00:00:00:00:00:00";
  getMAC(addr, snifferPacket->data, 10);
  Serial.print(" Peer MAC: ");
  Serial.print(addr);

  uint8_t SSID_length = snifferPacket->data[25];
  Serial.print(" SSID: ");
  printDataSpan(26, SSID_length, snifferPacket->data);

  Serial.println();
}

/**
 * Callback for promiscuous mode
 */
static void ICACHE_FLASH_ATTR sniffer_callback(uint8_t *buffer, uint16_t length)
{
  struct SnifferPacket *snifferPacket = (struct SnifferPacket *)buffer;
  showMetadata(snifferPacket);
}

static void printDataSpan(uint16_t start, uint16_t size, uint8_t *data)
{
  for (uint16_t i = start; i < DATA_LENGTH && i < start + size; i++)
  {
    Serial.write(data[i]);
  }
}

static void getMAC(char *addr, uint8_t *data, uint16_t offset)
{
  sprintf(addr, "%02x:%02x:%02x:%02x:%02x:%02x", data[offset + 0], data[offset + 1], data[offset + 2], data[offset + 3], data[offset + 4], data[offset + 5]);
}

#define DISABLE 0
#define ENABLE 1

void setup()
{
  // set the WiFi chip to "promiscuous" mode aka monitor mode
  Serial.begin(115200);
  delay(10);
  wifi_set_opmode(STATION_MODE);
  // Set channel 1 just because. We are only interested in WiFi probes (as recommended by
  // http://ridiculousfish.com/blog/posts/The-one-second-dash.html) and the Dash button
  // seems to transmit them in every channel. It kind of makes sense because routers can
  // be configured to choose the least congested channel, so the Dash can never be sure
  // about where (in which channel) it will find the network (SSID) it is looking for.
  // It's fastest to try them all. Or maybe WiFi probes are transmitted outside of any
  // channel. Either way, we don't need to scan all WiFi channels to catch WiFi probes.
  wifi_set_channel(1);
  wifi_promiscuous_enable(DISABLE);
  delay(10);
  wifi_set_promiscuous_rx_cb(sniffer_callback);
  delay(10);
  wifi_promiscuous_enable(ENABLE);
}

void loop()
{
  delay(10);
}
