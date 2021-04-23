/*
 * ruuviscan - Simple RuuviTag scanner using BlueZ D-Bus API
 *
 * Copyright (C) 2018  Andrzej Kaczmarek
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <stdio.h>
#include <signal.h>
#include <ell/ell.h>

#if __BYTE_ORDER != __LITTLE_ENDIAN
#error I am little-endian only :)
#endif

#define EDDYSTONE_UUID		"0000feaa-0000-1000-8000-00805f9b34fb"
#define EDDYSTONE_URL_PREFIX	"ruu.vi/#"
#define EDDYSTONE_DATA_OFFSET	(3 + strlen(EDDYSTONE_URL_PREFIX))
#define EDDYSTONE_DATA_LENGTH	(3 + 17)

#define RUUVI_COMPANY_ID	1177

struct ruuvitag {
	uint8_t data_format;
	float humidity;
	float temperature;
	float pressure;
	unsigned int battery;
	uint8_t tag_id;
	int8_t tx_pow;
	uint8_t move_counter;
	uint16_t meas_seq;
};

struct ruuvi3 {
	uint8_t dfd;
	uint8_t humidity;
	uint8_t temperature : 7;
	uint8_t temperature_neg : 1;
	uint8_t temperature_frac;
	uint16_t pressure;
	int16_t accel_x;
	int16_t accel_y;
	int16_t accel_z;
	uint16_t battery;
} __attribute__((packed));

struct ruuvi4 {
	uint8_t dfd;
	uint8_t humidity;
	uint8_t temperature : 7;
	uint8_t temperature_neg : 1;
	uint8_t temperature_frac;
	uint16_t pressure;
	uint8_t tag_id;
} __attribute__((packed));

struct ruuvi5 {
	uint8_t dfd;
	uint16_t temperature;
	uint16_t humidity;
	uint16_t pressure;
	uint16_t accel_x;
	uint16_t accel_y;
	uint16_t accel_z;
	uint16_t battery : 11;
	uint16_t tx_pow : 5;
	uint8_t move_counter;
	uint16_t meas_seq;
	uint8_t addr[6];
} __attribute__((packed));

static struct l_dbus *dbus;

static struct l_queue *ruuvitags;

static void start_discovery_reply(struct l_dbus_proxy *proxy,
						struct l_dbus_message *result,
						void *user_data)
{
	const char *name, *desc;

	if (l_dbus_message_is_error(result)) {
		l_dbus_message_get_error(result, &name, &desc);
		l_error("Failed to start discovery (%s), %s", name, desc);
		l_main_quit();
	}
}

static void set_discovery_filter_setup(struct l_dbus_message *message,
							void *user_data)
{
	struct l_dbus_message_builder *builder;

	builder = l_dbus_message_builder_new(message);

	l_dbus_message_builder_enter_array(builder, "{sv}");
	l_dbus_message_builder_enter_dict(builder, "sv");

	l_dbus_message_builder_append_basic(builder, 's', "Transport");
	l_dbus_message_builder_enter_variant(builder, "s");
	l_dbus_message_builder_append_basic(builder, 's', "le");
	l_dbus_message_builder_leave_variant(builder);

	l_dbus_message_builder_leave_dict(builder);
	l_dbus_message_builder_leave_array(builder);

	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);
}

static void set_discovery_filter_reply(struct l_dbus_proxy *proxy,
						struct l_dbus_message *result,
						void *user_data)
{
	const char *name, *desc;

	if (l_dbus_message_is_error(result)) {
		l_dbus_message_get_error(result, &name, &desc);
		l_error("Failed to set discovery filter (%s), %s", name, desc);
		l_main_quit();
		return;
	}

	l_dbus_proxy_method_call(proxy, "StartDiscovery", NULL,
					start_discovery_reply, NULL, NULL);
}

static void start_discovery(struct l_dbus_proxy *adapter)
{
	l_dbus_proxy_method_call(adapter, "SetDiscoveryFilter",
						set_discovery_filter_setup,
						set_discovery_filter_reply,
						NULL, NULL);
}

static void print_ruuvitag(struct l_dbus_proxy *proxy,
						const struct ruuvitag *ruuvitag)
{
	const char *address = "<unknown>";
	int16_t rssi = -127;

	l_dbus_proxy_get_property(proxy, "Address", "s", &address);
	l_dbus_proxy_get_property(proxy, "RSSI", "n", &rssi);

	printf("RuuviTag %s (rssi %d ver %d)\n", address, rssi,
							ruuvitag->data_format);

	printf("    H=%.1f %%\n", ruuvitag->humidity);
	printf("    T=%.2f C\n", ruuvitag->temperature);
	printf("    P=%.2f hPa\n", ruuvitag->pressure);
	if (ruuvitag->data_format == 3)
		printf("    B=%d mV\n", ruuvitag->battery);
	if (ruuvitag->data_format == 4)
		printf("    I=%d\n", ruuvitag->tag_id);
	if (ruuvitag->data_format == 5) {
		printf("    B=%d mV\n", ruuvitag->battery);
		printf("    TX=%d dBm\n", ruuvitag->tx_pow);
		printf("    M=%d\n", ruuvitag->move_counter);
		printf("    S=%d\n", ruuvitag->meas_seq);
	}
}

static bool decode_ruuvi3(const uint8_t *data, size_t length,
						struct ruuvitag *ruuvitag)
{
	struct ruuvi3 *r3 = (struct ruuvi3 *)data;

	if (length < sizeof(*r3))
		return false;

	memset(ruuvitag, 0, sizeof(*ruuvitag));

	ruuvitag->data_format = 3;
	ruuvitag->humidity = r3->humidity / 2.0;
	ruuvitag->temperature = r3->temperature + r3->temperature_frac / 100.0;
	if (r3->temperature_neg)
		ruuvitag->temperature *= 1;
	ruuvitag->pressure = (L_BE16_TO_CPU(r3->pressure) + 50000) / 100.0;
	ruuvitag->battery = L_BE16_TO_CPU(r3->battery);

	return true;
}

static bool decode_ruuvi4(const uint8_t *data, size_t length,
						struct ruuvitag *ruuvitag)
{
	struct ruuvi4 *r4 = (struct ruuvi4 *)data;

	if (length < sizeof(*r4))
		return false;

	memset(ruuvitag, 0, sizeof(*ruuvitag));

	ruuvitag->data_format = 4;
	ruuvitag->humidity = r4->humidity / 2.0;
	ruuvitag->temperature = r4->temperature;
	if (r4->temperature_neg)
		ruuvitag->temperature *= 1;
	ruuvitag->pressure = (L_BE16_TO_CPU(r4->pressure) + 50000) / 100.0;
	ruuvitag->tag_id = r4->tag_id;

	return true;
}

static bool decode_ruuvi5(const uint8_t *data, size_t length,
																										struct ruuvitag *ruuvitag) {
	struct ruuvi5 *r5 = (struct ruuvi5 *)data;

	if (length < sizeof(*r5))
		return false;

	memset(ruuvitag, 0, sizeof(*ruuvitag));

	ruuvitag->data_format = 5;
	ruuvitag->humidity = L_BE16_TO_CPU(r5->humidity) / 400.0;
	ruuvitag->temperature = L_BE16_TO_CPU(r5->temperature) / 200.0;
	ruuvitag->pressure = (L_BE16_TO_CPU(r5->pressure) + 50000) / 100.0;
	ruuvitag->battery = (L_BE16_TO_CPU(r5->battery) / 100) + 1600;
	ruuvitag->tx_pow = r5->tx_pow - 40;
	ruuvitag->move_counter = r5->move_counter;
	ruuvitag->meas_seq = r5->meas_seq;

	// XXX Bluetooth address is left

	return true;
}

static bool decode_ruuvi(const uint8_t *data, size_t length,
							struct ruuvitag *ruuvi)
{
	if (length < 1)
		return false;

	if (data[0] == 3)
		return decode_ruuvi3(data, length, ruuvi);
	else if (data[0] == 4)
		return decode_ruuvi4(data, length, ruuvi);
	else if (data[0] == 5)
		return decode_ruuvi5(data, length, ruuvi);

	return false;
}

static bool decode_base64ruuvi(const uint8_t *data, uint8_t *out)
{
	char encoded[12];
	uint8_t *decoded;
	size_t decoded_size;
	int i;

	/*
	 * Due to limited URL length in Eddystone-URL encoded data are truncated
	 * so we need to "recreate" missing part to form valid base64 stream.
	 */
	memcpy(encoded, data, 9);
	encoded[9] = 'A';
	encoded[10] = '=';
	encoded[11] = '=';

	/*
	 * RuvviTag data are encoded in base64url rather than regular base64
	 * thus we need to do some conversion before trying to decode.
	 */
	for (i = 0; i < sizeof(encoded); i++) {
		if (encoded[i] == '+')
			encoded[i] = '-';
		else if (encoded[i] == '/')
			encoded[i] = '_';
	}

	decoded = l_base64_decode(encoded, sizeof(encoded), &decoded_size);
	if (!decoded)
		return false;

	memcpy(out, decoded, decoded_size);

	l_free(decoded);

	return true;
}

static bool parse_service_data(struct l_dbus_message_iter *dict,
							struct ruuvitag *ruuvi)
{
	struct l_dbus_message_iter iter;
	const char *uuid;

	while (l_dbus_message_iter_next_entry(dict, &uuid, &iter)) {
		struct l_dbus_message_iter arr;
		const uint8_t *data;
		uint32_t n_elem;
		uint8_t decoded[7];

		if (strcmp(uuid, EDDYSTONE_UUID)) {
			continue;
		}

		if (!l_dbus_message_iter_get_variant(&iter, "ay", &arr))
			continue;

		if (!l_dbus_message_iter_get_fixed_array(&arr, &data, &n_elem))
			continue;

		if (n_elem != EDDYSTONE_DATA_LENGTH)
			continue;

		/* This is not an Eddystone-URL */
		if ((data[0] & 0xF0) != 0x10)
			continue;

		if (strncmp((char *)&data[3], EDDYSTONE_URL_PREFIX,
						strlen(EDDYSTONE_URL_PREFIX)))
			continue;

		if (!decode_base64ruuvi(&data[EDDYSTONE_DATA_OFFSET], decoded))
			continue;

		if (decode_ruuvi(decoded, sizeof(decoded), ruuvi))
			return true;
	}

	return false;
}

static bool parse_manufacturer_data(struct l_dbus_message_iter *dict,
						struct ruuvitag *ruuvitag)
{
	struct l_dbus_message_iter iter;
	uint16_t company_id;

	while (l_dbus_message_iter_next_entry(dict, &company_id, &iter)) {
		struct l_dbus_message_iter arr;
		const uint8_t *data = NULL;
		uint32_t n_elem;

		if (company_id != RUUVI_COMPANY_ID)
			continue;

		if (!l_dbus_message_iter_get_variant(&iter, "ay", &arr))
			continue;

		if (!l_dbus_message_iter_get_fixed_array(&arr, &data, &n_elem))
			continue;

		if (decode_ruuvi(data, n_elem, ruuvitag))
			return true;
	}

	return false;
}

static bool parse_device(struct l_dbus_proxy *proxy, struct ruuvitag *ruuvitag)
{
	struct l_dbus_message_iter dict;

	/* RuuviTag has either ManufacturerData or ServiceData, but not both */
	if (l_dbus_proxy_get_property(proxy, "ManufacturerData", "a{qv}",
									&dict))
		return parse_manufacturer_data(&dict, ruuvitag);
	else if (l_dbus_proxy_get_property(proxy, "ServiceData", "a{sv}",
									&dict))
		return parse_service_data(&dict, ruuvitag);

	return false;
}

static bool match_proxy(const void *proxy1, const void *proxy2)
{
	return proxy1 == proxy2;
}

static void property_changed(struct l_dbus_proxy *proxy, const char *name,
				struct l_dbus_message *msg, void *user_data)
{
	const char *interface = l_dbus_proxy_get_interface(proxy);
	struct l_dbus_message_iter dict;
	struct ruuvitag ruuvitag;

	if (strcmp(interface, "org.bluez.Device1"))
		return;

	if (l_queue_find(ruuvitags, match_proxy, proxy))
		return;

	if (!strcmp(name, "ServiceData")) {
		if (!l_dbus_message_get_arguments(msg, "a{sv}", &dict))
			return;

		if (!parse_service_data(&dict, &ruuvitag))
			return;
	} else if (!strcmp(name, "ManufacturerData")) {
		if (!l_dbus_message_get_arguments(msg, "a{qv}", &dict))
			return;

		if (!parse_manufacturer_data(&dict, &ruuvitag))
			return;
	} else if (!strcmp(name, "RSSI")) {
		if (!parse_device(proxy, &ruuvitag))
			return;
	} else {
		return;
	}

	l_queue_push_tail(ruuvitags, proxy);

	print_ruuvitag(proxy, &ruuvitag);
}

static void proxy_added(struct l_dbus_proxy *proxy, void *user_data)
{
	const char *interface = l_dbus_proxy_get_interface(proxy);

	if (!strcmp(interface, "org.bluez.Adapter1")) {
		start_discovery(proxy);
	} else if (!strcmp(interface, "org.bluez.Device1")) {
		struct ruuvitag ruuvitag;
		int16_t rssi;

		/* Skip devices without RSSI - these are not recently scanned */
		if (!l_dbus_proxy_get_property(proxy, "RSSI", "n", &rssi))
			return;

		if (!parse_device(proxy, &ruuvitag))
			return;

		l_queue_push_tail(ruuvitags, proxy);

		print_ruuvitag(proxy, &ruuvitag);
	}
}

static void proxy_removed(struct l_dbus_proxy *proxy, void *user_data)
{
	const char *interface = l_dbus_proxy_get_interface(proxy);

	if (strcmp(interface, "org.bluez.Adapter1"))
		return;

	l_main_quit();
}

static void client_disconnected(struct l_dbus *dbus, void *user_data)
{
	l_main_quit();
}

static void ready_callback(void *user_data)
{
	if (!l_dbus_object_manager_enable(dbus)) {
		l_info("Unable to register the ObjectManager");
		l_main_quit();
	}
}

static void signal_handler(void *user_data)
{
	l_main_quit();
}

static void scan_timeout(struct l_timeout *timeout, void *user_data)
{
	l_main_quit();
}

int main(int argc, char **argv)
{
	struct l_dbus_client *client;
	struct l_signal *signal;
	uint32_t signal_mask;
	struct l_timeout *timeout;

	l_log_set_stderr();

	if (!l_main_init())
		return EXIT_FAILURE;

	ruuvitags = l_queue_new();

	signal_mask = SIGINT | SIGTERM;
	signal = l_signal_create(signal_mask, signal_handler, NULL, NULL);

	dbus = l_dbus_new_default(L_DBUS_SYSTEM_BUS);
	l_dbus_set_ready_handler(dbus, ready_callback, NULL, NULL);
	client = l_dbus_client_new(dbus, "org.bluez", "/org/bluez");

	l_dbus_client_set_connect_handler(client, NULL, NULL, NULL);
	l_dbus_client_set_disconnect_handler(client, client_disconnected, NULL,
									NULL);

	l_dbus_client_set_proxy_handlers(client, proxy_added, proxy_removed,
						property_changed, NULL, NULL);

	timeout = l_timeout_create(10, scan_timeout, NULL, NULL);

	l_main_run();

	l_timeout_remove(timeout);

	l_dbus_client_destroy(client);
	l_dbus_destroy(dbus);
	l_signal_remove(signal);

	l_queue_destroy(ruuvitags, NULL);

	l_main_exit();

	return EXIT_SUCCESS;
}
