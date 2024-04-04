
/*
 * FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 * Copyright (C) 2005-2021, Anthony Minessale II <anthm@freeswitch.org>
 *
 * Version: MPL 1.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 *
 * The Initial Developer of the Original Code is
 * Anthony Minessale II <anthm@freeswitch.org>
 * Portions created by the Initial Developer are Copyright (C)
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 * Dragos Oancea <dragos@signalwire.com>
 *
 *
 * sipp-based-tests.c - Test FreeSwitch using sipp (https://github.com/SIPp/sipp)
 *
 */

#include <switch.h>
#include <test/switch_test.h>
#include <stdlib.h>

int test_success = 0;
int test_sofia_debug = 1;
static int timeout_sec = 10;

static void test_wait_for_uuid(char *uuid)
{
	switch_stream_handle_t stream = { 0 };
	int loop_count = 50;
	char *channel_data=NULL;

	do {
		SWITCH_STANDARD_STREAM(stream);
		switch_api_execute("show", "channels", NULL, &stream);

		if (stream.data && !strncmp((char *)stream.data, "uuid,", 5)) {
			channel_data = switch_mprintf("%s", (char *)stream.data);
			switch_safe_free(stream.data);
			break;
		}
		switch_safe_free(stream.data);
		switch_sleep(100 * 1000);
	} while (loop_count--);

	if (channel_data) {
		char *temp = NULL;
		int i;

		if ((temp = strchr(channel_data, '\n'))) {
			temp++;
			for (i = 0; temp[i] != ',' && i < 99; i++) {
				uuid[i] = temp[i];
			}
		}
		free(channel_data);
	}
}

static const char *test_wait_for_chan_var(switch_channel_t *channel, const char *seq) 
{
	int loop_count = 50;
	const char *var=NULL;
	do {
		const char *sip_cseq = switch_channel_get_variable(channel, "sip_cseq");

		if (sip_cseq && seq && !strcmp(sip_cseq, seq)){
			switch_sleep(100 * 1000);
			var = switch_channel_get_variable(channel, "rtp_local_sdp_str");
			break;
		}

		switch_sleep(100 * 1000);
	} while(loop_count--);

	return var;
}

static switch_bool_t has_ipv6(void)
{
	switch_stream_handle_t stream = { 0 };
	SWITCH_STANDARD_STREAM(stream);
	switch_api_execute("sofia", "status profile external-ipv6", NULL, &stream);

	if (strstr((char *)stream.data, "Invalid Profile")) {

		switch_safe_free(stream.data);

		return SWITCH_FALSE;
	}

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "STATUS PROFILE: %s\n", (char *) stream.data);
	
	switch_safe_free(stream.data);

	return SWITCH_TRUE;
}

static void register_gw(void)
{
	switch_stream_handle_t stream = { 0 };
	SWITCH_STANDARD_STREAM(stream);
	switch_api_execute("sofia", "profile external register testgw", NULL, &stream);
	switch_safe_free(stream.data);
}

static void unregister_gw(void)
{
	switch_stream_handle_t stream = { 0 };
	SWITCH_STANDARD_STREAM(stream);
	switch_api_execute("sofia", "profile external unregister testgw", NULL, &stream);
	switch_safe_free(stream.data);
}

static int start_sipp_uac(const char *ip, int remote_port, const char *dialed_number, const char *scenario_uac, const char *extra)
{
	char *cmd = switch_mprintf("sipp %s:%d -nr -p 5062 -m 1 -s %s -recv_timeout 10000 -timeout 10s -sf %s -bg %s", ip, remote_port, dialed_number, scenario_uac, extra);
	int sys_ret = switch_system(cmd, SWITCH_TRUE);

	printf("%s\n", cmd);
	switch_safe_free(cmd);
	switch_sleep(1000 * 1000);

	return sys_ret;
} 

static int start_sipp_uas(const char *ip, int listen_port, const char *scenario_uas, const char *extra)
{
	char *cmd = switch_mprintf("sipp %s -p %d -nr -m 1 -s 1001 -recv_timeout 10000 -timeout 10s -sf %s -bg %s", ip, listen_port, scenario_uas, extra);
	int sys_ret = switch_system(cmd, SWITCH_TRUE);

	printf("%s\n", cmd);
	switch_safe_free(cmd);
	switch_sleep(1000 * 1000);

	return sys_ret;
}
static int run_sipp(const char *ip, int remote_port, int listen_port, const char *dialed_number, const char *scenario_uac, const char *auth_password, const char *extra)
{
	char *cmd = switch_mprintf("sipp %s:%d -nr -p %d -m 1 -s %s -recv_timeout 10000 -timeout 10s -sf %s -au %s -ap %s -bg %s", ip, remote_port, listen_port, dialed_number, scenario_uac, dialed_number, auth_password, extra);
	int sys_ret = switch_system(cmd, SWITCH_TRUE);

	printf("%s\n", cmd);
	switch_safe_free(cmd);
	switch_sleep(1000 * 1000);

	return sys_ret;
}

static void kill_sipp(void)
{
	switch_system("pkill -x sipp", SWITCH_TRUE);
	switch_sleep(1000 * 1000);
}

static void show_event(switch_event_t *event) {
	char *str;
	/*print the event*/
	switch_event_serialize_json(event, &str);
	if (str) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "%s\n", str);
		switch_safe_free(str);
	}
}

static void event_handler(switch_event_t *event) 
{
	const char *new_ev = switch_event_get_header(event, "Event-Subclass");

	if (new_ev && !strcmp(new_ev, "sofia::gateway_invalid_digest_req")) { 
		test_success = 1;
	}

	show_event(event);
}

static void event_handler_reg_ok(switch_event_t *event) 
{
	const char *new_ev = switch_event_get_header(event, "Event-Subclass");
	
	if (new_ev && !strcmp(new_ev, "sofia::gateway_state")) {
		const char *state = switch_event_get_header(event, "State");
		if (state && !strcmp(state, "REGED")) {
			test_success++;
		}
	}

	show_event(event);
}

static void event_handler_reg_fail(switch_event_t *event) 
{
	const char *new_ev = switch_event_get_header(event, "Event-Subclass");

	if (new_ev && !strcmp(new_ev, "sofia::gateway_state")) {
		const char *state = switch_event_get_header(event, "State");
		if (state && !strcmp(state, "FAIL_WAIT")) {
			test_success++;
		}
	}

	show_event(event);
}

FST_CORE_EX_BEGIN("./conf-sipp", SCF_VG | SCF_USE_SQL)
{
	FST_MODULE_BEGIN(mod_sofia, uac-uas)
	{
		FST_TEST_BEGIN(uac_delay_offer)
		{
			const char *local_ip_v4 = switch_core_get_variable("local_ip_v4");
			char uuid[100] = "";
			int sipp_ret;
			int sdp_count = 0;

			sipp_ret = start_sipp_uac(local_ip_v4, 5080, "1212121212", "sipp-scenarios/uac_delay_offer.xml", "");
			if (sipp_ret < 0 || sipp_ret == 127) {
				fst_check(!"sipp not found");
			} else {
				test_wait_for_uuid(uuid);
				if (!zstr(uuid)) {
				printf("Channel uuid exists : %s",uuid)
//					const char *sdp_str1 = NULL, *sdp_str2 = NULL;
//					const char *temp = NULL, *temp1 = NULL;
//					switch_core_session_t *session = switch_core_session_locate(uuid);
//					switch_channel_t *channel = switch_core_session_get_channel(session);
//					fst_check(channel);
//
//					sdp_str1 = test_wait_for_chan_var(channel,"1");
//					sdp_str2 = test_wait_for_chan_var(channel,"2");

				} else {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Uuid not found in Channel Data.\n");
				}
				/* sipp should timeout, attempt kill, just in case.*/
				kill_sipp();
			}
		}
		FST_TEST_END()

	}
	FST_MODULE_END()
}
FST_CORE_END()
