import math
import icecream as ic
import requests
import time
import urllib3
from requests.auth import HTTPDigestAuth
from datetime import datetime
from datetime import timedelta


class Device:

    def __init__(self, ip: str, uname: str, pwd: str, timeout=5, assertion=False, logging=True):
        """
        Creates an instance of a 2N OS device.
        """
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        self.session = requests.Session()
        self.assertion = not assertion

        self.ip = ip
        self.auth_id = HTTPDigestAuth(uname, pwd)
        self.timeout = timeout
        self.failure = None
        self.logging = logging

        self.online = False
        self.uptime = math.inf
        self.model = "unknown"
        self.name = "unknown"
        self.fw_version = "unknown"
        self.build_type = "unknown"
        self.switches = ["uninitialized"]
        self.inputs = ["uninitialized"]
        self.outputs = ["uninitialized"]
        self.capabilities = {"uninitialized": "uninitialized"}
        self.phone_accounts = ["uninitialized"]
        self.phone_sessions = ["uninitialized"]
        self.camera_resolutions = ["uninitialized"]
        self.camera_sources = ["uninitialized"]
        self.eventlog_event_types = ["uninitialized"]
        self.audio_ok = None
        self.last_audio_test_attempt = None
        self._eventlog_active_channels = dict()

        self.logit(self.padding("internal_calls_start:") + "vvvvvvv", False, self.logging, False)
        self._fixed_caps_get()
        self.logit(self.padding("internal_calls_end:") + "^^^^^^^", False, self.logging, False)

    def padding(self, text:str) -> str:
        """
        Pads the given text with periods to make logging output more readable.
        """
        return text + (32 - len(text))*"."

    def offline_check(self, e: Exception) -> None:
        """
        Checks whether the given Exception is of the ConnectTimeout meaning the
        device does not respond at all.
        """
        if e.__class__.__name__ == "ConnectTimeout":
            self.online = False
            self.uptime = math.inf

    def logit(self, func, message, logging, verbose=False) -> None:
        """
        Basic logging to the command line.
        """
        if logging and verbose:
            ic.ic(func, message)
        elif logging:
            ic.ic(func)

    def _fixed_caps_get(self, logging="default", verbose_success=False, verbose_failure=True) -> bool:
        """
        Retrieves all capabilities of a device that are fixed.

        TODO: Test with a device without a camera support
        """
        if logging == "default":
            logging = self.logging
        try:
            command = self.session.get(
                (
                    "https://"
                    + self.ip
                    + "/api/camera/caps"
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id
            )

            command2 = self.session.get(
                (
                    "https://"
                    + self.ip
                    + "/api/log/caps"
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id
            )

            self.online = True
            if command.json()["success"] and command2.json()["success"]:
                self.logit(self.padding("init_fixed_caps_get:") + "success", command.text + "|" + command2.text, logging, verbose_success)
                self.camera_resolutions = command.json()["result"]["jpegResolution"]
                self.camera_sources = [source["source"] for source in command.json()["result"]["sources"]]
                self.eventlog_event_types = command2.json()["result"]["events"]
            else:
                if not self.assertion:
                    raise Exception(f"assetion is enabled and the script failed with api error: {command.text}")
                self.logit(self.padding("init_fixed_caps_get:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False
            self.failure = None
            return True
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("init_fixed_caps_get:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def info_get(self, logging="default", verbose_success=False, verbose_failure=True) -> bool:
        """
        Retrieves basic information about the device (model, name, fw version
        and build type).
        """
        if logging == "default":
            logging = self.logging
        try:
            command = self.session.get(
                (
                    "https://"
                    + self.ip
                    + "/api/system/info"
                ),
                timeout=self.timeout,
                verify=False
            )
            self.online = True
            self.model = command.json()["result"]["variant"]
            self.name = command.json()["result"]["deviceName"]
            self.fw_version = command.json()["result"]["swVersion"]
            self.build_type = command.json()["result"]["buildType"]
            self.logit(self.padding("info_get:") + "success", command.text, logging, verbose_success)
            self.failure = None
            return True
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("info_get:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def status_get(self, logging="default", verbose_success=False, verbose_failure=True) -> bool:
        """
        Retrieves uptime of the device.
        """
        if logging == "default":
            logging = self.logging
        try:
            command = self.session.get(
                (
                    "https://"
                    + self.ip
                    + "/api/system/status"
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id
            )

            self.online = True
            if command.json()["success"]:
                self.logit(self.padding("status_get:") + "success", command.text, logging, verbose_success)
                self.uptime = int(command.json()["result"]["upTime"])
            else:
                if not self.assertion:
                    raise Exception(f"assetion is enabled and the script failed with api error: {command.text}")
                self.logit(self.padding("status_get:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False
            self.failure = None
            return True
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("status_get:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def switches_get(self, logging="default", verbose_success=False, verbose_failure=True) -> bool:
        """
        Retrieves number of switches, their states, operation mode and basic settings.
        switch - int, indicates number of the switch (indexed from 1, corresponds to the order in the list)
        enabled - bool, if the the switch is disabled, it cannot be used and controlled
        mode - string, monostable or bistable indicating the switch mode (None if the switch is disabled)
        switchOnDuration - int, number of seconds the switch is activated (None if the switch is disabled)
        type - string, normal, inverted, security (type of output control) (None if the switch is disabled)
        active - bool, switch state
        locked - bool, switch operation locked
        held - bool, switch operation held
        """
        if logging == "default":
            logging = self.logging
        try:
            command = self.session.get(
                (
                    "https://"
                    + self.ip
                    + "/api/switch/caps"
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id
            )

            command2 = self.session.get(
                (
                    "https://"
                    + self.ip
                    + "/api/switch/status"
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id
            )

            self.online = True
            if command.json()["success"]:
                self.logit(self.padding("switches_get:") + "success", command.text + "|" + command2.text, logging, verbose_success)
                self.switches = []
                for sw_cap, sw_status in zip(command.json()["result"]["switches"], command2.json()["result"]["switches"]):
                    self.switches.append(sw_cap)
                    for key in sw_status.keys():
                        self.switches[-1][key] = sw_status[key]
                    for key in ["mode", "switchOnDuration", "type"]:
                        self.switches[-1][key] = self.switches[-1].get(key)
            else:
                if not self.assertion:
                    raise Exception(f"assetion is enabled and the script failed with api error: {command.text}")
                self.logit(self.padding("switches_get:") + "api error", command.text + "|" + command2.text, logging, verbose_failure)
                self.failure = command.text
                return False
            self.failure = None
            return True
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("switches_get:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def switches_set(self, idx, action, hold_timeout=0, logging="default", verbose_success=False, verbose_failure=True) -> bool:
        """
        Controls the device switch (get available switches using device.switches).
        Available actions:
        - on: switch it on (monostable for the configured duration)
        - off: switch it off (monostable - shorten the duration)
        - trigger: toggle the state of bistable switch, trigger monostable for the configured duration
        - lock: lock the switch (cannot be activated)
        - unlock: release the switch lock
        - hold: activate the switch indefinitely (or with defined hold_timeout)
        - release: release the switch hold
        """
        if logging == "default":
            logging = self.logging
        try:
            command = self.session.get(
                (
                    "https://"
                    + self.ip
                    + "/api/switch/ctrl?"
                    + "switch=" + str(idx)
                    + "&action=" + action
                    + "&timeout=" + str(hold_timeout)
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id
            )

            self.online = True
            if command.json()["success"]:
                self.logit(self.padding("switches_set " + str(idx) + " " + action + ":") + "success", command.text, logging, verbose_success)
            else:
                if not self.assertion:
                    raise Exception(f"assetion is enabled and the script failed with api error: {command.text}")
                self.logit(self.padding("switches_set:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False
            self.failure = None
            return True
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("switches_set:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def io_get(self, logging="default", verbose_success=False, verbose_failure=True) -> bool:
        """
        Retrieves number of inputs and outputs and their states.
        Input information can be retrieved by getting device.inputs.
        Ouput information can be retrieved by getting device.outputs.
        """
        if logging == "default":
            logging = self.logging
        try:
            command = self.session.get(
                (
                    "https://"
                    + self.ip
                    + "/api/io/caps"
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id
            )

            command2 = self.session.get(
                (
                    "https://"
                    + self.ip
                    + "/api/io/status"
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id
            )

            self.online = True
            if command.json()["success"]:
                self.logit(self.padding("io_get:") + "success", command.text + "|" + command2.text, logging, verbose_success)
                self.inputs = []
                self.outputs = []
                for io_cap, io_status in zip(command.json()["result"]["ports"], command2.json()["result"]["ports"]):
                    if io_cap["type"] == "input":
                        self.inputs.append(
                            {
                                "label": io_cap["port"],
                                "status": io_status["state"] == 1
                            }
                        )
                    elif io_cap["type"] == "output":
                        self.outputs.append(
                            {
                                "label": io_cap["port"],
                                "status": io_status["state"] == 1
                            }
                        )
            else:
                if not self.assertion:
                    raise Exception(f"assetion is enabled and the script failed with api error: {command.text}")
                self.logit(self.padding("io_get:") + "api error", command.text + "|" + command2.text, logging, verbose_failure)
                self.failure = command.text
                return False
            self.failure = None
            return True
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("io_get:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def config_download(self, logging="default", verbose_success=False, verbose_failure=True) -> bool:
        """
        Retrieves the configuration file.
        XML is returned in case of success.
        """
        if logging == "default":
            logging = self.logging
        try:
            command = self.session.get(
                (
                    "https://"
                    + self.ip
                    + "/api/config"
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id
            )

            self.online = True
            if command.headers["content-type"] == "application/xml":
                self.logit(self.padding("config:") + "success", "XML received", logging, verbose_success)
            else:
                if not self.assertion:
                    raise Exception(f"assetion is enabled and the script failed with api error: {command.text}")
                self.logit(self.padding("config:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False
            self.failure = None
            return command.content
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("config:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def config_upload(self, xml, password="", logging="default", verbose_success=False, verbose_failure=True) -> bool:
        """
        Uploads XML configuration file.
        """
        if logging == "default":
            logging = self.logging
        try:
            command = self.session.put(
                (
                    "https://"
                    + self.ip
                    + "/api/config?password="
                    + password
                ),
                timeout=self.timeout,
                verify=False,
                files = {"blob-cfg": xml},
                auth=self.auth_id
            )

            if command.json()["success"]:
                self.logit(self.padding("upload_config") + "success", command.text, logging, verbose_success)
            else:
                if not self.assertion:
                    raise Exception(f"assetion is enabled and the script failed with api error: {command.text}")
                self.logit(self.padding("upload_config:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False
            self.failure = None
            return True
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("upload_config:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def restart(self, logging="default", verbose_success=False, verbose_failure=True) -> bool:
        """
        Restarts the device.
        """
        if logging == "default":
            logging = self.logging
        try:
            command = self.session.get(
                (
                    "https://"
                    + self.ip
                    + "/api/system/restart"
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id
            )

            if command.json()["success"]:
                self.logit(self.padding("restart:") + "success", command.text, logging, verbose_success)
            else:
                if not self.assertion:
                    raise Exception(f"assetion is enabled and the script failed with api error: {command.text}")
                self.logit(self.padding("restart:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False
            self.failure = None
            return True
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("restart:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def caps_get(self, logging="default", verbose_success=False, verbose_failure=True) -> bool:
        """
        Retrieves the system capabilities of the device.
        """
        if logging == "default":
            logging = self.logging
        try:
            command = self.session.get(
                (
                    "https://"
                    + self.ip
                    + "/api/system/caps"
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id
            )

            if command.json()["success"]:
                self.logit(self.padding("caps:") + "success", command.text, logging, verbose_success)
                self.capabilities = command.json()["result"]["options"]
            else:
                if not self.assertion:
                    raise Exception(f"assetion is enabled and the script failed with api error: {command.text}")
                self.logit(self.padding("caps:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False
            self.failure = None
            return True
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("caps:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def time_get(self, logging="default", verbose_success=False, verbose_failure=True) -> bool:
        """
        Retrieves the device time and its settings.
        Time and its settings are returned as a directory:
        "utcTime":   int
        "source":    string
        "automatic": bool
        """
        if logging == "default":
            logging = self.logging
        try:
            command = self.session.get(
                (
                    "https://"
                    + self.ip
                    + "/api/system/time"
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id
            )

            if command.json()["success"]:
                self.logit(self.padding("time_get:") + "success", command.text, logging, verbose_success)
            else:
                if not self.assertion:
                    raise Exception(f"assetion is enabled and the script failed with api error: {command.text}")
                self.logit(self.padding("time_get:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False
            self.failure = None
            return command.json()["result"]
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("time_get:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def time_set(self, time=None, automatic=None, server=None, logging="default", verbose_success=False, verbose_failure=True) -> bool:
        """
        Sets the device time and its settings.
        Time and its settings are entered as URL params:
        utcTime=int
        source=string (URL)
        automatic=int (0, 1)
        At least one parameter is mandatory.
        """
        if logging == "default":
            logging = self.logging
        payload = ""
        if time is not None:
            payload += "utcTime=" + str(time)
        if automatic is not None:
            if payload:
                payload += "&"
            payload += "automatic=" + str(automatic)
        if server is not None:
            if payload:
                payload += "&"
            payload += "server=" + str(server)
        try:
            if not payload:
                raise Exception("At least one parameter time, automatic or server is mandatory.")
            if (automatic == 1 and time is not None) or (self.time_get(False)["automatic"] and (automatic == 1 or automatic is None) and time is not None):
                raise Exception("Time mode is automatic. Switch it to manual before setting the time.")
            command = self.session.put(
                (
                    "https://"
                    + self.ip
                    + "/api/system/time?"
                    + payload
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id,
            )

            if command.json()["success"]:
                self.logit(self.padding("time_set:") + "success", command.text, logging, verbose_success)
            else:
                if not self.assertion:
                    raise Exception(f"assetion is enabled and the script failed with api error: {command.text}")
                self.logit(self.padding("time_set:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False
            self.failure = None
            return True
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("time_set:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def timezone_caps_get(self, logging="default", verbose_success=False, verbose_failure=True) -> list:
        """
        Retrieves the device's list of supported standard timezones. A list is returned.
        """
        if logging == "default":
            logging = self.logging
        try:
            command = self.session.get(
                (
                    "https://"
                    + self.ip
                    + "/api/system/timezone/caps"
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id
            )

            if command.json()["success"]:
                self.logit(self.padding("timezone_caps_get:") + "success", command.text, logging, verbose_success)
            else:
                if not self.assertion:
                    raise Exception(f"assetion is enabled and the script failed with api error: {command.text}")
                self.logit(self.padding("timezone_caps_get:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False
            self.failure = None
            return command.json()["result"]["timezones"]
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("timezone_caps_get:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def timezone_get(self, logging="default", verbose_success=False, verbose_failure=True) -> dict:
        """
        Retrieves the device's timezone settings.
        "automatic": boolean
        "zone": string
        "custom": string (None if the zone is not custom)
        """
        if logging == "default":
            logging = self.logging
        try:
            command = self.session.get(
                (
                    "https://"
                    + self.ip
                    + "/api/system/timezone"
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id
            )

            if command.json()["success"]:
                self.logit(self.padding("timezone_get:") + "success", command.text, logging, verbose_success)
            else:
                if not self.assertion:
                    raise Exception(f"assetion is enabled and the script failed with api error: {command.text}")
                self.logit(self.padding("timezone_get:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False
            self.failure = None
            tz_dataset = command.json()["result"]
            tz_dataset["custom"] = tz_dataset.get("custom")
            return tz_dataset
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("timezone_get:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def timezone_set(self, automatic=1, zone=None, custom=None, logging="default", verbose_success=False, verbose_failure=True) -> bool:
        """
        Sets the device timezone and its settings.
        Timezone and its settings are entered as URL params:
        automatic=int (0, 1)
        zone=string (zone name, use timezone_caps_get for the list of names)
        custom=string (definition string of custom timezone, e.g., UTC0)
        Call the method without any parameters to set the automatic timezone mode.
        Call the method with zone (and custom) parameter to set manual timezone (timezone mode is automatically se to Manual, regardless of the automatic parameter)
        """
        if logging == "default":
            logging = self.logging
        payload = ""
        if zone is None:
            payload += "automatic=" + str(automatic)
        elif zone != "custom":
            payload += "automatic=0&zone=" + zone
        else:
            payload += "automatic=0&zone=" + zone + "&custom=" + custom

        try:
            if (zone != "custom" and custom is not None):
                raise Exception("To configure custom rule the timezone needs to be set to \"custom\".")
            if (zone == "custom" and custom is None):
                raise Exception("Custom rule needs to be defined when the timezone is set to \"custom\".")
            command = self.session.put(
                (
                    "https://"
                    + self.ip
                    + "/api/system/timezone?"
                    + payload
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id,
            )

            if command.json()["success"]:
                self.logit(self.padding("timezone_set:") + "success", command.text, logging, verbose_success)
            else:
                if not self.assertion:
                    raise Exception(f"assetion is enabled and the script failed with api error: {command.text}")
                self.logit(self.padding("timezone_set:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False
            self.failure = None
            return True
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("timezone_set:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def firmware_upload(self, fw, direct=True, logging="default", verbose_success=False, verbose_failure=True) -> bool:
        """
        Uploads firmware binary file. Use direct to apply the firmware immediately (by default True).
        If direct=False => fwid, version, downgrade and upgrade warning is returned in a dict for individual handling.
        fwid - identifier of the version used for confirmation or rejection
        version - version number read from the file header
        downgrade - bool informing on whether the device will be downgraded
        note - upgrade warning text for user's consideration

        Timeout for this operation is modified to self.timeout + 120.

        The uploaded firmware is stored and can be confirmed for 30 s after the upload.
        """
        if logging == "default":
            logging = self.logging
        if type(fw) is not bytes:
            if not self.assertion:
                raise Exception("assetion is enabled and the script failed with api error: Firmware must be in \"bytes\".")
            self.logit(self.padding("firmware_upload:") + "data error", "Firmware must be in \"bytes\".", logging, verbose_failure)
            self.failure = "Firmware must be in \"bytes\"."
            return False
        try:
            command = self.session.put(
                (
                    "https://"
                    + self.ip
                    + "/api/firmware"
                ),
                timeout=self.timeout + 120,
                verify=False,
                headers={"Content-Type": "application/octet-stream"},
                data=fw,
                auth=self.auth_id
            )

            if command.json()["success"]:
                self.logit(self.padding("firmware_upload:") + "success", command.text, logging, verbose_success)
            else:
                if not self.assertion:
                    raise Exception(f"assetion is enabled and the script failed with api error: {command.text}")
                self.logit(self.padding("firmware_upload:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False
            version_info = dict()
            version_info["fwid"] = command.json()["result"]["fileId"]
            version_info["version"] = command.json()["result"]["version"]
            version_info["downgrade"] = command.json()["result"]["downgrade"]
            version_info["note"] = command.json()["result"]["note"]

            if not direct:
                return version_info
            self.logit("firmware will be confirmed automatically (direct=True)")
            self.firmware_confirm(version_info["fwid"])
            self.failure = None
            return True
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("firmware_upload:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def firmware_confirm(self, fwid, logging="default", verbose_success=False, verbose_failure=True) -> bool:
        """
        Confirms uploaded firmware file with fwid to be applied to the device.
        """
        if logging == "default":
            logging = self.logging
        try:
            command = self.session.post(
                (
                    "https://"
                    + self.ip
                    + "/api/firmware/apply?fileid="
                    + fwid
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id
            )
            if command.json()["success"]:
                self.logit(self.padding("firmware_confirm:") + "success", command.text, logging, verbose_success)
            else:
                if not self.assertion:
                    raise Exception(f"assetion is enabled and the script failed with api error: {command.text}")
                self.logit(self.padding("firmware_confirm:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False
            self.failure = None
            return True
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("firmware_confirm:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def firmware_reject(self, fwid, logging="default", verbose_success=False, verbose_failure=True) -> bool:
        """
        Rejects uploaded firmware file with fwid - another firmware file can be uploaded immediately.
        """
        if logging == "default":
            logging = self.logging
        try:
            command = self.session.post(
                (
                    "https://"
                    + self.ip
                    + "/api/firmware/reject?fileid="
                    + fwid
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id
            )
            if command.json()["success"]:
                self.logit(self.padding("firmware_reject:") + "success", command.text, logging, verbose_success)
            else:
                if not self.assertion:
                    raise Exception(f"assetion is enabled and the script failed with api error: {command.text}")
                self.logit(self.padding("firmware_reject:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False
            self.failure = None
            return True
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("firmware_reject:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def factory_reset(self, sections=None, logging="default", verbose_success=False, verbose_failure=True) -> bool:
        """
        Reset the device to the factory default configuration.
        Using parameter sections=network all network parameters will be also reset. If the parameter is not specified, network parameters are not reset.
        """
        if logging == "default":
            logging = self.logging
        params = ""
        if sections == "network":
            params = "?sections=network"
        try:
            command = self.session.post(
                (
                    "https://"
                    + self.ip
                    + "/api/config/factoryreset"
                    + params
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id
            )
            if command.json()["success"]:
                self.logit(self.padding("factory_reset:") + "success", command.text, logging, verbose_success)
            else:
                if not self.assertion:
                    raise Exception(f"assetion is enabled and the script failed with api error: {command.text}")
                self.logit(self.padding("factory_reset:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False
            self.failure = None
            return True
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("factory_reset:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def phone_get(self, logging="default", verbose_success=False, verbose_failure=True) -> bool:
        """
        Retrieves status of SIP accounts and their calls (if there are any).
        List of accounts is populated. List of sessions is populated. Get them from the Device object.
        It is not possible to pair sessions with their respective accounts at the moment.

        phone_accounts is a list and contains a dict for each account with the following keys:
        - account (account ID indexed from 1)
        - accountType (string: general, local, msteams)
        - answerMode (int according to enum)
        - authId (string)
        - displayName (string)
        - domain (string)
        - domainPort (int, 0 means default port for individual SIP accounts)
        - enabled (bool)
        - proxyAddress (string)
        - proxyPort (int, 0 means default port for individual SIP accounts)
        - sipNumber (SIP URL, string)
        - registrationEnabled (bool)
        - registered (bool)
        - registerTime (int or None when the account is not registred)
        - registrarAddress (string)
        - registrarPort (int, 0 means default port for individual SIP accounts)

        phone_sessions is a list and contains a dict for each session (call) with the following keys:
        - calls (list of individual calls in a session, contains id (int), call type identifier, SIP URL and call state)
        - session (session ID indexed from 1)
        - direction (string: incoming or outgoing)
        - state (string: connecting, ringing, connected)
        Currently, there can be only one session in 2N OS devices. The list is empty if there is no session.
        """
        if logging == "default":
            logging = self.logging
        try:
            command = self.session.get(
                (
                    "https://"
                    + self.ip
                    + "/api/phone/status"
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id
            )

            command2 = self.session.get(
                (
                    "https://"
                    + self.ip
                    + "/api/call/status"
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id
            )

            command3 = self.session.get(
                (
                    "https://"
                    + self.ip
                    + "/api/phone/config"
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id
            )

            self.online = True
            if command.json()["success"] and command2.json()["success"] and command3.json()["success"]:
                self.logit(self.padding("phone_get:") + "success", command.text + "|" + command2.text + "|" + command3.text, logging, verbose_success)
                self.phone_sessions = command2.json()["result"]["sessions"]
                self.phone_accounts = []
                for ph_status, ph_config in zip(command.json()["result"]["accounts"], command3.json()["result"]["accounts"]):
                    self.phone_accounts.append(ph_status)
                    for key in ph_config.keys():
                        self.phone_accounts[-1][key] = ph_config[key]
                for account in self.phone_accounts:
                    account["registerTime"] = account.get("registerTime")
            else:
                if not self.assertion:
                    raise Exception(f"assetion is enabled and the script failed with api error: {command.text}")
                self.logit(self.padding("phone_get:") + "api error", command.text + "|" + command2.text, logging, verbose_failure)
                self.failure = command.text
                return False
            self.failure = None
            return True
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("phone_get:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def phone_set(self, payload, logging="default", verbose_success=False, verbose_failure=True) -> bool:
        """
        Sets parameters of SIP accounts.
        Current configuration is retrieved and unchanged parameters are used from the configuration.

        The following parameters can be configured (enter as a list of dicts):
        - account (mandatory, account ID indexed from 1)
        - enabled (bool)
        - answerMode (int according to enum)
        - authId (string)
        - displayName (string)
        - domain (string)
        - domainPort (int, 0 means default port for individual SIP accounts)
        - proxyAddress (string)
        - proxyPort (int, 0 means default port for individual SIP accounts)
        - sipNumber (SIP URL, string)
        - registrationEnabled (bool)
        - registrarAddress (string)
        - registrarPort (int, 0 means default port for individual SIP accounts)
        """
        if logging == "default":
            logging = self.logging
        keys = [
            "account",
            "enabled",
            "answerMode",
            "authId",
            "displayName",
            "domain",
            "domainPort",
            "proxyAddress",
            "proxyPort",
            "sipNumber",
            "registrationEnabled",
            "registrarAddress",
            "registrarPort"
        ]
        try:
            self.logit("phone_set gets current phone config before configuration change", "", True)
            self.phone_get()
            for account in payload:
                if "account" not in account.keys():
                    raise Exception("Account ID must be present in each configuration data set.")
                for key in self.phone_accounts[0]:
                    if key not in keys:
                        account[key] = self.phone_accounts[account["account"]-1][key]
            payload = {
                "accounts": payload
            }
            command = self.session.put(
                (
                    "https://"
                    + self.ip
                    + "/api/phone/config"
                ),
                timeout=self.timeout,
                verify=False,
                json=payload,
                auth=self.auth_id,
            )

            if command.json()["success"]:
                self.logit(self.padding("phone_set:") + "success", command.text, logging, verbose_success)
            else:
                if not self.assertion:
                    raise Exception(f"assetion is enabled and the script failed with api error: {command.text}")
                self.logit(self.padding("phone_set:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False
            self.failure = None
            self.logit("phone_set gets current phone config after configuration change", "", True)
            self.phone_get()
            return True
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("phone_set:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def phone_dial(self, number=None, users=None, logging="default", verbose_success=False, verbose_failure=True) -> int:
        """
        Dials a number, user or list of users
        Exactly one parameter (numbers or users) is mandatory.
        Enter a single number as a SIP URI.
        Enter one or multiple users as a list of strings representing uuids.

        Returns the session identifier, which can be used for monitoring of the session with phone_get or to hang it up with phone_hangup.
        """
        if logging == "default":
            logging = self.logging
        try:
            if number is not None and users is not None:
                raise Exception("Exactly one parameter numbers or users is mandatory.")
            payload = ""
            if number is not None:
                payload += "number=" + number
            if users is not None:
                payload += "users="
                for user in users:
                    payload += user + ","
                payload = payload[:-1]
            if not payload:
                raise Exception("Exactly one parameter numbers or users is mandatory.")
            command = self.session.post(
                (
                    "https://"
                    + self.ip
                    + "/api/call/dial?"
                    + payload
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id,
            )

            if command.json()["success"]:
                self.logit(self.padding("phone_dial:") + "success", command.text, logging, verbose_success)
            else:
                if not self.assertion:
                    raise Exception(f"assetion is enabled and the script failed with api error: {command.text}")
                self.logit(self.padding("phone_dial:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False
            self.failure = None
            return command.json()["result"]["session"]
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("phone_dial:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def phone_hangup(self, session, reason="normal", logging="default", verbose_success=False, verbose_failure=True) -> bool:
        """
        Hangs up a call in an active session.

        Use session id to select the session (phone_get and device.sessions to identify the session).
        Optionally, you can select the termination reason: normal (default), rejected, busy, noanswer.
        """
        if logging == "default":
            logging = self.logging
        try:
            command = self.session.post(
                (
                    "https://"
                    + self.ip
                    + "/api/call/hangup?"
                    + "session=" + str(session)
                    + "&reason=" + reason
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id,
            )

            if command.json()["success"]:
                self.logit(self.padding("phone_hangup:") + "success", command.text, logging, verbose_success)
            else:
                if not self.assertion:
                    raise Exception(f"assetion is enabled and the script failed with api error: {command.text}")
                self.logit(self.padding("phone_hangup:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False
            self.failure = None
            return True
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("phone_hangup:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def phone_pickup(self, session, logging="default", verbose_success=False, verbose_failure=True) -> bool:
        """
        Picks up a call in an active session.

        Use session id to select the session (phone_get and device.sessions to identify the session).
        """
        if logging == "default":
            logging = self.logging
        try:
            command = self.session.post(
                (
                    "https://"
                    + self.ip
                    + "/api/call/answer?"
                    + "session=" + str(session)
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id,
            )

            if command.json()["success"]:
                self.logit(self.padding("phone_pickup:") + "success", command.text, logging, verbose_success)
            else:
                if not self.assertion:
                    raise Exception(f"assetion is enabled and the script failed with api error: {command.text}")
                self.logit(self.padding("phone_pickup:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False
            self.failure = None
            return True
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("phone_pickup:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def cacert_upload(self, cert, id="", logging="default", verbose_success=False, verbose_failure=True) -> bool:
        """
        Uploads a CA certificate.

        Use id without @ (it is automatically added).
        The certificate file is loaded as bytes object.
        """
        if logging == "default":
            logging = self.logging
        if id:
            id = "?id=@" + id
        if type(cert) is not bytes:
            if not self.assertion:
                raise Exception("assetion is enabled and the script failed with api error: Certificate must be in \"bytes\".")
            self.logit(self.padding("cacert_upload:") + "data error", "Certificate must be in \"bytes\".", logging, verbose_failure)
            self.failure = "Certificate must be in \"bytes\"."
            return False
        try:
            command = self.session.put(
                (
                    "https://"
                    + self.ip
                    + "/api/cert/ca"
                    + id
                ),
                timeout=self.timeout + 120,
                verify=False,
                files = {"blob-cert": ("blob-cert", cert)},
                auth=self.auth_id
            )

            if command.json()["success"]:
                self.logit(self.padding("cacert_upload:") + "success", command.text, logging, verbose_success)
            else:
                if not self.assertion:
                    raise Exception(f"assetion is enabled and the script failed with api error: {command.text}")
                self.logit(self.padding("cacert_upload:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False

            self.failure = None
            return True
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("cacert_upload:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def cacert_list(self, logging="default", verbose_success=False, verbose_failure=True) -> list:
        """
        Retrieves a list of CA certificates in the device.

        The list contains all information about certificates (see 2N HTTP API documentation for more information).
        """
        if logging == "default":
            logging = self.logging
        try:
            command = self.session.get(
                (
                    "https://"
                    + self.ip
                    + "/api/cert/ca"
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id
            )

            if command.json()["success"]:
                self.logit(self.padding("cacert_list:") + "success", command.text, logging, verbose_success)
            else:
                if not self.assertion:
                    raise Exception(f"assetion is enabled and the script failed with api error: {command.text}")
                self.logit(self.padding("cacert_list:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False

            self.failure = None
            return command.json()["result"]["certificates"]
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("cacert_list:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def cacert_delete(self, id, logging="default", verbose_success=False, verbose_failure=True) -> list:
        """
        Deletes a CA certificate.

        Get the id (or use the fingerprint as id) to select the certificate. Get the list of certificate by using carcert_list.
        If the id is entered externally (it is not retrieved from cacert_list), enter it with the prefix @.
        """
        if logging == "default":
            logging = self.logging
        try:
            command = self.session.delete(
                (
                    "https://"
                    + self.ip
                    + "/api/cert/ca?id="
                    + id
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id
            )

            if command.json()["success"]:
                self.logit(self.padding("cacert_delete:") + "success", command.text, logging, verbose_success)
            else:
                if not self.assertion:
                    raise Exception(f"assetion is enabled and the script failed with api error: {command.text}")
                self.logit(self.padding("cacert_delete:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False

            self.failure = None
            return True
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("cacert_delete:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def usercert_upload(self, cert, pk, id="", logging="default", verbose_success=False, verbose_failure=True) -> bool:
        """
        Uploads a user certificate.

        Use id without @ (it is automatically added).
        The certificate and key file is loaded as bytes object.
        """
        if logging == "default":
            logging = self.logging
        if id:
            id = "?id=@" + id
        if type(cert) is not bytes or type(pk) is not bytes:
            if not self.assertion:
                raise Exception("assetion is enabled and the script failed with api error: Certificate or key must be in \"bytes\".")
            self.logit(self.padding("usercert_upload:") + "data error", "Certificate or key must be in \"bytes\".", logging, verbose_failure)
            self.failure = "Certificate or key must be in \"bytes\"."
            return False
        try:
            command = self.session.put(
                (
                    "https://"
                    + self.ip
                    + "/api/cert/user"
                    + id
                ),
                timeout=self.timeout + 120,
                verify=False,
                files = {"blob-cert": ("blob-cert", cert), "blob-pk": ("blob-pk", pk)},
                auth=self.auth_id
            )

            if command.json()["success"]:
                self.logit(self.padding("usercert_upload:") + "success", command.text, logging, verbose_success)
            else:
                if not self.assertion:
                    raise Exception(f"assetion is enabled and the script failed with api error: {command.text}")
                self.logit(self.padding("usercert_upload:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False

            self.failure = None
            return True
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("usercert_upload:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def usercert_list(self, logging="default", verbose_success=False, verbose_failure=True) -> list:
        """
        Retrieves a list of user certificates in the device.

        The list contains all information about certificates (see 2N HTTP API documentation for more information).
        """
        if logging == "default":
            logging = self.logging
        try:
            command = self.session.get(
                (
                    "https://"
                    + self.ip
                    + "/api/cert/user"
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id
            )

            if command.json()["success"]:
                self.logit(self.padding("usercert_list:") + "success", command.text, logging, verbose_success)
            else:
                if not self.assertion:
                    raise Exception(f"assetion is enabled and the script failed with api error: {command.text}")
                self.logit(self.padding("usercert_list:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False

            self.failure = None
            return command.json()["result"]["certificates"]
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("usercert_list:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def usercert_delete(self, id, logging="default", verbose_success=False, verbose_failure=True) -> list:
        """
        Deletes a user certificate.

        Get the id (or use the fingerprint as id) to select the certificate. Get the list of certificate by using usercert_list.
        If the id is entered externally (it is not retrieved from usercert_list), enter it with the prefix @.
        """
        if logging == "default":
            logging = self.logging
        try:
            command = self.session.delete(
                (
                    "https://"
                    + self.ip
                    + "/api/cert/user?id="
                    + id
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id
            )

            if command.json()["success"]:
                self.logit(self.padding("usercert_delete:") + "success", command.text, logging, verbose_success)
            else:
                if not self.assertion:
                    raise Exception(f"assetion is enabled and the script failed with api error: {command.text}")
                self.logit(self.padding("usercert_delete:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False

            self.failure = None
            return True
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("usercert_delete:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def snapshot_download(self, width=None, height=None, source="internal", quality=90, time=0, logging="default", verbose_success=False, verbose_failure=True) -> bool:
        """
        Retrieves a camera snapshot (JPEG image data is received).

        Parameters:
        width - the maximum available resolution is used when not specified. Use device.camera_resolutions to get available resolutions.
        height - the maximum available resolution is used when not specified. Use device.camera_resolutions to get available resolutions.
        source - internal source is used when not specified. Use device.camera_sources to get available sources.
        quality - JPEG quality factor, 90 is used when not specified.
        time - a time in the range 0 to -30 s. Older snapshots can be retrieved according to the specified time from the buffer. The most recent image is retrieved when not specified.
        """
        if logging == "default":
            logging = self.logging
        if not width:
            width = self.camera_resolutions[-1]["width"]
        if not height:
            height = self.camera_resolutions[-1]["height"]
        try:
            command = self.session.get(
                (
                    "https://"
                    + self.ip
                    + "/api/camera/snapshot?"
                    + "width="
                    + str(width)
                    + "&height="
                    + str(height)
                    + "&source="
                    + source
                    + "&quality="
                    + str(quality)
                    + "&time="
                    + str(time)
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id
            )

            self.online = True
            if command.headers["content-type"] == "image/jpeg":
                self.logit(self.padding("snapshot_download:") + "success", "JPEG received", logging, verbose_success)
            else:
                if not self.assertion:
                    raise Exception(f"assetion is enabled and the script failed with api error: {command.text}")
                self.logit(self.padding("snapshot_download:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False
            self.failure = None
            return command.content
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("snapshot_download:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def eventlog_active_channels_get(self) -> list:
        """
        Refreshes and returns the list of active eventlog channels with their details. The list contains dicts with keys:
        "id" - channel id, use for channel management
        "timestamp" - last time the channel was pulled (or created)
        "duration" - duration of the channel

        Do not retrieve device._eventlog_active_channels directly because it will not be refreshed.
        """
        trash = set()
        for channel_id in self._eventlog_active_channels.keys():
            age = datetime.now() - self._eventlog_active_channels[channel_id]["timestamp"]
            if age >= timedelta(seconds=self._eventlog_active_channels[channel_id]["duration"]):
                trash.add(channel_id)
        for key in trash:
            del self._eventlog_active_channels[key]
        output = []
        for channel_id in self._eventlog_active_channels.keys():
            output.append(
                {
                    "id": channel_id,
                    "duration": self._eventlog_active_channels[channel_id]["duration"],
                    "timestamp": self._eventlog_active_channels[channel_id]["timestamp"],
                    "events_list": self._eventlog_active_channels[channel_id]["events_list"],
                }
            )
        return output

    def eventlog_subscribe(self, events_list=None, duration=90, include="new", logging="default", verbose_success=False, verbose_failure=True) -> int:
        """
        Creates a subscription channel for event log.

        - events_list = specify event types that will be added to this channel as a list. All event types that are not hidden are added if not specified. Explicite subscribe to a specific hidden event type to get it. Use string "all" to subscribe to all event types the device provides.
        - duration = specify the duration of the subscription channel. It is automatically destroyed upon timeout if no new pull request is sent. 90 is assumed when not specified. Maximum duration is 3600 s.
        - include = specify whether only new events (after the channel creation), all (also all events that are in the device's memory) or -t (also events that happened in t seconds before the channel creation) are included upon the channel creation. Only new are included when not specified.

        Returns subsciption channel id (use it for channel management - pull or delete).
        Adds active channel subscription into device._eventlog_active_channels. Use device.eventlog_active_channels_get() to retrieve currently active subscription channels. Expired channels are removed.
        """
        if logging == "default":
            logging = self.logging
        payload = "duration=" + str(duration) + "&include=" + str(include)
        if events_list == "all":
            payload += "&filter="
            for event_type in self.eventlog_event_types:
                payload += event_type + ","
            payload = payload[:-1]
        elif events_list:
            payload += "&filter="
            for event_type in events_list:
                payload += event_type + ","
            payload = payload[:-1]
        else:
            events_list = "all unhidden"
        try:
            command = self.session.post(
                (
                    "https://"
                    + self.ip
                    + "/api/log/subscribe?"
                    + payload
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id
            )

            if command.json()["success"]:
                self.logit(self.padding("eventlog_subscribe:") + "success", command.text, logging, verbose_success)
            else:
                if not self.assertion:
                    raise Exception(f"assetion is enabled and the script failed with api error: {command.text}")
                self.logit(self.padding("eventlog_subscribe:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False

            self.failure = None
            self._eventlog_active_channels[command.json()["result"]["id"]] = {
                "duration": duration,
                "timestamp": datetime.now(),
                "events_list": events_list
            }
            return command.json()["result"]["id"]
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("eventlog_subscribe:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def eventlog_pull(self, id, timeout=None, logging="default", verbose_success=False, verbose_failure=True) -> list:
        """
        Retrieves contents (list) of an eventlog subscription channel. An empty list is retrieved when the channel has no new events to be pulled (even after timeout elapsed).

        Use device.eventlog_active_channels_get() to retrieve currently active channels. This is saved by the Device object and not retrieved from the device.
        Do not retrieve device._eventlog_active_channels directly because it will not be refreshed.
        """
        if logging == "default":
            logging = self.logging
        if not timeout:
            timeout = 0
        try:
            command = self.session.get(
                (
                    "https://"
                    + self.ip
                    + "/api/log/pull?id="
                    + str(id)
                    + "&timeout="
                    + str(timeout)
                ),
                timeout=timeout+1,
                verify=False,
                auth=self.auth_id
            )

            if command.json()["success"]:
                self.logit(self.padding("eventlog_pull:") + "success", command.text, logging, verbose_success)
            else:
                if not self.assertion:
                    raise Exception(f"assetion is enabled and the script failed with api error: {command.text}")
                self.logit(self.padding("eventlog_pull:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False

            self.failure = None
            self._eventlog_active_channels[id]["timestamp"] = datetime.now()
            return command.json()["result"]["events"]
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("eventlog_pull:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def eventlog_unsubscibe(self, id, logging="default", verbose_success=False, verbose_failure=True) -> bool:
        """
        Deletes a subscription channel. Use this to free up resources or just let subscription channels expire.

        Use device.eventlog_active_channels_get() to retrieve currently active channels.
        Do not retrieve device._eventlog_active_channels directly because it will not be refreshed.
        """
        if logging == "default":
            logging = self.logging
        try:
            command = self.session.get(
                (
                    "https://"
                    + self.ip
                    + "/api/log/unsubscribe?id="
                    + str(id)
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id
            )

            if command.json()["success"]:
                self.logit(self.padding("eventlog_unsubscribe:") + "success", command.text, logging, verbose_success)
            else:
                if not self.assertion:
                    raise Exception(f"assetion is enabled and the script failed with api error: {command.text}")
                self.logit(self.padding("eventlog_unsubscribe:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False

            self.failure = None
            del self._eventlog_active_channels[id]
            return True
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("eventlog_unsubscribe:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def perform_audio_test(self, logging="default", verbose_success=False, verbose_failure=True) -> bool:
        """
        Starts an audio test, subscribes an eventlog channel, gets the test result and unsubscribes the channel. The test takes 5 seconds.

        Get the result of the last test result in device.audio_ok (None - uninitialized or test did not run properly, False - failed, True - passed). This is saved by the Device object and not retrieved from the device.
        Get the time of the last test attempt (updated even when the test did not run properly) in device.last_audio_test_attempt. None if the test was never attempted. This is saved by the Device object and not retrieved from the device.
        """
        if logging == "default":
            logging = self.logging
        try:
            assert "AudioLoopTest" in self.eventlog_event_types, "The device does not support Audio Loop Test or was not initialized properly."
            self.logit(self.padding("internal_calls_start:") + "vvvvvvv", "", logging, False)
            log_id = self.eventlog_subscribe(["AudioLoopTest"], 10)
            command = self.session.get(
                (
                    "https://"
                    + self.ip
                    + "/api/audio/test"
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id
            )
            time.sleep(5)
            events = self.eventlog_pull(log_id)
            for event in events[::-1]:
                if event["params"]["result"] == "passed":
                    self.audio_ok = True
                    break
                elif event["params"]["result"] == "failed":
                    self.audio_ok = False
                    break
                else:
                    self.audio_ok = None
            self.last_audio_test_attempt = datetime.now()
            self.eventlog_unsubscibe(log_id)
            self.logit(self.padding("internal_calls_end:") + "^^^^^^^", False, logging, False)

            if command.json()["success"]:
                self.logit(self.padding("perform_audio_test:") + "success", command.text, logging, verbose_success)
            else:
                if not self.assertion:
                    raise Exception(f"assetion is enabled and the script failed with api error: {command.text}")
                self.logit(self.padding("perform_audio_test:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False

            self.failure = None
            return True
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("perform_audio_test:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False