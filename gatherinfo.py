#!/usr/bin/env python3

import requests
import json
import sys
import os.path

from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def redfishg(path):
    '''Takes the redfish api path using requests to get data in json format'''
    try:
        r = requests.get(url + path,
                         auth=HTTPBasicAuth(username, password),
                         verify=False)
        rjs = r.json()
        return rjs

    except Exception as err:
        sys.exit("Error querying redfish.  Error is %s" % err)


if __name__ == "__main__":

    username = "admin"
    password = "admin"

    ip = sys.argv[1]

    url = "https://" + ip
    path = "/redfish/v1/Chassis/Enclosure"

    inventory = {}
    inventory["System Info"] = {}

    jsq = redfishg(path)

    if os.path.isfile(jsq['SerialNumber'] + ".json"):
        print(jsq['SerialNumber'] + "has already been collected")
        exit()

    else:
        json_filename = jsq['SerialNumber']

    inventory["System Info"] = {}
    inventory["System Info"] = ({"Serial Number": jsq['SerialNumber'],
                                 "Model": jsq['Model'],
                                 "Manufacturer": jsq['Manufacturer'],
                                 "PartNumber": jsq['PartNumber'],
                                 "Status": jsq['Status']['Health']})

    #Query Power Supplies
    power_path =  path + "/Power"
    jcq = redfishg(power_path)

    inventory["Power Supplies"] = {}

    for i in range(0, len(jcq['PowerSupplies']), 1):
        tpower = jcq['PowerSupplies'][i]['Name']

        inventory["Power Supplies"][tpower] = (
            {"Manufacturer": jcq['PowerSupplies'][i]['Manufacturer'],
             "Model": jcq['PowerSupplies'][i]['Model'],
             "Part Number": jcq['PowerSupplies'][i]['PartNumber'],
             "Firmware Version": jcq['PowerSupplies'][i]['FirmwareVersion'],
             "Serial Number": jcq['PowerSupplies'][i]['SerialNumber'],
             "Status": jcq['PowerSupplies'][i]['Status']['Health']})

    # Query Temps
    temp_path = path + "/Thermal"
    jmq = redfishg(temp_path)

    inventory["Temperatures"] = {}

    for i in range(0, len(jmq['Temperatures']), 1):
        tbase = jmq['Temperatures'][i]
        tname = tbase['Name']

        inventory["Temperatures"][tname] = (
            {"Current Temp - Celsius": tbase['ReadingCelsius'],
            "Status": tbase['Status']['Health']})

    # Gather IOM Information

    iomid = ["A", "B"]
    iomelement = ['OOBM', "PrimarySXP", "Sec1SXP", "Sec2SXP"]

    inventory["IO Module Details"] = {}

    for i in iomid:
        iom_path = "/redfish/v1/Chassis/IOModule" + i + "FRU"
        jiq = redfishg(iom_path)

        mfg = jiq['Manufacturer']
        mdl = jiq['Model']
        sn = jiq['SerialNumber']
        part = jiq['PartNumber']
        status = jiq['Status']['Health']

        inventory["IO Module Details"]["IOM" + i] = (
            {"Manufacturer": mfg, "Model": mdl,
            "Serial Number": sn,
            "Part Number": part, "Status": status})

    inventory["IO Module Details"]["IO Module Firmware"] = {}

    for iome in iomelement:
        for iid in iomid:
            firmware_path = \
                "/redfish/v1/UpdateService/FirmwareInventory/IOModule" \
                + iid + "_" + iome

            fiq = redfishg(firmware_path)

            fwname = fiq['Name']
            fwver = fiq['Version']

            inventory["IO Module Details"]["IO Module Firmware"][fwname] = \
                ({fwname : fwver})

    # Gather Ethernet Interface Details

    inventory["Ethernet Interfaces"] = {}

    for i in iomid:
        iom_path = \
            "/redfish/v1/Systems/Self/EthernetInterfaces/IOModule" + i + "FRU"
        jie = redfishg(iom_path)

        ethdev = jie['Name']
        inventory["Ethernet Interfaces"][ethdev] = (
            {"MAC Address": jie['PermanentMACAddress'],
             "Link Status": jie['LinkStatus'],
             "Factory IP Address": jie['IPv4Addresses'][0]['Address']})

    # Gather Drive information

    inventory["Drives"] = {}

    storage_path = "/redfish/v1/Systems/Self/Storage"

    jii = redfishg(storage_path)

    enc_path = jii['Members'][0]['@odata.id']

    jid = redfishg(enc_path)

    for i in range(1, len(jid['Drives']) + 1, 1):
        drive_path = enc_path + "/Drives/" + str(i)
        drive = redfishg(drive_path)

        slot = drive['Name']
        model = drive['Model']

        if model is not None:

            status = drive['Status']['State']
            protocol = drive['Protocol']
            revision = drive['Revision']
            size = int(drive['CapacityBytes'] / 1e+12)
            blocksize = drive['BlockSizeBytes']
            mediatype = drive['MediaType']
            manufacturer = drive['Manufacturer']
            serial = drive['SerialNumber']
            durableid = drive['Identifiers'][0]['DurableName']
            isfailpredicted = drive['FailurePredicted']
            rotationspeed = drive['RotationSpeedRPM']

            inventory["Drives"][slot] = ({
                "Manufacturer": manufacturer,
                "Drive Model": model, "Size GB": size,
                "Rotation Speed": rotationspeed,
                "Serial Number": serial,
                "Durable ID": durableid,
                "Revision": revision,
                "Media Type": mediatype,
                "Protocol": protocol,
                "Status": status,
                "Failure Predicted": isfailpredicted
            })

        else:
            inventory["Drives"][slot] = ({"Status": "Drive Not Detected"})

    # Get SAS HOst Ports

    inventory["SAS Host Ports"] = {}

    sas_list_path = "/redfish/v1/Systems/Self#/Oem/WDC"

    jsq = redfishg(sas_list_path)
    sas_max = len(jsq['Oem']['WDC']['SASHostPorts'])

    for i in range(0, sas_max, 1):
        lp = jsq['Oem']['WDC']['SASHostPorts'][i]
        name = lp['Name']
        link = lp['IsCableConnected']

        if link is False:
            link_state = "Disconnected"
        else:
            link_state = "Connected"

        inventory["SAS Host Ports"][name] = ({"Link Status": link_state})

    # Get zoning

    inventory["Zoning"] = {}

    zoning_status = jid['Status']['Oem']['WDC']['Zoning']['status']

    if zoning_status != "DISABLED":
        for i in jid['Status']['Oem']['WDC']['Zoning']['config']:
            port_status = jid['Status']['Oem']['WDC']['Zoning']['config'][i]
            inventory["Zoning"][i] = ({"Status": port_status})
    else:
        inventory["Zoning"] = ({"Status": zoning_status})

    j = json.dumps(inventory, indent=4)

    with open(json_filename + ".json", 'w') as w:
        w.write(j)

    w.close()
