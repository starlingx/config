====================================================
Configuration API v1
====================================================

Manage configuration with the StarlingX system and service configuration.
This includes DNS, NTP, Storage Clusters, Service Parameters, Networks,
Address Pools, Certificates, and so forth.

The typical port used for the Configuration REST API is 6385. However,
proper technique would be to look up the sysinv service endpoint in
Keystone.

-------------
API versions
-------------

**************************************************************************
Lists information about all StarlingX Configuration API versions
**************************************************************************

.. rest_method:: GET /

**Normal response codes**

200, 300

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

::

   {
      "default_version":{
         "id":"v1",
         "links":[
            {
               "href":"http://128.224.150.54:6385/v1/",
               "rel":"self"
            }
         ]
      },
      "versions":[
         {
            "id":"v1",
            "links":[
               {
                  "href":"http://128.224.150.54:6385/v1/",
                  "rel":"self"
               }
            ]
         }
      ],
      "description":"StarlingX Cloud System API allows for the management of physical servers.  This includes inventory collection and configuration of hosts, ports, interfaces, CPUs, disk, memory, and system configuration.  The API also supports the configuration of the cloud's SNMP interface. ",
      "name":"StarlingX SysInv API"
   }

This operation does not accept a request body.

*******************************************
Shows details for Configuration API v1
*******************************************

.. rest_method:: GET /v1

**Normal response codes**

200, 203

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

::

   {
       "firewallrules": [
           {
               "href": "http://10.10.10.2:6385/v1/firewallrules/",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/firewallrules/",
               "rel": "bookmark"
           }
       ],
       "addresses": [
           {
               "href": "http://10.10.10.2:6385/v1/addresses/",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/addresses/",
               "rel": "bookmark"
           }
       ],
       "links": [
           {
               "href": "http://10.10.10.2:6385/v1/",
               "rel": "self"
           },
           {
               "href": "http://www.windriver.com/developer/sysinv/dev/api-spec-v1.html",
               "type": "text/html",
               "rel": "describedby"
           }
       ],
       "remotelogging": [
           {
               "href": "http://10.10.10.2:6385/v1/remotelogging/",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/remotelogging/",
               "rel": "bookmark"
           }
       ],
       "ceph_mon": [
           {
               "href": "http://10.10.10.2:6385/v1/ceph_mon/",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/ceph_mon/",
               "rel": "bookmark"
           }
       ],
       "lldp_neighbours": [
           {
               "href": "http://10.10.10.2:6385/v1/lldp_neighbours/",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/lldp_neighbours/",
               "rel": "bookmark"
           }
       ],
       "itrapdest": [
           {
               "href": "http://10.10.10.2:6385/v1/itrapdest/",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/itrapdest/",
               "rel": "bookmark"
           }
       ],
       "iextoam": [
           {
               "href": "http://10.10.10.2:6385/v1/iextoam/",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/iextoam/",
               "rel": "bookmark"
           }
       ],
       "intp": [
           {
               "href": "http://10.10.10.2:6385/v1/intp/",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/intp/",
               "rel": "bookmark"
           }
       ],
       "storage_file": [
           {
               "href": "http://10.10.10.2:6385/v1/storage_file/",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/storage_file/",
               "rel": "bookmark"
           }
       ],
       "storage_lvm": [
           {
               "href": "http://10.10.10.2:6385/v1/storage_lvm/",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/storage_lvm/",
               "rel": "bookmark"
           }
       ],
       "interface_networks": [
           {
               "href": "http://10.10.10.2:6385/v1/interface_networks/",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/interface_networks/",
               "rel": "bookmark"
           }
       ],
       "inode": [
           {
               "href": "http://10.10.10.2:6385/v1/inode/",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/inode/",
               "rel": "bookmark"
           }
       ],
       "id": "v1",
       "ptp": [
           {
               "href": "http://10.10.10.2:6385/v1/ptp/",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/ptp/",
               "rel": "bookmark"
           }
       ],
       "media_types": [
           {
               "base": "application/json",
               "type": "application/vnd.openstack.sysinv.v1+json"
           }
       ],
       "servicegroup": [
           {
               "href": "http://10.10.10.2:6385/v1/servicegroup/",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/servicegroup/",
               "rel": "bookmark"
           }
       ],
       "upgrade": [
           {
               "href": "http://10.10.10.2:6385/v1/upgrade/",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/upgrade/",
               "rel": "bookmark"
           }
       ],
       "imemory": [
           {
               "href": "http://10.10.10.2:6385/v1/imemory/",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/imemory/",
               "rel": "bookmark"
           }
       ],
       "networks": [
           {
               "href": "http://10.10.10.2:6385/v1/networks/",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/networks/",
               "rel": "bookmark"
           }
       ],
       "storage_ceph_external": [
           {
               "href": "http://10.10.10.2:6385/v1/storage_ceph_external/",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/storage_ceph_external/",
               "rel": "bookmark"
           }
       ],
       "health": [
           {
               "href": "http://10.10.10.2:6385/v1/health/",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/health/",
               "rel": "bookmark"
           }
       ],
       "clusters": [
           {
               "href": "http://10.10.10.2:6385/v1/clusters/",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/clusters/",
               "rel": "bookmark"
           }
       ],
       "drbdconfig": [
           {
               "href": "http://10.10.10.2:6385/v1/drbdconfig/",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/drbdconfig/",
               "rel": "bookmark"
           }
       ],
       "icommunity": [
           {
               "href": "http://10.10.10.2:6385/v1/icommunity/",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/icommunity/",
               "rel": "bookmark"
           }
       ],
       "helm_charts": [
           {
               "href": "http://10.10.10.2:6385/v1/helm_charts/",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/helm_charts/",
               "rel": "bookmark"
           }
       ],
       "ihosts": [
           {
               "href": "http://10.10.10.2:6385/v1/ihosts/",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/ihosts/",
               "rel": "bookmark"
           }
       ],
       "iprofile": [
           {
               "href": "http://10.10.10.2:6385/v1/iprofile/",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/iprofile/",
               "rel": "bookmark"
           }
       ],
       "servicenodes": [
           {
               "href": "http://10.10.10.2:6385/v1/servicenodes/",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/servicenodes/",
               "rel": "bookmark"
           }
       ],
       "iinfra": [
           {
               "href": "http://10.10.10.2:6385/v1/iinfra/",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/iinfra/",
               "rel": "bookmark"
           }
       ],
       "storage_backend": [
           {
               "href": "http://10.10.10.2:6385/v1/storage_backend/",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/storage_backend/",
               "rel": "bookmark"
           }
       ],
       "controller_fs": [
           {
               "href": "http://10.10.10.2:6385/v1/controller_fs/",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/controller_fs/",
               "rel": "bookmark"
           }
       ],
       "services": [
           {
               "href": "http://10.10.10.2:6385/v1/services/",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/services/",
               "rel": "bookmark"
           }
       ],
       "icpu": [
           {
               "href": "http://10.10.10.2:6385/v1/icpu/",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/icpu/",
               "rel": "bookmark"
           }
       ],
       "sdn_controller": [
           {
               "href": "http://10.10.10.2:6385/v1/sdn_controller/",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/sdn_controller/",
               "rel": "bookmark"
           }
       ],
       "addrpools": [
           {
               "href": "http://10.10.10.2:6385/v1/addrpools/",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/addrpools/",
               "rel": "bookmark"
           }
       ],
       "license": [
           {
               "href": "http://10.10.10.2:6385/v1/license/",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/license/",
               "rel": "bookmark"
           }
       ],
       "service_parameter": [
           {
               "href": "http://10.10.10.2:6385/v1/service_parameter/",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/service_parameter/",
               "rel": "bookmark"
           }
       ],
       "storage_ceph": [
           {
               "href": "http://10.10.10.2:6385/v1/storage_ceph/",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/storage_ceph/",
               "rel": "bookmark"
           }
       ],
       "idns": [
           {
               "href": "http://10.10.10.2:6385/v1/idns/",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/idns/",
               "rel": "bookmark"
           }
       ],
       "isystems": [
           {
               "href": "http://10.10.10.2:6385/v1/isystems/",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/isystems/",
               "rel": "bookmark"
           }
       ],
       "lldp_agents": [
           {
               "href": "http://10.10.10.2:6385/v1/lldp_agents/",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/lldp_agents/",
               "rel": "bookmark"
           }
       ],
       "storage_external": [
           {
               "href": "http://10.10.10.2:6385/v1/storage_external/",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/storage_external/",
               "rel": "bookmark"
           }
       ],
       "iuser": [
           {
               "href": "http://10.10.10.2:6385/v1/iuser/",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/iuser/",
               "rel": "bookmark"
           }
       ]
   }

This operation does not accept a request body.

-------
System
-------

The cloud server cluster is represented internally by a unique object
referred to as the system.

***************************************
Shows attributes of the System object
***************************************

.. rest_method:: GET /v1/isystems

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "name (Optional)", "plain", "xsd:string", "A user-specified name of the cloud system. The default value is the system UUID."
   "system_type (Optional)", "plain", "xsd:string", "A installed system type of the cloud system."
   "system_mode (Optional)", "plain", "xsd:string", "The system mode of the cloud system."
   "timezone (Optional)", "plain", "xsd:string", "The timezone of the cloud system."
   "description (Optional)", "plain", "xsd:string", "A user-specified description of the cloud system."
   "location (Optional)", "plain", "xsd:string", "The user-specified location of the cloud system."
   "capabilities (Optional)", "plain", "xsd:dictionary", "System capabilities. <ul><li>sdn_enabled : (Boolean) Software Defined Networking enabled. </li><li>region_config : (Boolean) region selection: <ul><li>true : Secondary region. </li><li>false : Primary region. </li></ul></li><li>shared_services : Services provided by Primary region. </li><li>bm_region : Board Management controller network selection: <ul><li>External : OAM network. </li><li>Internal : Management network. </li></ul></li><li>cinder_backend : backend selection for Cinder. </li><li>vswitch_type : vSwitch selection. </li><li>security_feature : Selection of Spectre and Meltdown mitigation options. </li><li>https_enabled : (Boolean) selection of https mode for public URLs. </li></ul>"
   "contact (Optional)", "plain", "xsd:string", "The user-specified contact for the cloud system."
   "software_version (Optional)", "plain", "xsd:string", "Contains the Cloud Server Software Version and the Software Version of the underlying Linux Kernel."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
     "isystems": [
       {
         "uuid": "67e5fca6-3580-4b06-acc8-3200dce794a4",
         "software_version": "Golden Gate 14.08 3.4.103-ovp-ga2-rt120-WR5.0.1.17_standard ",
         "name": "OTTAWA_LAB",
         "links": [
           {
             "href": "http://192.168.204.2:6385/v1/isystems/67e5fca6-3580-4b06-acc8-3200dce794a4",
             "rel": "self"
           },
           {
             "href": "http://192.168.204.2:6385/isystems/67e5fca6-3580-4b06-acc8-3200dce794a4",
             "rel": "bookmark"
           }
         ],
         "created_at": "2014-09-17T19:08:11.325946+00:00",
         "updated_at": "2014-09-24T14:35:38.091392+00:00",
         "contact": null,
         "location": null,
         "description": "The Ottawa Cloud Test Lab.",
         "system_type": "Standard",
         "system_mode": "duplex",
         "timezone": "UTC",
         "capabilities": {
           "sdn_enabled": false,
           "shared_services": "[]",
           "bm_region": "External",
           "cinder_backend": "lvm",
           "https_enabled": false,
           "region_config": false
         },
       }
     ]
   }

This operation does not accept a request body.

******************************************
Modifies attributes of the System object
******************************************

.. rest_method:: PATCH /v1/isystems

The attributes of the System object that are modifiable are:

-  name,

-  system_mode,

-  timezone,

-  description,

-  location,

-  sdn_enabled,

-  contact.

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "ihosts (Optional)", "plain", "xsd:list", "Links for retreiving the list of hosts for this system."
   "name (Optional)", "plain", "xsd:string", "A user-specified name of the cloud system. The default value is the system UUID."
   "system_type (Optional)", "plain", "xsd:string", "A installed system type of the cloud system."
   "system_mode (Optional)", "plain", "xsd:string", "The system mode of the cloud system."
   "timezone (Optional)", "plain", "xsd:string", "The timezone of the cloud system."
   "description (Optional)", "plain", "xsd:string", "A user-specified description of the cloud system."
   "location (Optional)", "plain", "xsd:string", "The user-specified location of the cloud system."
   "capabilities (Optional)", "plain", "xsd:dictionary", "System capabilities. <ul><li>sdn_enabled : (Boolean) Software Defined Networking enabled. </li><li>region_config : (Boolean) region selection: <ul><li>true : Secondary region. </li><li>false : Primary region. </li></ul></li><li>shared_services : Services provided by Primary region. </li><li>bm_region : Board Management controller network selection: <ul><li>External : OAM network. </li><li>Internal : Management network. </li></ul></li><li>cinder_backend : backend selection for Cinder. </li><li>vswitch_type : vSwitch selection. </li><li>security_feature : Selection of Spectre and Meltdown mitigation options. </li><li>https_enabled : (Boolean) selection of https mode for public URLs. </li></ul>"
   "contact (Optional)", "plain", "xsd:string", "The user-specified contact for the cloud system."
   "software_version (Optional)", "plain", "xsd:string", "Contains the Cloud Server Software Version and the Software Version of the underlying Linux Kernel."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   [
     {
       "path": "/name",
       "value": "OTTAWA_LAB_WEST",
       "op": "replace"
     }
     {
       "path": "/description",
       "value": "The Ottawa Cloud Test Lab - West Wing.",
       "op": "replace"
     }
     {
       "path": "/location",
       "value": "350 Terry Fox Dr, Kanata, Ontario, Canada",
       "op": "replace"
     }
     {
       "path": "/contact",
       "value": "support@windriver.com",
       "op": "replace"
     }
     {
       "path": "/system_mode",
       "value": "duplex-direct",
       "op": "replace"
     }
     {
       "path": "/timezone",
       "value": "UTC",
       "op": "replace"
     }
     {
       "path": "/sdn_enabled",
       "value": "true",
       "op": "replace"
     }
   ]

::

   {
     "isystems": [
       {
         "links": [
           {
             "href": "http://192.168.204.2:6385/v1/isystems/5ce48a37-f6f5-4f14-8fbd-ac6393464b19",
             "rel": "self"
           },
           {
             "href": "http://192.168.204.2:6385/isystems/5ce48a37-f6f5-4f14-8fbd-ac6393464b19",
             "rel": "bookmark"
           }
         ],
         "description": "The Ottawa Cloud Test Lab - West Wing.",
         "software_version": "18.03",
         "updated_at": "2017-07-31T17:44:06.051441+00:00",
         "created_at": "2017-07-31T17:35:46.836024+00:00",
         "location": "350 Terry Fox Dr, Kanata, Ontario, Canada",
         "capabilities": {
           "sdn_enabled": true,
           "shared_services": "[]",
           "bm_region": "External",
           "cinder_backend": "lvm",
           "https_enabled": true,
           "region_config": false
         },
         "name": "OTTAWA_LAB_WEST",
         "contact": "support@windriver.com",
         "system_type": "Standard",
         "system_mode": "duplex",
         "timezone": "UTC",
         "uuid": "5ce48a37-f6f5-4f14-8fbd-ac6393464b19"
       }
     ]
   }

---------
Clusters
---------

A cluster within the cloud server is represented internally by a unique
object referred to as the cluster.

****************************
Lists all cluster entities
****************************

.. rest_method:: GET /v1/clusters

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "clusters (Optional)", "plain", "xsd:list", "The list of cluster entities."
   "name (Optional)", "plain", "xsd:string", "A name of the cloud cluster."
   "type (Optional)", "plain", "xsd:string", "An installed cluster type of the cloud system."
   "uuid (Optional)", "plain", "csapi:UUID", "A system generated unique identifier for this cluster in the cloud system."
   "cluster_uuid (Optional)", "plain", "csapi:UUID", "The unique identifier of the underlying cluster instance represented by this cluster."

::

   {
       "clusters": [
           {
               "cluster_uuid": null,
               "type": "ceph",
               "uuid": "ba42aa45-7094-4bcd-b094-2848816441a3",
               "links": [
                   {
                       "href": "http://10.10.10.2:6385/v1/clusters/ba42aa45-7094-4bcd-b094-2848816441a3",
                       "rel": "self"
                   },
                   {
                       "href": "http://10.10.10.2:6385/clusters/ba42aa45-7094-4bcd-b094-2848816441a3",
                       "rel": "bookmark"
                   }
               ],
               "name": "ceph_cluster"
           }
       ]
   }

This operation does not accept a request body.

*****************************************************
Shows detailed information about a specific cluster
*****************************************************

.. rest_method:: GET /v1/clusters/​{uuid}​

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "uuid", "URI", "csapi:UUID", "The system generated unique identifier of a cluster."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "name (Optional)", "plain", "xsd:string", "A name of the cloud cluster."
   "type (Optional)", "plain", "xsd:string", "An installed cluster type of the cloud system."
   "uuid (Optional)", "plain", "csapi:UUID", "A system generated unique identifier for this cluster in the cloud system."
   "cluster_uuid (Optional)", "plain", "csapi:UUID", "The unique identifier of the underlying cluster instance represented by this cluster."
   "peers (Optional)", "plain", "xsd:list", "A list of dictionaries for each replication group of storage host peers."
   "tiers (Optional)", "plain", "xsd:list", "A list of dictionaries for each storage tier in the cluster"

::

   {
       "peers": [
           {
               "status": "provisioned",
               "hosts": [
                   "storage-0"
               ],
               "name": "group-0",
               "uuid": "779145f1-f0ba-42a9-b371-c2ddbd2c3617"
           }
       ],
       "name": "ceph_cluster",
       "links": [
           {
               "href": "http://10.10.10.2:6385/v1/clusters/ba42aa45-7094-4bcd-b094-2848816441a3",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/clusters/ba42aa45-7094-4bcd-b094-2848816441a3",
               "rel": "bookmark"
           }
       ],
       "storage_tiers": [
           {
               "href": "http://10.10.10.2:6385/v1/clusters/ba42aa45-7094-4bcd-b094-2848816441a3/storage_tiers",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/clusters/ba42aa45-7094-4bcd-b094-2848816441a3/storage_tiers",
               "rel": "bookmark"
           }
       ],
       "created_at": "2018-02-07T04:34:26.738705+00:00",
       "tiers": [
           {
               "status": "in-use",
               "name": "storage",
               "uuid": "70184946-7b3e-4833-a4f8-e46edf006e37"
           }
       ],
       "updated_at": null,
       "cluster_uuid": null,
       "type": "ceph",
       "id": 1,
       "uuid": "ba42aa45-7094-4bcd-b094-2848816441a3"
   }

This operation does not accept a request body.

-----------
Partitions
-----------

*************************************
Lists all disk partitions of a host
*************************************

.. rest_method:: GET /v1/ihosts/​{host_id}​/partitions

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "host_id", "URI", "csapi:UUID", "The unique identifier of an existing host."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "partitions (Optional)", "plain", "xsd:list", "The list of disk partition entities."
   "capabilities (Optional)", "plain", "xsd:string", "Additional capabilities info about the partition."
   "device_node (Optional)", "plain", "xsd:string", "The device node of the partition."
   "device_path (Optional)", "plain", "xsd:string", "The device path of the partition."
   "ihost_uuid (Optional)", "plain", "csapi:UUID", "The host UUID that the partition belongs to."
   "idisk_uuid (Optional)", "plain", "csapi:UUID", "The disk UUID that this partition belongs to."
   "ipv_uuid (Optional)", "plain", "csapi:UUID", "The LVM physical volume that this partition belongs to."
   "status (Optional)", "plain", "xsd:integer", "The status of the partition."
   "type_guid (Optional)", "plain", "csapi:UUID", "The GUID for the partition type."
   "type_name (Optional)", "plain", "xsd:string", "The name for the partition type."
   "size_mib (Optional)", "plain", "xsd:integer", "The size of the partition in MiBytes."
   "start_mib (Optional)", "plain", "xsd:integer", "The start of the partition MiBytes."
   "end_mib (Optional)", "plain", "xsd:integer", "The end of the partition in MiBytes."

::

   {
       "partitions": [
           {
               "capabilities": {},
               "created_at": "2017-08-30T21:10:53.160862+00:00",
               "device_node": "/dev/sdb2",
               "device_path": "/dev/disk/by-path/pci-0000:00:0d.0-ata-2.0-part2",
               "end_mib": 19968,
               "idisk_uuid": "9483349f-7612-4176-8ab7-957d840abf08",
               "ihost_uuid": "33178c5b-8b2b-45b4-b438-236a6eb4d0fd",
               "ipv_uuid": null,
               "links": [
                   {
                       "href": "http://192.168.204.2:6385/v1/partitions/209da106-ca41-4910-bb6a-8b498d5ac953",
                       "rel": "self"
                   },
                   {
                       "href": "http://192.168.204.2:6385/partitions/209da106-ca41-4910-bb6a-8b498d5ac953",
                       "rel": "bookmark"
                   }
               ],
               "size_mib": 512,
               "start_mib": 512,
               "status": 0,
               "type_guid": "ba5eba11-0000-1111-2222-000000000001",
               "type_name": "LVM Physical Volume",
               "updated_at": "2017-08-30T21:11:24.107207+00:00",
               "uuid": "209da106-ca41-4910-bb6a-8b498d5ac953"
           },
           {
               "capabilities": {},
               "created_at": "2017-08-30T22:10:39.796884+00:00",
               "device_node": "/dev/sdb3",
               "device_path": "/dev/disk/by-path/pci-0000:00:0d.0-ata-2.0-part3",
               "end_mib": 20225,
               "idisk_uuid": "9483349f-7612-4176-8ab7-957d840abf08",
               "ihost_uuid": "33178c5b-8b2b-45b4-b438-236a6eb4d0fd",
               "ipv_uuid": null,
               "links": [
                   {
                       "href": "http://192.168.204.2:6385/v1/partitions/eed80f15-0a31-43c3-a46c-a62cf4cecb7d",
                       "rel": "self"
                   },
                   {
                       "href": "http://192.168.204.2:6385/partitions/eed80f15-0a31-43c3-a46c-a62cf4cecb7d",
                       "rel": "bookmark"
                   }
               ],
               "size_mib": 258,
               "start_mib": 258,
               "status": 0,
               "type_guid": "ba5eba11-0000-1111-2222-000000000001",
               "type_name": "LVM Physical Volume",
               "updated_at": "2017-08-30T22:26:25.464595+00:00",
               "uuid": "eed80f15-0a31-43c3-a46c-a62cf4cecb7d"
           }
       ]
   }

This operation does not accept a request body.

************************************************************
Shows detailed information about a specific disk partition
************************************************************

.. rest_method:: GET /v1/partitions/​{partition_id}​

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "partition_id", "URI", "csapi:UUID", "The unique identifier of a physical partition."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "capabilities (Optional)", "plain", "xsd:string", "Additional capabilities info about the partition."
   "device_node (Optional)", "plain", "xsd:string", "The device node of the partition."
   "device_path (Optional)", "plain", "xsd:string", "The device path of the partition."
   "ihost_uuid (Optional)", "plain", "csapi:UUID", "The host UUID that the partition belongs to."
   "idisk_uuid (Optional)", "plain", "csapi:UUID", "The disk UUID that this partition belongs to."
   "ipv_uuid (Optional)", "plain", "csapi:UUID", "The LVM physical volume that this partition belongs to."
   "status (Optional)", "plain", "xsd:integer", "The status of the partition."
   "type_guid (Optional)", "plain", "csapi:UUID", "The GUID for the partition type."
   "type_name (Optional)", "plain", "xsd:string", "The name for the partition type."
   "size_mib (Optional)", "plain", "xsd:integer", "The size of the partition in MiBytes."
   "start_mib (Optional)", "plain", "xsd:integer", "The start of the partition MiBytes."
   "end_mib (Optional)", "plain", "xsd:integer", "The end of the partition in MiBytes."

::

   {
       "capabilities": {},
       "created_at": "2017-08-30T21:10:53.160862+00:00",
       "device_node": "/dev/sdb2",
       "device_path": "/dev/disk/by-path/pci-0000:00:0d.0-ata-2.0-part2",
       "end_mib": 19968,
       "idisk_uuid": "9483349f-7612-4176-8ab7-957d840abf08",
       "ihost_uuid": "33178c5b-8b2b-45b4-b438-236a6eb4d0fd",
       "ipv_uuid": null,
       "links": [
           {
               "href": "http://10.10.2.2:6385/v1/partitions/209da106-ca41-4910-bb6a-8b498d5ac953",
               "rel": "self"
           },
           {
               "href": "http://10.10.2.2:6385/partitions/209da106-ca41-4910-bb6a-8b498d5ac953",
               "rel": "bookmark"
           }
       ],
       "size_mib": 512,
       "start_mib": 512,
       "status": 0,
       "type_guid": "ba5eba11-0000-1111-2222-000000000001",
       "type_name": "LVM Physical Volume",
       "updated_at": "2017-08-30T21:11:24.107207+00:00",
       "uuid": "209da106-ca41-4910-bb6a-8b498d5ac953"
   }

This operation does not accept a request body.

**************************************************
Creates a partition on a specific disk of a host
**************************************************

.. rest_method:: POST /v1/ihosts/​{host_id}​/partitions

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "host_id", "URI", "csapi:UUID", "The unique identifier of an existing host."
   "ihost_uuid (Optional)", "plain", "csapi:UUID", "This parameter specifies the partition host uuid."
   "type_guid (Optional)", "plain", "csapi:UUID", "This parameter specifies the partition type guid."
   "idisk_uuid (Optional)", "plain", "csapi:UUID", "This parameter specifies the partition disk uuid."
   "size_mib (Optional)", "plain", "xsd:integer", "This parameter specifies the size of the partition."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "capabilities (Optional)", "plain", "xsd:string", "Additional capabilities info about the partition."
   "device_node (Optional)", "plain", "xsd:string", "The device node of the partition."
   "device_path (Optional)", "plain", "xsd:string", "The device path of the partition."
   "ihost_uuid (Optional)", "plain", "csapi:UUID", "The host UUID that the partition belongs to."
   "idisk_uuid (Optional)", "plain", "csapi:UUID", "The disk UUID that this partition belongs to."
   "ipv_uuid (Optional)", "plain", "csapi:UUID", "The LVM physical volume that this partition belongs to."
   "status (Optional)", "plain", "xsd:integer", "The status of the partition."
   "type_guid (Optional)", "plain", "csapi:UUID", "The GUID for the partition type."
   "type_name (Optional)", "plain", "xsd:string", "The name for the partition type."
   "size_mib (Optional)", "plain", "xsd:integer", "The size of the partition in MiBytes."
   "start_mib (Optional)", "plain", "xsd:integer", "The start of the partition MiBytes."
   "end_mib (Optional)", "plain", "xsd:integer", "The end of the partition in MiBytes."

::

   {
       "ihost_uuid": "33178c5b-8b2b-45b4-b438-236a6eb4d0fd",
       "size_mib": 256,
       "type_guid": "ba5eba11-0000-1111-2222-000000000001",
       "idisk_uuid": "9483349f-7612-4176-8ab7-957d840abf08"},
   }

::

   {
       "status": 2,
       "device_path": "/dev/disk/by-path/pci-0000:00:0d.0-ata-2.0-part3",
       "start_mib": null,
       "uuid": "eed80f15-0a31-43c3-a46c-a62cf4cecb7d",
       "links": [
           {
               "href": "http://192.168.204.2:6385/v1/partitions/eed80f15-0a31-43c3-a46c-a62cf4cecb7d",
               "rel": "self"
           },
           {
               "href": "http://192.168.204.2:6385/partitions/eed80f15-0a31-43c3-a46c-a62cf4cecb7d",
               "rel": "bookmark"
           }
       ],
       "capabilities": {},
       "created_at": "2017-08-30T22:10:39.796884+00:00",
       "type_name": null,
       "updated_at": null,
       "device_node": "/dev/sdb3",
       "ihost_uuid": "33178c5b-8b2b-45b4-b438-236a6eb4d0fd",
       "ipv_uuid": null,
       "end_mib": null,
       "idisk_uuid": "9483349f-7612-4176-8ab7-957d840abf08",
       "type_guid": "ba5eba11-0000-1111-2222-000000000001",
       "size_mib": 256
   }

************************************
Modifies a specific disk partition
************************************

.. rest_method:: PATCH /v1/partitions/​{partition_id}​

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "partition_id", "URI", "csapi:UUID", "The unique identifier of a physical partition."
   "size_mib (Optional)", "plain", "xsd:integer", "This parameter specifies a new size for the disk partition."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "capabilities (Optional)", "plain", "xsd:string", "Additional capabilities info about the partition."
   "device_node (Optional)", "plain", "xsd:string", "The device node of the partition."
   "device_path (Optional)", "plain", "xsd:string", "The device path of the partition."
   "ihost_uuid (Optional)", "plain", "csapi:UUID", "The host UUID that the partition belongs to."
   "idisk_uuid (Optional)", "plain", "csapi:UUID", "The disk UUID that this partition belongs to."
   "ipv_uuid (Optional)", "plain", "csapi:UUID", "The LVM physical volume that this partition belongs to."
   "status (Optional)", "plain", "xsd:integer", "The status of the partition."
   "type_guid (Optional)", "plain", "csapi:UUID", "The GUID for the partition type."
   "type_name (Optional)", "plain", "xsd:string", "The name for the partition type."
   "size_mib (Optional)", "plain", "xsd:integer", "The size of the partition in MiBytes."
   "start_mib (Optional)", "plain", "xsd:integer", "The start of the partition MiBytes."
   "end_mib (Optional)", "plain", "xsd:integer", "The end of the partition in MiBytes."

::

   {
       "size_mib": "512"
   }

::

   {
       "status": 2,
       "device_path": "/dev/disk/by-path/pci-0000:00:0d.0-ata-2.0-part3",
       "start_mib": null,
       "uuid": "eed80f15-0a31-43c3-a46c-a62cf4cecb7d",
       "links": [
           {
               "href": "http://192.168.204.2:6385/v1/partitions/eed80f15-0a31-43c3-a46c-a62cf4cecb7d",
               "rel": "self"
           },
           {
               "href": "http://192.168.204.2:6385/partitions/eed80f15-0a31-43c3-a46c-a62cf4cecb7d",
               "rel": "bookmark"
           }
       ],
       "capabilities": {},
       "created_at": "2017-08-30T22:10:39.796884+00:00",
       "type_name": null,
       "updated_at": null,
       "device_node": "/dev/sdb3",
       "ihost_uuid": "33178c5b-8b2b-45b4-b438-236a6eb4d0fd",
       "ipv_uuid": null,
       "end_mib": null,
       "idisk_uuid": "9483349f-7612-4176-8ab7-957d840abf08",
       "type_guid": "ba5eba11-0000-1111-2222-000000000001",
       "size_mib": 512
   }

***********************************
Deletes a specific disk partition
***********************************

.. rest_method:: DELETE /v1/partitions/​{partition_id}​

This is supported just for user created, LVM Physical Volume, partition.
In order to delete a partition, it must be the last partition on the
disk.

**Normal response codes**

204

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "partition_id", "URI", "csapi:UUID", "The unique identifier of a physical partition."

This operation does not accept a request body.

--------------
Volume Groups
--------------

These APIs allow the creation, deletion, and displaying of LVM volume
groups.

***************************************
Lists all LVM volume groups of a host
***************************************

.. rest_method:: GET /v1/ihosts/​{host_id}​/ilvgs

This will list all the LVM volume groups for a given host.

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "host_id", "URI", "csapi:UUID", "The unique identifier of an existing host."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "ilvgs (Optional)", "plain", "xsd:list", "The list of volume group entities."
   "capabilities (Optional)", "plain", "xsd:string", "Additional capabilities info about the volume group."
   "vg_state (Optional)", "plain", "xsd:string", "This is the state of the volume group which is one of the following: unprovisioned, adding, provisioned, or removing."
   "lvm_vg_name (Optional)", "plain", "xsd:string", "This is the LVM volume group name as retrieved from the vgdisplay command on the host."
   "lvm_vg_uuid (Optional)", "plain", "csapi:UUID", "This is the LVM generated volume group UUID as retrieved from the vgdisplay command on the host."
   "lvm_vg_access (Optional)", "plain", "xsd:string", "This is the LVM generated volume group access status as retrieved from the vgdisplay command on the host."
   "lvm_max_lv (Optional)", "plain", "xsd:integer", "This is the LVM generated max number of logical volumes allowed as retrieved from the vgdisplay command on the host."
   "lvm_cur_lv (Optional)", "plain", "xsd:integer", "This is the LVM generated current number of logical volumes as retrieved from the vgdisplay command on the host."
   "lvm_max_pv (Optional)", "plain", "xsd:integer", "This is the LVM generated max number of physical volumes allowed as retrieved from the vgdisplay command on the host."
   "lvm_cur_pv (Optional)", "plain", "xsd:integer", "This is the LVM generated current number of physical volumes as retrieved from the vgdisplay command on the host."
   "lvm_vg_size (Optional)", "plain", "xsd:integer", "This is the LVM generated volume group size in bytes as retrieved from the vgdisplay command on the host."
   "lvm_vg_total_pe (Optional)", "plain", "xsd:integer", "This is the LVM generated total number of physical extents within the volume group as retrieved from the vgdisplay command on the host."
   "lvm_vg_free_pe (Optional)", "plain", "xsd:integer", "This is the LVM generated number of physical extents not allocated within the volume group as retrieved from the vgdisplay command on the host."
   "ihost_uuid (Optional)", "plain", "csapi:UUID", "The UUID of the host containing the port."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
       "ilvgs": [
           {
               "lvm_vg_access": "wz--n-",
               "lvm_vg_size": 7310671872,
               "lvm_max_lv": 0,
               "lvm_vg_free_pe": 1743,
               "uuid": "039de9ef-b1db-4c31-9072-add0f888b8b9",
               "links": [
                   {
                       "href": "http://10.10.10.2:6385/v1/ilvgs/039de9ef-b1db-4c31-9072-add0f888b8b9",
                       "rel": "self"
                   },
                   {
                       "href": "http://10.10.10.2:6385/ilvgs/039de9ef-b1db-4c31-9072-add0f888b8b9",
                       "rel": "bookmark"
                   }
               ],
               "lvm_cur_lv": 0,
               "created_at": "2015-03-11T02:46:55.730611+00:00",
               "lvm_max_pv": 0,
               "updated_at": "2015-03-11T02:50:57.361006+00:00",
               "capabilities": {},
               "vg_state": "provisioned",
               "ihost_uuid": "1ef159f8-0192-4879-a08e-f60328486e34",
               "lvm_cur_pv": 1,
               "lvm_vg_uuid": "u7NzxA-1LeR-G88h-3lMk-eFvo-YnL8-HT9SEP",
               "lvm_vg_total_pe": 1743,
               "lvm_vg_name": "nova-local"
           }
       ]
   }

This operation does not accept a request body.

**************************************************************
Shows detailed information about a specific LVM volume group
**************************************************************

.. rest_method:: GET /v1/ilvgs/​{volumegroup_id}​

This will show detailed information about a specific LVM volume group.

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "volumegroup_id", "URI", "csapi:UUID", "The unique identifier of an existing LVM volume group."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "capabilities (Optional)", "plain", "xsd:string", "Additional capabilities info about the volume group."
   "vg_state (Optional)", "plain", "xsd:string", "This is the state of the volume group which is one of the following: unprovisioned, adding, provisioned, or removing."
   "lvm_vg_name (Optional)", "plain", "xsd:string", "This is the LVM volume group name as retrieved from the vgdisplay command on the host."
   "lvm_vg_uuid (Optional)", "plain", "csapi:UUID", "This is the LVM generated volume group UUID as retrieved from the vgdisplay command on the host."
   "lvm_vg_access (Optional)", "plain", "xsd:string", "This is the LVM generated volume group access status as retrieved from the vgdisplay command on the host."
   "lvm_max_lv (Optional)", "plain", "xsd:integer", "This is the LVM generated max number of logical volumes allowed as retrieved from the vgdisplay command on the host."
   "lvm_cur_lv (Optional)", "plain", "xsd:integer", "This is the LVM generated current number of logical volumes as retrieved from the vgdisplay command on the host."
   "lvm_max_pv (Optional)", "plain", "xsd:integer", "This is the LVM generated max number of physical volumes allowed as retrieved from the vgdisplay command on the host."
   "lvm_cur_pv (Optional)", "plain", "xsd:integer", "This is the LVM generated current number of physical volumes as retrieved from the vgdisplay command on the host."
   "lvm_vg_size (Optional)", "plain", "xsd:integer", "This is the LVM generated volume group size in bytes as retrieved from the vgdisplay command on the host."
   "lvm_vg_total_pe (Optional)", "plain", "xsd:integer", "This is the LVM generated total number of physical extents within the volume group as retrieved from the vgdisplay command on the host."
   "lvm_vg_free_pe (Optional)", "plain", "xsd:integer", "This is the LVM generated number of physical extents not allocated within the volume group as retrieved from the vgdisplay command on the host."
   "ihost_uuid (Optional)", "plain", "csapi:UUID", "The UUID of the host containing the port."
   "ipvs (Optional)", "plain", "xsd:list", "Links to associated physical volumes."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
       "lvm_vg_access": "wz--n-",
       "lvm_vg_size": 7310671872,
       "lvm_max_lv": 0,
       "lvm_vg_free_pe": 1743,
       "uuid": "039de9ef-b1db-4c31-9072-add0f888b8b9",
       "links": [
           {
               "href": "http://10.10.10.2:6385/v1/ilvgs/039de9ef-b1db-4c31-9072-add0f888b8b9",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/ilvgs/039de9ef-b1db-4c31-9072-add0f888b8b9",
               "rel": "bookmark"
           }
       ],
       "lvm_cur_lv": 0,
       "created_at": "2015-03-11T02:46:55.730611+00:00",
       "lvm_max_pv": 0,
       "updated_at": "2015-03-11T02:50:57.361006+00:00",
       "capabilities": {},
       "vg_state": "provisioned",
       "ihost_uuid": "1ef159f8-0192-4879-a08e-f60328486e34",
       "ipvs": [
           {
               "href": "http://10.10.10.2:6385/v1/ilvgs/039de9ef-b1db-4c31-9072-add0f888b8b9/ipvs",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/ilvgs/039de9ef-b1db-4c31-9072-add0f888b8b9/ipvs",
               "rel": "bookmark"
           }
       ],
       "lvm_cur_pv": 1,
       "lvm_vg_uuid": "u7NzxA-1LeR-G88h-3lMk-eFvo-YnL8-HT9SEP",
       "lvm_vg_total_pe": 1743,
       "lvm_vg_name": "nova-local"
   }

This operation does not accept a request body.

************************************************
Creates an LVM volume group on a specific host
************************************************

.. rest_method:: POST /v1/ilvgs

This will create an LVM volume group on the specified host. This
functionality is not available on storage hosts. In addition, the volume
group name is limited to "nova-local" or "cinder-volumes".

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "lvm_vg_name (Optional)", "plain", "xsd:string", "This parameter specifies the volume group name. Valid values are (is): ``nova-local``"
   "ihost_uuid (Optional)", "plain", "csapi:UUID", "This parameter specifies the compute host uuid."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "capabilities (Optional)", "plain", "xsd:string", "Additional capabilities info about the volume group."
   "vg_state (Optional)", "plain", "xsd:string", "This is the state of the volume group which is one of the following: unprovisioned, adding, provisioned, or removing."
   "lvm_vg_name (Optional)", "plain", "xsd:string", "This is the LVM volume group name as retrieved from the vgdisplay command on the host."
   "lvm_vg_uuid (Optional)", "plain", "csapi:UUID", "This is the LVM generated volume group UUID as retrieved from the vgdisplay command on the host."
   "lvm_vg_access (Optional)", "plain", "xsd:string", "This is the LVM generated volume group access status as retrieved from the vgdisplay command on the host."
   "lvm_max_lv (Optional)", "plain", "xsd:integer", "This is the LVM generated max number of logical volumes allowed as retrieved from the vgdisplay command on the host."
   "lvm_cur_lv (Optional)", "plain", "xsd:integer", "This is the LVM generated current number of logical volumes as retrieved from the vgdisplay command on the host."
   "lvm_max_pv (Optional)", "plain", "xsd:integer", "This is the LVM generated max number of physical volumes allowed as retrieved from the vgdisplay command on the host."
   "lvm_cur_pv (Optional)", "plain", "xsd:integer", "This is the LVM generated current number of physical volumes as retrieved from the vgdisplay command on the host."
   "lvm_vg_size (Optional)", "plain", "xsd:integer", "This is the LVM generated volume group size in bytes as retrieved from the vgdisplay command on the host."
   "lvm_vg_total_pe (Optional)", "plain", "xsd:integer", "This is the LVM generated total number of physical extents within the volume group as retrieved from the vgdisplay command on the host."
   "lvm_vg_free_pe (Optional)", "plain", "xsd:integer", "This is the LVM generated number of physical extents not allocated within the volume group as retrieved from the vgdisplay command on the host."
   "ihost_uuid (Optional)", "plain", "csapi:UUID", "The UUID of the host containing the port."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
       "lvm_vg_name":"nova-local",
       "ihost_uuid":"a0f0a6d5-75ad-4769-8e0e-3a7c7c0ce783"
   }

::

   {
       "lvm_vg_access": null,
       "lvm_vg_size": 0,
       "lvm_max_lv": 0,
       "lvm_vg_free_pe": 0,
       "uuid": "11ac6dfc-a5ea-4cc9-a0c9-50afb13f7b24",
       "links": [
           {
               "href": "http://10.10.10.2:6385/v1/ilvgs/11ac6dfc-a5ea-4cc9-a0c9-50afb13f7b24",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/ilvgs/11ac6dfc-a5ea-4cc9-a0c9-50afb13f7b24",
               "rel": "bookmark"
           }
       ],
       "lvm_cur_lv": 0,
       "created_at": "2015-03-11T04:52:32.007904+00:00",
       "lvm_max_pv": 0,
       "updated_at": null,
       "capabilities": {},
       "vg_state": "adding",
       "ihost_uuid": "a0f0a6d5-75ad-4769-8e0e-3a7c7c0ce783",
       "ipvs": [
           {
               "href": "http://10.10.10.2:6385/v1/ilvgs/11ac6dfc-a5ea-4cc9-a0c9-50afb13f7b24/ipvs",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/ilvgs/11ac6dfc-a5ea-4cc9-a0c9-50afb13f7b24/ipvs",
               "rel": "bookmark"
           }
       ],
       "lvm_cur_pv": 0,
       "lvm_vg_uuid": null,
       "lvm_vg_total_pe": 0,
       "lvm_vg_name": "nova-local"
   }

*********************************************
Modifies a specific volume group capability
*********************************************

.. rest_method:: PATCH /v1/ilvgs/​{volumegroup_id}​

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "volumegroup_id", "URI", "csapi:UUID", "The unique identifier of an existing LVM volume group."
   "capabilities (Optional)", "plain", "xsd:string", "A dictionary of key-value pairs prepresenting volume group parameters and values. Valid nova-local parameters are: ``instance_backing``, and ``concurrent_disk_operations``. Valid cinder-volumes parameters are: ``lvm_type``"

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "capabilities (Optional)", "plain", "xsd:string", "Additional capabilities info about the volume group."
   "vg_state (Optional)", "plain", "xsd:string", "This is the state of the volume group which is one of the following: unprovisioned, adding, provisioned, or removing."
   "lvm_vg_name (Optional)", "plain", "xsd:string", "This is the LVM volume group name as retrieved from the vgdisplay command on the host."
   "lvm_vg_uuid (Optional)", "plain", "csapi:UUID", "This is the LVM generated volume group UUID as retrieved from the vgdisplay command on the host."
   "lvm_vg_access (Optional)", "plain", "xsd:string", "This is the LVM generated volume group access status as retrieved from the vgdisplay command on the host."
   "lvm_max_lv (Optional)", "plain", "xsd:integer", "This is the LVM generated max number of logical volumes allowed as retrieved from the vgdisplay command on the host."
   "lvm_cur_lv (Optional)", "plain", "xsd:integer", "This is the LVM generated current number of logical volumes as retrieved from the vgdisplay command on the host."
   "lvm_max_pv (Optional)", "plain", "xsd:integer", "This is the LVM generated max number of physical volumes allowed as retrieved from the vgdisplay command on the host."
   "lvm_cur_pv (Optional)", "plain", "xsd:integer", "This is the LVM generated current number of physical volumes as retrieved from the vgdisplay command on the host."
   "lvm_vg_size (Optional)", "plain", "xsd:integer", "This is the LVM generated volume group size in bytes as retrieved from the vgdisplay command on the host."
   "lvm_vg_total_pe (Optional)", "plain", "xsd:integer", "This is the LVM generated total number of physical extents within the volume group as retrieved from the vgdisplay command on the host."
   "lvm_vg_free_pe (Optional)", "plain", "xsd:integer", "This is the LVM generated number of physical extents not allocated within the volume group as retrieved from the vgdisplay command on the host."
   "ihost_uuid (Optional)", "plain", "csapi:UUID", "The UUID of the host containing the port."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   [
      {
         "path": "/capabilities",
         "value": "{}",
         "op": "replace"
      }
   ]

::

   {
      "lvm_vg_access": null,
      "lvm_vg_size": 0,
      "lvm_max_lv": 0,
      "lvm_vg_free_pe": 0,
      "uuid": "79926a38-f60c-4ede-8201-da8b009a07ee",
      "links": [
         {
            "href": "http://192.168.204.2:6385/v1/ilvgs/79926a38-f60c-4ede-8201-da8b009a07ee",
            "rel": "self"
         },
         {
            "href": "http://192.168.204.2:6385/ilvgs/79926a38-f60c-4ede-8201-da8b009a07ee",
            "rel": "bookmark"
         }
      ],
      "lvm_cur_lv": 0,
      "created_at": "2015-09-29T07:36:24.251731+00:00",
      "lvm_max_pv": 0,
      "updated_at": null,
      "capabilities": {
      },
      "vg_state": "adding",
      "ihost_uuid": "6b55a4c8-4194-4e3b-8d32-ca658473314e",
      "ipvs": [
         {
            "href": "http://192.168.204.2:6385/v1/ilvgs/79926a38-f60c-4ede-8201-da8b009a07ee/ipvs",
            "rel": "self"
         },
         {
            "href": "http://192.168.204.2:6385/ilvgs/79926a38-f60c-4ede-8201-da8b009a07ee/ipvs",
            "rel": "bookmark"
         }
      ],
      "lvm_cur_pv": 0,
      "lvm_vg_uuid": null,
      "lvm_vg_total_pe": 0,
      "lvm_vg_name": "nova-local"
   }

*************************************
Deletes a specific LVM volume group
*************************************

.. rest_method:: DELETE /v1/ilvgs/​{volumegroup_id}​

In order to delete an LVM volume group, the host must be locked. All
physical volumes assigned to the volume group will also be deleted.

**Normal response codes**

204

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "volumegroup_id", "URI", "csapi:UUID", "The unique identifier of an existing LVM volume group."

This operation does not accept a request body.

-----------------
Physical Volumes
-----------------

These APIs allow the creation, deletion, and displaying of LVM physical
volumes.

******************************************
Lists all LVM physical volumes of a host
******************************************

.. rest_method:: GET /v1/ihosts/​{host_id}​/ipvs

This will list all the LVM physical volumes defined on the given host. A
physical volume can be a pre-defined disk partition or an entire extra
disk as supported by the Volume Group.

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "host_id", "URI", "csapi:UUID", "The unique identifier of an existing host."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "ivolumes (Optional)", "plain", "xsd:list", "The list of physical volume entities."
   "capabilities (Optional)", "plain", "xsd:string", "Additional capabilities info about the volume group."
   "pv_state (Optional)", "plain", "xsd:string", "This is the state of the physical volume. It has one of the following values: unprovisioned, adding, provisioned, or removing."
   "pv_type (Optional)", "plain", "xsd:string", "This is the type of physical volume that is allocated. This will have the value of disk or partition."
   "disk_or_part_uuid (Optional)", "plain", "csapi:UUID", "This is the UUID of the device that is associated with this physical volume."
   "disk_or_part_device_node (Optional)", "plain", "xsd:string", "This is the device node name associated with the physical volume."
   "disk_or_part_device_path (Optional)", "plain", "xsd:string", "This is the device path associated with the physical partition."
   "lvm_pv_name (Optional)", "plain", "xsd:string", "This is the physical volume name as retrieved from the pvdisplay command on the host."
   "lvm_vg_name (Optional)", "plain", "xsd:string", "This is the name of the volume group that this physical volume belongs as retrieved from the pvdisplay command on the host."
   "lvm_pv_uuid (Optional)", "plain", "csapi:UUID", "This is the LVM generated UUID for the physical volume as retrieved from the pvdisplay command on the host."
   "lvm_pv_size (Optional)", "plain", "xsd:integer", "This is the LVM generated size in bytes of the physical volume as retrieved from the pvdisplay command on the host."
   "lvm_pe_total (Optional)", "plain", "xsd:integer", "This is the LVM generated total number of physical extents associated with the physical volume as retrieved from the pvdisplay command on the host."
   "lvm_pe_alloced (Optional)", "plain", "xsd:integer", "This is the LVM generated number of allocated physical extents associated with the physical volume as retrieved from the pvdisplay command on the host."
   "ihost_uuid (Optional)", "plain", "csapi:UUID", "The UUID of the host containing the port."
   "ilvg_uuid (Optional)", "plain", "csapi:UUID", "The UUID of the volume group containing the physical volume."
   "forilvgid (Optional)", "plain", "xsd:integer", "The ID of the volume group containing the physical volume."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
       "ipvs": [
           {
               "capabilities": {},
               "created_at": "2018-01-03T13:06:36.888057+00:00",
               "disk_or_part_device_node": "/dev/sda4",
               "disk_or_part_device_path": "/dev/disk/by-path/pci-0000:00:0d.0-ata-1.0-part4",
               "disk_or_part_uuid": "38c24bde-0488-4b50-9576-cfb555179698",
               "forilvgid": 1,
               "ihost_uuid": "28d70ad2-d722-458c-b361-8cf956e096ed",
               "ilvg_uuid": "55786da6-0534-4f4c-b9d1-36a53b0ac510",
               "links": [
                   {
                       "href": "http://10.10.12.2:6385/v1/ipvs/a8f13d11-0d55-45ff-a964-98d6e75717ba",
                       "rel": "self"
                   },
                   {
                       "href": "http://10.10.12.2:6385/ipvs/a8f13d11-0d55-45ff-a964-98d6e75717ba",
                       "rel": "bookmark"
                   }
               ],
               "lvm_pe_alloced": 1658,
               "lvm_pe_total": 3199,
               "lvm_pv_name": "/dev/sda4",
               "lvm_pv_size": 107340627968,
               "lvm_pv_uuid": "M1k6bc-sP7j-kpe2-YWWV-ckZy-zLRh-F6hzff",
               "lvm_vg_name": "cgts-vg",
               "pv_state": "provisioned",
               "pv_type": "partition",
               "updated_at": "2018-01-04T09:24:56.071039+00:00",
               "uuid": "a8f13d11-0d55-45ff-a964-98d6e75717ba"
           }
       ]
   }

This operation does not accept a request body.

*****************************************************************
Shows detailed information about a specific LVM physical volume
*****************************************************************

.. rest_method:: GET /v1/ipvs/​{physicalvolume_id}​

This will show detailed information about a specific LVM physical
volume.

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "physicalvolume_id", "URI", "csapi:UUID", "The unique identifier of an existing LVM physical volume."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "capabilities (Optional)", "plain", "xsd:string", "Additional capabilities info about the volume group."
   "pv_state (Optional)", "plain", "xsd:string", "This is the state of the physical volume. It has one of the following values: unprovisioned, adding, provisioned, or removing."
   "pv_type (Optional)", "plain", "xsd:string", "This is the type of physical volume that is allocated. This will have the value of disk or partition."
   "disk_or_part_uuid (Optional)", "plain", "csapi:UUID", "This is the UUID of the device that is associated with this physical volume."
   "disk_or_part_device_node (Optional)", "plain", "xsd:string", "This is the device node name associated with the physical volume."
   "disk_or_part_device_path (Optional)", "plain", "xsd:string", "This is the device path associated with the physical partition."
   "lvm_pv_name (Optional)", "plain", "xsd:string", "This is the physical volume name as retrieved from the pvdisplay command on the host."
   "lvm_vg_name (Optional)", "plain", "xsd:string", "This is the name of the volume group that this physical volume belongs as retrieved from the pvdisplay command on the host."
   "lvm_pv_uuid (Optional)", "plain", "csapi:UUID", "This is the LVM generated UUID for the physical volume as retrieved from the pvdisplay command on the host."
   "lvm_pv_size (Optional)", "plain", "xsd:integer", "This is the LVM generated size in bytes of the physical volume as retrieved from the pvdisplay command on the host."
   "lvm_pe_total (Optional)", "plain", "xsd:integer", "This is the LVM generated total number of physical extents associated with the physical volume as retrieved from the pvdisplay command on the host."
   "lvm_pe_alloced (Optional)", "plain", "xsd:integer", "This is the LVM generated number of allocated physical extents associated with the physical volume as retrieved from the pvdisplay command on the host."
   "ihost_uuid (Optional)", "plain", "csapi:UUID", "The UUID of the host containing the port."
   "ilvg_uuid (Optional)", "plain", "csapi:UUID", "The UUID of the volume group containing the physical volume."
   "forilvgid (Optional)", "plain", "xsd:integer", "The ID of the volume group containing the physical volume."
   "idisks (Optional)", "plain", "xsd:list", "Links to associated disks."
   "partitions (Optional)", "plain", "xsd:list", "Links to associated partitions."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
       "capabilities": {},
       "created_at": "2018-01-03T13:32:50.025647+00:00",
       "disk_or_part_device_node": "/dev/sdb1",
       "disk_or_part_device_path": "/dev/disk/by-path/pci-0000:00:0d.0-ata-2.0-part1",
       "disk_or_part_uuid": "ab8852dd-6c2e-421e-b6b6-abebeee6b790",
       "forilvgid": 2,
       "idisks": [
           {
               "href": "http://10.10.12.2:6385/v1/ipvs/2182ecc6-aab0-40f8-8e0e-d1ad9a9ccbdd/idisks",
               "rel": "self"
           },
           {
               "href": "http://10.10.12.2:6385/ipvs/2182ecc6-aab0-40f8-8e0e-d1ad9a9ccbdd/idisks",
               "rel": "bookmark"
           }
       ],
       "ihost_uuid": "28d70ad2-d722-458c-b361-8cf956e096ed",
       "ilvg_uuid": "cf6094c9-380f-407e-91d2-4b3583702a96",
       "links": [
           {
               "href": "http://10.10.12.2:6385/v1/ipvs/2182ecc6-aab0-40f8-8e0e-d1ad9a9ccbdd",
               "rel": "self"
           },
           {
               "href": "http://10.10.12.2:6385/ipvs/2182ecc6-aab0-40f8-8e0e-d1ad9a9ccbdd",
               "rel": "bookmark"
           }
       ],
       "lvm_pe_alloced": 1236,
       "lvm_pe_total": 1249,
       "lvm_pv_name": "/dev/drbd4",
       "lvm_pv_size": 5238685696,
       "lvm_pv_uuid": "8i5nt3-gyS0-QTwy-aPIr-YRwL-i4vc-rBTLtK",
       "lvm_vg_name": "cinder-volumes",
       "partitions": [
           {
               "href": "http://10.10.12.2:6385/v1/ipvs/2182ecc6-aab0-40f8-8e0e-d1ad9a9ccbdd/partitions",
               "rel": "self"
           },
           {
               "href": "http://10.10.12.2:6385/ipvs/2182ecc6-aab0-40f8-8e0e-d1ad9a9ccbdd/partitions",
               "rel": "bookmark"
           }
       ],
       "pv_state": "provisioned",
       "pv_type": "partition",
       "updated_at": "2018-01-04T12:59:48.788114+00:00",
       "uuid": "2182ecc6-aab0-40f8-8e0e-d1ad9a9ccbdd"
   }

This operation does not accept a request body.

***************************************************
Creates an LVM physical volume on a specific host
***************************************************

.. rest_method:: POST /v1/ipvs

This will create an LVM physical volume on the specified host. This
functionality is disabled on storage nodes. A physical volume can be a
pre-defined disk partition or an entire extra disk as supported by the
Volume Group. In addition, the volume group name is limited to
"nova-local" or "cinder-volumes".

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "ilvg_uuid (Optional)", "plain", "csapi:UUID", "This parameter specifies the volume group uuid."
   "ihost_uuid (Optional)", "plain", "csapi:UUID", "This parameter specifies the compute host uuid."
   "idisk_uuid (Optional)", "plain", "csapi:UUID", "This parameter specifies the storage disk uuid."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "capabilities (Optional)", "plain", "xsd:string", "Additional capabilities info about the volume group."
   "pv_state (Optional)", "plain", "xsd:string", "This is the state of the physical volume. It has one of the following values: unprovisioned, adding, provisioned, or removing."
   "pv_type (Optional)", "plain", "xsd:string", "This is the type of physical volume that is allocated. This will have the value of disk or partition."
   "disk_or_part_uuid (Optional)", "plain", "csapi:UUID", "This is the UUID of the device that is associated with this physical volume."
   "disk_or_part_device_node (Optional)", "plain", "xsd:string", "This is the device node name associated with the physical volume."
   "disk_or_part_device_path (Optional)", "plain", "xsd:string", "This is the device path associated with the physical partition."
   "lvm_pv_name (Optional)", "plain", "xsd:string", "This is the physical volume name as retrieved from the pvdisplay command on the host."
   "lvm_vg_name (Optional)", "plain", "xsd:string", "This is the name of the volume group that this physical volume belongs as retrieved from the pvdisplay command on the host."
   "lvm_pv_uuid (Optional)", "plain", "csapi:UUID", "This is the LVM generated UUID for the physical volume as retrieved from the pvdisplay command on the host."
   "lvm_pv_size (Optional)", "plain", "xsd:integer", "This is the LVM generated size in bytes of the physical volume as retrieved from the pvdisplay command on the host."
   "lvm_pe_total (Optional)", "plain", "xsd:integer", "This is the LVM generated total number of physical extents associated with the physical volume as retrieved from the pvdisplay command on the host."
   "lvm_pe_alloced (Optional)", "plain", "xsd:integer", "This is the LVM generated number of allocated physical extents associated with the physical volume as retrieved from the pvdisplay command on the host."
   "ihost_uuid (Optional)", "plain", "csapi:UUID", "The UUID of the host containing the port."
   "ilvg_uuid (Optional)", "plain", "csapi:UUID", "The UUID of the volume group containing the physical volume."
   "forilvgid (Optional)", "plain", "xsd:integer", "The ID of the volume group containing the physical volume."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
       "ilvg_uuid":"11ac6dfc-a5ea-4cc9-a0c9-50afb13f7b24",
       "ihost_uuid":"a0f0a6d5-75ad-4769-8e0e-3a7c7c0ce783",
       "idisk_uuid":"0e2e3ca6-841e-4315-ba1c-ad624415da2f"
   }

::

   {
       "lvm_pe_alloced": 0,
       "lvm_pe_total": 0,
       "ilvg_uuid": "a0f0a6d5-75ad-4769-8e0e-3a7c7c0ce783",
       "uuid": "4f504017-b0e8-4563-bb74-fc4d521c59f6",
       "links": [
           {
               "href": "http://10.10.10.2:6385/v1/ipvs/4f504017-b0e8-4563-bb74-fc4d521c59f6",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/ipvs/4f504017-b0e8-4563-bb74-fc4d521c59f6",
               "rel": "bookmark"
           }
       ],
       "idisks": [
           {
               "href": "http://10.10.10.2:6385/v1/ipvs/4f504017-b0e8-4563-bb74-fc4d521c59f6/idisks",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/ipvs/4f504017-b0e8-4563-bb74-fc4d521c59f6/idisks",
               "rel": "bookmark"
           }
       ],
       "lvm_pv_name": "/dev/sda7",
       "created_at": "2015-03-11T05:03:31.649520+00:00",
       "forilvgid": 2,
       "idisk_uuid": "0e2e3ca6-841e-4315-ba1c-ad624415da2f",
       "updated_at": null,
       "pv_state": "adding",
       "ihost_uuid": "a0f0a6d5-75ad-4769-8e0e-3a7c7c0ce783",
       "pv_type": "partition",
       "capabilities": {},
       "idisk_device_node": "/dev/sda",
       "idisk_device_path": "/dev/disk/by-path/pci-0000:00:0d.0-ata-2.0",
       "lvm_vg_name": "nova-local",
       "lvm_pv_uuid": null,
       "lvm_pv_size": 0
   }

****************************************
Deletes a specific LVM physical volume
****************************************

.. rest_method:: DELETE /v1/ipvs/​{physicalvolume_id}​

In order to delete an LVM physical volume, the host must be locked.

**Normal response codes**

204

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "physicalvolume_id", "URI", "csapi:UUID", "The unique identifier of an existing LVM physical volume."

This operation does not accept a request body.

-----------------------
Ceph Storage Functions
-----------------------

********************************************
Lists all Ceph storage functions of a host
********************************************

.. rest_method:: GET /v1/ihosts/​{host_id}​/istors

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "host_id", "URI", "csapi:UUID", "The unique identifier of an existing host."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "stors (Optional)", "plain", "xsd:list", "The list of Ceph storage function entities."
   "capabilities (Optional)", "plain", "xsd:string", "Additional capabilities info about the storage function."
   "function (Optional)", "plain", "xsd:string", "The storage function e.g. ""osd"" (object storage daemon) or ""journal"" (backing stor for journals) for ceph."
   "ihost_uuid (Optional)", "plain", "csapi:UUID", "The host UUID that the storage belongs to."
   "isystem_uuid (Optional)", "plain", "csapi:UUID", "The System UUID which the storage belongs to."
   "osdid (Optional)", "plain", "xsd:integer", "The object storage daemon identifier of the storage function."
   "journal_location (Optional)", "plain", "csapi:UUID", "The journal stor on which the journal is kept."
   "journal_size_mib (Optional)", "plain", "xsd:integer", "The size of the journal."
   "journal_path (Optional)", "plain", "xsd:string", "The device path of the journal."
   "journal_node (Optional)", "plain", "xsd:string", "The device node of the journal."
   "state (Optional)", "plain", "xsd:string", "The state info of the storage function."
   "tier_name (Optional)", "plain", "xsd:string", "The name of the storage tier that is using this storage function."
   "tier_uuid (Optional)", "plain", "xsd:string", "The UUID of the storage tier that is using this storage function."

::

   { 
      "istors":[
         {
            "function":"osd",
            "uuid":"31c7a5a3-9154-462a-9ea3-ab5c5e0d06e0",
            "journal_location":"0929aa31-ee1a-406d-82b1-308be72b300a",
            "journal_size_mib":2500,
            "links":[
               {
                  "href":"http://192.168.204.2:6385/v1/istors/31c7a5a3-9154-462a-9ea3-ab5c5e0d06e0",
                  "rel":"self"
               },
               {
                  "href":"http://192.168.204.2:6385/istors/31c7a5a3-9154-462a-9ea3-ab5c5e0d06e0",
                  "rel":"bookmark"
               }
            ],
            "created_at":"2014-10-01T21:41:23.973344+00:00",
            "updated_at":"2014-10-01T21:41:24.129134+00:00",
            "capabilities":{

            },
            "ihost_uuid":"42d72247-e0e3-4a5a-8cb1-40bbee52c8db",
            "state":null,
            "osdid":2
         }
      ]
   }

This operation does not accept a request body.

*******************************************************************
Shows detailed information about a specific Ceph storage function
*******************************************************************

.. rest_method:: GET /v1/istors/​{stor_id}​

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "stor_id", "URI", "csapi:UUID", "The unique identifier of an existing Ceph storage function."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "capabilities (Optional)", "plain", "xsd:string", "Additional capabilities info about the storage function."
   "function (Optional)", "plain", "xsd:string", "The storage function e.g. ""osd"" (object storage daemon) or ""journal"" (backing stor for journals) for ceph."
   "ihost_uuid (Optional)", "plain", "csapi:UUID", "The host UUID that the storage belongs to."
   "isystem_uuid (Optional)", "plain", "csapi:UUID", "The System UUID which the storage belongs to."
   "osdid (Optional)", "plain", "xsd:integer", "The object storage daemon identifier of the storage function."
   "journal_location (Optional)", "plain", "csapi:UUID", "The journal stor on which the journal is kept."
   "journal_size_mib (Optional)", "plain", "xsd:integer", "The size of the journal."
   "journal_path (Optional)", "plain", "xsd:string", "The device path of the journal."
   "journal_node (Optional)", "plain", "xsd:string", "The device node of the journal."
   "state (Optional)", "plain", "xsd:string", "The state info of the storage function."
   "tier_name (Optional)", "plain", "xsd:string", "The name of the storage tier that is using this storage function."
   "tier_uuid (Optional)", "plain", "xsd:string", "The UUID of the storage tier that is using this storage function."

::

   {
      "istors":[
         {
            "function":"osd",
            "uuid":"31c7a5a3-9154-462a-9ea3-ab5c5e0d06e0",
            "journal_location":"0929aa31-ee1a-406d-82b1-308be72b300a",
            "journal_size":1024,
            "links":[
               {
                  "href":"http://192.168.204.2:6385/v1/istors/31c7a5a3-9154-462a-9ea3-ab5c5e0d06e0",
                  "rel":"self"
               },
               {
                  "href":"http://192.168.204.2:6385/istors/31c7a5a3-9154-462a-9ea3-ab5c5e0d06e0",
                  "rel":"bookmark"
               }
            ],
            "created_at":"2014-10-01T21:41:23.973344+00:00",
            "updated_at":"2014-10-01T21:41:24.129134+00:00",
            "capabilities":{

            },
            "ihost_uuid":"42d72247-e0e3-4a5a-8cb1-40bbee52c8db",
            "state":null,
            "osdid":2
         }
      ]
   }

This operation does not accept a request body.

****************************************************
Creates a Ceph storage function on a specific host
****************************************************

.. rest_method:: POST /v1/ihosts/​{host_id}​/istors

PREREQUISITES: A 'ceph' storage backend must be configured in the
system. If multiple storage tiers are defined then a tier_uuid must be
specified.

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "host_id", "URI", "csapi:UUID", "The unique identifier of an existing host."
   "function (Optional)", "plain", "xsd:string", "This parameter specifies the Ceph storage function. Valid values are (is): ``osd`` or ``journal``."
   "ihost_uuid (Optional)", "plain", "csapi:UUID", "This parameter specifies the storage host uuid."
   "idisk_uuid (Optional)", "plain", "csapi:UUID", "This parameter specifies the storage disk uuid."
   "journal_location (Optional)", "plain", "csapi:UUID", "This parameter specifies the uuid of the journal stor on which the stor's journal will reside. Needed only for ""osd"" functions."
   "journal_size_mib (Optional)", "plain", "xsd:integer", "This parameter specifies the size of the journal. Needed only for ""osd"" functions."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "capabilities (Optional)", "plain", "xsd:string", "Additional capabilities info about the storage function."
   "function (Optional)", "plain", "xsd:string", "The storage function e.g. ""osd"" (object storage daemon) or ""journal"" (backing stor for journals) for ceph."
   "ihost_uuid (Optional)", "plain", "csapi:UUID", "The host UUID that the storage belongs to."
   "isystem_uuid (Optional)", "plain", "csapi:UUID", "The System UUID which the storage belongs to."
   "osdid (Optional)", "plain", "xsd:integer", "The object storage daemon identifier of the storage function."
   "journal_location (Optional)", "plain", "csapi:UUID", "The journal stor on which the journal is kept."
   "journal_size_mib (Optional)", "plain", "xsd:integer", "The size of the journal."
   "journal_path (Optional)", "plain", "xsd:string", "The device path of the journal."
   "journal_node (Optional)", "plain", "xsd:string", "The device node of the journal."
   "state (Optional)", "plain", "xsd:string", "The state info of the storage function."
   "tier_name (Optional)", "plain", "xsd:string", "The name of the storage tier that is using this storage function."
   "tier_uuid (Optional)", "plain", "xsd:string", "The UUID of the storage tier that is using this storage function."

::

   {
      "function":"osd",
      "ihost_uuid":"42d72247-e0e3-4a5a-8cb1-40bbee52c8db",
      "idisk_uuid":"4da10410-2959-46df-b571-04e954c0e115",
      "journal_location":"0929aa31-ee1a-406d-82b1-308be72b300a",
      "journal_size":1024,
   }

::

   {
      "function":"osd",
      "uuid":"31c7a5a3-9154-462a-9ea3-ab5c5e0d06e0",
      "journal_location":"0929aa31-ee1a-406d-82b1-308be72b300a",
      "journal_size_mib":1024,
      "journal_path": "/dev/disk/by-path/pci-0000:00:0d.0-ata-2.0-part2",
      "journal_node": "/dev/sdb2",
      "tier_name": "storage",
      "tier_uuid": "dcb41fcc-307a-4d0b-b5dd-af8c6a48a3c5",
      "links":[
         {
            "href":"http://192.168.204.2:6385/v1/istors/31c7a5a3-9154-462a-9ea3-ab5c5e0d06e0",
            "rel":"self"
         },
         {
            "href":"http://192.168.204.2:6385/istors/31c7a5a3-9154-462a-9ea3-ab5c5e0d06e0",
            "rel":"bookmark"
         }
      ],
      "idisks":[
         {
            "href":"http://192.168.204.2:6385/v1/istors/31c7a5a3-9154-462a-9ea3-ab5c5e0d06e0/idisks",
            "rel":"self"
         },
         {
            "href":"http://192.168.204.2:6385/istors/31c7a5a3-9154-462a-9ea3-ab5c5e0d06e0/idisks",
            "rel":"bookmark"
         }
      ],
      "created_at":"2014-10-01T21:41:23+00:00",
      "updated_at":null,
      "idisk_uuid":"4da10410-2959-46df-b571-04e954c0e115",
      "ihost_uuid":"42d72247-e0e3-4a5a-8cb1-40bbee52c8db",
      "state":null,
      "capabilities":{

      },
      "osdid":2
   }

*******************************************
Modifies a specific Ceph storage function
*******************************************

.. rest_method:: PATCH /v1/istors/​{stor_id}​

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "stor_id", "URI", "csapi:UUID", "The unique identifier of an existing Ceph storage function."
   "journal_location (Optional)", "plain", "csapi:UUID", "This parameter specifies a new location for the stor's journal. Needed only for ""osd"" functions."
   "journal_size_mib (Optional)", "plain", "xsd:integer", "This parameter specifies a new size for the stor's journal. Needed only for ""osd"" functions."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "capabilities (Optional)", "plain", "xsd:string", "Additional capabilities info about the storage function."
   "function (Optional)", "plain", "xsd:string", "The storage function e.g. ""osd"" (object storage daemon) or ""journal"" (backing stor for journals) for ceph."
   "ihost_uuid (Optional)", "plain", "csapi:UUID", "The host UUID that the storage belongs to."
   "isystem_uuid (Optional)", "plain", "csapi:UUID", "The System UUID which the storage belongs to."
   "osdid (Optional)", "plain", "xsd:integer", "The object storage daemon identifier of the storage function."
   "journal_location (Optional)", "plain", "csapi:UUID", "The journal stor on which the journal is kept."
   "journal_size_mib (Optional)", "plain", "xsd:integer", "The size of the journal."
   "journal_path (Optional)", "plain", "xsd:string", "The device path of the journal."
   "journal_node (Optional)", "plain", "xsd:string", "The device node of the journal."
   "state (Optional)", "plain", "xsd:string", "The state info of the storage function."
   "tier_name (Optional)", "plain", "xsd:string", "The name of the storage tier that is using this storage function."
   "tier_uuid (Optional)", "plain", "xsd:string", "The UUID of the storage tier that is using this storage function."

::

   {
      "journal_location":"e0f12323-f9b9-4ca0-a79b-bc9e7a6d7084",
      "journal_size_mib":2500,
   }

::

   {
      "function":"osd",
      "uuid":"31c7a5a3-9154-462a-9ea3-ab5c5e0d06e0",
      "journal_location":"e0f12323-f9b9-4ca0-a79b-bc9e7a6d7084",
      "journal_size_mib":2500,
      "journal_path": "/dev/disk/by-path/pci-0000:00:0d.0-ata-3.0-part1",
      "journal_node": "/dev/sdc1",
      "tier_name": "storage",
      "tier_uuid": "dcb41fcc-307a-4d0b-b5dd-af8c6a48a3c5",
      "links":[
         {
            "href":"http://192.168.204.2:6385/v1/istors/31c7a5a3-9154-462a-9ea3-ab5c5e0d06e0",
            "rel":"self"
         },
         {
            "href":"http://192.168.204.2:6385/istors/31c7a5a3-9154-462a-9ea3-ab5c5e0d06e0",
            "rel":"bookmark"
         }
      ],
      "idisks":[
         {
            "href":"http://192.168.204.2:6385/v1/istors/31c7a5a3-9154-462a-9ea3-ab5c5e0d06e0/idisks",
            "rel":"self"
         },
         {
            "href":"http://192.168.204.2:6385/istors/31c7a5a3-9154-462a-9ea3-ab5c5e0d06e0/idisks",
            "rel":"bookmark"
         }
      ],
      "created_at":"2014-10-01T21:41:23+00:00",
      "updated_at":null,
      "idisk_uuid":"4da10410-2959-46df-b571-04e954c0e115",
      "ihost_uuid":"42d72247-e0e3-4a5a-8cb1-40bbee52c8db",
      "state":null,
      "capabilities":{

      },
      "osdid":2
   }

******************************************
Deletes a specific Ceph storage function
******************************************

.. rest_method:: DELETE /v1/istors/​{stor_id}​

This is supported just for journal type stors. The host must be locked.
In order to delete an osd stor, the host must be locked and deleted.

**Normal response codes**

204

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "stor_id", "URI", "csapi:UUID", "The unique identifier of an existing Ceph storage function."

This operation does not accept a request body.


----------
Interfaces
----------

These APIs allow the create, display, modify and delete of the L2
interfaces of a host.

*****************************************
List the L2 interfaces of a specific host
*****************************************

.. rest_method:: GET /v1/ihosts/{host_id}/iinterfaces


**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "host_id", "URI", "csapi:UUID", "The unique identifier of an existing host."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "iinterfaces (Optional)", "plain", "xsd:list", "The list of L2 interfaces for a specific host."
   "ifname (Optional)", "plain", "xsd:string", "The user-specified name of the interface."
   "ifclass (Optional)", "plain", "xsd:string", "The class of the interface: ``platform``, ``data``, ``pci-passthrough`` or ``pci-sriov``."
   "iftype (Optional)", "plain", "xsd:string", "Indicates the type of L2 interface; ``ethernet`` or ``ae`` (aggregated ethernet or link aggregation (LAG)) or ``vlan`` (virtual lan)."
   "aemode (Optional)", "plain", "xsd:string", "Only applicable if ``iftype : ae``, this attribute indicates the basic mode of operation for the AE/LAG interface. Supported modes are: balanced round robin, active-backup, balanced xor, broadcast, 802.3ad, balance-tlb, balance-alb. NOTE only balanced xor and active-standby modes are supported by interfaces of ifclass=data."
   "txhashpolicy (Optional)", "plain", "xsd:string", "Only applicable if ``iftype : ae`` and ``aemode : balanced``, this attribute indicates what packet headers the AE/LAG is using to distribute packets across the different links/ports of the AE/LAG group; ``layer2``, ``layer2+3`` or ``layer3+4``."
   "vlan_id (Optional)", "plain", "xsd:integer", "Only applicable if ``iftype : vlan``, this attribute indicates that the vlan interface id. A vlan id between 1 and 4094 (inclusive) must be selected. NOTE The vlan id must be unique for the host interface."
   "networks (Optional)", "plain", "xsd:list", "Only applicable if ``ifclass : platform``, this attribute provides a list of platform networks that this interface is attached to."
   "datanetworks (Optional)", "plain", "xsd:list", "Only applicable if ``ifclass : data``, this attribute provides a list of data networks that this ``data`` interface is attached to."
   "imac (Optional)", "plain", "xsd:string", "The MAC Address being used by the interface. In the case of AE/LAG, the MAC address of one of the physical ports of the AE/LAG group is used."
   "imtu (Optional)", "plain", "xsd:integer", "The Maximum Transmission Unit (MTU) of the interface, in bytes."
   "sriov_numvfs (Optional)", "plain", "xsd:integer", "The number of VFs configured on the interfaces port; only applicable if ``ifclass : pci-sriov`` where only a single port is associated with the interface."
   "schedpolicy (Optional)", "plain", "xsd:string", "Currently not supported."
   "forihostId (Optional)", "plain", "xsd:string", "The ID of the host of this interface."
   "ihost_uuid (Optional)", "plain", "csapi:UUID", "The UUID of the host of this interface."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."
   "uses (Optional)", "plain", "xsd:list", "Interfaces which the current interface uses."
   "used_by (Optional)", "plain", "xsd:list", "Interfaces which use the current interface."

::

   {
     "iinterfaces": [
       {
         "forihostid": 2,
         "iftype": "ethernet",
         "uuid": "1425e76f-eb40-41bd-825f-f692a3064043",
         "links": [
           {
             "href": "http://192.168.204.2:6385/v1/iinterfaces/1425e76f-eb40-41bd-825f-f692a3064043",
             "rel": "self"
           },
           {
             "href": "http://192.168.204.2:6385/iinterfaces/1425e76f-eb40-41bd-825f-f692a3064043",
             "rel": "bookmark"
           }
         ],
         "txhashpolicy": null,
         "schedpolicy": null,
         "imac": "08:00:27:80:aa:6e",
         "sriov_numvfs": 0,
         "ihost_uuid": "ff453a51-1d3b-437f-a65e-b2d163f79f85",
         "vlan_id": null,
         "imtu": 1500,
         "aemode": null,
         "networks": ["1"],
         "datanetworks": [],
         "ifclass": "platform"
         "ifname": "eth1"
       },
       {
         "forihostid": 2,
         "iftype": "ae",
         "uuid": "92dec2e1-a793-4c63-a408-affc492b7856",
         "links": [
           {
             "href": "http://192.168.204.2:6385/v1/iinterfaces/92dec2e1-a793-4c63-a408-affc492b7856",
             "rel": "self"
           },
           {
             "href": "http://192.168.204.2:6385/iinterfaces/92dec2e1-a793-4c63-a408-affc492b7856",
             "rel": "bookmark"
           }
         ],
         "txhashpolicy": "layer2",
         "schedpolicy": null,
         "imac": null,
         "sriov_numvfs": 0,
         "ihost_uuid": "ff453a51-1d3b-437f-a65e-b2d163f79f85",
         "imtu": 1500,
         "uses": [
           "eth2",
           "eth3"
         ],
         "used_by": [

         ],
         "aemode": "balanced",
         "networks": [],
         "datanetworks": ["physnet-0,physnet-1"],
         "ifclass": "data"
         "ifname": "data1"
       }
     ]
   }

This operation does not accept a request body.

***********************************************
Shows information about a specific L2 interface
***********************************************

.. rest_method:: GET /v1/iinterfaces/{interface_id}

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "interface_id", "URI", "csapi:UUID", "The unique identifier of an existing interface."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "ifname (Optional)", "plain", "xsd:string", "The user-specified name of the interface."
   "ifclass (Optional)", "plain", "xsd:string", "The class of the interface: ``platform``, ``data``, ``pci-passthrough`` or ``pci-sriov``."
   "iftype (Optional)", "plain", "xsd:string", "Indicates the type of L2 interface; ``ethernet`` or ``ae`` (aggregated ethernet or link aggregation (LAG)) or ``vlan`` (virtual lan)."
   "aemode (Optional)", "plain", "xsd:string", "Only applicable if ``iftype : ae``, this attribute indicates the basic mode of operation for the AE/LAG interface. Supported modes are: balanced round robin, active-backup, balanced xor, broadcast, 802.3ad, balance-tlb, balance-alb. NOTE only balanced xor and active-standby modes are supported by interfaces of ifclass=data."
   "txhashpolicy (Optional)", "plain", "xsd:string", "Only applicable if ``iftype : ae`` and ``aemode : balanced``, this attribute indicates what packet headers the AE/LAG is using to distribute packets across the different links/ports of the AE/LAG group; ``layer2``, ``layer2+3`` or ``layer3+4``."
   "vlan_id (Optional)", "plain", "xsd:integer", "Only applicable if ``iftype : vlan``, this attribute indicates that the vlan interface id. A vlan id between 1 and 4094 (inclusive) must be selected. NOTE The vlan id must be unique for the host interface."
   "networks (Optional)", "plain", "xsd:list", "Only applicable if ``ifclass : platform``, this attribute provides a list of platform networks that this interface is attached to."
   "datanetworks (Optional)", "plain", "xsd:list", "Only applicable if ``ifclass : data``, this attribute provides a list of data networks that this ``data`` interface is attached to."
   "imac (Optional)", "plain", "xsd:string", "The MAC Address being used by the interface. In the case of AE/LAG, the MAC address of one of the physical ports of the AE/LAG group is used."
   "imtu (Optional)", "plain", "xsd:integer", "The Maximum Transmission Unit (MTU) of the interface, in bytes."
   "sriov_numvfs (Optional)", "plain", "xsd:integer", "The number of VFs configured on the interfaces port; only applicable if ``ifclass : pci-sriov`` where only a single port is associated with the interface."
   "schedpolicy (Optional)", "plain", "xsd:string", "Currently not supported."
   "forihostId (Optional)", "plain", "xsd:string", "The ID of the host of this interface."
   "ihost_uuid (Optional)", "plain", "csapi:UUID", "The UUID of the host of this interface."
   "ifcapabilities (Optional)", "plain", "xsd:list", "Currently not supported."
   "ports (Optional)", "plain", "xsd:list", "URIs to the physical ports of this interface."
   "uses (Optional)", "plain", "xsd:list", "Interfaces which the current interface uses."
   "used_by (Optional)", "plain", "xsd:list", "Interfaces which use the current interface."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
      "ports" : [
         {
            "rel" : "self",
            "href" : "http://10.10.10.2:6385/v1/iinterfaces/740a5bec-b7a8-4645-93ed-aea0d4cfbf86/ports"
         },
         {
            "rel" : "bookmark",
            "href" : "http://10.10.10.2:6385/iinterfaces/740a5bec-b7a8-4645-93ed-aea0d4cfbf86/ports"
         }
      ],
      "datanetworks" : ["physnet-0,physnet-1"],
      "networks": [],
      "txhashpolicy" : "layer2",
      "schedpolicy" : null,
      "uuid" : "740a5bec-b7a8-4645-93ed-aea0d4cfbf86",
      "ihost_uuid" : "ff453a51-1d3b-437f-a65e-b2d163f79f85",
      "vlan_id": null,
      "created_at" : "2014-09-29T11:12:42.556372+00:00",
      "ifcapabilities" : {},
      "iftype" : "ae",
      "links" : [
         {
            "rel" : "self",
            "href" : "http://10.10.10.2:6385/v1/iinterfaces/740a5bec-b7a8-4645-93ed-aea0d4cfbf86"
         },
         {
            "rel" : "bookmark",
            "href" : "http://10.10.10.2:6385/iinterfaces/740a5bec-b7a8-4645-93ed-aea0d4cfbf86"
         }
      ],
      "imac" : null,
      "sriov_numvfs": 0,
      "aemode" : "balanced",
      "ifclass": "data",
      "ifname" : "data1",
      "ports" : null,
      "uses": [

      ],
      "used_by": [

      ],
      "forihostid" : 2,
      "updated_at" : null,
      "imtu" : 1500
   }

This operation does not accept a request body.

******************************************
Creates an L2 interface on a specific host
******************************************

.. rest_method:: POST /v1/ihosts/{host_id}/iinterfaces

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "host_id", "URI", "csapi:UUID", "The unique identifier of an existing host."
   "ifname (Optional)", "plain", "xsd:string", "The name for the interface."
   "ifclass (Optional)", "plain", "xsd:string", "The class of the interface: ``platform``, ``data``, ``pci-passthrough`` or ``pci-sriov``."
   "iftype (Optional)", "plain", "xsd:string", "The type of interface; i.e. ``ae`` or ``vlan``."
   "aemode (Optional)", "plain", "xsd:string", "Only applicable if ``iftype : ae``, this attribute specifies whether the AE/LAG should operate as ``balanced`` or ``active_standby`` or ``802.3ad`` across its links. The ``balanced`` and ``active_standby`` are the only modes supported by ``data`` type interface. For ``mgmt`` type interface the ``802.3ad`` option must be selected."
   "txhashpolicy (Optional)", "plain", "xsd:string", "Only applicable if ``iftype : ae`` and ``aemode : balanced``, this attribute specifies what packet headers the AE/LAG should use to distribute packets across the different links/ports of the AE/LAG group; ``layer2``, ``layer2+3`` or ``layer3+4``."
   "vlan_id (Optional)", "plain", "xsd:integer", "Only applicable if ``iftype : vlan``, this attribute specifies a virtual lan id for a vlan interface type."
   "networks (Optional)", "plain", "xsd:list", "Only applicable if ``ifclass : platform``, this attribute provides a list of platform networks that this interface is attached to."
   "datanetworks (Optional)", "plain", "xsd:list", "Only applicable if ``ifclass : data``, this attribute specifies a list of data networks that this ``data`` interface is attached to."
   "ports (Optional)", "plain", "xsd:list", "This attribute specifies a comma-separated list of ports that this interface contains. If ``iftype : ethernet`` then only one port is allowed."
   "uses (Optional)", "plain", "xsd:list", "Only applicable if ``iftype : ae`` or ``iftype: vlan``, this attribute specifies a comma-separated list of interfaces that this interface uses."
   "used_by (Optional)", "plain", "xsd:list", "This attribute specifies a comma-separated list of interfaces that use this interface."
   "imtu (Optional)", "plain", "xsd:integer", "This attribute specifies the interface's Maximum Transmit Unit."
   "sriov_numvfs (Optional)", "plain", "xsd:integer", "The number of VFs to configure on the interface's port; only applicable if ``ifclass : pci-sriov`` where only a single port is associated with the interface."
   "ihost_uuid (Optional)", "plain", "csapi:UUID", "The UUID of the host to create the interface on."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "ifname (Optional)", "plain", "xsd:string", "The user-specified name of the interface."
   "ifclass (Optional)", "plain", xsd:string", "The class of the interface: ``platform``, ``data``, ``pci-passthrough`` or ``pci-sriov``."
   "iftype (Optional)", "plain", "xsd:string", "Indicates the type of L2 interface; ``ethernet`` or ``ae`` (aggregated ethernet or link aggregation (LAG)) or ``vlan`` (virtual lan)."
   "aemode (Optional)", "plain", "xsd:string", "Only applicable if ``iftype : ae``, this attribute indicates the basic mode of operation for the AE/LAG interface. Supported modes are: balanced round robin, active-backup, balanced xor, broadcast, 802.3ad, balance-tlb, balance-alb. NOTE only balanced xor and active-standby modes are supported by interfaces of ifclass=data."
   "txhashpolicy (Optional)", "plain", "xsd:string", "Only applicable if ``iftype : ae`` and ``aemode : balanced``, this attribute indicates what packet headers the AE/LAG is using to distribute packets across the different links/ports of the AE/LAG group; ``layer2``, ``layer2+3`` or ``layer3+4``."
   "vlan_id (Optional)", "plain", "xsd:integer", "Only applicable if ``iftype : vlan``, this attribute indicates that the vlan interface id. A vlan id between 1 and 4094 (inclusive) must be selected. NOTE The vlan id must be unique for the host interface."
   "networks (Optional)", "plain", "xsd:list", "Only applicable if ``ifclass : platform``, this attribute provides a list of platform networks that this interface is attached to."
   "datanetworks (Optional)", "plain", "xsd:list", "Only applicable if ``ifclass : data``, this attribute provides a list of data networks that this ``data`` interface is attached to."
   "imac (Optional)", "plain", "xsd:string", "The MAC Address being used by the interface. In the case of AE/LAG, the MAC address of one of the physical ports of the AE/LAG group is used."
   "imtu (Optional)", "plain", "xsd:integer", "The Maximum Transmission Unit (MTU) of the interface, in bytes."
   "sriov_numvfs (Optional)", "plain", "xsd:integer", "The number of VFs configured on the interfaces port; only applicable if ``ifclass : pci-sriov`` where only a single port is associated with the interface."
   "schedpolicy (Optional)", "plain", "xsd:string", "Currently not supported."
   "forihostId (Optional)", "plain", "xsd:string", "The ID of the host of this interface."
   "ihost_uuid (Optional)", "plain", "csapi:UUID", "The UUID of the host of this interface."
   "ifcapabilities (Optional)", "plain", "xsd:list", "Currently not supported."
   "ports (Optional)", "plain", "xsd:list", "URIs to the physical ports of this interface."
   "uses (Optional)", "plain", "xsd:list", "Interfaces which the current interface uses."
   "used_by (Optional)", "plain", "xsd:list", "Interfaces which use the current interface."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
     "iftype": "ae",
     "txhashpolicy": "layer2",
     "ihost_uuid": "ff453a51-1d3b-437f-a65e-b2d163f79f85",
     "imtu": "1500",
     "networks": [],
     "datanetworks": "physnet-0,physnet1",
     "ifclass": "data",
     "ifname": "data1",
     "uses": ['eth2','eth3'],
     "aemode": "balanced",
     "sriov_numvfs": 0
   }

::

   {
     "ports": [
       {
         "href": "http://192.168.204.2:6385/v1/iinterfaces/92dec2e1-a793-4c63-a408-affc492b7856/ports",
         "rel": "self"
       },
       {
         "href": "http://192.168.204.2:6385/iinterfaces/92dec2e1-a793-4c63-a408-affc492b7856/ports",
         "rel": "bookmark"
       }
     ],
     "forihostid": 2,
     "iftype": "ae",
     "uuid": "92dec2e1-a793-4c63-a408-affc492b7856",
     "links": [
       {
         "href": "http://192.168.204.2:6385/v1/iinterfaces/92dec2e1-a793-4c63-a408-affc492b7856",
         "rel": "self"
       },
       {
         "href": "http://192.168.204.2:6385/iinterfaces/92dec2e1-a793-4c63-a408-affc492b7856",
         "rel": "bookmark"
       }
     ],
     "ihost_uuid": "ff453a51-1d3b-437f-a65e-b2d163f79f85",
     "vlan_id": null,
     "txhashpolicy": "layer2",
     "created_at": "2014-09-29T10:55:20.515705+00:00",
     "schedpolicy": null,
     "imac": null,
     "updated_at": null,
     "ifcapabilities": {

     },
     "imtu": 1500,
     "uses": [
       "eth2",
       "eth3"
     ],
     "used_by": [

     ],
     "aemode": "balanced",
     "sriov_numvfs": 0,
     'networks": [],
     "datanetworks": ["physnet-0,physnet-1"],
     "ifclass": "data",
     "ifname": "data1",
     "ports": null,
   }


********************************
Modifies a specific L2 interface
********************************

.. rest_method:: PATCH /v1/iinterfaces/{interface_id}

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "interface_id", "URI", "csapi:UUID", "The unique identifier of an existing interface."
   "ifname (Optional)", "plain", "xsd:string", "The name for the interface."
   "ifclass (Optional)", "plain", "xsd:string", "The class of the interface: ``platform``, ``data``, ``pci-passthrough`` or ``pci-sriov``."
   "iftype (Optional)", "plain", "xsd:string", "The type of interface; i.e. ``ethernet`` or ``ae`` or ``vlan``."
   "aemode (Optional)", "plain", "xsd:string", "Only applicable if ``iftype : ae``, this attribute specifies whether the AE/LAG should operate as ``balanced`` or ``active_standby`` across its links. These are the only modes supported by ``data`` type interface."
   "txhashpolicy (Optional)", "plain", "xsd:string", "Only applicable if ``iftype : ae`` and ``aemode : balanced``, this attribute specifies what packet headers the AE/LAG should use to distribute packets across the different links/ports of the AE/LAG group; ``layer2``, ``layer2+3`` or ``layer3+4``."
   "vlan_id (Optional)", "plain", "xsd:integer", "Only applicable if ``iftype : vlan``, this attribute specifies a virtual lan id for a vlan interface type."
   "networks (Optional)", "plain", "xsd:list", "Only applicable if ``ifclass : platform``, this attribute provides a list of platform networks that this interface is attached to."
   "datanetworks (Optional)", "plain", "xsd:list", "Only applicable if ``ifclass : data``, this attribute specifies a list of data networks that this ``data`` interface is attached to."
   "ports (Optional)", "plain", "xsd:list", "This attribute specifies a comma-separated list of ports that this interface contains. If ``iftype : ethernet`` then only one port is allowed."
   "uses (Optional)", "plain", "xsd:list", "Only applicable if ``iftype : ae`` or ``iftype: vlan``, this attribute specifies a comma-separated list of interfaces that this interface uses."
   "used_by (Optional)", "plain", "xsd:list", "This attribute specifies a comma-separated list of interfaces that use this interface."
   "imtu (Optional)", "plain", "xsd:integer", "This attribute specifies the interface's Maximum Transmit Unit."
   "sriov_numvfs (Optional)", "plain", "xsd:integer", "The number of VFs to configure on the interface's port; only applicable if ``ifclass : pci-sriov`` where only a single port is associated with the interface."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "ifname (Optional)", "plain", "xsd:string", "The user-specified name of the interface."
   "ifclass (Optional)", "plain", "xsd:string", "The class of the interface: ``platform``, ``data``, ``pci-passthrough`` or ``pci-sriov``."
   "iftype (Optional)", "plain", "xsd:string", "Indicates the type of L2 interface; ``ethernet`` or ``ae`` (aggregated ethernet or link aggregation (LAG)) or ``vlan`` (virtual lan)."
   "aemode (Optional)", "plain", "xsd:string", "Only applicable if ``iftype : ae``, this attribute indicates the basic mode of operation for the AE/LAG interface. Supported modes are: balanced round robin, active-backup, balanced xor, broadcast, 802.3ad, balance-tlb, balance-alb. NOTE only balanced xor and active-standby modes are supported by interfaces of ifclass=data."
   "txhashpolicy (Optional)", "plain", "xsd:string", "Only applicable if ``iftype : ae`` and ``aemode : balanced``, this attribute indicates what packet headers the AE/LAG is using to distribute packets across the different links/ports of the AE/LAG group; ``layer2``, ``layer2+3`` or ``layer3+4``."
   "vlan_id (Optional)", "plain", "xsd:integer", "Only applicable if ``iftype : vlan``, this attribute indicates that the vlan interface id. A vlan id between 1 and 4094 (inclusive) must be selected. NOTE The vlan id must be unique for the host interface."
   "networks (Optional)", "plain", "xsd:list", "Only applicable if ``ifclass : platform``, this attribute provides a list of platform networks that this interface is attached to."
   "datanetworks (Optional)", "plain", "xsd:list", "Only applicable if ``ifclass : data``, this attribute provides a list of data networks that this ``data`` interface is attached to."
   "imac (Optional)", "plain", "xsd:string", "The MAC Address being used by the interface. In the case of AE/LAG, the MAC address of one of the physical ports of the AE/LAG group is used."
   "imtu (Optional)", "plain", "xsd:integer", "The Maximum Transmission Unit (MTU) of the interface, in bytes."
   "sriov_numvfs (Optional)", "plain", "xsd:integer", "The number of VFs configured on the interfaces port; only applicable if ``ifclass : pci-sriov`` where only a single port is associated with the interface."
   "schedpolicy (Optional)", "plain", "xsd:string", "Currently not supported."
   "forihostId (Optional)", "plain", "xsd:string", "The ID of the host of this interface."
   "ihost_uuid (Optional)", "plain", "csapi:UUID", "The UUID of the host of this interface."
   "ifcapabilities (Optional)", "plain", "xsd:list", "Currently not supported."
   "ports (Optional)", "plain", "xsd:list", "URIs to the physical ports of this interface."
   "uses (Optional)", "plain", "xsd:list", "Interfaces which the current interface uses."
   "used_by (Optional)", "plain", "xsd:list", "Interfaces which use the current interface."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   [
     {
       "path": "/imtu",
       "value": "1500",
       "op": "replace"
     },
     {
       "path": "/txhashpolicy",
       "value": "layer2",
       "op": "replace"
     },
     {
       "path": "/datanetworks",
       "value": "physnet-0,physnet-1",
       "op": "replace"
     },
     {
       "path": "/aemode",
       "value": "active_standby",
       "op": "replace"
     },
     {
       "path": "/uses",
       "value": ['eth2','eth3'],
       "op": "replace"
     }
   ]

::

   {
     "ports": [
       {
         "href": "http://192.168.204.2:6385/v1/iinterfaces/92dec2e1-a793-4c63-a408-affc492b7856/ports",
         "rel": "self"
       },
       {
         "href": "http://192.168.204.2:6385/iinterfaces/92dec2e1-a793-4c63-a408-affc492b7856/ports",
         "rel": "bookmark"
       }
     ],
     "forihostid": 2,
     "iftype": "ae",
     "uuid": "92dec2e1-a793-4c63-a408-affc492b7856",
     "links": [
       {
         "href": "http://192.168.204.2:6385/v1/iinterfaces/92dec2e1-a793-4c63-a408-affc492b7856",
         "rel": "self"
       },
       {
         "href": "http://192.168.204.2:6385/iinterfaces/92dec2e1-a793-4c63-a408-affc492b7856",
         "rel": "bookmark"
       }
     ],
     "ihost_uuid": "ff453a51-1d3b-437f-a65e-b2d163f79f85",
     "vlan_id": null,
     "txhashpolicy": "layer2",
     "created_at": "2014-09-29T10:55:20.515705+00:00",
     "schedpolicy": null,
     "imac": null,
     "sriov_numvfs": 0,
     "updated_at": "2014-09-29T11:08:21.016145+00:00",
     "ifcapabilities": {

     },
     "imtu": 1500,
     "uses": [
       "eth2",
       "eth3"
     ],
     "used_by": [

     ],
     "aemode": "active_standby",
     "networks": [],
     "datanetworks": ["physnet-0,physnet-1"],
     "ifclass": "data",
     "ifname": "data1",
     "ports": null
   }

*******************************
Deletes a specific L2 interface
*******************************

.. rest_method:: DELETE /v1/iinterfaces/{interface_id}

**Normal response codes**

204

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "interface_id", "URI", "csapi:UUID", "The unique identifier of an existing interface."

This operation does not accept a request body.

------------------
Interface Networks
------------------

These APIs allow the create, display, and delete of the
Interface Network.

**********************************************
List the Interface Networks of a specific host
**********************************************

.. rest_method:: GET /v1/ihosts/{host_id}/interface_networks


**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "host_id", "URI", "csapi:UUID", "The unique identifier of an existing host."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "interface_networks", "plain", "xsd:list", "The list of Interface Networks."
   "uuid", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "interface_uuid", "plain", "csapi:UUID", "The universally unique identifier for the interface."
   "network_uuid", "plain", "csapi:UUID", "The universally unique identifier for the network."
   "network_name", "plain", "xsd:string", "The name of the network."
   "ifname", "plain", "xsd:string", "The name of the interface."

::

   {
      "interface_networks":[
        {
            "network_uuid": "783cabc6-6105-4195-b1ff-4453d4e1144e",
            "uuid": "bef00740-0d2b-48a5-8371-8956c0dbe2d8",
            "ifname": "enp0s8",
            "interface_uuid": "b38876cd-a17a-4e60-ba9f-7588531039e0",
            "network_name": "mgmt",
            "id": 1
        },
        {
            "network_uuid": "1514793b-8d01-4156-b051-e4aaf85fe106",
            "uuid": "49827e51-1d9c-4ffb-8ed2-5c82fa044afa",
            "ifname": "enp0s3",
            "interface_uuid": "03276210-f585-45c0-8a5c-15408de05594",
            "network_name": "oam",
            "id": 2
        },
        {
            "network_uuid": "7b1e43d4-4c5c-4166-940c-5b50ef1e522e",
            "uuid": "7b6838da-6f0a-4874-92ff-bf1b10bf9102",
            "ifname": "enp0s8",
            "interface_uuid": "b38876cd-a17a-4e60-ba9f-7588531039e0",
            "network_name": "cluster-host",
            "id": 3
        }
      ]
   }

This operation does not accept a request body.

****************************************************
Shows information about a specific Interface Network
****************************************************

.. rest_method:: GET /v1/interface_networks/{interface_network_id}

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "interface_network_id", "URI", "csapi:UUID", "The unique identifier of an existing network."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "uuid", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "interface_uuid", "plain", "csapi:UUID", "The universally unique identifier for the interface."
   "network_uuid", "plain", "csapi:UUID", "The universally unique identifier for the network."
   "network_name", "plain", "xsd:string", "The name of the network."
   "ifname", "plain", "xsd:string", "The name of the interface."

::

   {
      "network_uuid": "1514793b-8d01-4156-b051-e4aaf85fe106",
      "uuid": "49827e51-1d9c-4ffb-8ed2-5c82fa044afa",
      "ifname": "enp0s3",
      "interface_uuid": "03276210-f585-45c0-8a5c-15408de05594",
      "network_name": "oam",
      "id": 2
   }

This operation does not accept a request body.

****************************
Creates an Interface Network
****************************

.. rest_method:: POST /v1/interface_networks

This will create an interface network i.e. assign a network to an interface.

**Normal response codes**

200

**Error response codes**

Conflict (409)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "interface_uuid", "plain", "csapi:UUID", "The universally unique identifier for the interface."
   "network_uuid", "plain", "csapi:UUID", "The universally unique identifier for the network."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "uuid", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "interface_uuid", "plain", "csapi:UUID", "The universally unique identifier for the interface."
   "network_uuid", "plain", "csapi:UUID", "The universally unique identifier for the network."
   "network_name", "plain", "xsd:string", "The name of the network."
   "ifname", "plain", "xsd:string", "The name of the interface."

::

   {
      "interface_uuid":"2731d293-8124-4963-9d7c-36bdb220b38c"
      "network_uuid":"3a0b7357-eb36-42fb-a800-55ff3549cc3c",
   }

::

   {
      "network_uuid": "1514793b-8d01-4156-b051-e4aaf85fe106",
      "uuid": "49827e51-1d9c-4ffb-8ed2-5c82fa044afa",
      "ifname": "enp0s3",
      "interface_uuid": "03276210-f585-45c0-8a5c-15408de05594",
      "network_name": "oam",
      "id": 2
   }

************************************
Deletes a specific Interface Network
************************************

.. rest_method:: DELETE /v1/interface_networks/{interface_network_id}

This will remove from the interface the network assigned.

**Normal response codes**

204

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "interface_network_id", "URI", "csapi:UUID", "The unique identifier of an existing interface network."

This operation does not accept a request body.

-------------
Data Networks
-------------

These APIs allow the create, display, modify and delete of the
Data Networks.

**********************
List the Data Networks
**********************

.. rest_method:: GET /v1/datanetworks


**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "datanetworks (Optional)", "plain", "xsd:list", "The list of Data Networks."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "network_type (Optional)", "plain", "xsd:string", "Indicates the type of data network ; ``flat``, ``vlan``, ``vxlan``."
   "name (Optional)", "plain", "xsd:string", "The user-specified name of the data network."
   "description (Optional)", "plain", "xsd:string", "The user-specified description of the data network."
   "mtu (Optional)", "plain", "xsd:integer", "The Maximum Transmission Unit (MTU) of the data network, in bytes."
   "mode (Optional)", "plain", "xsd:string", "Only applicable if ``network_type : vxlan``, the mode of the data network; ``dynamic``, ``static``."
   "multicast_group (Optional)", "plain", "xsd:string", "Only applicable if ``network_type : vxlan`` and ``network_type : dynamic``, this attribute indicates the multicast group address."
   "port_num (Optional)", "plain", "xsd:integer", "Only applicable if ``network_type : vxlan``, this attribute indicates the port number of the vxlan datanetwork."
   "ttl (Optional)", "plain", "xsd:integer", "Only applicable if ``network_type : vxlan``, this attribute indicates the time to live.  A value between 1 and 255 inclusive is allowed."

::

   {
      "datanetworks":[
	 {
	    "description":null,
	    "port_num":null,
	    "uuid":"e1f6786d-df5a-4df8-9e6c-ced71797afe7",
	    "mtu":1500,
	    "multicast_group":null,
	    "mode":null,
	    "ttl":null,
	    "id":1,
	    "network_type":"vlan",
	    "name":"group0-data0"
	 },
	 {
	    "description":null,
	    "port_num":4789,
	    "uuid":"216c59cc-9713-4071-beab-c37dc2b6d153",
	    "mtu":1400,
	    "multicast_group":"239.0.6.10",
	    "mode":"dynamic",
	    "ttl":1,
	    "id":2,
	    "network_type":"vxlan",
	    "name":"group0-data1"
	 }
      ]
   }

This operation does not accept a request body.

***********************************************
Shows information about a specific Data Network
***********************************************

.. rest_method:: GET /v1/datanetworks/{datanetwork_id}

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "datanetwork_id", "URI", "csapi:UUID", "The unique identifier of an existing datanetwork."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "network_type (Optional)", "plain", "xsd:string", "Indicates the type of data network ; ``flat``, ``vlan``, ``vxlan``."
   "name (Optional)", "plain", "xsd:string", "The user-specified name of the data network."
   "description (Optional)", "plain", "xsd:string", "The user-specified description of the data network."
   "mtu (Optional)", "plain", "xsd:integer", "The Maximum Transmission Unit (MTU) of the data network, in bytes."
   "mode (Optional)", "plain", "xsd:string", "Only applicable if ``network_type : vxlan``, the mode of the data network; ``dynamic``, ``static``."
   "multicast_group (Optional)", "plain", "xsd:string", "Only applicable if ``network_type : vxlan`` and ``network_type : dynamic``, this attribute indicates the multicast group address."
   "port_num (Optional)", "plain", "xsd:integer", "Only applicable if ``network_type : vxlan``, this attribute indicates the port number of the vxlan datanetwork."
   "ttl (Optional)", "plain", "xsd:integer", "Only applicable if ``network_type : vxlan``, this attribute indicates the time to live."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."


::

   {
      "description":null,
      "updated_at":null,
      "created_at":"2019-02-02T15:03:29.255937+00:00",
      "port_num":4789,
      "uuid":"216c59cc-9713-4071-beab-c37dc2b6d153",
      "mtu":1400,
      "multicast_group":"239.0.6.10",
      "mode":"dynamic",
      "ttl":1,
      "id":2,
      "network_type":"vxlan",
      "name":"group0-data1"
   }


This operation does not accept a request body.

**********************
Creates a Data Network
**********************

.. rest_method:: POST /v1/datanetworks

This will create a data network.

**Normal response codes**

200

**Error response codes**

Conflict (409)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "network_type", "plain", "xsd:string", "Indicates the type of data network ; ``flat``, ``vlan``, ``vxlan``."
   "name", "plain", "xsd:string", "The user-specified name of the data network."
   "mtu", "plain", "xsd:integer", "The Maximum Transmission Unit (MTU) of the data network, in bytes."
   "description (Optional)", "plain", "xsd:string", "The user-specified description of the data network."
   "mode (Optional)", "plain", "xsd:string", "Only applicable if ``network_type : vxlan``, the mode of the data network; ``dynamic``, ``static``."
   "multicast_group (Optional)", "plain", "xsd:string", "Only applicable if ``network_type : vxlan`` and ``network_type : dynamic``, this attribute indicates the multicast group address."
   "port_num (Optional)", "plain", "xsd:integer", "Only applicable if ``network_type : vxlan``, this attribute indicates the port number of the vxlan datanetwork."
   "ttl (Optional)", "plain", "xsd:integer", "Only applicable if ``network_type : vxlan``, this attribute indicates the time to live."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "uuid", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "network_type", "plain", "xsd:string", "Indicates the type of data network ; ``flat``, ``vlan``, ``vxlan``."
   "name", "plain", "xsd:string", "The user-specified name of the data network."
   "description (Optional)", "plain", "xsd:string", "The user-specified description of the data network."
   "mtu", "plain", "xsd:integer", "The Maximum Transmission Unit (MTU) of the data network, in bytes."
   "mode (Optional)", "plain", "xsd:string", "Only applicable if ``network_type : vxlan``, the mode of the data network; ``dynamic``, ``static``."
   "multicast_group (Optional)", "plain", "xsd:string", "Only applicable if ``network_type : vxlan`` and ``network_type : dynamic``, this attribute indicates the multicast group address."
   "port_num (Optional)", "plain", "xsd:integer", "Only applicable if ``network_type : vxlan``, this attribute indicates the port number of the vxlan datanetwork."
   "ttl (Optional)", "plain", "xsd:integer", "Only applicable if ``network_type : vxlan``, this attribute indicates the time to live."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
      "description":"group2-data2 description",
      "port_num":"4789",
      "mtu":"1400",
      "multicast_group":"239.0.6.10",
      "mode":"dynamic",
      "ttl":"1",
      "network_type":"vxlan",
      "name":"group2-data2"
   }

::

   {
      "description":"group2-data2 description",
      "updated_at":null,
      "created_at":"2019-02-03T15:31:39.997833+00:00",
      "port_num":4789,
      "uuid":"3a0b7357-eb36-42fb-a800-55ff3549cc3c",
      "mtu":1400,
      "multicast_group":"239.0.6.10",
      "mode":"dynamic",
      "ttl":1,
      "id":4,
      "network_type":"vxlan",
      "name":"group2-data2"
   }

********************************
Modifies a specific Data Network
********************************

.. rest_method:: PATCH /v1/datanetworks/{datanetwork_id}

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "datanetwork_id", "URI", "csapi:UUID", "The unique identifier of an existing datanetwork."
   "mtu (Optional)", "plain", "xsd:integer", "This attribute specifies the data network's Maximum Transmit Unit."
   "description (Optional)", "plain", "xsd:string", "The user-specified description of the data network."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "uuid", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "network_type", "plain", "xsd:string", "Indicates the type of data network ; ``flat``, ``vlan``, ``vxlan``."
   "name", "plain", "xsd:string", "The user-specified name of the data network."
   "description (Optional)", "plain", "xsd:string", "The user-specified description of the data network."
   "mtu", "plain", "xsd:integer", "The Maximum Transmission Unit (MTU) of the data network, in bytes."
   "mode (Optional)", "plain", "xsd:string", "Only applicable if ``network_type : vxlan``, the mode of the data network; ``dynamic``, ``static``."
   "multicast_group (Optional)", "plain", "xsd:string", "Only applicable if ``network_type : vxlan`` and ``network_type : dynamic``, this attribute indicates the multicast group address."
   "port_num (Optional)", "plain", "xsd:integer", "Only applicable if ``network_type : vxlan``, this attribute indicates the port number of the vxlan datanetwork."
   "ttl (Optional)", "plain", "xsd:integer", "Only applicable if ``network_type : vxlan``, this attribute indicates the time to live."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   [
      {
	 "path":"/description",
	 "value":"group2-data2 datanetwork description",
	 "op":"replace"
      },
      {
	 "path":"/mtu",
	 "value":"1500",
	 "op":"replace"
      }
   ]

::

   {
      "description":"group2-data2 datanetwork description",
      "updated_at":"2019-02-03T15:49:50.897532+00:00",
      "created_at":"2019-02-03T15:31:39.997833+00:00",
      "port_num":4789,
      "uuid":"3a0b7357-eb36-42fb-a800-55ff3549cc3c",
      "mtu":1500,
      "multicast_group":"239.0.6.10",
      "mode":"dynamic",
      "ttl":1,
      "id":4,
      "network_type":"vxlan",
      "name":"group2-data2"
   }

*******************************
Deletes a specific Data Network
*******************************

.. rest_method:: DELETE /v1/datanetworks/{datanetwork_id}

**Normal response codes**

204

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "datanetwork_id", "URI", "csapi:UUID", "The unique identifier of an existing datanetwork."

This operation does not accept a request body.

-----------------------
Interface Data Networks
-----------------------

These APIs allow the create, display, and delete of the
Interface Data Network.

***************************************************
List the Interface Data Networks of a specific host
***************************************************

.. rest_method:: GET /v1/ihosts/{host_id}/interface_datanetworks


**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "host_id", "URI", "csapi:UUID", "The unique identifier of an existing host."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "interface_datanetworks", "plain", "xsd:list", "The list of Interface Data Networks."
   "uuid", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "interface_uuid", "plain", "csapi:UUID", "The universally unique identifier for the interface."
   "datanetwork_uuid", "plain", "csapi:UUID", "The universally unique identifier for the datanetwork."
   "datanetwork_name", "plain", "xsd:string", "The name of the data network."
   "ifname", "plain", "xsd:string", "The name of the interface."

::

   {
      "interface_datanetworks":[
	 {
	    "datanetwork_uuid":"1ea7d61d-e988-4457-83bf-3ba37f5f6f8d",
	    "datanetwork_id":1,
	    "uuid":"e3502084-22c4-4e1d-acd3-0f2594fa7281",
	    "datanetwork_name":"group0-data0",
	    "ifname":"data0",
	    "interface_uuid":"2731d293-8124-4963-9d7c-36bdb220b38c",
	    "id":1
	 },
	 {
	    "datanetwork_uuid":"01bafd19-63ea-4a1e-8b3c-35e96b7d3a6c",
	    "datanetwork_id":2,
	    "uuid":"ffccd4ce-0c47-4bdc-b38d-549b2f2a0d03",
	    "datanetwork_name":"group0-data1",
	    "ifname":"data1",
	    "interface_uuid":"cdd2e58b-abe7-4d27-b4ef-2ff6b5e5e774",
	    "id":2
	 }
      ]
   }

This operation does not accept a request body.

*********************************************************
Shows information about a specific Interface Data Network
*********************************************************

.. rest_method:: GET /v1/interface_datanetworks/{interface_datanetwork_id}

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "interface_datanetwork_id", "URI", "csapi:UUID", "The unique identifier of an existing datanetwork."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "uuid", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "interface_uuid", "plain", "csapi:UUID", "The universally unique identifier for the interface."
   "datanetwork_uuid", "plain", "csapi:UUID", "The universally unique identifier for the datanetwork."
   "datanetwork_name", "plain", "xsd:string", "The name of the data network."
   "ifname", "plain", "xsd:string", "The name of the interface."

::

   {
      "datanetwork_uuid":"1ea7d61d-e988-4457-83bf-3ba37f5f6f8d",
      "datanetwork_id":1,
      "uuid":"e3502084-22c4-4e1d-acd3-0f2594fa7281",
      "datanetwork_name":"group0-data0",
      "ifname":"data0",
      "interface_uuid":"2731d293-8124-4963-9d7c-36bdb220b38c",
      "id":1
   }

This operation does not accept a request body.

*********************************
Creates an Interface Data Network
*********************************

.. rest_method:: POST /v1/interface_datanetworks

This will create an interface data network i.e. assign a datanetwork to an interface.

**Normal response codes**

200

**Error response codes**

Conflict (409)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "interface_uuid", "plain", "csapi:UUID", "The universally unique identifier for the interface."
   "datanetwork_uuid", "plain", "csapi:UUID", "The universally unique identifier for the interface."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "uuid", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "interface_uuid", "plain", "csapi:UUID", "The universally unique identifier for the interface."
   "datanetwork_uuid", "plain", "csapi:UUID", "The universally unique identifier for the datanetwork."
   "datanetwork_name", "plain", "xsd:string", "The name of the data network."
   "ifname", "plain", "xsd:string", "The name of the interface."

::

   {
      "interface_uuid":"2731d293-8124-4963-9d7c-36bdb220b38c"
      "datanetwork_uuid":"3a0b7357-eb36-42fb-a800-55ff3549cc3c",
   }

::

   {
      "datanetwork_uuid":"3a0b7357-eb36-42fb-a800-55ff3549cc3c",
      "datanetwork_id":4,
      "uuid":"0ddd0621-7956-42bc-96ca-03c2ebc61b9b",
      "created_at":"2019-02-04T00:14:50.277991+00:00",
      "updated_at":null,
      "datanetwork_name":"group2-data2",
      "ifname":"data0",
      "interface_uuid":"2731d293-8124-4963-9d7c-36bdb220b38c",
      "id":3
   }

*****************************************
Deletes a specific Interface Data Network
*****************************************

.. rest_method:: DELETE /v1/interface_datanetworks/{interface_datanetwork_id}

This will remove from the interface the datanetwork assigned.

**Normal response codes**

204

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "interface_datanetwork_id", "URI", "csapi:UUID", "The unique identifier of an existing interface datanetwork."

This operation does not accept a request body.


---------
Profiles
---------

These APIs allow the create, display and delete of host profiles. This
includes interface profiles, cpu profiles, and volume profiles. NOTE
that the same record is used in the database for both hosts and host
profiles.

********************
Lists all profiles
********************

.. rest_method:: GET /v1/iprofiles

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "iprofiles (Optional)", "plain", "xsd:list", "The list of profile entities."
   "recordtype (Optional)", "plain", "xsd:string", "Indicates that the record is being used for host profile rather than a host."
   "hostname (Optional)", "plain", "xsd:string", "The name of the profile."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
     "iprofiles": [
       {
         "uuid": "b6bde724-4fda-4941-ae3f-15abd3d4107b",
         "recordtype": "profile",
         "task": null,
         "reserved": "False",
         "mgmt_ip": null,
         "links": [
           {
             "href": "http://192.168.204.2:6385/v1/iprofile/b6bde724-4fda-4941-ae3f-15abd3d4107b",
             "rel": "self"
           },
           {
             "href": "http://192.168.204.2:6385/iprofile/b6bde724-4fda-4941-ae3f-15abd3d4107b",
             "rel": "bookmark"
           }
         ],
         "personality": null,
         "created_at": "2014-09-29T13:36:36.760707+00:00",
         "hostname": "ifprofile-type-1",
         "updated_at": null,
         "id": 23,
         "ihost_uuid": null,
         "profiletype": null,
         "location": {
         },
         "action": "none",
         "profilename": null,
         "operational": "disabled",
         "administrative": "locked",
         "availability": "offline",
         "uptime": 0,
         "mgmt_mac": null
       },
       {
         "uuid": "85b8d979-a1d5-4b06-8666-22646d45dcdf",
         "recordtype": "profile",
         "task": null,
         "reserved": "False",
         "mgmt_ip": null,
         "links": [
           {
             "href": "http://192.168.204.2:6385/v1/iprofile/85b8d979-a1d5-4b06-8666-22646d45dcdf",
             "rel": "self"
           },
           {
             "href": "http://192.168.204.2:6385/iprofile/85b8d979-a1d5-4b06-8666-22646d45dcdf",
             "rel": "bookmark"
           }
         ],
         "personality": null,
         "created_at": "2014-09-29T13:42:40.592612+00:00",
         "hostname": "ifprofile-type-2",
         "updated_at": null,
         "id": 24,
         "ihost_uuid": null,
         "profiletype": null,
         "location": {
         },
         "action": "none",
         "profilename": null,
         "operational": "disabled",
         "administrative": "locked",
         "availability": "offline",
         "uptime": 0,
         "mgmt_mac": null
       }
     ]
   }

This operation does not accept a request body.

********************************************
Shows information about a specific profile
********************************************

.. rest_method:: GET /v1/iprofiles/​{profile_id}​

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "profile_id", "URI", "csapi:UUID", "The unique identifier of an existing profile."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "recordtype (Optional)", "plain", "xsd:string", "Indicates that the record is being used for host profile rather than a host."
   "hostname (Optional)", "plain", "xsd:string", "The name of the profile."
   "ports (Optional)", "plain", "xsd:list", "Links to the ports of the profile."
   "interfaces (Optional)", "plain", "xsd:list", "Links to the interfaces of the profile."
   "idisks (Optional)", "plain", "xsd:list", "Links to the disks of the profile."
   "partitions (Optional)", "plain", "xsd:list", "Links to the partitions of the profile."
   "istors (Optional)", "plain", "xsd:list", "Links to the physical volume storage resources of the profile."
   "ipvs (Optional)", "plain", "xsd:list", "Links to the physical volumes of the profile."
   "ilvgs (Optional)", "plain", "xsd:list", "Links to the logical volume group storage resources of the profile."
   "inodes (Optional)", "plain", "xsd:list", "Links to the NUMA Nodes of the profile."
   "icpus (Optional)", "plain", "xsd:list", "Links to the logical cores (CPUs) of the profile."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
      "ports" : [
         {
            "rel" : "self",
            "href" : "http://128.224.151.244:6385/v1/iprofile/85b8d979-a1d5-4b06-8666-22646d45dcdf/ports"
         },
         {
            "rel" : "bookmark",
            "href" : "http://128.224.151.244:6385/iprofile/85b8d979-a1d5-4b06-8666-22646d45dcdf/ports"
         }
      ],
      "operational" : "disabled",
      "imemorys" : [
         {
            "rel" : "self",
            "href" : "http://128.224.151.244:6385/v1/ihosts/85b8d979-a1d5-4b06-8666-22646d45dcdf/imemorys"
         },
         {
            "rel" : "bookmark",
            "href" : "http://128.224.151.244:6385/ihosts/85b8d979-a1d5-4b06-8666-22646d45dcdf/imemorys"
         }
      ],
      "iinterfaces" : [
         {
            "rel" : "self",
            "href" : "http://128.224.151.244:6385/v1/iprofile/85b8d979-a1d5-4b06-8666-22646d45dcdf/iinterfaces"
         },
         {
            "rel" : "bookmark",
            "href" : "http://128.224.151.244:6385/iprofile/85b8d979-a1d5-4b06-8666-22646d45dcdf/iinterfaces"
         }
      ],
      "personality" : null,
      "serialId" : null,
      "hostname" : "ifprofile-type-2",
      "profilename" : null,
      "uuid" : "85b8d979-a1d5-4b06-8666-22646d45dcdf",
      "profiletype" : null,
      "ihost_uuid" : null,
      "created_at" : "2014-09-29T13:42:40.592612+00:00",
      "availability" : "offline",
      "recordtype" : "profile",
      "istors" : [
         {
            "rel" : "self",
            "href" : "http://128.224.151.244:6385/v1/iprofile/85b8d979-a1d5-4b06-8666-22646d45dcdf/istors"
         },
         {
            "rel" : "bookmark",
            "href" : "http://128.224.151.244:6385/iprofile/85b8d979-a1d5-4b06-8666-22646d45dcdf/istors"
         }
      ],
      "idisks" : [
         {
            "rel" : "self",
            "href" : "http://128.224.151.244:6385/v1/iprofile/85b8d979-a1d5-4b06-8666-22646d45dcdf/idisks"
         },
         {
            "rel" : "bookmark",
            "href" : "http://128.224.151.244:6385/iprofile/85b8d979-a1d5-4b06-8666-22646d45dcdf/idisks"
         }
      ],
      "uptime" : 0,
      "icpus" : [
         {
            "rel" : "self",
            "href" : "http://128.224.151.244:6385/v1/ihosts/85b8d979-a1d5-4b06-8666-22646d45dcdf/icpus"
         },
         {
            "rel" : "bookmark",
            "href" : "http://128.224.151.244:6385/ihosts/85b8d979-a1d5-4b06-8666-22646d45dcdf/icpus"
         }
      ],
      "id" : 24,
      "mgmt_ip" : null,
      "links" : [
         {
            "rel" : "self",
            "href" : "http://128.224.151.244:6385/v1/iprofile/85b8d979-a1d5-4b06-8666-22646d45dcdf"
         },
         {
            "rel" : "bookmark",
            "href" : "http://128.224.151.244:6385/iprofile/85b8d979-a1d5-4b06-8666-22646d45dcdf"
         }
      ],
      "location" : {},
      "inodes" : [
         {
            "rel" : "self",
            "href" : "http://128.224.151.244:6385/v1/ihosts/85b8d979-a1d5-4b06-8666-22646d45dcdf/inodes"
         },
         {
            "rel" : "bookmark",
            "href" : "http://128.224.151.244:6385/ihosts/85b8d979-a1d5-4b06-8666-22646d45dcdf/inodes"
         }
      ],
      "task" : null,
      "mgmt_mac" : null,
      "invprovision" : null,
      "administrative" : "locked",
      "updated_at" : null,
      "action" : "none",
      "reserved" : "False"
   }

This operation does not accept a request body.

*******************
Creates a profile
*******************

.. rest_method:: POST /v1/iprofiles

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "profilename (Optional)", "plain", "xsd:string", "The name for the new profile."
   "profiletype (Optional)", "plain", "xsd:string", "The type of profile to be created. Valid values are: ``if``, ``cpu`` or ``stor``."
   "ihost_uuid (Optional)", "plain", "csapi:UUID", "The UUID of the Host to create the profile based on."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "recordtype (Optional)", "plain", "xsd:string", "Indicates that the record is being used for host profile rather than a host."
   "hostname (Optional)", "plain", "xsd:string", "The name of the profile."
   "ports (Optional)", "plain", "xsd:list", "Links to the ports of the profile."
   "interfaces (Optional)", "plain", "xsd:list", "Links to the interfaces of the profile."
   "idisks (Optional)", "plain", "xsd:list", "Links to the disks of the profile."
   "partitions (Optional)", "plain", "xsd:list", "Links to the partitions of the profile."
   "istors (Optional)", "plain", "xsd:list", "Links to the physical volume storage resources of the profile."
   "ipvs (Optional)", "plain", "xsd:list", "Links to the physical volumes of the profile."
   "ilvgs (Optional)", "plain", "xsd:list", "Links to the logical volume group storage resources of the profile."
   "inodes (Optional)", "plain", "xsd:list", "Links to the NUMA Nodes of the profile."
   "icpus (Optional)", "plain", "xsd:list", "Links to the logical cores (CPUs) of the profile."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
     "profilename": "ifprofile-type-1",
     "profiletype": "if",
     "ihost_uuid": "959f785b-6387-4b98-aa30-bc861061d7a1"
   }

::

   {
     "ports": [
       {
         "href": "http://192.168.204.2:6385/v1/iprofile/b6bde724-4fda-4941-ae3f-15abd3d4107b/ports",
         "rel": "self"
       },
       {
         "href": "http://192.168.204.2:6385/iprofile/b6bde724-4fda-4941-ae3f-15abd3d4107b/ports",
         "rel": "bookmark"
       }
     ],
     "reserved": "False",
     "links": [
       {
         "href": "http://192.168.204.2:6385/v1/iprofile/b6bde724-4fda-4941-ae3f-15abd3d4107b",
         "rel": "self"
       },
       {
         "href": "http://192.168.204.2:6385/iprofile/b6bde724-4fda-4941-ae3f-15abd3d4107b",
         "rel": "bookmark"
       }
     ],
     "idisks": [
       {
         "href": "http://192.168.204.2:6385/v1/iprofile/b6bde724-4fda-4941-ae3f-15abd3d4107b/idisks",
         "rel": "self"
       },
       {
         "href": "http://192.168.204.2:6385/iprofile/b6bde724-4fda-4941-ae3f-15abd3d4107b/idisks",
         "rel": "bookmark"
       }
     ],
     "availability": "offline",
     "updated_at": null,
     "ihost_uuid": null,
     "id": 23,
     "icpus": [
       {
         "href": "http://192.168.204.2:6385/v1/ihosts/b6bde724-4fda-4941-ae3f-15abd3d4107b/icpus",
         "rel": "self"
       },
       {
         "href": "http://192.168.204.2:6385/ihosts/b6bde724-4fda-4941-ae3f-15abd3d4107b/icpus",
         "rel": "bookmark"
       }
     ],
     "uptime": 0,
     "uuid": "b6bde724-4fda-4941-ae3f-15abd3d4107b",
     "mgmt_ip": null,
     "hostname": "ifprofile-type-1",
     "istors": [
       {
         "href": "http://192.168.204.2:6385/v1/iprofile/b6bde724-4fda-4941-ae3f-15abd3d4107b/istors",
         "rel": "self"
       },
       {
         "href": "http://192.168.204.2:6385/iprofile/b6bde724-4fda-4941-ae3f-15abd3d4107b/istors",
         "rel": "bookmark"
       }
     ],
     "operational": "disabled",
     "location": {
     },
     "invprovision": null,
     "administrative": "locked",
     "personality": null,
     "iinterfaces": [
       {
         "href": "http://192.168.204.2:6385/v1/iprofile/b6bde724-4fda-4941-ae3f-15abd3d4107b/iinterfaces",
         "rel": "self"
       },
       {
         "href": "http://192.168.204.2:6385/iprofile/b6bde724-4fda-4941-ae3f-15abd3d4107b/iinterfaces",
         "rel": "bookmark"
       }
     ],
     "profiletype": null,
     "mgmt_mac": null,
     "task": null,
     "recordtype": "profile",
     "created_at": "2014-09-29T13:36:36.760707+00:00",
     "action": "none",
     "profilename": null,
     "serialId": null,
     "inodes": [
       {
         "href": "http://192.168.204.2:6385/v1/ihosts/b6bde724-4fda-4941-ae3f-15abd3d4107b/inodes",
         "rel": "self"
       },
       {
         "href": "http://192.168.204.2:6385/ihosts/b6bde724-4fda-4941-ae3f-15abd3d4107b/inodes",
         "rel": "bookmark"
       }
     ],
     "imemorys": [
       {
         "href": "http://192.168.204.2:6385/v1/ihosts/b6bde724-4fda-4941-ae3f-15abd3d4107b/imemorys",
         "rel": "self"
       },
       {
         "href": "http://192.168.204.2:6385/ihosts/b6bde724-4fda-4941-ae3f-15abd3d4107b/imemorys",
         "rel": "bookmark"
       }
     ]
   }

****************************
Deletes a specific profile
****************************

.. rest_method:: DELETE /v1/iprofiles/​{profile_id}​

**Normal response codes**

204

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "profile_id", "URI", "csapi:UUID", "The unique identifier of an existing profile."

This operation does not accept a request body.

----
DNS
----

The DNS is the Domain Name Server entity for the system.

************************************
Shows attributes of the DNS object
************************************

.. rest_method:: GET /v1/idns

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "nameservers (Optional)", "plain", "xsd:string", "The comma-separated list of DNS nameservers."
   "isystem_uuid (Optional)", "plain", "csapi:UUID", "The System UUID which the DNS belongs to."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
     "idnss": [
       {
         "links": [
           {
             "href": "http://192.168.204.2:6385/v1/idnss/fab4ff99-ed44-41d0-9e04-2efb3138cf03",
             "rel": "self"
           },
           {
             "href": "http://192.168.204.2:6385/idnss/fab4ff99-ed44-41d0-9e04-2efb3138cf03",
             "rel": "bookmark"
           }
         ],
         "nameservers": "8.8.8.4,8.8.4.5",
         "created_at": "2014-09-30T14:42:16.676726+00:00",
         "updated_at": "2014-10-01T15:10:42.328364+00:00",
         "isystem_uuid": "ce178041-2b2c-405d-bf87-f19334a35582",
         "uuid": "fab4ff99-ed44-41d0-9e04-2efb3138cf03"
       }
     ]
   }

This operation does not accept a request body.

***************************************
Modifies attributes of the DNS object
***************************************

.. rest_method:: PATCH /v1/idns/​{dns_id}​

The attributes of the DNS object that are configurable are:

-  nameservers

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "dns_id", "URI", "csapi:UUID", "The unique identifier of the DNS for this system."
   "nameservers (Optional)", "plain", "xsd:string", "This parameter specifies the list of Domain Name Servers (DNS). Comma separated list."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "nameservers (Optional)", "plain", "xsd:string", "The comma-separated list of DNS nameservers."
   "isystem_uuid (Optional)", "plain", "csapi:UUID", "The System UUID which the DNS belongs to."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   [
     {
       "path": "/nameservers",
       "value": "8.8.8.99,8.8.4.99",
       "op": "replace"
     },
     {
       "path": "/action",
       "value": "apply",
       "op": "replace"
     }
   ]

::

   {
     "links": [
       {
         "href": "http://192.168.204.2:6385/v1/idnss/fab4ff99-ed44-41d0-9e04-2efb3138cf03",
         "rel": "self"
       },
       {
         "href": "http://192.168.204.2:6385/idnss/fab4ff99-ed44-41d0-9e04-2efb3138cf03",
         "rel": "bookmark"
       }
     ],
     "nameservers": "8.8.8.99,8.8.4.99",
     "created_at": "2014-09-30T14:42:16.676726+00:00",
     "updated_at": "2014-10-01T15:13:42.356658+00:00",
     "isystem_uuid": "ce178041-2b2c-405d-bf87-f19334a35582",
     "action": null,
     "forisystemid": 1,
     "uuid": "fab4ff99-ed44-41d0-9e04-2efb3138cf03"
   }

----
NTP
----

The NTP is the Network Time Protocol entity for the system.

************************************
Shows attributes of the NTP object
************************************

.. rest_method:: GET /v1/intp

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "ntpservers (Optional)", "plain", "xsd:string", "The comma-separated list of NTP ntpservers."
   "isystem_uuid (Optional)", "plain", "csapi:UUID", "The System UUID which the NTP belongs to."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
      "intps":[
         {
            "links":[
               {
                  "href":"http://192.168.204.2:6385/v1/intps/81321749-5092-4faf-94ba-6a6853440725",
                  "rel":"self"
               },
               {
                  "href":"http://192.168.204.2:6385/intps/81321749-5092-4faf-94ba-6a6853440725",
                  "rel":"bookmark"
               }
            ],
            "created_at":"2014-09-30T14:42:16.693209+00:00",
            "updated_at":"2014-10-01T17:33:43.169595+00:00",
            "ntpservers":"0.pool.ntp.org,2.pool.ntp.org,1.pool.ntp.org",
            "isystem_uuid":"ce178041-2b2c-405d-bf87-f19334a35582",
            "uuid":"81321749-5092-4faf-94ba-6a6853440725"
         }
      ]
   }

This operation does not accept a request body.

***************************************
Modifies attributes of the NTP object
***************************************

.. rest_method:: PATCH /v1/intp/​{ntp_id}​

The attributes of the NTP object that are configurable are:

-  ntpservers

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "ntp_id", "URI", "csapi:UUID", "The unique identifier of the NTP for this system."
   "ntpservers (Optional)", "plain", "xsd:string", "This parameter specifies the list of Network Time Protocol (NTP) Servers. Comma separated list."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "ntpservers (Optional)", "plain", "xsd:string", "The comma-separated list of NTP ntpservers."
   "isystem_uuid (Optional)", "plain", "csapi:UUID", "The System UUID which the NTP belongs to."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   [
      {
         "path":"/ntpservers",
         "value":"0.pool.ntp.org,1.pool.ntp.org,2.pool.ntp.org",
         "op":"replace"
      },
      {
         "path":"/action",
         "value":"apply",
         "op":"replace"
      }
   ]

::

   {
      "links":[
         {
            "href":"http://192.168.204.2:6385/v1/intps/81321749-5092-4faf-94ba-6a6853440725",
            "rel":"self"
         },
         {
            "href":"http://192.168.204.2:6385/intps/81321749-5092-4faf-94ba-6a6853440725",
            "rel":"bookmark"
         }
      ],
      "created_at":"2014-09-30T14:42:16.693209+00:00",
      "updated_at":"2014-10-01T17:35:43.162472+00:00",
      "ntpservers":"0.pool.ntp.org,1.pool.ntp.org,2.pool.ntp.org",
      "isystem_uuid":"ce178041-2b2c-405d-bf87-f19334a35582",
      "forisystemid":1,
      "uuid":"81321749-5092-4faf-94ba-6a6853440725"
   }

-------------
External OAM
-------------

The extoam is the External OAM entity for the system.

*********************************************
Shows attributes of the External OAM object
*********************************************

.. rest_method:: GET /v1/iextoam

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "oam_subnet (Optional)", "plain", "xsd:string", "The External OAM IP Subnet."
   "oam_gateway_ip (Optional)", "plain", "xsd:string", "The External OAM Gateway IP Address."
   "oam_floating_ip (Optional)", "plain", "xsd:string", "The External OAM Floating IP Address."
   "oam_c0_ip (Optional)", "plain", "xsd:string", "The External OAM Controller-0 IP Address."
   "oam_c1_ip (Optional)", "plain", "xsd:string", "The External OAM Controller-1 IP Address."
   "isystem_uuid (Optional)", "plain", "csapi:UUID", "The System UUID which the External OAM IP belongs to."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
      "iextoams":[
         {
            "links":[
               {
                  "href":"http://192.168.204.2:6385/v1/iextoams/2056b372-10a5-47d3-b1da-8957c370b630",
                  "rel":"self"
               },
               {
                  "href":"http://192.168.204.2:6385/iextoams/2056b372-10a5-47d3-b1da-8957c370b630",
                  "rel":"bookmark"
               }
            ],
            "created_at":"2014-09-30T14:42:16.656226+00:00",
            "updated_at":"2014-10-01T17:35:43.131331+00:00",
            "oam_subnet":"10.10.10.0/24",
            "oam_ifcs":"eth0",
            "oam_gateway_ip":"10.10.10.1",
            "oam_floating_ip":"10.10.10.2",
            "oam_c0_ip":"10.10.10.3",
            "oam_c1_ip":"10.10.10.4",
            "isystem_uuid":"ce178041-2b2c-405d-bf87-f19334a35582",
            "uuid":"2056b372-10a5-47d3-b1da-8957c370b630"
         }
      ]
   }

This operation does not accept a request body.

************************************************
Modifies attributes of the External OAM object
************************************************

.. rest_method:: PATCH /v1/iextoam/​{extoam_id}​

The attributes of the External OAM objects that are configurable are:

-  oam_subnet

-  oam_gateway_ip

-  oam_floating_ip

-  oam_c0_ip

-  oam_c1_ip

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "extoam_id", "URI", "csapi:UUID", "The unique identifier of the External OAM for this system."
   "oam_subnet (Optional)", "plain", "xsd:string", "This parameter specifies External OAM IP Subnet."
   "oam_gateway_ip (Optional)", "plain", "xsd:string", "This parameter specifies External OAM Gateway IP Address."
   "oam_floating_ip (Optional)", "plain", "xsd:string", "This parameter specifies External OAM Floating IP."
   "oam_c0_ip (Optional)", "plain", "xsd:string", "This parameter specifies External OAM Controller-0 IP Address."
   "oam_c1_ip (Optional)", "plain", "xsd:string", "This parameter specifies External OAM Controller-1 IP Address."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "oam_subnet (Optional)", "plain", "xsd:string", "The External OAM IP Subnet."
   "oam_gateway_ip (Optional)", "plain", "xsd:string", "The External OAM Gateway IP Address."
   "oam_floating_ip (Optional)", "plain", "xsd:string", "The External OAM Floating IP Address."
   "oam_c0_ip (Optional)", "plain", "xsd:string", "The External OAM Controller-0 IP Address."
   "oam_c1_ip (Optional)", "plain", "xsd:string", "The External OAM Controller-1 IP Address."
   "isystem_uuid (Optional)", "plain", "csapi:UUID", "The System UUID which the External OAM IP belongs to."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   [
      {
         "path":"/oam_c1_ip",
         "value":"10.10.10.4",
         "op":"replace"
      },
      {
         "path":"/action",
         "value":"apply",
         "op":"replace"
      }
   ]

::

   {
      "iextoams":[
         {
            "links":[
               {
                  "href":"http://192.168.204.2:6385/v1/iextoams/2056b372-10a5-47d3-b1da-8957c370b630",
                  "rel":"self"
               },
               {
                  "href":"http://192.168.204.2:6385/iextoams/2056b372-10a5-47d3-b1da-8957c370b630",
                  "rel":"bookmark"
               }
            ],
            "created_at":"2014-09-30T14:42:16.656226+00:00",
            "updated_at":"2014-10-01T17:35:43.131331+00:00",
            "oam_subnet":"10.10.10.0/24",
            "oam_gateway_ip":"10.10.10.1",
            "oam_floating_ip":"10.10.10.2",
            "oam_c0_ip":"10.10.10.3",
            "oam_c1_ip":"10.10.10.4",
            "isystem_uuid":"ce178041-2b2c-405d-bf87-f19334a35582",
            "uuid":"2056b372-10a5-47d3-b1da-8957c370b630"
         }
      ]
   }

----------------------
Infrastructure Subnet
----------------------

The infra is the Infrastructure subnet entity for the system.

*****************************************************************
Shows attributes of the infrastructure network IP subnet object
*****************************************************************

.. rest_method:: GET /v1/iinfra

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "infra_subnet (Optional)", "plain", "xsd:string", "The infrastructure network IP subnet."
   "infra_start (Optional)", "plain", "xsd:string", "The infrastructure network start IP address."
   "infra_end (Optional)", "plain", "xsd:string", "The infrastructure network end IP address."
   "infra_mtu (Optional)", "plain", "xsd:string", "The MTU of the infrastructure interface."
   "infra_vlan (Optional)", "plain", "xsd:string", "The VLAN id of the infrastructure interface."
   "isystem_uuid (Optional)", "plain", "csapi:UUID", "The System UUID which the infrastructure network IP subnet belongs to."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
      "iinfras":[
         {
            "infra_subnet": "192.168.205.0/24",
            "infra_start": "192.168.205.2",
            "infra_end": "192.168.205.254",
            "infra_mtu": "9216",
            "infra_vlan_id": "137",
            "links":[
               {
                  "href": "http://10.10.10.2:6385/v1/iinfras/15ba72aa-442f-4b57-a8a1-e3f3cdd5b04c",
                  "rel": "self"
               },
               {
                  "href": "http://10.10.10.2:6385/iinfras/15ba72aa-442f-4b57-a8a1-e3f3cdd5b04c",
                  "rel": "bookmark"
               }
            ],
            "created_at": "2014-12-01T19:35:36.965657+00:00",
            "updated_at": "2014-12-02T20:38:51.646902+00:00",
            "isystem_uuid": "b7fdc4dd-333d-471b-b21d-ba664ea87714",
            "uuid": "15ba72aa-442f-4b57-a8a1-e3f3cdd5b04c"
         }
      ]
   }

This operation does not accept a request body.

***************************************************************
Add attributes of the infrastructure network IP subnet object
***************************************************************

.. rest_method:: POST /v1/iinfra

The attributes of the infrastructure network IP subnet object that are
configurable are:

-  infra_subnet

-  infra_start

-  infra_end

-  infra_mtu

-  infra_vlan_id

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "infra_subnet (Optional)", "plain", "xsd:string", "This parameter specifies the infrastructure network IP subnet."
   "infra_start (Optional)", "plain", "xsd:string", "This parameter specifies the infrastructure network start IP address."
   "infra_end (Optional)", "plain", "xsd:string", "This parameter specifies the infrastructure network end IP address."
   "infra_mtu (Optional)", "plain", "xsd:string", "This parameter specifies the MTU of the infrastructure interface."
   "infra_vlan_id (Optional)", "plain", "xsd:string", "This parameter specifies the VLAN ID of the infrastructure interface."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "infra_subnet (Optional)", "plain", "xsd:string", "The infrastructure network IP subnet."
   "infra_start (Optional)", "plain", "xsd:string", "The infrastructure network start IP address."
   "infra_end (Optional)", "plain", "xsd:string", "The infrastructure network end IP address."
   "infra_mtu (Optional)", "plain", "xsd:string", "The MTU of the infrastructure interface."
   "infra_vlan (Optional)", "plain", "xsd:string", "The VLAN id of the infrastructure interface."
   "isystem_uuid (Optional)", "plain", "csapi:UUID", "The System UUID which the infrastructure network IP subnet belongs to."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
      "infra_subnet": "192.168.205.0/24"
      "infra_start": "192.168.205.2",
      "infra_end": "192.168.205.254",
      "infra_mtu": "9216",
      "infra_vlan_id": "137",
   }

::

   {
      "iinfras":[
         {
            "infra_subnet":"192.168.205.0/24",
            "infra_start":"192.168.205.2",
            "infra_end":"192.168.205.254",
            "infra_mtu": "9216",
            "infra_vlan_id": "137",
            "links":[
               {
                  "href":"http://10.10.10.2:6385/v1/iinfras/15ba72aa-442f-4b57-a8a1-e3f3cdd5b04c",
                  "rel":"self"
               },
               {
                  "href":"http://10.10.10.2:6385/iinfras/15ba72aa-442f-4b57-a8a1-e3f3cdd5b04c",
                  "rel":"bookmark"
               }
            ],
            "created_at": "2014-12-01T19:35:36.965657+00:00",
            "updated_at": "2014-12-02T20:38:51.646902+00:00",
            "isystem_uuid": "b7fdc4dd-333d-471b-b21d-ba664ea87714",
            "uuid": "15ba72aa-442f-4b57-a8a1-e3f3cdd5b04c"
         }
      ]
   }

********************************************************************
Modifies attributes of the infrastructure network IP subnet object
********************************************************************

.. rest_method:: PATCH /v1/iinfra/​{infra_id}​

The attributes of the infrastructure network IP subnet object that are
configurable are:

-  infra_start

-  infra_end

-  infra_mtu

-  infra_vlan_id

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "infra_id", "URI", "csapi:UUID", "The unique identifier of the infrastructure network subnet configuration for this system."
   "infra_subnet (Optional)", "plain", "xsd:string", "This parameter specifies the infrastructure network IP subnet."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "infra_subnet (Optional)", "plain", "xsd:string", "The infrastructure network IP subnet."
   "infra_start (Optional)", "plain", "xsd:string", "The infrastructure network start IP address."
   "infra_end (Optional)", "plain", "xsd:string", "The infrastructure network end IP address."
   "infra_mtu (Optional)", "plain", "xsd:string", "The MTU of the infrastructure interface."
   "infra_vlan (Optional)", "plain", "xsd:string", "The VLAN id of the infrastructure interface."
   "isystem_uuid (Optional)", "plain", "csapi:UUID", "The System UUID which the infrastructure network IP subnet belongs to."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   [
      {
         "path":"/infra_subnet",
         "value":"192.168.205.0/24",
         "op":"replace"
      }
   ]

::

   {
      "iinfras":[
         {
            "infra_subnet":"192.168.205.0/24",
            "infra_start":"192.168.205.2",
            "infra_end":"192.168.205.254",
            "infra_mtu": "9216",
            "infra_vlan_id": "137",
            "links":[
               {
                  "href":"http://10.10.10.2:6385/v1/iinfras/15ba72aa-442f-4b57-a8a1-e3f3cdd5b04c",
                  "rel":"self"
               },
               {
                  "href":"http://10.10.10.2:6385/iinfras/15ba72aa-442f-4b57-a8a1-e3f3cdd5b04c",
                  "rel":"bookmark"
               }
            ],
            "created_at": "2014-12-01T19:35:36.965657+00:00",
            "updated_at": "2014-12-02T20:38:51.646902+00:00",
            "isystem_uuid": "b7fdc4dd-333d-471b-b21d-ba664ea87714",
            "uuid": "15ba72aa-442f-4b57-a8a1-e3f3cdd5b04c"
         }
      ]
   }

*******************************************************************
Applies attributes of the infrastructure network IP subnet object
*******************************************************************

.. rest_method:: PATCH /v1/iinfra/​{infra_id}​

**Normal response codes**

204

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "infra_id", "URI", "csapi:UUID", "The unique identifier of the infrastructure network subnet configuration for this system."

::

   [
      {
         "path":"/action",
         "value":"apply",
         "op":"replace"
      }
   ]

::

   {
      "iinfras":[
         {
            "infra_subnet":"192.168.205.0/24",
            "infra_start":"192.168.205.2",
            "infra_end":"192.168.205.254",
            "infra_mtu": "9216",
            "infra_vlan_id": "137",
            "links":[
               {
                  "href":"http://10.10.10.2:6385/v1/iinfras/15ba72aa-442f-4b57-a8a1-e3f3cdd5b04c",
                  "rel":"self"
               },
               {
                  "href":"http://10.10.10.2:6385/iinfras/15ba72aa-442f-4b57-a8a1-e3f3cdd5b04c",
                  "rel":"bookmark"
               }
            ],
            "created_at": "2014-12-01T19:35:36.965657+00:00",
            "updated_at": "2014-12-02T20:38:51.646902+00:00",
            "isystem_uuid": "b7fdc4dd-333d-471b-b21d-ba664ea87714",
            "uuid": "15ba72aa-442f-4b57-a8a1-e3f3cdd5b04c"
         }
      ]
   }

-------------------
DRBD Configuration
-------------------

The drbdconfig is the Distributed Replicated Block Device (DRBD)
configuration entity for the system.

***************************************************
Shows attributes of the DRBD configuration object
***************************************************

.. rest_method:: GET /v1/drbdconfig

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "link_util (Optional)", "plain", "xsd:integer", "The DRBD engineered link utilization percent during resync."
   "num_parallel (Optional)", "plain", "xsd:integer", "The DRBD number of parallel devices to resync."
   "rtt_ms (Optional)", "plain", "xsd:float", "The DRBD replication nodes round-trip-time milliseconds."
   "isystem_uuid (Optional)", "plain", "csapi:UUID", "The System UUID which the DRBD link belongs to."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
       "drbdconfigs": [
           {
               "created_at": "2015-12-14T21:20:23.329867+00:00",
               "isystem_uuid": "88770f18-1ade-4222-b08f-dadd8aa78b32",
               "link_util": 40,
               "links": [
                   {
                       "href": "http://192.168.204.2:6385/v1/drbdconfigs/e23b99b4-62b3-4bcc-a78b-ece63bc0edc5",
                       "rel": "self"
                   },
                   {
                       "href": "http://192.168.204.2:6385/drbdconfigs/e23b99b4-62b3-4bcc-a78b-ece63bc0edc5",
                       "rel": "bookmark"
                   }
               ],
               "num_parallel": 1,
               "rtt_ms": 0.2,
               "updated_at": "2015-12-14T22:15:03.909772+00:00",
               "uuid": "e23b99b4-62b3-4bcc-a78b-ece63bc0edc5"
           }
       ]
   }

This operation does not accept a request body.

******************************************************
Modifies attributes of the DRBD configuration object
******************************************************

.. rest_method:: PATCH /v1/drbdconfig/​{drbdconfig_id}​

The attributes of the DRBD configuration object that are configurable
are:

-  link_util

-  num_parallel

-  rtt_ms

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "drbdconfig_id", "URI", "csapi:UUID", "The unique identifier of the DRBD config for this system."
   "link_util (Optional)", "plain", "xsd:integer", "This parameter specifies the DRBD engineered link utilization percent during resync."
   "num_parallel (Optional)", "plain", "xsd:integer", "This parameter specifies the DRBD number of parallel devices to resync."
   "rtt_ms (Optional)", "plain", "xsd:float", "This parameter specifies the DRBD replication nodes round-trip-time milliseconds."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "link_util (Optional)", "plain", "xsd:integer", "The DRBD engineered link utilization percent during resync."
   "num_parallel (Optional)", "plain", "xsd:integer", "The DRBD number of parallel devices to resync."
   "rtt_ms (Optional)", "plain", "xsd:float", "The DRBD replication nodes round-trip-time milliseconds."
   "isystem_uuid (Optional)", "plain", "csapi:UUID", "The System UUID which the DRBD link belongs to."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   [
       {
           "op": "replace",
           "path": "/link_util",
           "value": "40"
       },
       {
           "op": "replace",
           "path": "/rtt_ms",
           "value": "0.2"
       },
       {
           "op": "replace",
           "path": "/action",
           "value": "apply"
       }
   ]

::

   {
       "action": null,
       "created_at": "2015-12-14T21:20:23.329867+00:00",
       "forisystemid": 1,
       "isystem_uuid": "88770f18-1ade-4222-b08f-dadd8aa78b32",
       "link_util": 40,
       "links": [
           {
               "href": "http://192.168.204.2:6385/v1/drbdconfigs/e23b99b4-62b3-4bcc-a78b-ece63bc0edc5",
               "rel": "self"
           },
           {
               "href": "http://192.168.204.2:6385/drbdconfigs/e23b99b4-62b3-4bcc-a78b-ece63bc0edc5",
               "rel": "bookmark"
           }
       ],
       "num_parallel": 1,
       "rtt_ms": 0.2,
       "updated_at": "2015-12-14T21:20:26.792494+00:00",
       "uuid": "e23b99b4-62b3-4bcc-a78b-ece63bc0edc5"
   }

-----------------
SNMP Communities
-----------------

****************************
Lists all SNMP Communities
****************************

.. rest_method:: GET /v1/icommunity

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "icommunity (Optional)", "plain", "xsd:list", "The list of SNMP Communities."
   "access (Optional)", "plain", "xsd:string", "The SNMP GET/SET access control for a specific community."
   "community (Optional)", "plain", "xsd:string", "The community string of which the SNMP client is a member."
   "view (Optional)", "plain", "xsd:string", "The SNMP MIB view of which the community has access to."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
     "icommunity": [
       {
       "access": "ro",
       "uuid": "744cddaa-8a24-4573-aa0e-4f8b535d95b7",
       "community": "new",
       "view": ".1"
       },
       {
       "access": "ro",
       "uuid": "73706882-9d7c-4a8f-9409-185ffee0066c",
       "community": "guest",
       "view": ".1"
       }
     ]
   }

This operation does not accept a request body.

***************************************************
Shows information about a specific SNMP Community
***************************************************

.. rest_method:: GET /v1/icommunity/​{community_id}​

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "community_id", "URI", "xsd:string", "The unique community string of an existing SNMP Community."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "access (Optional)", "plain", "xsd:string", "The SNMP GET/SET access control for a specific community."
   "community (Optional)", "plain", "xsd:string", "The community string of which the SNMP client is a member."
   "view (Optional)", "plain", "xsd:string", "The SNMP MIB view of which the community has access to."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
       "uuid": "73706882-9d7c-4a8f-9409-185ffee0066c",
       "created_at": "2014-09-24T20:06:54.386982+00:00",
       "updated_at": null,
       "community": "guest",
       "access": "ro",
       "view": ".1"
   }

This operation does not accept a request body.

**************************
Creates a SNMP Community
**************************

.. rest_method:: POST /v1/icommunity

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "community (Optional)", "plain", "xsd:string", "This parameter specifies the community string to create."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "access (Optional)", "plain", "xsd:string", "The SNMP GET/SET access control for a specific community."
   "community (Optional)", "plain", "xsd:string", "The community string of which the SNMP client is a member."
   "view (Optional)", "plain", "xsd:string", "The SNMP MIB view of which the community has access to."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
       "community": "guest"
   }

::

   {
       "uuid": "73706882-9d7c-4a8f-9409-185ffee0066c",
       "created_at": "2014-09-24T20:06:54.386982+00:00",
       "updated_at": null,
       "community": "guest",
       "access": "ro",
       "view": ".1"
   }

************************************
Modifies a specific SNMP Community
************************************

.. rest_method:: PATCH /v1/icommunity/​{community_id}​

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "community_id", "URI", "xsd:string", "The unique community string of an existing SNMP Community."
   "community (Optional)", "plain", "xsd:string", "This parameter specifies the new community string."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "access (Optional)", "plain", "xsd:string", "The SNMP GET/SET access control for a specific community."
   "community (Optional)", "plain", "xsd:string", "The community string of which the SNMP client is a member."
   "view (Optional)", "plain", "xsd:string", "The SNMP MIB view of which the community has access to."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   [
     {
       "path": "/community",
       "value": "wrs",
       "op": "replace"
     }
   ]

::

   {
       "uuid": "744cddaa-8a24-4573-aa0e-4f8b535d95b7",
       "created_at": "2014-09-23T15:01:53.187164+00:00",
       "updated_at": "2014-09-24T19:46:40.138145+00:00",
       "community": "wrs",
       "access": "ro",
        "view": ".1"
   }

***********************************
Deletes a specific SNMP Community
***********************************

.. rest_method:: DELETE /v1/icommunity/​{community_id}​

**Normal response codes**

204

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "community_id", "URI", "xsd:string", "The unique community string of an existing SNMP Community."

This operation does not accept a request body.

-----------------------
SNMP Trap Destinations
-----------------------

**********************************
Lists all SNMP Trap Destinations
**********************************

.. rest_method:: GET /v1/itrapdest

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "itrapdests (Optional)", "plain", "xsd:list", "The list of SNMP Trap Destinations."
   "ip_address (Optional)", "plain", "xsd:string", "The IP address of a specific trap destination."
   "community (Optional)", "plain", "xsd:string", "The community of which the trap destination is a member."
   "type (Optional)", "plain", "xsd:string", "The SNMP version of the trap message for a specific destination."
   "port (Optional)", "plain", "xsd:integer", "The port number of which SNMP manager is listening for traps."
   "transport (Optional)", "plain", "xsd:string", "The transport protocol used by the trap messages."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
     "itrapdest": [
       {
           "uuid": "fc33945c-7aba-4d83-9216-a60db7097a23", "links": [
           {
               "href": "http://192.168.204.2:6385/v1/itrapdest/fc33945c-7aba-4d83-9216-a60db7097a23",
               "rel": "self"
           },
           {
               "href": "http://192.168.204.2:6385/itrapdest/fc33945c-7aba-4d83-9216-a60db7097a23",
               "rel": "bookmark"
           }
         ],
           "ip_address": "10.10.10.1",
           "community": "cgts",
           "type": "snmpv2c_trap",
           "port": 162, "transport": "udp"
       },
       {
           "uuid": "22f0497c-0a09-41c4-8514-cb5afcbf930d", "links": [
           {
               "href": "http://192.168.204.2:6385/v1/itrapdest/22f0497c-0a09-41c4-8514-cb5afcbf930d",
               "rel": "self"
           },
           {
               "href": "http://192.168.204.2:6385/itrapdest/22f0497c-0a09-41c4-8514-cb5afcbf930d",
               "rel": "bookmark"
           }
         ],
           "ip_address": "27.134.0.8",
           "community": "sprint",
           "type": "snmpv2c_trap",
           "port": 162,
           "transport": "udp"
       }
     ]
   }

This operation does not accept a request body.

**********************************************************
Shows information about a specific SNMP Trap Destination
**********************************************************

.. rest_method:: GET /v1/itrapdest/​{trapdest_id}​

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "trapdest_id", "URI", "csapi:UUID", "The unique identifier of an existing SNMP Trap Destination."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "ip_address (Optional)", "plain", "xsd:string", "The IP address of a specific trap destination."
   "community (Optional)", "plain", "xsd:string", "The community of which the trap destination is a member."
   "type (Optional)", "plain", "xsd:string", "The SNMP version of the trap message for a specific destination."
   "port (Optional)", "plain", "xsd:integer", "The port number of which SNMP manager is listening for traps."
   "transport (Optional)", "plain", "xsd:string", "The transport protocol used by the trap messages."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
     "uuid": "22f0497c-0a09-41c4-8514-cb5afcbf930d", "links": [
       {
           "href": "http://192.168.204.2:6385/v1/itrapdest/22f0497c-0a09-41c4-8514-cb5afcbf930d",
           "rel": "self"
       },
       {
           "href": "http://192.168.204.2:6385/itrapdest/22f0497c-0a09-41c4-8514-cb5afcbf930d",
           "rel": "bookmark"
       }
     ],
       "type": "snmpv2c_trap",
       "created_at": "2014-09-24T21:09:02.842231+00:00",
       "updated_at": null,
       "community": "sprint",
       "ip_address": "27.134.0.8",
       "port": 162,
       "transport": "udp"
   }

This operation does not accept a request body.

*********************************
Creates a SNMP Trap Destination
*********************************

.. rest_method:: POST /v1/itrapdest

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "ip_address (Optional)", "plain", "xsd:string", "This parameter specifies the IP address of a new trap destination."
   "community (Optional)", "plain", "xsd:string", "This parameter specifies the community of which the trap destination is a member."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "ip_address (Optional)", "plain", "xsd:string", "The IP address of a specific trap destination."
   "community (Optional)", "plain", "xsd:string", "The community of which the trap destination is a member."
   "type (Optional)", "plain", "xsd:string", "The SNMP version of the trap message for a specific destination."
   "port (Optional)", "plain", "xsd:integer", "The port number of which SNMP manager is listening for traps."
   "transport (Optional)", "plain", "xsd:string", "The transport protocol used by the trap messages."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
       "ip_address": "27.134.0.8",
       "community": "sprint"
   }

::

   {
     "uuid": "22f0497c-0a09-41c4-8514-cb5afcbf930d", "links":
       [
         {
           "href": "http://192.168.204.2:6385/v1/itrapdest/22f0497c-0a09-41c4-8514-cb5afcbf930d",
           "rel": "self"
         },
         {
           "href": "http://192.168.204.2:6385/itrapdest/22f0497c-0a09-41c4-8514-cb5afcbf930d",
           "rel": "bookmark"
         }
       ],
       "type": "snmpv2c_trap",
       "created_at": "2014-09-24T21:09:02.842231+00:00",
       "updated_at": null,
       "community": "sprint",
       "ip_address": "27.134.0.8",
       "port": 162,
       "transport": "udp"
   }

*******************************************
Modifies a specific SNMP Trap Destination
*******************************************

.. rest_method:: PATCH /v1/itrapdest/​{trapdest_id}​

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "trapdest_id", "URI", "csapi:UUID", "The unique identifier of an existing SNMP Trap Destination."
   "ip_address (Optional)", "plain", "xsd:string", "This parameter specifies the IP address of a specific trap destination."
   "community (Optional)", "plain", "xsd:string", "This parameter specifies the community of which the trap destination is a member."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "ip_address (Optional)", "plain", "xsd:string", "The IP address of a specific trap destination."
   "community (Optional)", "plain", "xsd:string", "The community of which the trap destination is a member."
   "type (Optional)", "plain", "xsd:string", "The SNMP version of the trap message for a specific destination."
   "port (Optional)", "plain", "xsd:integer", "The port number of which SNMP manager is listening for traps."
   "transport (Optional)", "plain", "xsd:string", "The transport protocol used by the trap messages."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   [
     {
       "path": "/ip_address",
       "value": "47.10.1.128",
       "op": "replace"
     },
     {
       "path": "/community",
       "value": "sprint",
       "op": "replace"
     }
   ]

::

   {
     "uuid": "22f0497c-0a09-41c4-8514-cb5afcbf930d", "links": [
       {
           "href": "http://192.168.204.2:6385/v1/itrapdest/22f0497c-0a09-41c4-8514-cb5afcbf930d",
           "rel": "self"
       },
       {
           "href": "http://192.168.204.2:6385/itrapdest/22f0497c-0a09-41c4-8514-cb5afcbf930d",
           "rel": "bookmark"
       }
     ],
       "type": "snmpv2c_trap",
       "created_at": "2014-09-24T21:09:02.842231+00:00",
       "updated_at": "2014-09-24T21:13:51.061300+00:00",
       "community": "sprint",
       "ip_address": "47.10.1.128",
       "port": 162,
       "transport": "udp"
   }

******************************************
Deletes a specific SNMP Trap Destination
******************************************

.. rest_method:: DELETE /v1/itrapdest/​{trapdest_id}​

**Normal response codes**

204

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "trapdest_id", "URI", "csapi:UUID", "The unique identifier of an existing SNMP Trap Destination."

This operation does not accept a request body.

--------
Devices
--------

These APIs allow the display of the pci devices of a host and their
attributes.

********************************
List the PCI devices of a host
********************************

.. rest_method:: GET /v1/ihosts/​{host_id}​/pci_devices

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "host_id", "URI", "csapi:UUID", "The unique identifier of an existing host."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "devices (Optional)", "plain", "xsd:list", "The list of PCI devices of a host."
   "name (Optional)", "plain", "xsd:string", "The user-specified name for the PCI device"
   "pciaddr (Optional)", "plain", "xsd:string", "The PCI Address of the device."
   "pclass_id (Optional)", "plain", "xsd:string", "The class or type identifier of the physical IO controller device of the device."
   "pvendor_id (Optional)", "plain", "xsd:boolean", "The primary vendor identifier of the device hardware."
   "pdevice_id (Optional)", "plain", "xsd:boolean", "The primary type and model identifier of the devicehardware."
   "pclass (Optional)", "plain", "xsd:string", "The class or type name of the physical IO controller device of the device."
   "pvendor (Optional)", "plain", "xsd:boolean", "The primary vendor name of the port hardware."
   "pdevice (Optional)", "plain", "xsd:boolean", "The primary type and model information of the device hardware."
   "psvendor (Optional)", "plain", "xsd:boolean", "The secondary vendor information of the device hardware."
   "psdevice (Optional)", "plain", "xsd:boolean", "The secondary type and model information of the device hardware."
   "sriov_totalvfs (Optional)", "plain", "xsd:integer", "Indicates the maximum number of VFs that this device can support."
   "sriov_numvfs (Optional)", "plain", "xsd:integer", "Indicates the actual number of VFs configured for the interface using this device."
   "sriov_vfs_pci_address (Optional)", "plain", "xsd:string", "A comma-separated list of the PCI addresses of the configured VFs."
   "driver (Optional)", "plain", "xsd:string", "The driver being used for the device."
   "enabled (Optional)", "plain", "xsd:string", "The availability status of the device."
   "extra_info (Optional)", "plain", "xsd:string", "Extra information about the device."
   "numa_node (Optional)", "plain", "xsd:integer", "The NUMA Node of the device."
   "host_uuid (Optional)", "plain", "csapi:UUID", "The UUID of the host containing the device."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
     "pci_devices": [
       {
         "uuid": "b2b411a8-1522-4d22-9679-e9fb8b24813b",
         "sriov_numvfs": 0,
         "updated_at": null,
         "pdevice": "440FX - 82441FX PMC [Natoma]",
         "created_at": "2015-11-02T02:15:23.608001+00:00",
         "sriov_totalvfs": null,
         "pdevice_id": "1237",
         "links": [
           {
             "href": "http:\/\/192.168.204.2:6385\/v1\/pci_devices\/b2b411a8-1522-4d22-9679-e9fb8b24813b",
             "rel": "self"
           },
           {
             "href": "http:\/\/192.168.204.2:6385\/pci_devices\/b2b411a8-1522-4d22-9679-e9fb8b24813b",
             "rel": "bookmark"
           }
         ],
         "pclass": "Host bridge",
         "host_uuid": "ae8d3ec5-b2e1-425d-a73f-d7c7b00551fd",
         "psdevice": "",
         "sriov_vfs_pci_address": "",
         "pvendor": "Intel Corporation",
         "pciaddr": "0000:00:00.0",
         "numa_node": -1,
         "pvendor_id": "8086",
         "pclass_id": "60000",
         "driver": null,
         "psvendor": "",
         "enabled": "False",
         "name": "pci_0000_00_00_0"
       },
       {
         "uuid": "49139dd2-3e46-4056-b91d-c7d5cb453524",
         "sriov_numvfs": 0,
         "updated_at": null,
         "pdevice": "82371SB PIIX3 ISA [Natoma\/Triton II]",
         "created_at": "2015-11-02T02:15:23.615088+00:00",
         "sriov_totalvfs": null,
         "pdevice_id": "7000",
         "links": [
           {
             "href": "http:\/\/192.168.204.2:6385\/v1\/pci_devices\/49139dd2-3e46-4056-b91d-c7d5cb453524",
             "rel": "self"
           },
           {
             "href": "http:\/\/192.168.204.2:6385\/pci_devices\/49139dd2-3e46-4056-b91d-c7d5cb453524",
             "rel": "bookmark"
           }
         ],
         "pclass": "ISA bridge",
         "host_uuid": "ae8d3ec5-b2e1-425d-a73f-d7c7b00551fd",
         "psdevice": "",
         "sriov_vfs_pci_address": "",
         "pvendor": "Intel Corporation",
         "pciaddr": "0000:00:01.0",
         "numa_node": -1,
         "pvendor_id": "8086",
         "pclass_id": "60100",
         "driver": null,
         "psvendor": "",
         "enabled": "False",
         "name": "pci_0000_00_01_0"
       },
       {
         "uuid": "4a11043c-c1fe-463f-ab13-01e0b6c12376",
         "sriov_numvfs": 0,
         "updated_at": null,
         "pdevice": "82371AB\/EB\/MB PIIX4 IDE",
         "created_at": "2015-11-02T02:15:23.620579+00:00",
         "sriov_totalvfs": null,
         "pdevice_id": "7111",
         "links": [
           {
             "href": "http:\/\/192.168.204.2:6385\/v1\/pci_devices\/4a11043c-c1fe-463f-ab13-01e0b6c12376",
             "rel": "self"
           },
           {
             "href": "http:\/\/192.168.204.2:6385\/pci_devices\/4a11043c-c1fe-463f-ab13-01e0b6c12376",
             "rel": "bookmark"
           }
         ],
         "pclass": "IDE interface",
         "host_uuid": "ae8d3ec5-b2e1-425d-a73f-d7c7b00551fd",
         "psdevice": "",
         "sriov_vfs_pci_address": "",
         "pvendor": "Intel Corporation",
         "pciaddr": "0000:00:01.1",
         "numa_node": -1,
         "pvendor_id": "8086",
         "pclass_id": "1018a",
         "driver": null,
         "psvendor": "-p8a",
         "enabled": "False",
         "name": "pci_0000_00_01_1"
       },
       {
         "uuid": "09746d46-9ca9-4ef4-a7a4-0fa46c2a9165",
         "sriov_numvfs": 0,
         "updated_at": null,
         "pdevice": "VirtualBox Graphics Adapter",
         "created_at": "2015-11-02T02:15:23.627342+00:00",
         "sriov_totalvfs": null,
         "pdevice_id": "beef",
         "links": [
           {
             "href": "http:\/\/192.168.204.2:6385\/v1\/pci_devices\/09746d46-9ca9-4ef4-a7a4-0fa46c2a9165",
             "rel": "self"
           },
           {
             "href": "http:\/\/192.168.204.2:6385\/pci_devices\/09746d46-9ca9-4ef4-a7a4-0fa46c2a9165",
             "rel": "bookmark"
           }
         ],
         "pclass": "VGA compatible controller",
         "host_uuid": "ae8d3ec5-b2e1-425d-a73f-d7c7b00551fd",
         "psdevice": "",
         "sriov_vfs_pci_address": "",
         "pvendor": "InnoTek Systemberatung GmbH",
         "pciaddr": "0000:00:02.0",
         "numa_node": -1,
         "pvendor_id": "80ee",
         "pclass_id": "30000",
         "driver": null,
         "psvendor": "",
         "enabled": "False",
         "name": "pci_0000_00_02_0"
       },
       {
         "uuid": "56686ced-6dd7-445a-aed9-6ff7399b322e",
         "sriov_numvfs": 0,
         "updated_at": null,
         "pdevice": "82540EM Gigabit Ethernet Controller",
         "created_at": "2015-11-02T02:15:23.632929+00:00",
         "sriov_totalvfs": null,
         "pdevice_id": "100e",
         "links": [
           {
             "href": "http:\/\/192.168.204.2:6385\/v1\/pci_devices\/56686ced-6dd7-445a-aed9-6ff7399b322e",
             "rel": "self"
           },
           {
             "href": "http:\/\/192.168.204.2:6385\/pci_devices\/56686ced-6dd7-445a-aed9-6ff7399b322e",
             "rel": "bookmark"
           }
         ],
         "pclass": "Ethernet controller",
         "host_uuid": "ae8d3ec5-b2e1-425d-a73f-d7c7b00551fd",
         "psdevice": "PRO\/1000 MT Desktop Adapter",
         "sriov_vfs_pci_address": "",
         "pvendor": "Intel Corporation",
         "pciaddr": "0000:00:03.0",
         "numa_node": -1,
         "pvendor_id": "8086",
         "pclass_id": "20000",
         "driver": null,
         "psvendor": "Intel Corporation",
         "enabled": "False",
         "name": "pci_0000_00_03_0"
       },
       {
         "uuid": "93c27653-7858-4025-babf-e72e4b1ba45e",
         "sriov_numvfs": 0,
         "updated_at": null,
         "pdevice": "VirtualBox Guest Service",
         "created_at": "2015-11-02T02:15:23.639261+00:00",
         "sriov_totalvfs": null,
         "pdevice_id": "cafe",
         "links": [
           {
             "href": "http:\/\/192.168.204.2:6385\/v1\/pci_devices\/93c27653-7858-4025-babf-e72e4b1ba45e",
             "rel": "self"
           },
           {
             "href": "http:\/\/192.168.204.2:6385\/pci_devices\/93c27653-7858-4025-babf-e72e4b1ba45e",
             "rel": "bookmark"
           }
         ],
         "pclass": "System peripheral",
         "host_uuid": "ae8d3ec5-b2e1-425d-a73f-d7c7b00551fd",
         "psdevice": "",
         "sriov_vfs_pci_address": "",
         "pvendor": "InnoTek Systemberatung GmbH",
         "pciaddr": "0000:00:04.0",
         "numa_node": -1,
         "pvendor_id": "80ee",
         "pclass_id": "88000",
         "driver": null,
         "psvendor": "",
         "enabled": "False",
         "name": "pci_0000_00_04_0"
       },
       {
         "uuid": "c67c2c89-fc01-4bc7-97a8-d913f5623b7e",
         "sriov_numvfs": 0,
         "updated_at": null,
         "pdevice": "KeyLargo\/Intrepid USB",
         "created_at": "2015-11-02T02:15:23.644716+00:00",
         "sriov_totalvfs": null,
         "pdevice_id": "3f",
         "links": [
           {
             "href": "http:\/\/192.168.204.2:6385\/v1\/pci_devices\/c67c2c89-fc01-4bc7-97a8-d913f5623b7e",
             "rel": "self"
           },
           {
             "href": "http:\/\/192.168.204.2:6385\/pci_devices\/c67c2c89-fc01-4bc7-97a8-d913f5623b7e",
             "rel": "bookmark"
           }
         ],
         "pclass": "USB controller",
         "host_uuid": "ae8d3ec5-b2e1-425d-a73f-d7c7b00551fd",
         "psdevice": "",
         "sriov_vfs_pci_address": "",
         "pvendor": "Apple Inc.",
         "pciaddr": "0000:00:06.0",
         "numa_node": -1,
         "pvendor_id": "106b",
         "pclass_id": "c0310",
         "driver": null,
         "psvendor": "",
         "enabled": "False",
         "name": "pci_0000_00_06_0"
       },
       {
         "uuid": "a769a7d0-c32f-4072-ba2e-73b754361ac6",
         "sriov_numvfs": 0,
         "updated_at": null,
         "pdevice": "82371AB\/EB\/MB PIIX4 ACPI",
         "created_at": "2015-11-02T02:15:23.651222+00:00",
         "sriov_totalvfs": null,
         "pdevice_id": "7113",
         "links": [
           {
             "href": "http:\/\/192.168.204.2:6385\/v1\/pci_devices\/a769a7d0-c32f-4072-ba2e-73b754361ac6",
             "rel": "self"
           },
           {
             "href": "http:\/\/192.168.204.2:6385\/pci_devices\/a769a7d0-c32f-4072-ba2e-73b754361ac6",
             "rel": "bookmark"
           }
         ],
         "pclass": "Bridge",
         "host_uuid": "ae8d3ec5-b2e1-425d-a73f-d7c7b00551fd",
         "psdevice": "",
         "sriov_vfs_pci_address": "",
         "pvendor": "Intel Corporation",
         "pciaddr": "0000:00:07.0",
         "numa_node": -1,
         "pvendor_id": "8086",
         "pclass_id": "68000",
         "driver": null,
         "psvendor": "",
         "enabled": "False",
         "name": "pci_0000_00_07_0"
       },
       {
         "uuid": "40fc39e7-d6bb-4ae5-9c98-0e7a0c71dc6f",
         "sriov_numvfs": 0,
         "updated_at": null,
         "pdevice": "82540EM Gigabit Ethernet Controller",
         "created_at": "2015-11-02T02:15:23.657036+00:00",
         "sriov_totalvfs": null,
         "pdevice_id": "100e",
         "links": [
           {
             "href": "http:\/\/192.168.204.2:6385\/v1\/pci_devices\/40fc39e7-d6bb-4ae5-9c98-0e7a0c71dc6f",
             "rel": "self"
           },
           {
             "href": "http:\/\/192.168.204.2:6385\/pci_devices\/40fc39e7-d6bb-4ae5-9c98-0e7a0c71dc6f",
             "rel": "bookmark"
           }
         ],
         "pclass": "Ethernet controller",
         "host_uuid": "ae8d3ec5-b2e1-425d-a73f-d7c7b00551fd",
         "psdevice": "PRO\/1000 MT Desktop Adapter",
         "sriov_vfs_pci_address": "",
         "pvendor": "Intel Corporation",
         "pciaddr": "0000:00:08.0",
         "numa_node": -1,
         "pvendor_id": "8086",
         "pclass_id": "20000",
         "driver": null,
         "psvendor": "Intel Corporation",
         "enabled": "False",
         "name": "pci_0000_00_08_0"
       },
       {
         "uuid": "a674ae59-aa08-4bef-85a5-ad209809725d",
         "sriov_numvfs": 0,
         "updated_at": null,
         "pdevice": "Virtio network device",
         "created_at": "2015-11-02T02:15:23.662643+00:00",
         "sriov_totalvfs": null,
         "pdevice_id": "1000",
         "links": [
           {
             "href": "http:\/\/192.168.204.2:6385\/v1\/pci_devices\/a674ae59-aa08-4bef-85a5-ad209809725d",
             "rel": "self"
           },
           {
             "href": "http:\/\/192.168.204.2:6385\/pci_devices\/a674ae59-aa08-4bef-85a5-ad209809725d",
             "rel": "bookmark"
           }
         ],
         "pclass": "Ethernet controller",
         "host_uuid": "ae8d3ec5-b2e1-425d-a73f-d7c7b00551fd",
         "psdevice": "Device 0001",
         "sriov_vfs_pci_address": "",
         "pvendor": "Red Hat, Inc",
         "pciaddr": "0000:00:09.0",
         "numa_node": -1,
         "pvendor_id": "1af4",
         "pclass_id": "20000",
         "driver": null,
         "psvendor": "Red Hat, Inc",
         "enabled": "False",
         "name": "pci_0000_00_09_0"
       },
       {
         "uuid": "67d75625-12a6-48ca-8e93-40a704eb7bf7",
         "sriov_numvfs": 0,
         "updated_at": null,
         "pdevice": "Virtio network device",
         "created_at": "2015-11-02T02:15:23.668183+00:00",
         "sriov_totalvfs": null,
         "pdevice_id": "1000",
         "links": [
           {
             "href": "http:\/\/192.168.204.2:6385\/v1\/pci_devices\/67d75625-12a6-48ca-8e93-40a704eb7bf7",
             "rel": "self"
           },
           {
             "href": "http:\/\/192.168.204.2:6385\/pci_devices\/67d75625-12a6-48ca-8e93-40a704eb7bf7",
             "rel": "bookmark"
           }
         ],
         "pclass": "Ethernet controller",
         "host_uuid": "ae8d3ec5-b2e1-425d-a73f-d7c7b00551fd",
         "psdevice": "Device 0001",
         "sriov_vfs_pci_address": "",
         "pvendor": "Red Hat, Inc",
         "pciaddr": "0000:00:0a.0",
         "numa_node": -1,
         "pvendor_id": "1af4",
         "pclass_id": "20000",
         "driver": null,
         "psvendor": "Red Hat, Inc",
         "enabled": "False",
         "name": "pci_0000_00_0a_0"
       },
       {
         "uuid": "4b1d9cf8-81bd-40cb-b873-594faa9d23ef",
         "sriov_numvfs": 0,
         "updated_at": null,
         "pdevice": "82801FB\/FBM\/FR\/FW\/FRW (ICH6 Family) USB2 EHCI Controller",
         "created_at": "2015-11-02T02:15:23.673775+00:00",
         "sriov_totalvfs": null,
         "pdevice_id": "265c",
         "links": [
           {
             "href": "http:\/\/192.168.204.2:6385\/v1\/pci_devices\/4b1d9cf8-81bd-40cb-b873-594faa9d23ef",
             "rel": "self"
           },
           {
             "href": "http:\/\/192.168.204.2:6385\/pci_devices\/4b1d9cf8-81bd-40cb-b873-594faa9d23ef",
             "rel": "bookmark"
           }
         ],
         "pclass": "USB controller",
         "host_uuid": "ae8d3ec5-b2e1-425d-a73f-d7c7b00551fd",
         "psdevice": "",
         "sriov_vfs_pci_address": "",
         "pvendor": "Intel Corporation",
         "pciaddr": "0000:00:0b.0",
         "numa_node": -1,
         "pvendor_id": "8086",
         "pclass_id": "c0320",
         "driver": null,
         "psvendor": "",
         "enabled": "False",
         "name": "pci_0000_00_0b_0"
       }
     ]
   }

This operation does not accept a request body.

***********************************************
Shows the attributes of a specific PCI device
***********************************************

.. rest_method:: GET /v1/devices/​{device_id}​

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "device_id", "URI", "csapi:UUID", "The unique identifier of an existing pci device. PCI address or name."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "name (Optional)", "plain", "xsd:string", "The user-specified name for the PCI device"
   "pciaddr (Optional)", "plain", "xsd:string", "The PCI Address of the device."
   "pclass_id (Optional)", "plain", "xsd:string", "The class or type identifier of the physical IO controller device of the device."
   "pvendor_id (Optional)", "plain", "xsd:boolean", "The primary vendor identifier of the device hardware."
   "pdevice_id (Optional)", "plain", "xsd:boolean", "The primary type and model identifier of the devicehardware."
   "pclass (Optional)", "plain", "xsd:string", "The class or type name of the physical IO controller device of the device."
   "pvendor (Optional)", "plain", "xsd:boolean", "The primary vendor name of the port hardware."
   "pdevice (Optional)", "plain", "xsd:boolean", "The primary type and model information of the device hardware."
   "psvendor (Optional)", "plain", "xsd:boolean", "The secondary vendor information of the device hardware."
   "psdevice (Optional)", "plain", "xsd:boolean", "The secondary type and model information of the device hardware."
   "sriov_totalvfs (Optional)", "plain", "xsd:integer", "Indicates the maximum number of VFs that this device can support."
   "sriov_numvfs (Optional)", "plain", "xsd:integer", "Indicates the actual number of VFs configured for the interface using this device."
   "sriov_vfs_pci_address (Optional)", "plain", "xsd:string", "A comma-separated list of the PCI addresses of the configured VFs."
   "driver (Optional)", "plain", "xsd:string", "The driver being used for the device."
   "enabled (Optional)", "plain", "xsd:string", "The availability status of the device."
   "extra_info (Optional)", "plain", "xsd:string", "Extra information about the device."
   "numa_node (Optional)", "plain", "xsd:integer", "The NUMA Node of the device."
   "host_uuid (Optional)", "plain", "csapi:UUID", "The UUID of the host containing the device."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
     "uuid": "8fdab3b1-c90a-421b-ba5f-5dc2d677dac6",
     "sriov_numvfs": 32,
     "updated_at": "2015-11-04T18:48:09.051858+00:00",
     "pdevice": "Coleto Creek PCIe Endpoint",
     "created_at": "2015-11-04T04:22:59.406921+00:00",
     "sriov_totalvfs": 32,
     "pdevice_id": "435",
     "links": [
       {
         "href": "http:\/\/192.168.204.2:6385\/v1\/pci_devices\/8fdab3b1-c90a-421b-ba5f-5dc2d677dac6",
         "rel": "self"
       },
       {
         "href": "http:\/\/192.168.204.2:6385\/pci_devices\/8fdab3b1-c90a-421b-ba5f-5dc2d677dac6",
         "rel": "bookmark"
       }
     ],
     "pclass": "Co-processor",
     "host_uuid": "aa3fabca-e007-485b-bea9-4f1a0ad9049a",
     "psdevice": "Device 35c5",
     "sriov_vfs_pci_address": "0000:09:01.0,0000:09:01.1,0000:09:01.2,0000:09:01.3,0000:09:01.4,0000:09:01.5,0000:09:01.6,0000:09:01.7,0000:09:02.0,0000:09:02.1,0000:09:02.2,0000:09:02.3,0000:09:02.4,0000:09:02.5,0000:09:02.6,0000:09:02.7,0000:09:03.0,0000:09:03.1,0000:09:03.2,0000:09:03.3,0000:09:03.4,0000:09:03.5,0000:09:03.6,0000:09:03.7,0000:09:04.0,0000:09:04.1,0000:09:04.2,0000:09:04.3,0000:09:04.4,0000:09:04.5,0000:09:04.6,0000:09:04.7",
     "pvendor": "Intel Corporation",
     "pciaddr": "0000:09:00.0",
     "numa_node": 0,
     "pvendor_id": "8086",
     "pclass_id": "b4000",
     "driver": null,
     "psvendor": "Intel Corporation",
     "enabled": "True",
     "name": "pci_0000_09_00_0"
   }

This operation does not accept a request body.

********************************
Modifies a specific PCI device
********************************

.. rest_method:: PATCH /v1/devices/​{device_id}​

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "device_id", "URI", "csapi:UUID", "The unique identifier of an existing pci device. PCI address or name."
   "name (Optional)", "plain", "xsd:string", "The name for the device."
   "enabled (Optional)", "plain", "xsd:string", "The status of this device; i.e. ``True``, ``False``."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "devices (Optional)", "plain", "xsd:list", "URIs to the PCI devices of this host."
   "name (Optional)", "plain", "xsd:string", "The user-specified name for the PCI device"
   "pciaddr (Optional)", "plain", "xsd:string", "The PCI Address of the device."
   "pclass_id (Optional)", "plain", "xsd:string", "The class or type identifier of the physical IO controller device of the device."
   "pvendor_id (Optional)", "plain", "xsd:boolean", "The primary vendor identifier of the device hardware."
   "pdevice_id (Optional)", "plain", "xsd:boolean", "The primary type and model identifier of the devicehardware."
   "pclass (Optional)", "plain", "xsd:string", "The class or type name of the physical IO controller device of the device."
   "pvendor (Optional)", "plain", "xsd:boolean", "The primary vendor name of the port hardware."
   "pdevice (Optional)", "plain", "xsd:boolean", "The primary type and model information of the device hardware."
   "psvendor (Optional)", "plain", "xsd:boolean", "The secondary vendor information of the device hardware."
   "psdevice (Optional)", "plain", "xsd:boolean", "The secondary type and model information of the device hardware."
   "sriov_totalvfs (Optional)", "plain", "xsd:integer", "Indicates the maximum number of VFs that this device can support."
   "sriov_numvfs (Optional)", "plain", "xsd:integer", "Indicates the actual number of VFs configured for the interface using this device."
   "sriov_vfs_pci_address (Optional)", "plain", "xsd:string", "A comma-separated list of the PCI addresses of the configured VFs."
   "driver (Optional)", "plain", "xsd:string", "The driver being used for the device."
   "enabled (Optional)", "plain", "xsd:string", "The availability status of the device."
   "extra_info (Optional)", "plain", "xsd:string", "Extra information about the device."
   "numa_node (Optional)", "plain", "xsd:integer", "The NUMA Node of the device."
   "host_uuid (Optional)", "plain", "csapi:UUID", "The UUID of the host containing the device."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   [
     {
       "path": "/enabled",
       "value": "True",
       "op": "replace"
     },
     {
       "path": "/name",
       "value": "pci_0000_09_00_0",
       "op": "replace"
     }
   ]

::

   {
     "links": [
       {
         "href": "http:\/\/192.168.204.2:6385\/v1\/pci_devices\/8fdab3b1-c90a-421b-ba5f-5dc2d677dac6",
         "rel": "self"
       },
       {
         "href": "http:\/\/192.168.204.2:6385\/pci_devices\/8fdab3b1-c90a-421b-ba5f-5dc2d677dac6",
         "rel": "bookmark"
       }
     ],
     "enabled": "True",
     "updated_at": "2015-11-04T18:48:09.051858+00:00",
     "extra_info": null,
     "uuid": "8fdab3b1-c90a-421b-ba5f-5dc2d677dac6",
     "pdevice": "Coleto Creek PCIe Endpoint",
     "psvendor": "Intel Corporation",
     "psdevice": "Device 35c5",
     "pclass_id": "b4000",
     "pvendor": "Intel Corporation",
     "sriov_numvfs": 32,
     "driver": null,
     "host_uuid": "aa3fabca-e007-485b-bea9-4f1a0ad9049a",
     "name": "pci_0000_09_00_0",
     "numa_node": 0,
     "created_at": "2015-11-04T04:22:59.406921+00:00",
     "pdevice_id": "435",
     "pclass": "Co-processor",
     "sriov_vfs_pci_address": "0000:09:01.0,0000:09:01.1,0000:09:01.2,0000:09:01.3,0000:09:01.4,0000:09:01.5,0000:09:01.6,0000:09:01.7,0000:09:02.0,0000:09:02.1,0000:09:02.2,0000:09:02.3,0000:09:02.4,0000:09:02.5,0000:09:02.6,0000:09:02.7,0000:09:03.0,0000:09:03.1,0000:09:03.2,0000:09:03.3,0000:09:03.4,0000:09:03.5,0000:09:03.6,0000:09:03.7,0000:09:04.0,0000:09:04.1,0000:09:04.2,0000:09:04.3,0000:09:04.4,0000:09:04.5,0000:09:04.6,0000:09:04.7",
     "sriov_totalvfs": 32,
     "pciaddr": "0000:09:00.0",
     "pvendor_id": "8086"
   }

------------------
Service Parameter
------------------

*****************************
List the service parameters
*****************************

.. rest_method:: GET /v1/service_parameter

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "parameters (Optional)", "plain", "xsd:list", "The list of service parameters."
   "service (Optional)", "plain", "xsd:string", "The name of the service."
   "section (Optional)", "plain", "xsd:string", "The section name within the configuration file for the specified service."
   "name (Optional)", "plain", "xsd:string", "The name of the service parameter."
   "value (Optional)", "plain", "xsd:string", "The value of the service parameter."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
      "parameters":[
         {
            "uuid":"7694eca1-21e0-4998-bf2c-15f71b3bddc5",
            "links":[
               {
                  "href":"http://10.10.10.2:6385/v1/parameters/7694eca1-21e0-4998-bf2c-15f71b3bddc5",
                  "rel":"self"
               },
               {
                  "href":"http://10.10.10.2:6385/parameters/7694eca1-21e0-4998-bf2c-15f71b3bddc5",
                  "rel":"bookmark"
               }
            ],
            "section":"assignment",
            "value":"keystone.assignment.backends.sql.Assignment",
            "service":"identity",
            "name":"driver"
         },
         {
            "uuid":"5eeebd50-4809-4d2e-b4ce-1acd9cfeadab",
            "links":[
               {
                  "href":"http://10.10.10.2:6385/v1/parameters/5eeebd50-4809-4d2e-b4ce-1acd9cfeadab",
                  "rel":"self"
               },
               {
                  "href":"http://10.10.10.2:6385/parameters/5eeebd50-4809-4d2e-b4ce-1acd9cfeadab",
                  "rel":"bookmark"
               }
            ],
            "section":"identity",
            "value":"keystone.identity.backends.sql.Identity",
            "service":"identity",
            "name":"driver"
         },
         {
            "uuid":"b84378ae-6e0a-48f0-b394-f8a519fc14f4",
            "links":[
               {
                  "href":"http://10.10.10.2:6385/v1/parameters/b84378ae-6e0a-48f0-b394-f8a519fc14f4",
                  "rel":"self"
               },
               {
                  "href":"http://10.10.10.2:6385/parameters/b84378ae-6e0a-48f0-b394-f8a519fc14f4",
                  "rel":"bookmark"
               }
            ],
            "section":"resource",
            "value":"keystone.resource.backends.sql.Resource",
            "service":"identity",
            "name":"driver"
         },
         {
            "uuid":"6634285f-428e-4ebe-becd-cbb0ab7f30ad",
            "links":[
               {
                  "href":"http://10.10.10.2:6385/v1/parameters/6634285f-428e-4ebe-becd-cbb0ab7f30ad",
                  "rel":"self"
               },
               {
                  "href":"http://10.10.10.2:6385/parameters/6634285f-428e-4ebe-becd-cbb0ab7f30ad",
                  "rel":"bookmark"
               }
            ],
            "section":"role",
            "value":"keystone.assignment.role_backends.sql.Role",
            "service":"identity",
            "name":"driver"
         }
      ]
   }

This operation does not accept a request body.

**************************************************
Shows attributes of the Service parameter object
**************************************************

.. rest_method:: GET /v1/service_parameter/​{parameter_id}​

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "parameter_id", "URI", "csapi:UUID", "The unique identifier of a service parameter."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "service (Optional)", "plain", "xsd:string", "The name of the service."
   "section (Optional)", "plain", "xsd:string", "The section name within the configuration file for the specified service."
   "name (Optional)", "plain", "xsd:string", "The name of the service parameter."
   "value (Optional)", "plain", "xsd:string", "The value of the service parameter."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
      "uuid":"fd5e5e4c-2723-430a-b162-b06b49d94313",
      "links":[
         {
            "href":"http://192.168.204.2:6385/v1/parameters/fd5e5e4c-2723-430a-b162-b06b49d94313",
            "rel":"self"
         },
         {
            "href":"http://192.168.204.2:6385/parameters/fd5e5e4c-2723-430a-b162-b06b49d94313",
            "rel":"bookmark"
         }
      ],
      "section":"identity",
      "updated_at":"2015-12-23T19:07:41.257052+00:00",
      "value":"keystone.identity.backends.sql.Identity",
      "service":"identity",
      "created_at":"2015-12-23T18:54:53.676200+00:00",
      "name":"driver"
   }

This operation does not accept a request body.

**********************************
Creates parameters for a service
**********************************

.. rest_method:: POST /v1/service_parameter

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "service (Optional)", "plain", "xsd:string", "This parameter specifies the name of the service. Valid values are (is): ``identity``"
   "section (Optional)", "plain", "xsd:string", "This parameter specifies the section of the configuration file for the service."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "service (Optional)", "plain", "xsd:string", "The name of the service."
   "section (Optional)", "plain", "xsd:string", "The section name within the configuration file for the specified service."
   "name (Optional)", "plain", "xsd:string", "The name of the service parameter."
   "value (Optional)", "plain", "xsd:string", "The value of the service parameter."

::

   {
      "section":"ldap",
      "parameters":{
         "url":"ldap://localhost",
         "allow_subtree_delete":"False"
      },
      "service":"identity"
   }

::

   {
      "uuid":"399ec29b-5cf4-45e2-a9d0-a640a5a1760c",
      "links":[
         {
            "href":"http://192.168.204.2:6385/v1/parameters/399ec29b-5cf4-45e2-a9d0-a640a5a1760c",
            "rel":"self"
         },
         {
            "href":"http://192.168.204.2:6385/parameters/399ec29b-5cf4-45e2-a9d0-a640a5a1760c",
            "rel":"bookmark"
         }
      ],
      "section":"ldap",
      "updated_at":null,
      "value":"ldap://localhost",
      "service":"identity",
      "created_at":"2015-12-24T15:29:54.954563+00:00",
      "name":"url"
   }
   {
      "uuid":"cff25627-0f2e-42b3-a8b0-34d491c15728",
      "links":[
         {
            "href":"http://192.168.204.2:6385/v1/parameters/cff25627-0f2e-42b3-a8b0-34d491c15728",
            "rel":"self"
         },
         {
            "href":"http://192.168.204.2:6385/parameters/cff25627-0f2e-42b3-a8b0-34d491c15728",
            "rel":"bookmark"
         }
      ],
      "section":"ldap",
      "updated_at":null,
      "value":"False",
      "service":"identity",
      "created_at":"2015-12-24T15:29:54.957636+00:00",
      "name":"allow_subtree_delete"
   }

********************************
Applies the service parameters
********************************

.. rest_method:: POST /v1/service_parameter/apply

**Normal response codes**

204

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "service (Optional)", "plain", "xsd:string", "This parameter specifies the name of the service. Valid values are (is): ``identity``"

::

   {
      "service":"identity"
   }

****************************************************
Modifies the value of the Service parameter object
****************************************************

.. rest_method:: PATCH /v1/service_parameter/​{parameter_id}​

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "parameter_id", "URI", "csapi:UUID", "The unique identifier of a service parameter."
   "name (Optional)", "plain", "xsd:string", "The name for the service parameter."
   "value (Optional)", "plain", "xsd:string", "The value of the service parameter."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "parameters (Optional)", "plain", "xsd:list", "URIs to the service parameters."
   "service (Optional)", "plain", "xsd:string", "The name of the service."
   "section (Optional)", "plain", "xsd:string", "The section name within the configuration file for the specified service."
   "name (Optional)", "plain", "xsd:string", "The name of the service parameter."
   "value (Optional)", "plain", "xsd:string", "The value of the service parameter."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   [
     {
        "path":"/name",
        "value":"suffix",
        "op":"replace"
     },
     {
        "path":"/value",
        "value":"dc=openstack,dc=org",
        "op":"replace"
     }
   ]

::

   {
      "uuid":"b1d07555-ac16-4d5a-ba00-8191f4047bd6",
      "links":[
         {
            "href":"http://192.168.204.2:6385/v1/parameters/b1d07555-ac16-4d5a-ba00-8191f4047bd6",
            "rel":"self"
         },
         {
            "href":"http://192.168.204.2:6385/parameters/b1d07555-ac16-4d5a-ba00-8191f4047bd6",
            "rel":"bookmark"
         }
      ],
      "section":"ldap",
      "updated_at":"2015-12-24T15:37:06.091315+00:00",
      "value":"dc=openstack,dc=org",
      "service":"identity",
      "created_at":"2015-12-23T18:58:03.166244+00:00",
      "name":"suffix"
   }

*****************************
Deletes a service parameter
*****************************

.. rest_method:: DELETE /v1/service_parameter/​{parameter_id}​

**Normal response codes**

204

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "parameter_id", "URI", "csapi:UUID", "The unique identifier of a service parameter."

This operation does not accept a request body.

----------------
SDN Controllers
----------------

These APIs allow for the display and configuration of the SDN
controllers that each of the compute nodes will connect to for the
purpose of SDN manager interface (i.e. OVSDB connection). The SDN
controllers configured are for active connections to the SDN controller
for each of the virtual switch instances running on the compute nodes,
and is shared across all compute nodes.

**************************
List the SDN controllers
**************************

.. rest_method:: GET /v1/sdn_controller

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "sdn_controllers (Optional)", "plain", "xsd:list", "The list of SDN controllers."
   "ip_address (Optional)", "plain", "xsd:string", "This parameter specifies the IP address or FQDN of the SDN controller."
   "port (Optional)", "plain", "xsd:string", "This parameter specifies the listening port number of the OVSDB southbound API of the SDN controller."
   "transport (Optional)", "plain", "xsd:string", "This parameter specifies the transport protocol to use for the connection of the OVSDB protocol. Expected value is TCP. Valid values are: ``UDP`` or ``TCP.``"
   "state (Optional)", "plain", "xsd:string", "This parameter specifies the administrative state of the SDN controller. Valid values are: ``enabled`` or ``disabled.``"
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
       "sdn_controllers" : [{
               "uuid" : "cdae53f1-d842-4a51-a64a-30a682611a24",
               "links" : [{
                       "href" : "http://192.168.204.2:6385/v1/sdn_controllers/cdae53f1-d842-4a51-a64a-30a682611a24",
                       "rel" : "self"
                   }, {
                       "href" : "http://192.168.204.2:6385/sdn_controllers/cdae53f1-d842-4a51-a64a-30a682611a24",
                       "rel" : "bookmark"
                   }
               ],
               "state" : "enabled",
               "ip_address" : "192.168.0.1",
               "port" : 6640,
               "transport" : "TCP"
           }
       ]
   }

This operation does not accept a request body.

****************************************
Shows attributes of the SDN controller
****************************************

.. rest_method:: GET /v1/sdn_controller/​{controller_id}​

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "controller_id", "URI", "csapi:UUID", "The unique identifier of the SDN controller."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "ip_address (Optional)", "plain", "xsd:string", "This parameter specifies the IP address or FQDN of the SDN controller."
   "port (Optional)", "plain", "xsd:string", "This parameter specifies the listening port number of the OVSDB southbound API of the SDN controller."
   "transport (Optional)", "plain", "xsd:string", "This parameter specifies the transport protocol to use for the connection of the OVSDB protocol. Expected value is TCP. Valid values are: ``UDP`` or ``TCP.``"
   "state (Optional)", "plain", "xsd:string", "This parameter specifies the administrative state of the SDN controller. Valid values are: ``enabled`` or ``disabled.``"
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
       "uuid" : "cdae53f1-d842-4a51-a64a-30a682611a24",
       "links" : [{
               "href" : "http://192.168.204.2:6385/v1/sdn_controllers/cdae53f1-d842-4a51-a64a-30a682611a24",
               "rel" : "self"
           }, {
               "href" : "http://192.168.204.2:6385/sdn_controllers/cdae53f1-d842-4a51-a64a-30a682611a24",
               "rel" : "bookmark"
           }
       ],
       "created_at" : "2016-08-16T13:04:30.997350+00:00",
       "updated_at" : null,
       "state" : "enabled",
       "ip_address" : "192.168.0.1",
       "port" : 6640,
       "transport" : "TCP"
   }

This operation does not accept a request body.

************************
Adds an SDN controller
************************

.. rest_method:: POST /v1/sdn_controller

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "ip_address (Optional)", "plain", "xsd:string", "This parameter specifies the IP address or FQDN of the SDN controller."
   "port (Optional)", "plain", "xsd:string", "This parameter specifies the listening port number of the OVSDB southbound API of the SDN controller."
   "transport (Optional)", "plain", "xsd:string", "This parameter specifies the transport protocol to use for the connection of the OVSDB protocol. Expected value is TCP. Valid values are: ``UDP`` or ``TCP.``"
   "state (Optional)", "plain", "xsd:string", "This parameter specifies the administrative state of the SDN controller. Valid values are: ``enabled`` or ``disabled.``"

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "ip_address (Optional)", "plain", "xsd:string", "This parameter specifies the IP address or FQDN of the SDN controller."
   "port (Optional)", "plain", "xsd:string", "This parameter specifies the listening port number of the OVSDB southbound API of the SDN controller."
   "transport (Optional)", "plain", "xsd:string", "This parameter specifies the transport protocol to use for the connection of the OVSDB protocol. Expected value is TCP. Valid values are: ``UDP`` or ``TCP.``"
   "state (Optional)", "plain", "xsd:string", "This parameter specifies the administrative state of the SDN controller. Valid values are: ``enabled`` or ``disabled.``"
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
       "state" : "enabled",
       "ip_address" : "192.168.0.1",
       "port" : "6640",
       "transport" : "TCP"
   }

::

   {
       "uuid" : "55390e8e-1262-4945-8792-40a26206c8a0",
       "links" : [{
               "href" : "http://192.168.204.2:6385/v1/sdn_controllers/55390e8e-1262-4945-8792-40a26206c8a0",
               "rel" : "self"
           }, {
               "href" : "http://192.168.204.2:6385/sdn_controllers/55390e8e-1262-4945-8792-40a26206c8a0",
               "rel" : "bookmark"
           }
       ],
       "created_at" : "2016-08-16T17:06:25.368111+00:00",
       "updated_at" : null,
       "state" : "enabled",
       "ip_address" : "192.168.0.1",
       "port" : 6640,
       "transport" : "TCP"
   }

***********************************************
Modifies the attributes of the SDN controller
***********************************************

.. rest_method:: PATCH /v1/sdn_controller/​{controller_id}​

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "controller_id", "URI", "csapi:UUID", "The unique identifier of the SDN controller."
   "ip_address (Optional)", "plain", "xsd:string", "This parameter specifies the IP address or FQDN of the SDN controller."
   "port (Optional)", "plain", "xsd:string", "This parameter specifies the listening port number of the OVSDB southbound API of the SDN controller."
   "transport (Optional)", "plain", "xsd:string", "This parameter specifies the transport protocol to use for the connection of the OVSDB protocol. Expected value is TCP. Valid values are: ``UDP`` or ``TCP.``"
   "state (Optional)", "plain", "xsd:string", "This parameter specifies the administrative state of the SDN controller. Valid values are: ``enabled`` or ``disabled.``"

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "ip_address (Optional)", "plain", "xsd:string", "This parameter specifies the IP address or FQDN of the SDN controller."
   "port (Optional)", "plain", "xsd:string", "This parameter specifies the listening port number of the OVSDB southbound API of the SDN controller."
   "transport (Optional)", "plain", "xsd:string", "This parameter specifies the transport protocol to use for the connection of the OVSDB protocol. Expected value is TCP. Valid values are: ``UDP`` or ``TCP.``"
   "state (Optional)", "plain", "xsd:string", "This parameter specifies the administrative state of the SDN controller. Valid values are: ``enabled`` or ``disabled.``"
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   [{
           "path" : "/state",
           "value" : "disabled",
           "op" : "replace"
       }, {
           "path" : "/transport",
           "value" : "TCP",
           "op" : "replace"
       }
   ]

::

   {
       "uuid" : "55390e8e-1262-4945-8792-40a26206c8a0",
       "links" : [{
               "href" : "http://192.168.204.2:6385/v1/sdn_controllers/55390e8e-1262-4945-8792-40a26206c8a0",
               "rel" : "self"
           }, {
               "href" : "http://192.168.204.2:6385/sdn_controllers/55390e8e-1262-4945-8792-40a26206c8a0",
               "rel" : "bookmark"
           }
       ],
       "created_at" : "2016-08-16T17:06:25.368111+00:00",
       "updated_at" : "2016-08-16T17:13:31.035249+00:00",
       "state" : "disabled",
       "ip_address" : "192.168.0.1",
       "port" : 6640,
       "transport" : "TCP"
   }

***************************
Deletes an SDN controller
***************************

.. rest_method:: DELETE /v1/sdn_controller/​{controller_id}​

**Normal response codes**

204

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "controller_id", "URI", "csapi:UUID", "The unique identifier of the SDN controller."

This operation does not accept a request body.

---------------
Remote Logging
---------------

These APIs allow the display and configuration of the remote logging
settings

***************************************
Show configuration for remote logging
***************************************

.. rest_method:: GET /v1/remotelogging

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "remoteloggings (Optional)", "plain", "xsd:list", "The list of remotelogging configuration."
   "ip_address (Optional)", "plain", "xsd:string", "IP Address of remote log server."
   "enabled (Optional)", "plain", "xsd:boolean", "Remote log server enabled."
   "transport (Optional)", "plain", "xsd:string", "Remote log server transport protocol."
   "port (Optional)", "plain", "xsd:integer", "Remote log server port."
   "key_file (Optional)", "plain", "xsd:string", "Remote log server TLS key file."

::

   {
      "remoteloggings":[
         {
            "uuid":"319a1a4c-a1b1-4dc0-a29f-b257497619ef",
            "links":[
               {
                  "href":"http://192.168.204.2:6385/v1/remoteloggings/319a1a4c-a1b1-4dc0-a29f-b257497619ef",
                  "rel":"self"
               },
               {
                  "href":"http://192.168.204.2:6385/remoteloggings/319a1a4c-a1b1-4dc0-a29f-b257497619ef",
                  "rel":"bookmark"
               }
            ],
            "created_at":"2016-11-10T19:57:37.969067+00:00",
            "enabled":"False",
            "updated_at":null,
            "key_file":null,
            "ip_address":null,
            "port":514,
            "transport":"udp"
         }
      ]
   }

This operation does not accept a request body.

*****************************************************************
Modifies the configuration of the remote logging of this system
*****************************************************************

.. rest_method:: PATCH /v1/remotelogging/​{remotelogging_id}​

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "remotelogging_id", "URI", "csapi:UUID", "The unique identifier of a remotelogging settings entry."
   "ip_address (Optional)", "plain", "xsd:string", "IP Address of remote log server."
   "enabled (Optional)", "plain", "xsd:boolean", "Remote log server enabled."
   "transport (Optional)", "plain", "xsd:string", "Remote log server transport protocol."
   "port (Optional)", "plain", "xsd:integer", "Remote log server port."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "ip_address (Optional)", "plain", "xsd:string", "IP Address of remote log server."
   "enabled (Optional)", "plain", "xsd:boolean", "Remote log server enabled."
   "transport (Optional)", "plain", "xsd:string", "Remote log server transport protocol."
   "port (Optional)", "plain", "xsd:integer", "Remote log server port."
   "key_file (Optional)", "plain", "xsd:string", "Remote log server TLS key file."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   [
      {
         "path":"/ip_address",
         "value":"10.10.10.45",
         "op":"replace"
      },
      {
         "path":"/enabled",
         "value":"True",
         "op":"replace"
      },
      {
         "path":"/transport",
         "value":"tcp",
         "op":"replace"
      },
      {
         "path":"/port",
         "value":"514",
         "op":"replace"
      },
      {
         "path":"/action",
         "value":"apply",
         "op":"replace"
      }
   ]

::

   {
      "uuid":"319a1a4c-a1b1-4dc0-a29f-b257497619ef",
      "links":[
         {
            "href":"http://192.168.204.2:6385/v1/remoteloggings/319a1a4c-a1b1-4dc0-a29f-b257497619ef",
            "rel":"self"
         },
         {
            "href":"http://192.168.204.2:6385/remoteloggings/319a1a4c-a1b1-4dc0-a29f-b257497619ef",
            "rel":"bookmark"
         }
      ],
      "created_at":"2016-11-10T19:57:37.969067+00:00",
      "enabled":"True",
      "updated_at":null,
      "isystem_uuid":"036b338e-8217-4378-97b2-6a3c097882b4",
      "action":null,
      "key_file":null,
      "ip_address":"10.10.10.45",
      "port":514,
      "transport":"tcp"
   }

---------
Networks
---------

These APIs allow the display of system managed networks. They are
intended for internal system use only.

***********************************************
Shows detailed information about all networks
***********************************************

.. rest_method:: GET /v1/networks

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "uuid (Optional)", "plain", "csapi:UUID", "The uuid of the network resource."
   "name (Optional)", "plain", "xsd:string", "The name of network resource."
   "type (Optional)", "plain", "xsd:string", "The type of network resource."
   "dynamic (Optional)", "plain", "xsd:boolean", "A boolean describing whether IP addresses are assigned by the user (``False``) or by the system (``True``)."
   "pool_uuid (Optional)", "plain", "csapi:UUID", "The uuid of the address pool from which IP addresses are allocated or registered."

::

   {
       "networks": [{
           "uuid": "7b322329-8097-4233-a7df-83eafaba8447",
           "name": "mgmt",
           "type": "mgmt",
           "dynamic": true,
           "pool_uuid": "d7187d17-8715-4934-8754-4827e604a468",
       },
       {
           "uuid": "bf226d1f-39a3-4c3f-abde-8077077835a4",
           "name": "cluster-host",
           "type": "cluster-host",
           "dynamic": true,
           "pool_uuid": "7b299949-614c-4f1a-85cb-c46a09827f0c",
       },
       {
           "uuid": "d735fe97-6e10-4534-8720-1ee2d24ec8ae",
           "name": "oam",
           "type": "oam",
           "dynamic": false,
           "pool_uuid": "c5fced12-40ad-47fa-ad01-6800d1e418b7",
       }]
   }

This operation does not accept a request body.

*****************************************************
Shows detailed information about a specific network
*****************************************************

.. rest_method:: GET /v1/networks/​{network_id}​

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "network_id", "URI", "csapi:UUID", "The unique identifier of the network resource."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "uuid (Optional)", "plain", "csapi:UUID", "The uuid of the network resource."
   "name (Optional)", "plain", "xsd:string", "The name of network resource."
   "type (Optional)", "plain", "xsd:string", "The type of network resource."
   "dynamic (Optional)", "plain", "xsd:boolean", "A boolean describing whether IP addresses are assigned by the user (``False``) or by the system (``True``)."
   "pool_uuid (Optional)", "plain", "csapi:UUID", "The uuid of the address pool from which IP addresses are allocated or registered."

::

   {
       "uuid": "bf226d1f-39a3-4c3f-abde-8077077835a4",
       "created_at": "2016-11-09T14:53:20.185156+00:00",
       "dynamic": true,
       "updated_at": null,
       "pool_uuid": "7b299949-614c-4f1a-85cb-c46a09827f0c",
       "name": "cluster-host",
       "type": "cluster-host",
       "id": 2,
   }

This operation does not accept a request body.

--------------
Address Pools
--------------

These APIs allow the display and configuration of IP address pools.

****************************************************
Shows detailed information about all address pools
****************************************************

.. rest_method:: GET /v1/addrpools

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "name (Optional)", "plain", "xsd:string", "The name (or network type) of the address pool resource."
   "network (Optional)", "plain", "xsd:string", "The IP address of the network."
   "prefix (Optional)", "plain", "xsd:integer", "The network address prefix length in bits."
   "order (Optional)", "plain", "xsd:string", "A string representing the IP address allocation scheme; ``random`` to allocate in random order, or ``sequential`` to allocate in sequential order."
   "ranges (Optional)", "plain", "xsd:string", "A python list, formatted as a JSON string, representing a series of start-end pairs which define the allocatable ranges of IP addresses in the pool."
   "floating_address (Optional)", "plain", "xsd:string", "The floating IP address of the network."
   "controller0_address (Optional)", "plain", "xsd:string", "The controller-0 IP address of the network."
   "controller1_address (Optional)", "plain", "xsd:string", "The  controller-1 IP address of the network."
   "gateway_address (Optional)", "plain", "xsd:string", "The gateway IP address of the network."
   "uuid (Optional)", "plain", "csapi:UUID", "The uuid of the address pool resource."

::

   {
       "addrpools": [{
           "network": "192.168.204.0",
           "name": "management",
           "ranges": [["192.168.204.2",
           "192.168.204.254"]],
           "prefix": 24,
           "order": "random",
           "floating_address": "192.168.204.2",
           "controller0_address": "192.168.204.3",
           "controller1_address": "192.168.204.4",
           "gateway_address": null,
           "uuid": "d7187d17-8715-4934-8754-4827e604a468"
       },
       {
           "network": "192.168.206.0",
           "name": "cluster-host",
           "ranges": [["192.168.206.2",
           "192.168.206.254"]],
           "prefix": 24,
           "order": "random",
           "floating_address": "192.168.206.2",
           "controller0_address": "192.168.206.3",
           "controller1_address": "192.168.206.4",
           "gateway_address": null,
           "uuid": "7b299949-614c-4f1a-85cb-c46a09827f0c"
       },
       {
           "network": "10.10.10.0",
           "name": "oam",
           "ranges": [["10.10.10.1",
           "10.10.10.254"]],
           "prefix": 24,
           "order": "random",
           "floating_address": "10.10.10.3",
           "controller0_address": "10.10.10.4",
           "controller1_address": "10.10.10.5",
           "gateway_address": "10.10.10.1",
           "uuid": "c5fced12-40ad-47fa-ad01-6800d1e418b7"
       }]
   }

This operation does not accept a request body.

**********************
Adds an address pool
**********************

.. rest_method:: POST /v1/addrpools

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "name (Optional)", "plain", "xsd:string", "The name (or network type) of the address pool resource."
   "network (Optional)", "plain", "xsd:string", "The IP address of the network."
   "prefix (Optional)", "plain", "xsd:integer", "The network address prefix length in bits."
   "order (Optional)", "plain", "xsd:string", "A string representing the IP address allocation scheme; ``random`` to allocate in random order, or ``sequential`` to allocate in sequential order."
   "ranges (Optional)", "plain", "xsd:string", "A python list, formatted as a JSON string, representing a series of start-end pairs which define the allocatable ranges of IP addresses in the pool."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "name (Optional)", "plain", "xsd:string", "The name (or network type) of the address pool resource."
   "network (Optional)", "plain", "xsd:string", "The IP address of the network."
   "prefix (Optional)", "plain", "xsd:integer", "The network address prefix length in bits."
   "order (Optional)", "plain", "xsd:string", "A string representing the IP address allocation scheme; ``random`` to allocate in random order, or ``sequential`` to allocate in sequential order."
   "ranges (Optional)", "plain", "xsd:string", "A python list, formatted as a JSON string, representing a series of start-end pairs which define the allocatable ranges of IP addresses in the pool."
   "uuid (Optional)", "plain", "csapi:UUID", "The uuid of the address pool resource."

::

   {
       "ranges": [["1.2.3.1", "1.2.3.10"], ["1.2.3.20", "1.2.3.29"]],
       "network": "1.2.3.0",
       "prefix": "24",
       "order": "random",
       "name": "test1"
   }

::

   {
       "network": "1.2.3.0",
       "updated_at": null,
       "created_at": "2016-11-16T15:50:00.628246+00:00",
       "uuid": "dbac9f9d-2d1f-4c48-99d0-77eb9acac856",
       "id": 8,
       "ranges": [["1.2.3.1", "1.2.3.10"], ["1.2.3.20", "1.2.3.29"]],
       "prefix": 24,
       "order": "random",
       "name": "test1"
   }

**********************************************************
Shows detailed information about a specific address pool
**********************************************************

.. rest_method:: GET /v1/addrpools/​{pool_id}​

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "pool_id", "URI", "csapi:UUID", "The unique identifier of the address pool resource."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "name (Optional)", "plain", "xsd:string", "The name (or network type) of the address pool resource."
   "network (Optional)", "plain", "xsd:string", "The IP address of the network."
   "prefix (Optional)", "plain", "xsd:integer", "The network address prefix length in bits."
   "order (Optional)", "plain", "xsd:string", "A string representing the IP address allocation scheme; ``random`` to allocate in random order, or ``sequential`` to allocate in sequential order."
   "ranges (Optional)", "plain", "xsd:string", "A python list, formatted as a JSON string, representing a series of start-end pairs which define the allocatable ranges of IP addresses in the pool."
   "floating_address (Optional)", "plain", "xsd:string", "The floating IP address of the network."
   "controller0_address (Optional)", "plain", "xsd:string", "The controller-0 IP address of the network."
   "controller1_address (Optional)", "plain", "xsd:string", "The controller-1 IP address of the network."
   "gateway_address (Optional)", "plain", "xsd:string", "The gateway IP address of the network."
   "uuid (Optional)", "plain", "csapi:UUID", "The uuid of the address pool resource."

::

   {
       "network": "192.168.204.0",
       "updated_at": null,
       "created_at": "2016-11-09T15:13:59.652107+00:00",
       "uuid": "366e08ac-a5c8-4554-b019-0a0d2d011e6e",
       "id": 6,
       "ranges": [["192.168.204.2",
       "192.168.204.254"]],
       "prefix": 24,
       "floating_address": "192.168.204.2",
       "controller0_address": "192.168.204.3",
       "controller1_address": "192.168.204.4",
       "order": "random",
       "name": "management",
   }

This operation does not accept a request body.

**************************
Modifies an address pool
**************************

.. rest_method:: PATCH /v1/addrpools/​{pool_id}​

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "pool_id", "URI", "csapi:UUID", "The unique identifier of the address pool resource."
   "name (Optional)", "plain", "xsd:string", "The name (or network type) of the address pool resource."
   "order (Optional)", "plain", "xsd:string", "A string representing the IP address allocation scheme; ``random`` to allocate in random order, or ``sequential`` to allocate in sequential order."
   "ranges (Optional)", "plain", "xsd:string", "A python list, formatted as a JSON string, representing a series of start-end pairs which define the allocatable ranges of IP addresses in the pool."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "name (Optional)", "plain", "xsd:string", "The name (or network type) of the address pool resource."
   "network (Optional)", "plain", "xsd:string", "The IP address of the network."
   "prefix (Optional)", "plain", "xsd:integer", "The network address prefix length in bits."
   "order (Optional)", "plain", "xsd:string", "A string representing the IP address allocation scheme; ``random`` to allocate in random order, or ``sequential`` to allocate in sequential order."
   "ranges (Optional)", "plain", "xsd:string", "A python list, formatted as a JSON string, representing a series of start-end pairs which define the allocatable ranges of IP addresses in the pool."
   "uuid (Optional)", "plain", "csapi:UUID", "The uuid of the address pool resource."

::

   [{
       "path": "/ranges",
       "value": [["192.168.57.2", "192.168.57.11"]],
       "op": "replace"
   },
   {
       "path": "/name",
       "value": "group0-data0v4-modified",
       "op": "replace"
   }]

::

   {
       "network": "192.168.57.0",
       "updated_at": "2016-11-16T15:40:54.855820+00:00",
       "created_at": "2016-11-09T15:13:59.652107+00:00",
       "uuid": "366e08ac-a5c8-4554-b019-0a0d2d011e6e",
       "id": 6,
       "ranges": [["192.168.57.2", "192.168.57.10"]],
       "prefix": 24,
       "order": "random",
       "name": "group0-data0v4-modified"
   }

*************************
Deletes an address pool
*************************

.. rest_method:: DELETE /v1/addrpools/​{pool_id}​

**Normal response codes**

204

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "pool_id", "URI", "csapi:UUID", "The unique identifier of the address pool resource."

This operation does not accept a request body.

----------
Addresses
----------

These APIs allow the display and configuration of IP addresses for a
specific host resource.

************************************************
Shows detailed information about all addresses
************************************************

.. rest_method:: GET /v1/ihosts/​{host_id}​/addresses

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "host_id", "URI", "csapi:UUID", "The unique identifier of an existing host."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "interface_uuid (Optional)", "plain", "csapi:UUID", "The interface uuid to which the address is assigned."
   "address (Optional)", "plain", "xsd:string", "The IP address."
   "prefix (Optional)", "plain", "xsd:integer", "The IP address prefix length in bits."
   "uuid (Optional)", "plain", "csapi:UUID", "The uuid of the address resource."
   "ifname (Optional)", "plain", "xsd:string", "The interface name to which the address is assigned."
   "enable_dad (Optional)", "plain", "xsd:boolean", "Whether duplicate address detection is enabled on allocated addresses."

::

   {
       "addresses": [{
           "forihostid": 1,
           "uuid": "268241c3-99b8-4d0a-9172-49d2ff9681bc",
           "prefix": 24,
           "address": "192.168.204.3",
           "enable_dad": false,
           "ifname": "enp0s8",
           "interface_uuid": "49e994d5-2733-4fab-8e1b-54523afdd2d9",
           "pool_uuid": "d7187d17-8715-4934-8754-4827e604a468"
       },
       {
           "forihostid": 1,
           "uuid": "1a3fb522-be74-4563-a418-6063f9fcf8a1",
           "prefix": 24,
           "address": "192.168.205.3",
           "enable_dad": false,
           "ifname": "eth0.99",
           "interface_uuid": "434df886-4709-4187-8639-ec10d0784a36",
           "pool_uuid": "7b299949-614c-4f1a-85cb-c46a09827f0c"
       },
       {
           "forihostid": 1,
           "uuid": "7040521a-6a59-49ad-a703-0fc35573d4db",
           "prefix": 24,
           "address": "192.168.59.2",
           "enable_dad": false,
           "ifname": "vlan11",
           "interface_uuid": "280baad6-7791-41a5-97f9-f8f8e0f879c5",
           "pool_uuid": null
       },
       {
           "forihostid": 1,
           "uuid": "e7169f61-9b8e-455f-bac3-936b774d4b69",
           "prefix": 64,
           "address": "fd00:0:0:b::2",
           "enable_dad": true,
           "ifname": "vlan11",
           "interface_uuid": "280baad6-7791-41a5-97f9-f8f8e0f879c5",
           "pool_uuid": null
       },
       {
           "forihostid": 1,
           "uuid": "08608f9c-d5f7-4f29-bd71-2d6feee22a6e",
           "prefix": 24,
           "address": "192.168.58.2",
           "enable_dad": false,
           "ifname": "data1",
           "interface_uuid": "6db88b94-fbaa-47a9-95f5-0633036a1a27",
           "pool_uuid": "15a1fa4e-d1c0-49f8-80d9-484640fb95a0"
       },
       {
           "forihostid": 1,
           "uuid": "53bb0f7e-1547-4635-9faf-4d9b8dad2698",
           "prefix": 64,
           "address": "fd00:0:0:2::7",
           "enable_dad": true,
           "ifname": "data1",
           "interface_uuid": "6db88b94-fbaa-47a9-95f5-0633036a1a27",
           "pool_uuid": "04ff8781-9042-4602-a19e-7ed90f0979ad"
       },
       {
           "forihostid": 1,
           "uuid": "369c552a-1da6-4181-afdb-778d3b90d4c9",
           "prefix": 24,
           "address": "192.168.57.2",
           "enable_dad": false,
           "ifname": "data0",
           "interface_uuid": "7a3331e2-88c4-4c30-a49e-67bf924661b4",
           "pool_uuid": "366e08ac-a5c8-4554-b019-0a0d2d011e6e"
       },
       {
           "forihostid": 1,
           "uuid": "af3c8e3c-57ad-4eda-ad5a-f1dbab93875b",
           "prefix": 64,
           "address": "fd00:0:0:1::2",
           "enable_dad": true,
           "ifname": "data0",
           "interface_uuid": "7a3331e2-88c4-4c30-a49e-67bf924661b4",
           "pool_uuid": "950a4587-2baf-4075-994a-98189de51acc"
       }]
   }

This operation does not accept a request body.

*****************
Adds an address
*****************

.. rest_method:: POST /v1/ihosts/​{host_id}​/addresses

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "host_id", "URI", "csapi:UUID", "The unique identifier of an existing host."
   "interface_uuid (Optional)", "plain", "csapi:UUID", "The interface uuid to which the address is assigned."
   "address (Optional)", "plain", "xsd:string", "The IP address."
   "prefix (Optional)", "plain", "xsd:integer", "The IP address prefix length in bits."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "interface_uuid (Optional)", "plain", "csapi:UUID", "The interface uuid to which the address is assigned."
   "address (Optional)", "plain", "xsd:string", "The IP address."
   "prefix (Optional)", "plain", "xsd:integer", "The IP address prefix length in bits."
   "uuid (Optional)", "plain", "csapi:UUID", "The uuid of the address resource."
   "ifname (Optional)", "plain", "xsd:string", "The interface name to which the address is assigned."
   "enable_dad (Optional)", "plain", "xsd:boolean", "Whether duplicate address detection is enabled on allocated addresses."

::

   {
       "prefix": "24",
       "interface_uuid": "4e49a054-3c72-43b8-8e48-1f63dcc5ff7d",
       "address": "192.168.59.3"
   }

::

   {
       "forihostid": 3,
       "uuid": "5dc26260-d825-424d-88d2-b1906022c374",
       "created_at": "2016-11-16T16:03:14.614922+00:00",
       "updated_at": null,
       "pool_uuid": null,
       "prefix": 24,
       "address": "192.168.59.3",
       "enable_dad": false,
       "ifname": "vlan11",
       "interface_uuid": "4e49a054-3c72-43b8-8e48-1f63dcc5ff7d",
       "id": 25,
       "name": null
   }

*****************************************************
Shows detailed information about a specific address
*****************************************************

.. rest_method:: GET /v1/ihosts/​{host_id}​/addresses/​{address_id}​

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "host_id", "URI", "csapi:UUID", "The unique identifier of an existing host."
   "address_id", "URI", "csapi:UUID", "The unique identifier of an address resource."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "interface_uuid (Optional)", "plain", "csapi:UUID", "The interface uuid to which the address is assigned."
   "address (Optional)", "plain", "xsd:string", "The IP address."
   "prefix (Optional)", "plain", "xsd:integer", "The IP address prefix length in bits."
   "uuid (Optional)", "plain", "csapi:UUID", "The uuid of the address resource."
   "ifname (Optional)", "plain", "xsd:string", "The interface name to which the address is assigned."
   "enable_dad (Optional)", "plain", "xsd:boolean", "Whether duplicate address detection is enabled on allocated addresses."

::

   {
       "forihostid": 1,
       "uuid": "369c552a-1da6-4181-afdb-778d3b90d4c9",
       "created_at": "2016-11-09T15:14:09.409615+00:00",
       "updated_at": null,
       "pool_uuid": "366e08ac-a5c8-4554-b019-0a0d2d011e6e",
       "prefix": 24,
       "address": "192.168.57.2",
       "enable_dad": false,
       "ifname": "data0",
       "interface_uuid": "7a3331e2-88c4-4c30-a49e-67bf924661b4",
       "id": 17,
       "name": null
   }

This operation does not accept a request body.

********************
Deletes an address
********************

.. rest_method:: DELETE /v1/ihosts/​{host_id}​/addresses/​{address_id}​

**Normal response codes**

204

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "host_id", "URI", "csapi:UUID", "The unique identifier of an existing host."
   "address_id", "URI", "csapi:UUID", "The unique identifier of an address resource."

This operation does not accept a request body.

-------
Routes
-------

These APIs allow the display and configuration of IP route for a
specific host resource.

*********************************************
Shows detailed information about all routes
*********************************************

.. rest_method:: GET /v1/ihosts/​{host_id}​/routes

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "host_id", "URI", "csapi:UUID", "The unique identifier of an existing host."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "interface_uuid (Optional)", "plain", "csapi:UUID", "The interface uuid to which the address is assigned."
   "network (Optional)", "plain", "xsd:string", "The IP address of the network."
   "prefix (Optional)", "plain", "xsd:integer", "The network address prefix length in bits."
   "gateway (Optional)", "plain", "xsd:string", "The IP address of the nexthop gateway device."
   "metric (Optional)", "plain", "xsd:integer", "The IP route metric/weight."
   "uuid (Optional)", "plain", "csapi:UUID", "The uuid of the route resource."
   "ifname (Optional)", "plain", "xsd:string", "The interface name to which the address is assigned."

::

   {
       "routes": [{
           "forihostid": 3,
           "uuid": "dbacbb57-b3cd-4b9c-b365-0ecf5dec4d60",
           "metric": 1,
           "prefix": 0,
           "ifname": "vlan11",
           "gateway": "192.168.59.1",
           "network": "0.0.0.0"
       },
       {
           "forihostid": 3,
           "uuid": "354968fc-6f18-46dc-93a1-6118280e3cee",
           "metric": 1,
           "prefix": 0,
           "ifname": "vlan11",
           "gateway": "fd00:0:0:b::1",
           "network": "::"
       },
       {
           "forihostid": 3,
           "uuid": "014b66b2-3d57-4c3c-a305-5d417ee75125",
           "metric": 1,
           "prefix": 0,
           "ifname": "data1",
           "gateway": "192.168.58.1",
           "network": "0.0.0.0"
       },
       {
           "forihostid": 3,
           "uuid": "1ef1bc3f-813d-4947-a1a6-1ee9945010d4",
           "metric": 1,
           "prefix": 0,
           "ifname": "data1",
           "gateway": "fd00:0:0:2::1",
           "network": "::"
       },
       {
           "forihostid": 3,
           "uuid": "67255752-ad7f-496d-8d72-b42775fca330",
           "metric": 1,
           "prefix": 0,
           "ifname": "data0",
           "gateway": "192.168.57.1",
           "network": "0.0.0.0"
       },
       {
           "forihostid": 3,
           "uuid": "77c9ac25-49c4-4327-aa3c-f9e868b6a56d",
           "metric": 1,
           "prefix": 0,
           "ifname": "data0",
           "gateway": "fd00:0:0:1::1",
           "network": "::"
       }]
   }

This operation does not accept a request body.

**************
Adds a route
**************

.. rest_method:: POST /v1/ihosts/​{host_id}​/routes

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "host_id", "URI", "csapi:UUID", "The unique identifier of an existing host."
   "interface_uuid (Optional)", "plain", "csapi:UUID", "The interface uuid to which the address is assigned."
   "network (Optional)", "plain", "xsd:string", "The IP address of the network."
   "prefix (Optional)", "plain", "xsd:integer", "The network address prefix length in bits."
   "gateway (Optional)", "plain", "xsd:string", "The IP address of the nexthop gateway device."
   "metric (Optional)", "plain", "xsd:integer", "The IP route metric/weight."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "interface_uuid (Optional)", "plain", "csapi:UUID", "The interface uuid to which the address is assigned."
   "network (Optional)", "plain", "xsd:string", "The IP address of the network."
   "prefix (Optional)", "plain", "xsd:integer", "The network address prefix length in bits."
   "gateway (Optional)", "plain", "xsd:string", "The IP address of the nexthop gateway device."
   "metric (Optional)", "plain", "xsd:integer", "The IP route metric/weight."
   "uuid (Optional)", "plain", "csapi:UUID", "The uuid of the route resource."
   "ifname (Optional)", "plain", "xsd:string", "The interface name to which the address is assigned."

::

   {
       "prefix": "0",
       "interface_uuid": "4e49a054-3c72-43b8-8e48-1f63dcc5ff7d",
       "gateway": "192.168.59.1",
       "metric": "1",
       "network": "0.0.0.0"
   }

::

   {
       "forihostid": 3,
       "network": "0.0.0.0",
       "metric": 1,
       "updated_at": null,
       "gateway": "192.168.59.1",
       "created_at": "2016-11-16T16:49:58.044211+00:00",
       "prefix": 0,
       "ifname": "vlan11",
       "interface_uuid": "4e49a054-3c72-43b8-8e48-1f63dcc5ff7d",
       "id": 14,
       "uuid": "83c1d4e1-9dd4-414b-93e9-61875bc5a180"
   }

***************************************************
Shows detailed information about a specific route
***************************************************

.. rest_method:: GET /v1/ihosts/​{host_id}​/routes/​{route_id}​

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "host_id", "URI", "csapi:UUID", "The unique identifier of an existing host."
   "host_id", "URI", "csapi:UUID", "The unique identifier of a route resource."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "interface_uuid (Optional)", "plain", "csapi:UUID", "The interface uuid to which the address is assigned."
   "network (Optional)", "plain", "xsd:string", "The IP address of the network."
   "prefix (Optional)", "plain", "xsd:integer", "The network address prefix length in bits."
   "gateway (Optional)", "plain", "xsd:string", "The IP address of the nexthop gateway device."
   "metric (Optional)", "plain", "xsd:integer", "The IP route metric/weight."
   "uuid (Optional)", "plain", "csapi:UUID", "The uuid of the route resource."
   "ifname (Optional)", "plain", "xsd:string", "The interface name to which the address is assigned."

::

   {
       "forihostid": 3,
       "network": "0.0.0.0",
       "metric": 1,
       "updated_at": null,
       "gateway": "192.168.57.1",
       "created_at": "2016-11-09T15:58:31.830131+00:00",
       "prefix": 0,
       "ifname": "data0",
       "interface_uuid": "da107d6c-3844-482b-aa5d-2c355f5434d3",
       "id": 11,
       "uuid": "67255752-ad7f-496d-8d72-b42775fca330"
   }

This operation does not accept a request body.

*****************
Deletes a route
*****************

.. rest_method:: DELETE /v1/ihosts/​{host_id}​/routes/​{route_id}​

**Normal response codes**

204

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "host_id", "URI", "csapi:UUID", "The unique identifier of an existing host."
   "host_id", "URI", "csapi:UUID", "The unique identifier of a route resource."

This operation does not accept a request body.

-----------------
Storage Backends
-----------------

These APIs allow the display and configuration of different storage
backends.

***************************
List the storage backends
***************************

.. rest_method:: GET /v1/storage_backend

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "name (Optional)", "plain", "xsd:string", "Name of this backend."
   "backend (Optional)", "plain", "xsd:string", "The type of the storage backend."
   "state (Optional)", "plain", "xsd:string", "The admin state of the storage backend."
   "task (Optional)", "plain", "xsd:string", "The current task of the storage backend when in ""configuring"" state."
   "isystem_uuid (Optional)", "plain", "csapi:UUID", "The System UUID which the storage backend belongs to."
   "capabilities (Optional)", "plain", "xsd:string", "A dictionary of storage backend capabilities."
   "services (Optional)", "plain", "xsd:string", "A comma separated list of backend services."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
       "storage_backends": [
           {
               "task": null,
               "uuid": "9172f885-4a84-41e0-89cd-e350d7fcfeb7",
               "links": [
                   {
                       "href": "http://10.10.10.2:6385/v1/storage_backends/9172f885-4a84-41e0-89cd-e350d7fcfeb7",
                       "rel": "self"
                   },
                   {
                       "href": "http://10.10.10.2:6385/storage_backends/9172f885-4a84-41e0-89cd-e350d7fcfeb7",
                       "rel": "bookmark"
                   }
               ],
               "created_at": "2018-02-06T07:03:55.373879+00:00",
               "updated_at": "2018-02-06T07:04:04.760902+00:00",
               "capabilities": {},
               "services": "glance",
               "state": "configured",
               "isystem_uuid": "d0f2c2ff-9fc2-4ad3-869f-ef9ea6367c0e",
               "backend": "file",
               "name": "file-store"
           }
       ]
   }

This operation does not accept a request body.

*********************************
List the storage backends usage
*********************************

.. rest_method:: GET /v1/storage_backend/usage

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "service_name (Optional)", "plain", "xsd:string", "The name of the storage service."
   "name (Optional)", "plain", "xsd:string", "The name of the storage backend."
   "backend (Optional)", "plain", "xsd:string", "The type of the storage backend."
   "free_capacity (Optional)", "plain", "xsd:decimal", "The free storage capacity in GiB."
   "total_capacity (Optional)", "plain", "xsd:decimal", "The total capacity in GiB."

::

   [
       {
           "free_capacity": 7.48,
           "service_name": "glance",
           "total_capacity": 7.84,
           "name": "file-store",
           "backend": "file"
       },
       {
           "free_capacity": 6.9,
           "service_name": "cinder",
           "total_capacity": 6.9,
           "name": "lvm-store",
           "backend": "lvm"
       }
   ]

This operation does not accept a request body.

***************************
List LVM storage backends
***************************

.. rest_method:: GET /v1/storage_lvm

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "name (Optional)", "plain", "xsd:string", "Name of this backend."
   "backend (Optional)", "plain", "xsd:string", "The type of the storage backend."
   "state (Optional)", "plain", "xsd:string", "The admin state of the storage backend."
   "task (Optional)", "plain", "xsd:string", "The current task of the storage backend when in ""configuring"" state."
   "isystem_uuid (Optional)", "plain", "csapi:UUID", "The System UUID which the storage backend belongs to."
   "capabilities (Optional)", "plain", "xsd:string", "A dictionary of storage backend capabilities."
   "services (Optional)", "plain", "xsd:string", "A comma separated list of backend services."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
       "storage_lvm": [
           {
               "backend": "lvm",
               "capabilities": {},
               "created_at": "2018-03-08T07:52:40.795489+00:00",
               "links": [
                   {
                       "href": "http://192.168.144.103:6385/v1/storage_lvm/4d966cf9-c721-4d44-b9f8-7b7f98e4dc89",
                       "rel": "self"
                   },
                   {
                       "href": "http://192.168.144.103:6385/storage_lvm/4d966cf9-c721-4d44-b9f8-7b7f98e4dc89",
                       "rel": "bookmark"
                   }
               ],
               "name": "lvm-store",
               "services": "cinder",
               "state": "configured",
               "task": null,
               "updated_at": "2018-03-08T07:55:07.253739+00:00",
               "uuid": "4d966cf9-c721-4d44-b9f8-7b7f98e4dc89"
           }
       ]
   }

This operation does not accept a request body.

***************************
Add a Lvm storage backend
***************************

.. rest_method:: POST /v1/storage_lvm

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "backend (Optional)", "plain", "xsd:string", "This parameter specifies the type of the backend. Valid values are (is): ``lvm``"
   "name (Optional)", "plain", "xsd:string", "This parameter specifies the name of the backend."
   "services (Optional)", "plain", "xsd:string", "The name of the storage service."
   "capabilities (Optional)", "plain", "xsd:string", "A dictionary of storage backend capabilities."
   "confirmed (Optional)", "plain", "xsd:boolean", "When ""false"" it will run in test mode without applying any modification. This allow checking a request for validity before performing non-reversible changes. When set to ""true"" the modifications are immediately applied."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "name (Optional)", "plain", "xsd:string", "Name of this backend."
   "backend (Optional)", "plain", "xsd:string", "The type of the storage backend."
   "state (Optional)", "plain", "xsd:string", "The admin state of the storage backend."
   "task (Optional)", "plain", "xsd:string", "The current task of the storage backend when in ""configuring"" state."
   "isystem_uuid (Optional)", "plain", "csapi:UUID", "The System UUID which the storage backend belongs to."
   "capabilities (Optional)", "plain", "xsd:string", "A dictionary of storage backend capabilities."
   "services (Optional)", "plain", "xsd:string", "A comma separated list of backend services."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
       "services": "cinder",
       "confirmed": true
   }

::

   {
       "confirmed": false,
       "task": null,
       "name": "lvm-store",
       "links": [
           {
               "href": "http://10.10.10.2:6385/v1/storage_lvm/5798d210-bbfc-436a-84f3-66dfd1d18aef",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/storage_lvm/5798d210-bbfc-436a-84f3-66dfd1d18aef",
               "rel": "bookmark"
           }
       ],
       "created_at": "2018-02-07T07:47:42.841988+00:00",
       "uuid": "5798d210-bbfc-436a-84f3-66dfd1d18aef",
       "capabilities": {},
       "updated_at": null,
       "state": "configuring",
       "services": "cinder",
       "backend": "lvm"
   }

*********************************************
Shows attributes of the Lvm storage backend
*********************************************

.. rest_method:: GET /v1/storage_lvm/​{storage_lvm_id}​

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "storage_lvm_id", "URI", "csapi:UUID", "The unique identifier of the storage backend."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "name (Optional)", "plain", "xsd:string", "Name of this backend."
   "backend (Optional)", "plain", "xsd:string", "The type of the storage backend."
   "state (Optional)", "plain", "xsd:string", "The admin state of the storage backend."
   "task (Optional)", "plain", "xsd:string", "The current task of the storage backend when in ""configuring"" state."
   "isystem_uuid (Optional)", "plain", "csapi:UUID", "The System UUID which the storage backend belongs to."
   "capabilities (Optional)", "plain", "xsd:string", "A dictionary of storage backend capabilities."
   "services (Optional)", "plain", "xsd:string", "A comma separated list of backend services."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
       "backend": "lvm",
       "capabilities": {},
       "confirmed": false,
       "created_at": "2018-03-08T07:52:40.795489+00:00",
       "links": [
           {
               "href": "http://192.168.144.103:6385/v1/storage_lvm/4d966cf9-c721-4d44-b9f8-7b7f98e4dc89",
               "rel": "self"
           },
           {
               "href": "http://192.168.144.103:6385/storage_lvm/4d966cf9-c721-4d44-b9f8-7b7f98e4dc89",
               "rel": "bookmark"
           }
       ],
       "name": "lvm-store",
       "services": "cinder",
       "state": "configured",
       "task": null,
       "updated_at": "2018-03-08T07:55:07.253739+00:00",
       "uuid": "4d966cf9-c721-4d44-b9f8-7b7f98e4dc89"
   }

This operation does not accept a request body.

**********************************
Modifies the Lvm storage backend
**********************************

.. rest_method:: PATCH /v1/storage_lvm/​{storage_lvm_id}​

LVM backend only supports cinder service and is mandatory. Also, there
is currently no modifiable parameter in the capabilities field. Any
custom defined parameter will remain unused.

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "storage_lvm_id", "URI", "csapi:UUID", "The unique identifier of the storage backend."
   "services (Optional)", "plain", "xsd:string", "The name of the storage service."
   "capabilities (Optional)", "plain", "xsd:string", "A dictionary of storage backend capabilities."
   "confirmed (Optional)", "plain", "xsd:boolean", "When ""false"" it will run in test mode without applying any modification. This allow checking a request for validity before performing non-reversible changes. When set to ""true"" the modifications are immediately applied."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "confirmed (Optional)", "plain", "xsd:boolean", "Returns back parameter in request."
   "name (Optional)", "plain", "xsd:string", "Name of this backend."
   "backend (Optional)", "plain", "xsd:string", "The type of the storage backend."
   "state (Optional)", "plain", "xsd:string", "The admin state of the storage backend."
   "task (Optional)", "plain", "xsd:string", "The current task of the storage backend when in ""configuring"" state."
   "isystem_uuid (Optional)", "plain", "csapi:UUID", "The System UUID which the storage backend belongs to."
   "capabilities (Optional)", "plain", "xsd:string", "A dictionary of storage backend capabilities."
   "services (Optional)", "plain", "xsd:string", "A comma separated list of backend services."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   [
       {
           "path": "/services",
           "value": "cinder,glance",
           "op": "replace"
       }
   ]

::

   {
       "error_message": "{\"debuginfo\": null, \"faultcode\": \"Client\", \"faultstring\": \"Service glance is not supported for the lvm backend\"}"
   }

********************************
Deletes an LVM storage backend
********************************

.. rest_method:: DELETE /v1/storage_lvm/​{storage_lvm_id}​

**Normal response codes**

204

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "storage_lvm_id", "URI", "csapi:UUID", "The unique identifier of the storage backend."

This operation does not accept a request body.

****************************
List Ceph storage backends
****************************

.. rest_method:: GET /v1/storage_ceph

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "name (Optional)", "plain", "xsd:string", "Name of this backend."
   "backend (Optional)", "plain", "xsd:string", "The type of the storage backend."
   "state (Optional)", "plain", "xsd:string", "The admin state of the storage backend."
   "task (Optional)", "plain", "xsd:string", "The current task of the storage backend when in ""configuring"" state."
   "isystem_uuid (Optional)", "plain", "csapi:UUID", "The System UUID which the storage backend belongs to."
   "capabilities (Optional)", "plain", "xsd:string", "A dictionary of storage backend capabilities."
   "services (Optional)", "plain", "xsd:string", "A comma separated list of backend services."
   "cinder_pool_gib (Optional)", "plain", "xsd:integer", "The cinder volumes pool quota in GiB."
   "glance_pool_gib (Optional)", "plain", "xsd:integer", "The glance image pool quota in GiB."
   "ephemeral_pool_gib (Optional)", "plain", "xsd:integer", "The ephemeral pool quota in GiB."
   "object_pool_gib (Optional)", "plain", "xsd:integer", "The object gateway pool quota in GiB."
   "ceph_total_space_gib (Optional)", "plain", "xsd:integer", "The total ceph pool space in GiB."
   "object_gateway (Optional)", "plain", "xsd:boolean", "This specifies if object gateway is configured."
   "tier_name (Optional)", "plain", "xsd:string", "This specifies storage tier name this backend is using ."
   "tier_uuid (Optional)", "plain", "csapi:UUID", "This specifies storage tier uuid this backend is using ."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
       "storage_ceph": [
           {
               "backend": "ceph",
               "capabilities": {
                   "min_replication": "1",
                   "replication": "2"
               },
               "ceph_total_space_gib": 0,
               "cinder_pool_gib": 27,
               "created_at": "2018-03-04T07:19:51.699172+00:00",
               "ephemeral_pool_gib": 0,
               "glance_pool_gib": 21,
               "links": [
                   {
                       "href": "http://192.168.204.2:6385/v1/storage_ceph/bb6a60f6-7fe2-407d-afd0-21d8b6e2f128",
                       "rel": "self"
                   },
                   {
                       "href": "http://192.168.204.2:6385/storage_ceph/bb6a60f6-7fe2-407d-afd0-21d8b6e2f128",
                       "rel": "bookmark"
                   }
               ],
               "name": "ceph-store",
               "object_gateway": true,
               "object_pool_gib": 0,
               "services": "cinder,glance,swift",
               "state": "configured",
               "task": "restore",
               "tier_name": "storage",
               "tier_uuid": "dcb41fcc-307a-4d0b-b5dd-af8c6a48a3c5",
               "updated_at": "2018-03-08T06:13:02.485985+00:00",
               "uuid": "bb6a60f6-7fe2-407d-afd0-21d8b6e2f128"
           },
           {
               "backend": "ceph",
               "capabilities": {
                   "min_replication": "1",
                   "replication": "2"
               },
               "ceph_total_space_gib": 0,
               "cinder_pool_gib": 0,
               "created_at": "2018-03-07T18:56:22.525053+00:00",
               "ephemeral_pool_gib": null,
               "glance_pool_gib": null,
               "links": [
                   {
                       "href": "http://192.168.204.2:6385/v1/storage_ceph/6320a6d5-e3d7-4e63-a02c-964b9a4460f8",
                       "rel": "self"
                   },
                   {
                       "href": "http://192.168.204.2:6385/storage_ceph/6320a6d5-e3d7-4e63-a02c-964b9a4460f8",
                       "rel": "bookmark"
                   }
               ],
               "name": "gold-store",
               "object_gateway": false,
               "object_pool_gib": null,
               "services": "cinder",
               "state": "configured",
               "task": null,
               "tier_name": "gold",
               "tier_uuid": "270e8fa4-8f38-4410-a54a-8e44d8f24f6f",
               "updated_at": "2018-03-07T18:56:56.221489+00:00",
               "uuid": "6320a6d5-e3d7-4e63-a02c-964b9a4460f8"
           }
       ]
   }

This operation does not accept a request body.

****************************
Add a Ceph storage backend
****************************

.. rest_method:: POST /v1/storage_ceph

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "backend (Optional)", "plain", "xsd:string", "This parameter specifies the type of the backend. Valid values are (is): ``ceph``"
   "name (Optional)", "plain", "xsd:string", "This parameter specifies the name of the backend."
   "services (Optional)", "plain", "xsd:string", "The name of the storage service."
   "capabilities (Optional)", "plain", "xsd:string", "A dictionary of storage backend capabilities."
   "confirmed (Optional)", "plain", "xsd:boolean", "When ""false"" it will run in test mode without applying any modification. This allow checking a request for validity before performing non-reversible changes. When set to ""true"" the modifications are immediately applied."
   "cinder_pool_gib (Optional)", "plain", "xsd:integer", "The cinder volumes pool quota in GiB."
   "glance_pool_gib (Optional)", "plain", "xsd:integer", "The glance image pool quota in GiB."
   "ephemeral_pool_gib (Optional)", "plain", "xsd:integer", "The ephemeral pool quota in GiB."
   "object_pool_gib (Optional)", "plain", "xsd:integer", "The object gateway pool quota in GiB."
   "ceph_total_space_gib (Optional)", "plain", "xsd:integer", "The total ceph pool space in GiB."
   "object_gateway (Optional)", "plain", "xsd:boolean", "This specifies if object gateway is configured."
   "tier_name (Optional)", "plain", "xsd:string", "This specifies storage tier name this backend is using ."
   "tier_uuid (Optional)", "plain", "csapi:UUID", "This specifies storage tier uuid this backend is using ."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "name (Optional)", "plain", "xsd:string", "Name of this backend."
   "backend (Optional)", "plain", "xsd:string", "The type of the storage backend."
   "state (Optional)", "plain", "xsd:string", "The admin state of the storage backend."
   "task (Optional)", "plain", "xsd:string", "The current task of the storage backend when in ""configuring"" state."
   "isystem_uuid (Optional)", "plain", "csapi:UUID", "The System UUID which the storage backend belongs to."
   "capabilities (Optional)", "plain", "xsd:string", "A dictionary of storage backend capabilities."
   "services (Optional)", "plain", "xsd:string", "A comma separated list of backend services."
   "cinder_pool_gib (Optional)", "plain", "xsd:integer", "The cinder volumes pool quota in GiB."
   "glance_pool_gib (Optional)", "plain", "xsd:integer", "The glance image pool quota in GiB."
   "ephemeral_pool_gib (Optional)", "plain", "xsd:integer", "The ephemeral pool quota in GiB."
   "object_pool_gib (Optional)", "plain", "xsd:integer", "The object gateway pool quota in GiB."
   "ceph_total_space_gib (Optional)", "plain", "xsd:integer", "The total ceph pool space in GiB."
   "object_gateway (Optional)", "plain", "xsd:boolean", "This specifies if object gateway is configured."
   "tier_name (Optional)", "plain", "xsd:string", "This specifies storage tier name this backend is using ."
   "tier_uuid (Optional)", "plain", "csapi:UUID", "This specifies storage tier uuid this backend is using ."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
       "services": "cinder,glance",
       "confirmed": true
   }

::

   {
       "confirmed": false,
       "tier_uuid": null,
       "cinder_pool_gib": null,
       "uuid": "253f5801-e8bc-468d-a040-1bfa918541ac",
       "links": [
           {
               "href": "http://10.10.10.2:6385/v1/storage_ceph/253f5801-e8bc-468d-a040-1bfa918541ac",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/storage_ceph/253f5801-e8bc-468d-a040-1bfa918541ac",
               "rel": "bookmark"
           }
       ],
       "name": "ceph-store",
       "object_pool_gib": null,
       "updated_at": null,
       "capabilities": {
           "min_replication": "1",
           "replication": "2"
       },
       "ceph_total_space_gib": 0,
       "backend": "ceph",
       "glance_pool_gib": null,
       "state": "configuring",
       "task": "applying-manifests",
       "tier_name": null,
       "services": "cinder,glance",
       "object_gateway": false,
       "created_at": "2018-02-07T08:39:00.880044+00:00",
       "ephemeral_pool_gib": null
   }

**********************************************
Shows attributes of the Ceph storage backend
**********************************************

.. rest_method:: GET /v1/storage_ceph/​{storage_ceph_id}​

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "storage_ceph_id", "URI", "csapi:UUID", "The unique identifier of the storage backend."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "name (Optional)", "plain", "xsd:string", "Name of this backend."
   "backend (Optional)", "plain", "xsd:string", "The type of the storage backend."
   "state (Optional)", "plain", "xsd:string", "The admin state of the storage backend."
   "task (Optional)", "plain", "xsd:string", "The current task of the storage backend when in ""configuring"" state."
   "isystem_uuid (Optional)", "plain", "csapi:UUID", "The System UUID which the storage backend belongs to."
   "capabilities (Optional)", "plain", "xsd:string", "A dictionary of storage backend capabilities."
   "services (Optional)", "plain", "xsd:string", "A comma separated list of backend services."
   "cinder_pool_gib (Optional)", "plain", "xsd:integer", "The cinder volumes pool quota in GiB."
   "glance_pool_gib (Optional)", "plain", "xsd:integer", "The glance image pool quota in GiB."
   "ephemeral_pool_gib (Optional)", "plain", "xsd:integer", "The ephemeral pool quota in GiB."
   "object_pool_gib (Optional)", "plain", "xsd:integer", "The object gateway pool quota in GiB."
   "ceph_total_space_gib (Optional)", "plain", "xsd:integer", "The total ceph pool space in GiB."
   "object_gateway (Optional)", "plain", "xsd:boolean", "This specifies if object gateway is configured."
   "tier_name (Optional)", "plain", "xsd:string", "This specifies storage tier name this backend is using ."
   "tier_uuid (Optional)", "plain", "csapi:UUID", "This specifies storage tier uuid this backend is using ."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
       "backend": "ceph",
       "capabilities": {
           "min_replication": "1",
           "replication": "2"
       },
       "ceph_total_space_gib": 0,
       "cinder_pool_gib": 27,
       "created_at": "2018-03-04T07:19:51.699172+00:00",
       "ephemeral_pool_gib": 0,
       "glance_pool_gib": 21,
       "links": [
           {
               "href": "http://192.168.204.2:6385/v1/storage_ceph/bb6a60f6-7fe2-407d-afd0-21d8b6e2f128",
               "rel": "self"
           },
           {
               "href": "http://192.168.204.2:6385/storage_ceph/bb6a60f6-7fe2-407d-afd0-21d8b6e2f128",
               "rel": "bookmark"
           }
       ],
       "name": "ceph-store",
       "object_gateway": true,
       "object_pool_gib": 0,
       "services": "cinder,glance,swift",
       "state": "configured",
       "task": "restore",
       "tier_name": "storage",
       "tier_uuid": "dcb41fcc-307a-4d0b-b5dd-af8c6a48a3c5",
       "updated_at": "2018-03-08T06:13:02.485985+00:00",
       "uuid": "bb6a60f6-7fe2-407d-afd0-21d8b6e2f128"
   }

This operation does not accept a request body.

***********************************
Modifies the Ceph storage backend
***********************************

.. rest_method:: PATCH /v1/storage_ceph/​{storage_ceph_id}​

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "storage_ceph_id", "URI", "csapi:UUID", "The unique identifier of the storage backend."
   "services (Optional)", "plain", "xsd:string", "The name of the storage service."
   "capabilities (Optional)", "plain", "xsd:string", "A dictionary of storage backend capabilities."
   "confirmed (Optional)", "plain", "xsd:boolean", "When ""false"" it will run in test mode without applying any modification. This allow checking a request for validity before performing non-reversible changes. When set to ""true"" the modifications are immediately applied."
   "cinder_pool_gib (Optional)", "plain", "xsd:integer", "The cinder volumes pool quota in GiB."
   "glance_pool_gib (Optional)", "plain", "xsd:integer", "The glance image pool quota in GiB."
   "ephemeral_pool_gib (Optional)", "plain", "xsd:integer", "The ephemeral pool quota in GiB."
   "object_pool_gib (Optional)", "plain", "xsd:integer", "The object gateway pool quota in GiB."
   "ceph_total_space_gib (Optional)", "plain", "xsd:integer", "The total ceph pool space in GiB."
   "object_gateway (Optional)", "plain", "xsd:boolean", "This specifies if object gateway is configured."
   "tier_name (Optional)", "plain", "xsd:string", "This specifies storage tier name this backend is using ."
   "tier_uuid (Optional)", "plain", "csapi:UUID", "This specifies storage tier uuid this backend is using ."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "name (Optional)", "plain", "xsd:string", "Name of this backend."
   "backend (Optional)", "plain", "xsd:string", "The type of the storage backend."
   "state (Optional)", "plain", "xsd:string", "The admin state of the storage backend."
   "task (Optional)", "plain", "xsd:string", "The current task of the storage backend when in ""configuring"" state."
   "isystem_uuid (Optional)", "plain", "csapi:UUID", "The System UUID which the storage backend belongs to."
   "capabilities (Optional)", "plain", "xsd:string", "A dictionary of storage backend capabilities."
   "services (Optional)", "plain", "xsd:string", "A comma separated list of backend services."
   "cinder_pool_gib (Optional)", "plain", "xsd:integer", "The cinder volumes pool quota in GiB."
   "glance_pool_gib (Optional)", "plain", "xsd:integer", "The glance image pool quota in GiB."
   "ephemeral_pool_gib (Optional)", "plain", "xsd:integer", "The ephemeral pool quota in GiB."
   "object_pool_gib (Optional)", "plain", "xsd:integer", "The object gateway pool quota in GiB."
   "ceph_total_space_gib (Optional)", "plain", "xsd:integer", "The total ceph pool space in GiB."
   "object_gateway (Optional)", "plain", "xsd:boolean", "This specifies if object gateway is configured."
   "tier_name (Optional)", "plain", "xsd:string", "This specifies storage tier name this backend is using ."
   "tier_uuid (Optional)", "plain", "csapi:UUID", "This specifies storage tier uuid this backend is using ."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
       "path": "/capabilities",
       "value": "{\\"min_replication\\": \\"2\\"}",
       "op": "replace"
   }

::

   {
       "backend": "ceph",
       "capabilities": {
           "min_replication": "2",
           "replication": "2"
       },
       "ceph_total_space_gib": 0,
       "cinder_pool_gib": 0,
       "confirmed": false,
       "created_at": "2018-01-04T11:15:41.957698+00:00",
       "ephemeral_pool_gib": 0,
       "glance_pool_gib": 20,
       "links": [
           {
               "href": "http://192.168.204.2:6385/v1/storage_ceph/3f14980c-018f-4f6c-8bfb-82d7c665df06",
               "rel": "self"
           },
           {
               "href": "http://192.168.204.2:6385/storage_ceph/3f14980c-018f-4f6c-8bfb-82d7c665df06",
               "rel": "bookmark"
           }
       ],
       "object_gateway": false,
       "object_pool_gib": 0,
       "services": "cinder,glance",
       "state": "configured",
       "task": null,
       "updated_at": "2018-01-08T01:53:44.446623+00:00",
       "uuid": "3f14980c-018f-4f6c-8bfb-82d7c665df06"
   }

********************************
Deletes a ceph storage backend
********************************

.. rest_method:: DELETE /v1/storage_ceph/​{storage_ceph_id}​

**Normal response codes**

204

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "storage_ceph_id", "URI", "csapi:UUID", "The unique identifier of the storage backend."

This operation does not accept a request body.

*************************************
List Ceph External storage backends
*************************************

.. rest_method:: GET /v1/storage_ceph_external

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "name (Optional)", "plain", "xsd:string", "Name of this backend."
   "backend (Optional)", "plain", "xsd:string", "The type of the storage backend."
   "state (Optional)", "plain", "xsd:string", "The admin state of the storage backend."
   "task (Optional)", "plain", "xsd:string", "The current task of the storage backend when in ""configuring"" state."
   "isystem_uuid (Optional)", "plain", "csapi:UUID", "The System UUID which the storage backend belongs to."
   "capabilities (Optional)", "plain", "xsd:string", "A dictionary of storage backend capabilities."
   "services (Optional)", "plain", "xsd:string", "A comma separated list of backend services."
   "ceph_conf (Optional)", "plain", "xsd:integer", "The Ceph External configuration file."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
       "storage_ceph_external": [
           {
               "task": null,
               "uuid": "ced40c30-5499-48a7-8197-3e1a90b3f402",
               "links": [
                   {
                       "href": "http://192.168.204.2:6385/v1/storage_backends/ced40c30-5499-48a7-8197-3e1a90b3f402",
                       "rel": "self"
                   },
                   {
                       "href": "http://192.168.204.2:6385/storage_backends/ced40c30-5499-48a7-8197-3e1a90b3f402",
                       "rel": "bookmark"
                   }
               ],
               "created_at": "2018-06-27T13:30:38.557700+00:00",
               "updated_at": "2018-06-27T13:35:13.213177+00:00",
               "capabilities": {
                   "cinder_pool": "cinder-volumes"
               },
               "services": "cinder",
               "state": "configured",
               "backend": "ceph-external",
               "name": "ceph-ext-bk"
           }
       ]
   }

This operation does not accept a request body.

*************************************
Add a Ceph External storage backend
*************************************

.. rest_method:: POST /v1/storage_ceph_external

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "backend (Optional)", "plain", "xsd:string", "This parameter specifies the type of the backend. Valid values are (is): ``ceph-external``"
   "name (Optional)", "plain", "xsd:string", "This parameter specifies the name of the backend."
   "services (Optional)", "plain", "xsd:string", "The name of the storage service."
   "capabilities (Optional)", "plain", "xsd:string", "A dictionary of storage backend capabilities."
   "confirmed (Optional)", "plain", "xsd:boolean", "When ""false"" it will run in test mode without applying any modification. This allow checking a request for validity before performing non-reversible changes. When set to ""true"" the modifications are immediately applied."
   "ceph_conf (Optional)", "plain", "xsd:integer", "The Ceph External configuration file."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "name (Optional)", "plain", "xsd:string", "Name of this backend."
   "backend (Optional)", "plain", "xsd:string", "The type of the storage backend."
   "state (Optional)", "plain", "xsd:string", "The admin state of the storage backend."
   "task (Optional)", "plain", "xsd:string", "The current task of the storage backend when in ""configuring"" state."
   "isystem_uuid (Optional)", "plain", "csapi:UUID", "The System UUID which the storage backend belongs to."
   "capabilities (Optional)", "plain", "xsd:string", "A dictionary of storage backend capabilities."
   "services (Optional)", "plain", "xsd:string", "A comma separated list of backend services."
   "ceph_conf (Optional)", "plain", "xsd:integer", "The Ceph External configuration file."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
       "services": "cinder",
       "confirmed": true,
       "name": "ceph-ext-bk",
       "ceph_conf": "ext-ceph.conf",
       "capabilities": {"cinder_pool": "cinder-volumes"}
   }

::

   {
       "confirmed": false,
       "task": null,
       "name": "ceph-ext-bk",
       "links": [
           {
               "href": "http://192.168.204.2:6385/v1/storage_ceph_external/ced40c30-5499-48a7-8197-3e1a90b3f402",
               "rel": "self"
           },
           {
               "href": "http://192.168.204.2:6385/storage_ceph_external/ced40c30-5499-48a7-8197-3e1a90b3f402",
               "rel": "bookmark"
           }
       ],
       "created_at": "2018-06-27T13:30:38.557700+00:00",
       "updated_at": null,
       "uuid": "ced40c30-5499-48a7-8197-3e1a90b3f402",
       "capabilities": {
           "cinder_pool": "cinder-volumes"
       },
       "ceph_conf": null,
       "state": "configuring",
       "services": "cinder",
       "backend": "ceph-external"
   }

*******************************************************
Shows attributes of the Ceph External storage backend
*******************************************************

.. rest_method:: GET /v1/storage_ceph_external/​{storage_ceph_external_id}​

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "storage_ceph_external_id", "URI", "csapi:UUID", "The unique identifier of the storage backend."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "name (Optional)", "plain", "xsd:string", "Name of this backend."
   "backend (Optional)", "plain", "xsd:string", "The type of the storage backend."
   "state (Optional)", "plain", "xsd:string", "The admin state of the storage backend."
   "task (Optional)", "plain", "xsd:string", "The current task of the storage backend when in ""configuring"" state."
   "isystem_uuid (Optional)", "plain", "csapi:UUID", "The System UUID which the storage backend belongs to."
   "capabilities (Optional)", "plain", "xsd:string", "A dictionary of storage backend capabilities."
   "services (Optional)", "plain", "xsd:string", "A comma separated list of backend services."
   "ceph_conf (Optional)", "plain", "xsd:integer", "The Ceph External configuration file."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
       "confirmed": false,
       "task": null,
       "uuid": "ced40c30-5499-48a7-8197-3e1a90b3f402",
       "links": [
            {
                "href": "http://192.168.204.2:6385/v1/storage_ceph_external/ced40c30-5499-48a7-8197-3e1a90b3f402",
                "rel": "self"
            },
            {
                "href": "http://192.168.204.2:6385/storage_ceph_external/ced40c30-5499-48a7-8197-3e1a90b3f402",
                "rel": "bookmark"
            }
       ],
       "created_at": "2018-06-27T13:30:38.557700+00:00",
       "updated_at": "2018-06-27T13:35:13.213177+00:00",
       "capabilities": {
           "cinder_pool": "cinder-volumes"
       },
       "name": "ceph-ext-bk",
       "services": "cinder",
       "state": "configured",
       "ceph_conf": "ext-ceph.conf",
       "backend": "ceph-external"
   }

This operation does not accept a request body.

*********************************************
Modifies the Ceph External storage backend
*********************************************

.. rest_method:: PATCH /v1/storage_ceph_external/​{storage_ceph_external_id}​

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "storage_ceph_external_id", "URI", "csapi:UUID", "The unique identifier of the storage backend."
   "services (Optional)", "plain", "xsd:string", "The name of the storage service."
   "capabilities (Optional)", "plain", "xsd:string", "A dictionary of storage backend capabilities."
   "confirmed (Optional)", "plain", "xsd:boolean", "When ""false"" it will run in test mode without applying any modification. This allow checking a request for validity before performing non-reversible changes. When set to ""true"" the modifications are immediately applied."
   "ceph_conf (Optional)", "plain", "xsd:integer", "The Ceph External configuration file."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "name (Optional)", "plain", "xsd:string", "Name of this backend."
   "backend (Optional)", "plain", "xsd:string", "The type of the storage backend."
   "state (Optional)", "plain", "xsd:string", "The admin state of the storage backend."
   "task (Optional)", "plain", "xsd:string", "The current task of the storage backend when in ""configuring"" state."
   "isystem_uuid (Optional)", "plain", "csapi:UUID", "The System UUID which the storage backend belongs to."
   "capabilities (Optional)", "plain", "xsd:string", "A dictionary of storage backend capabilities."
   "services (Optional)", "plain", "xsd:string", "A comma separated list of backend services."
   "ceph_conf (Optional)", "plain", "xsd:integer", "The Ceph External configuration file."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   [
       {
           "path": "/services",
           "value": "cinder,glance",
           "op": "replace"
       }
       {
           "path": "/capabilities",
           "value": "{\\"glance_pool\\": \\"images\\"}",
           "op": "replace"
       }
   ]

::

   {
       "confirmed": false,
       "task": null,
       "uuid": "ced40c30-5499-48a7-8197-3e1a90b3f402",
       "links": [
           {
               "href": "http://192.168.204.2:6385/v1/storage_ceph_external/ced40c30-5499-48a7-8197-3e1a90b3f402",
               "rel": "self"
           },
           {
               "href": "http://192.168.204.2:6385/storage_ceph_external/ced40c30-5499-48a7-8197-3e1a90b3f402",
               "rel": "bookmark"
           }
       ],
       "created_at": "2018-06-27T13:30:38.557700+00:00",
       "updated_at": "2018-06-27T13:35:13.213177+00:00",
       "capabilities": {
           "glance_pool": "images",
           "cinder_pool": "cinder-volumes"
       },
       "name": "ceph-ext-bk",
       "services": "cinder,glance",
       "state": "configured",
       "ceph_conf": "ext-ceph.conf",
       "backend": "ceph-external"
   }

******************************************
Deletes a ceph External storage backend
******************************************

.. rest_method:: DELETE /v1/storage_ceph_external/​{storage_ceph_external_id}​

**Normal response codes**

204

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "storage_ceph_external_id", "URI", "csapi:UUID", "The unique identifier of the storage backend."

This operation does not accept a request body.

****************************
List file storage backends
****************************

.. rest_method:: GET /v1/storage_file

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "name (Optional)", "plain", "xsd:string", "Name of this backend."
   "backend (Optional)", "plain", "xsd:string", "The type of the storage backend."
   "state (Optional)", "plain", "xsd:string", "The admin state of the storage backend."
   "task (Optional)", "plain", "xsd:string", "The current task of the storage backend when in ""configuring"" state."
   "isystem_uuid (Optional)", "plain", "csapi:UUID", "The System UUID which the storage backend belongs to."
   "capabilities (Optional)", "plain", "xsd:string", "A dictionary of storage backend capabilities."
   "services (Optional)", "plain", "xsd:string", "A comma separated list of backend services."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
       "storage_file": [
           {
               "backend": "file",
               "capabilities": {},
               "created_at": "2018-03-08T05:29:55.246907+00:00",
               "links": [
                   {
                       "href": "http://192.168.144.2:6385/v1/storage_file/e9e734b0-8143-4835-b70a-21267f5d8ca9",
                       "rel": "self"
                   },
                   {
                       "href": "http://192.168.144.2:6385/storage_file/e9e734b0-8143-4835-b70a-21267f5d8ca9",
                       "rel": "bookmark"
                   }
               ],
               "name": "file-store",
               "services": "glance",
               "state": "configured",
               "task": null,
               "updated_at": "2018-03-08T05:29:59.518621+00:00",
               "uuid": "e9e734b0-8143-4835-b70a-21267f5d8ca9"
           }
       ]
   }

This operation does not accept a request body.

****************************
Add a File storage backend
****************************

.. rest_method:: POST /v1/storage_file

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "backend (Optional)", "plain", "xsd:string", "This parameter specifies the type of the backend. Valid values are (is): ``file``"
   "name (Optional)", "plain", "xsd:string", "This parameter specifies the name of the backend."
   "services (Optional)", "plain", "xsd:string", "The name of the storage service."
   "capabilities (Optional)", "plain", "xsd:string", "A dictionary of storage backend capabilities."
   "confirmed (Optional)", "plain", "xsd:boolean", "When ""false"" it will run in test mode without applying any modification. This allow checking a request for validity before performing non-reversible changes. When set to ""true"" the modifications are immediately applied."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "name (Optional)", "plain", "xsd:string", "Name of this backend."
   "backend (Optional)", "plain", "xsd:string", "The type of the storage backend."
   "state (Optional)", "plain", "xsd:string", "The admin state of the storage backend."
   "task (Optional)", "plain", "xsd:string", "The current task of the storage backend when in ""configuring"" state."
   "isystem_uuid (Optional)", "plain", "csapi:UUID", "The System UUID which the storage backend belongs to."
   "capabilities (Optional)", "plain", "xsd:string", "A dictionary of storage backend capabilities."
   "services (Optional)", "plain", "xsd:string", "A comma separated list of backend services."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
       "name": "new-file-store",
       "services": "glance",
       "confirmed": true
   }

::

   {
       "confirmed": false,
       "task": null,
       "uuid": "c70ab134-20f3-419f-8048-66ba9fae960d",
       "links": [
           {
               "href": "http://10.10.10.2:6385/v1/storage_file/c70ab134-20f3-419f-8048-66ba9fae960d",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/storage_file/c70ab134-20f3-419f-8048-66ba9fae960d",
               "rel": "bookmark"
           }
       ],
       "created_at": "2018-02-07T09:19:35.077198+00:00",
       "updated_at": null,
       "capabilities": {},
       "name": "new-file-store",
       "state": "configuring",
       "services": "glance",
       "backend": "file"
   }

**********************************************
Shows attributes of the file storage backend
**********************************************

.. rest_method:: GET /v1/storage_file/​{storage_file_id}​

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "storage_file_id", "URI", "csapi:UUID", "The unique identifier of the storage backend."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "name (Optional)", "plain", "xsd:string", "Name of this backend."
   "backend (Optional)", "plain", "xsd:string", "The type of the storage backend."
   "state (Optional)", "plain", "xsd:string", "The admin state of the storage backend."
   "task (Optional)", "plain", "xsd:string", "The current task of the storage backend when in ""configuring"" state."
   "isystem_uuid (Optional)", "plain", "csapi:UUID", "The System UUID which the storage backend belongs to."
   "capabilities (Optional)", "plain", "xsd:string", "A dictionary of storage backend capabilities."
   "services (Optional)", "plain", "xsd:string", "A comma separated list of backend services."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
       "backend": "file",
       "capabilities": {},
       "confirmed": false,
       "created_at": "2018-03-08T19:12:34.419453+00:00",
       "links": [
           {
               "href": "http://192.168.144.103:6385/v1/storage_file/a9c3d775-8913-4b92-a091-3bd1b905a6a5",
               "rel": "self"
           },
           {
               "href": "http://192.168.144.103:6385/storage_file/a9c3d775-8913-4b92-a091-3bd1b905a6a5",
               "rel": "bookmark"
           }
       ],
       "name": "file-store",
       "services": "glance",
       "state": "configured",
       "task": null,
       "updated_at": "2018-03-08T19:12:34.463159+00:00",
       "uuid": "a9c3d775-8913-4b92-a091-3bd1b905a6a5"
   }

This operation does not accept a request body.

***********************************
Modifies the File storage backend
***********************************

.. rest_method:: PATCH /v1/storage_file/​{storage_file_id}​

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "storage_file_id", "URI", "csapi:UUID", "The unique identifier of the storage backend."
   "services (Optional)", "plain", "xsd:string", "The name of the storage service."
   "capabilities (Optional)", "plain", "xsd:string", "A dictionary of storage backend capabilities."
   "confirmed (Optional)", "plain", "xsd:boolean", "When ""false"" it will run in test mode without applying any modification. This allow checking a request for validity before performing non-reversible changes. When set to ""true"" the modifications are immediately applied."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "name (Optional)", "plain", "xsd:string", "Name of this backend."
   "backend (Optional)", "plain", "xsd:string", "The type of the storage backend."
   "state (Optional)", "plain", "xsd:string", "The admin state of the storage backend."
   "task (Optional)", "plain", "xsd:string", "The current task of the storage backend when in ""configuring"" state."
   "isystem_uuid (Optional)", "plain", "csapi:UUID", "The System UUID which the storage backend belongs to."
   "capabilities (Optional)", "plain", "xsd:string", "A dictionary of storage backend capabilities."
   "services (Optional)", "plain", "xsd:string", "A comma separated list of backend services."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   [
       {
           "path": "/services",
           "value": "glance,cinder",
           "op": "replace"
       }
   ]

::

   {
       "error_message": "{\"debuginfo\": null, \"faultcode\": \"Client\", \"faultstring\": \"Service cinder is not supported for the file backend\"}"
   }

********************************
Deletes a file storage backend
********************************

.. rest_method:: DELETE /v1/storage_file/​{storage_file_id}​

**Normal response codes**

204

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "storage_file_id", "URI", "csapi:UUID", "The unique identifier of the storage backend."

This operation does not accept a request body.

********************************
List external storage backends
********************************

.. rest_method:: GET /v1/storage_external

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "name (Optional)", "plain", "xsd:string", "Name of this backend."
   "backend (Optional)", "plain", "xsd:string", "The type of the storage backend."
   "state (Optional)", "plain", "xsd:string", "The admin state of the storage backend."
   "task (Optional)", "plain", "xsd:string", "The current task of the storage backend when in ""configuring"" state."
   "isystem_uuid (Optional)", "plain", "csapi:UUID", "The System UUID which the storage backend belongs to."
   "capabilities (Optional)", "plain", "xsd:string", "A dictionary of storage backend capabilities."
   "services (Optional)", "plain", "xsd:string", "A comma separated list of backend services."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
       "storage_external": [
           {
               "backend": "external",
               "capabilities": {},
               "created_at": "2018-03-08T07:28:59.840381+00:00",
               "links": [
                   {
                       "href": "http://192.168.144.103:6385/v1/storage_external/38803ac0-aa33-431f-ae43-e09d86eb4fa5",
                       "rel": "self"
                   },
                   {
                       "href": "http://192.168.144.103:6385/storage_external/38803ac0-aa33-431f-ae43-e09d86eb4fa5",
                       "rel": "bookmark"
                   }
               ],
               "name": "shared_services",
               "services": "glance",
               "state": "configured",
               "task": null,
               "updated_at": null,
               "uuid": "38803ac0-aa33-431f-ae43-e09d86eb4fa5"
           }
       ]
   }

This operation does not accept a request body.

*********************************
Add an External storage backend
*********************************

.. rest_method:: POST /v1/storage_external

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "backend (Optional)", "plain", "xsd:string", "This parameter specifies the type of the backend. Valid values are (is): ``external``"
   "name (Optional)", "plain", "xsd:string", "This parameter specifies the name of the backend."
   "services (Optional)", "plain", "xsd:string", "The name of the storage service."
   "capabilities (Optional)", "plain", "xsd:string", "A dictionary of storage backend capabilities."
   "confirmed (Optional)", "plain", "xsd:boolean", "When ""false"" it will run in test mode without applying any modification. This allow checking a request for validity before performing non-reversible changes. When set to ""true"" the modifications are immediately applied."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "name (Optional)", "plain", "xsd:string", "Name of this backend."
   "backend (Optional)", "plain", "xsd:string", "The type of the storage backend."
   "state (Optional)", "plain", "xsd:string", "The admin state of the storage backend."
   "task (Optional)", "plain", "xsd:string", "The current task of the storage backend when in ""configuring"" state."
   "isystem_uuid (Optional)", "plain", "csapi:UUID", "The System UUID which the storage backend belongs to."
   "capabilities (Optional)", "plain", "xsd:string", "A dictionary of storage backend capabilities."
   "services (Optional)", "plain", "xsd:string", "A comma separated list of backend services."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
       "name": "new-shared-services",
       "services": "cinder",
       "confirmed": true
   }

::

   {
       "backend": "external",
       "capabilities": {},
       "confirmed": false,
       "created_at": "2018-03-08T19:12:34.419453+00:00",
       "links": [
           {
               "href": "http://192.168.144.103:6385/v1/storage_file/a9c3d775-8913-4b92-a091-3bd1b905a6a5",
               "rel": "self"
           },
           {
               "href": "http://192.168.144.103:6385/storage_file/a9c3d775-8913-4b92-a091-3bd1b905a6a5",
               "rel": "bookmark"
           }
       ],
       "name": "new-shared-services",
       "services": "glance",
       "state": "configuring",
       "task": null,
       "updated_at": null,
       "uuid": "a9c3d775-8913-4b92-a091-3bd1b905a6a5"
   }

**************************************************
Shows attributes of the external storage backend
**************************************************

.. rest_method:: GET /v1/storage_external/​{storage_external_id}​

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "storage_external_id", "URI", "csapi:UUID", "The unique identifier of the storage backend."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "name (Optional)", "plain", "xsd:string", "Name of this backend."
   "backend (Optional)", "plain", "xsd:string", "The type of the storage backend."
   "state (Optional)", "plain", "xsd:string", "The admin state of the storage backend."
   "task (Optional)", "plain", "xsd:string", "The current task of the storage backend when in ""configuring"" state."
   "isystem_uuid (Optional)", "plain", "csapi:UUID", "The System UUID which the storage backend belongs to."
   "capabilities (Optional)", "plain", "xsd:string", "A dictionary of storage backend capabilities."
   "services (Optional)", "plain", "xsd:string", "A comma separated list of backend services."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
       "backend": "external",
       "capabilities": {},
       "confirmed": false,
       "created_at": "2018-03-08T07:28:59.840381+00:00",
       "links": [
           {
               "href": "http://192.168.144.103:6385/v1/storage_external/38803ac0-aa33-431f-ae43-e09d86eb4fa5",
               "rel": "self"
           },
           {
               "href": "http://192.168.144.103:6385/storage_external/38803ac0-aa33-431f-ae43-e09d86eb4fa5",
               "rel": "bookmark"
           }
       ],
       "name": "shared_services",
       "services": "glance",
       "state": "configured",
       "task": null,
       "updated_at": null,
       "uuid": "38803ac0-aa33-431f-ae43-e09d86eb4fa5"
   }

This operation does not accept a request body.

***************************************
Modifies the External storage backend
***************************************

.. rest_method:: PATCH /v1/storage_external/​{storage_external_id}​

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "storage_external_id", "URI", "csapi:UUID", "The unique identifier of the storage backend."
   "services (Optional)", "plain", "xsd:string", "The name of the storage service."
   "capabilities (Optional)", "plain", "xsd:string", "A dictionary of storage backend capabilities."
   "confirmed (Optional)", "plain", "xsd:boolean", "When ""false"" it will run in test mode without applying any modification. This allow checking a request for validity before performing non-reversible changes. When set to ""true"" the modifications are immediately applied."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "name (Optional)", "plain", "xsd:string", "Name of this backend."
   "backend (Optional)", "plain", "xsd:string", "The type of the storage backend."
   "state (Optional)", "plain", "xsd:string", "The admin state of the storage backend."
   "task (Optional)", "plain", "xsd:string", "The current task of the storage backend when in ""configuring"" state."
   "isystem_uuid (Optional)", "plain", "csapi:UUID", "The System UUID which the storage backend belongs to."
   "capabilities (Optional)", "plain", "xsd:string", "A dictionary of storage backend capabilities."
   "services (Optional)", "plain", "xsd:string", "A comma separated list of backend services."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   [
       {
           "path": "/services",
           "value": "glance,cinder",
           "op": "replace"
       }
   ]

*************************************
Deletes an external storage backend
*************************************

.. rest_method:: Delete /v1/storage_external/​{storage_external_id}​

**Normal response codes**

204

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "storage_external_id", "URI", "csapi:UUID", "The unique identifier of the storage backend."

This operation does not accept a request body.

--------------
Storage Tiers
--------------

These APIs allow the create, display, modify and delete of the storage
tiers.

************************
List the storage tiers
************************

.. rest_method:: GET /v1/storage_tiers

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "name (Optional)", "plain", "xsd:string", "Name of this storage tier."
   "type (Optional)", "plain", "xsd:string", "The type of storage tier. This maps to a backend type.."
   "status (Optional)", "plain", "xsd:string", "The status of the storage tier: defined or in-use."
   "stors (Optional)", "plain", "xsd:list", "The list of osd ids assigned to this tier."
   "capabilities (Optional)", "plain", "xsd:string", "A dictionary of storage backend capabilities."
   "backend_uuid (Optional)", "plain", "csapi:UUID", "The backend UUID which is using this tier."
   "cluster_uuid (Optional)", "plain", "csapi:UUID", "The cluster UUID which this tier is associated."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
       "storage_tiers": [
           {
               "status": "in-use",
               "uuid": "70184946-7b3e-4833-a4f8-e46edf006e37",
               "links": [
                   {
                       "href": "http://10.10.10.2:6385/v1/storage_tiers/70184946-7b3e-4833-a4f8-e46edf006e37",
                       "rel": "self"
                   },
                   {
                       "href": "http://10.10.10.2:6385/storage_tiers/70184946-7b3e-4833-a4f8-e46edf006e37",
                       "rel": "bookmark"
                   }
               ],
               "stors": [],
               "created_at": "2018-02-07T04:34:27.078558+00:00",
               "updated_at": "2018-02-07T08:39:00.950066+00:00",
               "capabilities": {},
               "cluster_uuid": "ba42aa45-7094-4bcd-b094-2848816441a3",
               "backend_uuid": "253f5801-e8bc-468d-a040-1bfa918541ac",
               "type": "ceph",
               "name": "storage"
           }
       ]
   }

This operation does not accept a request body.

*************************************
Shows attributes of a storage tier
*************************************

.. rest_method:: GET /v1/storage_tiers/​{storage_tier_id}​

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "storage_tier_id", "URI", "csapi:UUID", "The unique identifier of the storage tier resource."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "name (Optional)", "plain", "xsd:string", "Name of this storage tier."
   "type (Optional)", "plain", "xsd:string", "The type of storage tier. This maps to a backend type.."
   "status (Optional)", "plain", "xsd:string", "The status of the storage tier: defined or in-use."
   "stors (Optional)", "plain", "xsd:list", "The list of osd ids assigned to this tier."
   "capabilities (Optional)", "plain", "xsd:string", "A dictionary of storage backend capabilities."
   "backend_uuid (Optional)", "plain", "csapi:UUID", "The backend UUID which is using this tier."
   "cluster_uuid (Optional)", "plain", "csapi:UUID", "The cluster UUID which this tier is associated."

::

   {
       "status": "in-use",
       "uuid": "70184946-7b3e-4833-a4f8-e46edf006e37",
       "links": [
           {
               "href": "http://10.10.10.2:6385/v1/storage_tiers/70184946-7b3e-4833-a4f8-e46edf006e37",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/storage_tiers/70184946-7b3e-4833-a4f8-e46edf006e37",
               "rel": "bookmark"
           }
       ],
       "stors": [],
       "created_at": "2018-02-07T04:34:27.078558+00:00",
       "istors": [
           {
               "href": "http://10.10.10.2:6385/v1/storage_tiers/70184946-7b3e-4833-a4f8-e46edf006e37/istors",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/storage_tiers/70184946-7b3e-4833-a4f8-e46edf006e37/istors",
               "rel": "bookmark"
           }
       ],
       "updated_at": "2018-02-07T08:39:00.950066+00:00",
       "capabilities": {},
       "cluster_uuid": "ba42aa45-7094-4bcd-b094-2848816441a3",
       "backend_uuid": "253f5801-e8bc-468d-a040-1bfa918541ac",
       "type": "ceph",
       "name": "storage"
   }

This operation does not accept a request body.

********************
Add a storage tier
********************

.. rest_method:: POST /v1/storage_tiers

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "name (Optional)", "plain", "xsd:string", "This parameter specifies the unique name of the storage tier."
   "type (Optional)", "plain", "xsd:string", "The type of storage tier. This corresponds to the backend type that will be attached to the tier. Currently only a tier type of ``ceph`` is supported."
   "backend_uuid (Optional)", "plain", "csapi:UUID", "The UUID of the backend that is attached to this tier. The backend is attached to enable service(s) to use the storage tier resources."
   "cluster_uuid (Optional)", "plain", "csapi:UUID", "For tier type of ``ceph``, this provides the cluster_uuid that this tier is associated."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "name (Optional)", "plain", "xsd:string", "Name of this storage tier."
   "type (Optional)", "plain", "xsd:string", "The type of storage tier. This maps to a backend type.."
   "status (Optional)", "plain", "xsd:string", "The status of the storage tier: defined or in-use."
   "stors (Optional)", "plain", "xsd:list", "The list of osd ids assigned to this tier."
   "capabilities (Optional)", "plain", "xsd:string", "A dictionary of storage backend capabilities."
   "backend_uuid (Optional)", "plain", "csapi:UUID", "The backend UUID which is using this tier."
   "cluster_uuid (Optional)", "plain", "csapi:UUID", "The cluster UUID which this tier is associated."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
       "name": "new-tier",
       "type": "ceph",
       "cluster_uuid": "ba42aa45-7094-4bcd-b094-2848816441a3"
   }

::

   {
       "status": "defined",
       "uuid": "5ff4a489-dcbc-4fd2-a04a-1a95f4a45780",
       "links": [
           {
               "href": "http://10.10.10.2:6385/v1/storage_tiers/5ff4a489-dcbc-4fd2-a04a-1a95f4a45780",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/storage_tiers/5ff4a489-dcbc-4fd2-a04a-1a95f4a45780",
               "rel": "bookmark"
           }
       ],
       "stors": [],
       "created_at": "2018-02-07T09:27:24.482961+00:00",
       "istors": [
           {
               "href": "http://10.10.10.2:6385/v1/storage_tiers/5ff4a489-dcbc-4fd2-a04a-1a95f4a45780/istors",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/storage_tiers/5ff4a489-dcbc-4fd2-a04a-1a95f4a45780/istors",
               "rel": "bookmark"
           }
       ],
       "updated_at": null,
       "capabilities": {},
       "cluster_uuid": "ba42aa45-7094-4bcd-b094-2848816441a3",
       "backend_uuid": null,
       "type": "ceph",
       "forclusterid": 1,
       "name": "new-tier"
   }

***************************
Modifies the storage tier
***************************

.. rest_method:: PATCH /v1/storage_tiers/​{storage_tier_id}​

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "storage_tier_id", "URI", "csapi:UUID", "The unique identifier of the storage tier resource."
   "type (Optional)", "plain", "xsd:string", "The type of storage tier. This corresponds to the backend type that will be attached to the tier. Currently only a tier type of ``ceph`` is supported."
   "backend_uuid (Optional)", "plain", "csapi:UUID", "The UUID of the backend that is attached to this tier. The backend is attached to enable service(s) to use the storage tier resources."
   "cluster_uuid (Optional)", "plain", "csapi:UUID", "For tier type of ``ceph``, this provides the cluster_uuid that this tier is associated."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "name (Optional)", "plain", "xsd:string", "Name of this storage tier."
   "type (Optional)", "plain", "xsd:string", "The type of storage tier. This maps to a backend type.."
   "status (Optional)", "plain", "xsd:string", "The status of the storage tier: defined or in-use."
   "stors (Optional)", "plain", "xsd:list", "The list of osd ids assigned to this tier."
   "capabilities (Optional)", "plain", "xsd:string", "A dictionary of storage backend capabilities."
   "backend_uuid (Optional)", "plain", "csapi:UUID", "The backend UUID which is using this tier."
   "cluster_uuid (Optional)", "plain", "csapi:UUID", "The cluster UUID which this tier is associated."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   [
       {
           "path": "/name",
           "value": "really-new-tier",
           "op": "replace"
       }
   ]

::

   {
       "status": "defined",
       "uuid": "5ff4a489-dcbc-4fd2-a04a-1a95f4a45780",
       "links": [
           {
               "href": "http://10.10.10.2:6385/v1/storage_tiers/5ff4a489-dcbc-4fd2-a04a-1a95f4a45780",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/storage_tiers/5ff4a489-dcbc-4fd2-a04a-1a95f4a45780",
               "rel": "bookmark"
           }
       ],
       "stors": [],
       "created_at": "2018-02-07T09:27:24.482961+00:00",
       "istors": [
           {
               "href": "http://10.10.10.2:6385/v1/storage_tiers/5ff4a489-dcbc-4fd2-a04a-1a95f4a45780/istors",
               "rel": "self"
           },
           {
               "href": "http://10.10.10.2:6385/storage_tiers/5ff4a489-dcbc-4fd2-a04a-1a95f4a45780/istors",
               "rel": "bookmark"
           }
       ],
       "updated_at": null,
       "capabilities": {},
       "cluster_uuid": "ba42aa45-7094-4bcd-b094-2848816441a3",
       "backend_uuid": null,
       "type": "ceph",
       "forclusterid": 1,
       "name": "really-new-tier"
   }

************************
Deletes a storage tier
************************

.. rest_method:: DELETE /v1/storage_tiers/​{storage_tier_id}​

**Normal response codes**

204

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "storage_tier_id", "URI", "csapi:UUID", "The unique identifier of the storage tier resource."

This operation does not accept a request body.

----------------------
Controller Filesystem
----------------------

These APIs allow the display and configuration of the controller
filesystem.

*********************************
List the Controller filesystems
*********************************

.. rest_method:: GET /v1/controller_fs

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "name (Optional)", "plain", "xsd:string", "The name of the filesystem."
   "size (Optional)", "plain", "xsd:integer", "The size of the filesystem in GiB."
   "logical_volume (Optional)", "plain", "xsd:string", "The logical volume of the filesystem."
   "replicated (Optional)", "plain", "xsd:boolean", "Specifies if the filesystem is drbd replicated."
   "state (Optional)", "plain", "xsd:integer", "The state of the filesystem; ``None``, ``availabe`` or ``drbd_fs_resizing_in_progress``"
   "isystem_uuid (Optional)", "plain", "csapi:UUID", "The System UUID which the storage backend belongs to."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {"controller_fs":
   [
      {
         "logical_volume": "backup-lv",
         "uuid": "3ce46550-4703-4161-b654-5573045546b3",
         "links": [{"href": "http://127.168.204.2:6385/v1/controller_fs/3ce46550-4703-4161-b654-5573045546b3", "rel": "self"}, {"href": "http://127.168.204.2:6385/controller_fs/3ce46550-4703-4161-b654-5573045546b3", "rel": "bookmark"}],
         "created_at": "2017-09-14T17:54:15.853307+00:00",
         "updated_at": "2017-09-15T15:18:38.006260+00:00",
         "name": "backup",
         "state": "available",
         "isystem_uuid": "a5b7f26c-423f-41ed-a660-cd8cff4627eb",
         "replicated": false, "size": 92
      },
      {
         "logical_volume": "cgcs-lv",
         "uuid": "d30cc018-9218-403e-a1c2-9a5691a8bffb",
         "links": [{"href": "http://127.168.204.2:6385/v1/controller_fs/d30cc018-9218-403e-a1c2-9a5691a8bffb", "rel": "self"}, {"href": "http://127.168.204.2:6385/controller_fs/d30cc018-9218-403e-a1c2-9a5691a8bffb", "rel": "bookmark"}],
         "created_at": "2017-09-14T17:54:15.896408+00:00",
         "updated_at": "2017-09-14T20:59:53.114344+00:00",
         "name": "glance",
         "state": "available",
         "isystem_uuid": "a5b7f26c-423f-41ed-a660-cd8cff4627eb",
         "replicated": true,
         "size": 36},
      {
         "logical_volume": "pgsql-lv",
         "uuid": "d5fd96f5-05c2-4d4c-b2b7-a46d7b0eb6e7",
         "links": [{"href": "http://127.168.204.2:6385/v1/controller_fs/d5fd96f5-05c2-4d4c-b2b7-a46d7b0eb6e7", "rel": "self"}, {"href": "http://127.168.204.2:6385/controller_fs/d5fd96f5-05c2-4d4c-b2b7-a46d7b0eb6e7", "rel": "bookmark"}],
         "created_at": "2017-09-14T17:54:15.955574+00:00",
         "updated_at": "2017-09-14T20:50:53.032463+00:00",
         "name": "database",
         "state": "available",
         "isystem_uuid": "a5b7f26c-423f-41ed-a660-cd8cff4627eb",
         "replicated": true,
         "size": 30},
      {
         "logical_volume": "scratch-lv",
         "uuid": "a12de715-0037-4083-b652-121d3908bc6c",
         "links": [{"href": "http://127.168.204.2:6385/v1/controller_fs/a12de715-0037-4083-b652-121d3908bc6c", "rel": "self"}, {"href": "http://127.168.204.2:6385/controller_fs/a12de715-0037-4083-b652-121d3908bc6c", "rel": "bookmark"}],
         "created_at": "2017-09-14T17:54:16.012491+00:00",
         "updated_at": "2017-09-14T18:35:51.859954+00:00",
         "name": "scratch",
         "state": "available",
         "isystem_uuid": "a5b7f26c-423f-41ed-a660-cd8cff4627eb",
         "replicated": false,
         "size": 8},
      {
         "logical_volume": "img-conversions-lv",
         "uuid": "f7bae4fe-3cd1-4335-8664-a149579b2b47",
         "links": [{"href": "http://127.168.204.2:6385/v1/controller_fs/f7bae4fe-3cd1-4335-8664-a149579b2b47", "rel": "self"}, {"href": "http://127.168.204.2:6385/controller_fs/f7bae4fe-3cd1-4335-8664-a149579b2b47", "rel": "bookmark"}],
         "created_at": "2017-09-14T17:54:16.050789+00:00",
         "updated_at": "2017-09-14T18:35:51.876670+00:00",
         "name": "img-conversions",
         "state": "available",
         "isystem_uuid": "a5b7f26c-423f-41ed-a660-cd8cff4627eb",
         "replicated": false, "size": 20
      },
      {
         "logical_volume": "extension-lv",
         "uuid": "320dc274-1e35-4700-bfaa-cee2f2d448c5",
         "links": [{"href": "http://127.168.204.2:6385/v1/controller_fs/320dc274-1e35-4700-bfaa-cee2f2d448c5", "rel": "self"}, {"href": "http://127.168.204.2:6385/controller_fs/320dc274-1e35-4700-bfaa-cee2f2d448c5", "rel": "bookmark"}],
         "created_at": "2017-09-14T17:54:16.090570+00:00",
         "updated_at": "2017-09-14T18:35:51.893766+00:00",
         "name": "extension",
         "state": "available",
         "isystem_uuid": "a5b7f26c-423f-41ed-a660-cd8cff4627eb",
         "replicated": true,
         "size": 1
      }
   ]
   }

This operation does not accept a request body.

**********************************
Modifies a Controller filesystem
**********************************

.. rest_method:: PATCH /v1/controller_fs/​{controller_fs_id}​

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "controller_fs_id", "URI", "csapi:UUID", "The unique identifier of the controller filesystem."
   "name (Optional)", "plain", "xsd:string", "The name of the filesystem."
   "size (Optional)", "plain", "xsd:integer", "The size of the filesystem in GiB."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "name (Optional)", "plain", "xsd:string", "The name of the filesystem."
   "size (Optional)", "plain", "xsd:integer", "The size of the filesystem in GiB."
   "logical_volume (Optional)", "plain", "xsd:string", "The logical volume of the filesystem."
   "replicated (Optional)", "plain", "xsd:boolean", "Specifies if the filesystem is drbd replicated."
   "state (Optional)", "plain", "xsd:integer", "The state of the filesystem; ``None``, ``availabe`` or ``drbd_fs_resizing_in_progress``"
   "isystem_uuid (Optional)", "plain", "csapi:UUID", "The System UUID which the storage backend belongs to."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   [
       {
           "path": "/name",
           "value": "backup",
           "op": "replace"},
       {
           "path": "/size",
           "value": "94",
           "op": "replace"
       }
   ]

::

   {
       "logical_volume": "backup-lv",
       "uuid": "3ce46550-4703-4161-b654-5573045546b3",
       "links": [{"href": "http://127.168.204.2:6385/v1/controller_fs/3ce46550-4703-4161-b654-5573045546b3", "rel": "self"}, {"href": "http://127.168.204.2:6385/controller_fs/3ce46550-4703-4161-b654-5573045546b3", "rel": "bookmark"}],
       "created_at": "2017-09-14T17:54:15.853307+00:00",
       "updated_at": "2017-09-15T15:18:38.006260+00:00",
       "name": "backup",
       "state": "available",
       "isystem_uuid": "a5b7f26c-423f-41ed-a660-cd8cff4627eb",
       "replicated": false,
       "forisystemid": 1,
       "size": 94
   }

***********************************
Modifies Controller Filesystem(s)
***********************************

.. rest_method:: PUT /v1/isystems/​{system_uuid}​/controller_fs/update_many

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "system_uuid", "URI", "csapi:UUID", "The unique identifier of the system."
   "name (Optional)", "plain", "xsd:string", "The name of the filesystem."
   "size (Optional)", "plain", "xsd:integer", "The size of the filesystem in GiB."

::

   [
     [{
        "path": "/name",
        "value": "extension",
        "op": "replace"},
      {
        "path": "/size",
        "value": "2",
        "op": "replace"}],
     [{
        "path": "/name",
        "value": "backup",
        "op": "replace"},
      {
        "path": "/size",
        "value": "6",
        "op": "replace"}]
   ]

*********************************************
Shows attributes of a Controller filesystem
*********************************************

.. rest_method:: GET /v1/controller_fs/​{controller_fs_id}​

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "controller_fs_id", "URI", "csapi:UUID", "The unique identifier of the controller filesystem."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "name (Optional)", "plain", "xsd:string", "The name of the filesystem."
   "size (Optional)", "plain", "xsd:integer", "The size of the filesystem in GiB."
   "logical_volume (Optional)", "plain", "xsd:string", "The logical volume of the filesystem."
   "replicated (Optional)", "plain", "xsd:boolean", "Specifies if the filesystem is drbd replicated."
   "state (Optional)", "plain", "xsd:integer", "The state of the filesystem; ``None``, ``availabe`` or ``drbd_fs_resizing_in_progress``"
   "isystem_uuid (Optional)", "plain", "csapi:UUID", "The System UUID which the storage backend belongs to."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
       "controller_fs":
       [
           {
               "logical_volume": "backup-lv",
               "uuid": "3ce46550-4703-4161-b654-5573045546b3",
               "links": [{"href": "http://127.168.204.2:6385/v1/controller_fs/3ce46550-4703-4161-b654-5573045546b3", "rel": "self"}, {"href": "http://127.168.204.2:6385/controller_fs/3ce46550-4703-4161-b654-5573045546b3", "rel": "bookmark"}],
               "created_at": "2017-09-14T17:54:15.853307+00:00",
               "updated_at": "2017-09-15T15:36:32.304443+00:00",
               "name": "backup",
               "state": "available",
               "isystem_uuid": "a5b7f26c-423f-41ed-a660-cd8cff4627eb",
               "replicated": false,
               "size": 94},
           {
               "logical_volume": "cgcs-lv",
               "uuid": "d30cc018-9218-403e-a1c2-9a5691a8bffb",
               "links": [{"href": "http://127.168.204.2:6385/v1/controller_fs/d30cc018-9218-403e-a1c2-9a5691a8bffb", "rel": "self"}, {"href": "http://127.168.204.2:6385/controller_fs/d30cc018-9218-403e-a1c2-9a5691a8bffb", "rel": "bookmark"}],
               "created_at": "2017-09-14T17:54:15.896408+00:00",
               "updated_at": "2017-09-14T20:59:53.114344+00:00",
               "name": "glance",
               "state": "available",
               "isystem_uuid": "a5b7f26c-423f-41ed-a660-cd8cff4627eb",
               "replicated": true,
               "size": 36
           },
           {
               "logical_volume": "pgsql-lv",
               "uuid": "d5fd96f5-05c2-4d4c-b2b7-a46d7b0eb6e7",
               "links": [{"href": "http://127.168.204.2:6385/v1/controller_fs/d5fd96f5-05c2-4d4c-b2b7-a46d7b0eb6e7", "rel": "self"}, {"href": "http://127.168.204.2:6385/controller_fs/d5fd96f5-05c2-4d4c-b2b7-a46d7b0eb6e7", "rel": "bookmark"}],
               "created_at": "2017-09-14T17:54:15.955574+00:00",
               "updated_at": "2017-09-14T20:50:53.032463+00:00",
               "name": "database",
               "state": "available",
               "isystem_uuid": "a5b7f26c-423f-41ed-a660-cd8cff4627eb",
               "replicated": true,
               "size": 30
           },
           {
               "logical_volume": "scratch-lv",
               "uuid": "a12de715-0037-4083-b652-121d3908bc6c",
               "links": [{"href": "http://127.168.204.2:6385/v1/controller_fs/a12de715-0037-4083-b652-121d3908bc6c", "rel": "self"}, {"href": "http://127.168.204.2:6385/controller_fs/a12de715-0037-4083-b652-121d3908bc6c", "rel": "bookmark"}],
               "created_at": "2017-09-14T17:54:16.012491+00:00",
               "updated_at": "2017-09-14T18:35:51.859954+00:00",
               "name": "scratch",
               "state": "available",
               "isystem_uuid": "a5b7f26c-423f-41ed-a660-cd8cff4627eb",
               "replicated": false,
               "size": 8},
           {
               "logical_volume": "img-conversions-lv",
               "uuid": "f7bae4fe-3cd1-4335-8664-a149579b2b47",
               "links": [{"href": "http://127.168.204.2:6385/v1/controller_fs/f7bae4fe-3cd1-4335-8664-a149579b2b47", "rel": "self"}, {"href": "http://127.168.204.2:6385/controller_fs/f7bae4fe-3cd1-4335-8664-a149579b2b47", "rel": "bookmark"}],
               "created_at": "2017-09-14T17:54:16.050789+00:00",
               "updated_at": "2017-09-14T18:35:51.876670+00:00",
               "name": "img-conversions",
               "state": "available",
               "isystem_uuid": "a5b7f26c-423f-41ed-a660-cd8cff4627eb",
               "replicated": false, "size": 20},
           {
               "logical_volume": "extension-lv",
               "uuid": "320dc274-1e35-4700-bfaa-cee2f2d448c5",
               "links": [{"href": "http://127.168.204.2:6385/v1/controller_fs/320dc274-1e35-4700-bfaa-cee2f2d448c5", "rel": "self"}, {"href": "http://127.168.204.2:6385/controller_fs/320dc274-1e35-4700-bfaa-cee2f2d448c5", "rel": "bookmark"}],
               "created_at": "2017-09-14T17:54:16.090570+00:00",
               "updated_at": "2017-09-14T18:35:51.893766+00:00",
               "name": "extension",
               "state": "available",
               "isystem_uuid": "a5b7f26c-423f-41ed-a660-cd8cff4627eb",
               "replicated": true,
               "size": 1}
       ]
   }

This operation does not accept a request body.

--------------
Ceph Monitors
--------------

These APIs allow the display and configuration of the Ceph monitors.

********************
List Ceph monitors
********************

.. rest_method:: GET /v1/ceph_mon

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "device_node (Optional)", "plain", "xsd:string", "[Deprecated] The disk device node on the host that cgts-vg will be extended to create ceph-mon-lv."
   "device_path (Optional)", "plain", "xsd:string", "[Deprecated] The disk device path on the host that cgts-vg will be extended to create ceph-mon-lv."
   "host (Optional)", "plain", "xsd:string", "The name of host this ceph mon belongs to."
   "ceph_mon_gib (Optional)", "plain", "xsd:integer", "The ceph-mon-lv size in GiB, for Ceph backend only."
   "ceph_mon_dev (Optional)", "plain", "xsd:string", "[Deprecated] The disk device on both controllers that cgts-vg will be extended to create ceph-mon-lv."
   "ceph_mon_dev_ctrl0 (Optional)", "plain", "xsd:string", "[Deprecated] The disk device on controller-0 that cgts-vg will be extended to create ceph-mon-lv."
   "ceph_mon_dev_ctrl1 (Optional)", "plain", "xsd:string", "[Deprecated] The disk device on controller-1 that cgts-vg will be extended to create ceph-mon-lv."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
       "ceph_mon": [
           {
               "ceph_mon_dev_ctrl0": null,
               "ceph_mon_dev_ctrl1": null,
               "ceph_mon_gib": 20,
               "created_at": "2016-12-08T17:48:06.623435+00:00",
               "device_node": null,
               "device_path": null,
               "hostname": "controller-0",
               "links": [
                   {
                       "href": "http://10.10.20.2:6385/v1/ceph_mon/9608cc7f-ace6-4fc7-8eb8-01cfebf6906e",
                       "rel": "self"
                   },
                   {
                       "href": "http://10.10.20.2:6385/ceph_mon/9608cc7f-ace6-4fc7-8eb8-01cfebf6906e",
                       "rel": "bookmark"
                   }
               ],
               "updated_at": null,
               "uuid": "9608cc7f-ace6-4fc7-8eb8-01cfebf6906e"
           },
           {
               "ceph_mon_dev_ctrl0": null,
               "ceph_mon_dev_ctrl1": null,
               "ceph_mon_gib": 20,
               "created_at": "2016-12-08T19:02:02.359114+00:00",
               "device_node": null,
               "device_path": null,
               "hostname": "controller-1",
               "links": [
                   {
                       "href": "http://10.10.20.2:6385/v1/ceph_mon/9c1d1dce-40aa-4c58-bdf2-9715ec870944",
                       "rel": "self"
                   },
                   {
                       "href": "http://10.10.20.2:6385/ceph_mon/9c1d1dce-40aa-4c58-bdf2-9715ec870944",
                       "rel": "bookmark"
                   }
               ],
               "updated_at": null,
               "uuid": "9c1d1dce-40aa-4c58-bdf2-9715ec870944"
           }
       ]
   }

This operation does not accept a request body.

************************************
Shows attributes of a Ceph monitor
************************************

.. rest_method:: GET /v1/ceph_mon/​{ceph_mon_id}​

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "ceph_mon_id", "URI", "csapi:UUID", "The unique identifier of Ceph monitor."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "device_node (Optional)", "plain", "xsd:string", "[Deprecated] The disk device node on the host that cgts-vg will be extended to create ceph-mon-lv."
   "device_path (Optional)", "plain", "xsd:string", "[Deprecated] The disk device path on the host that cgts-vg will be extended to create ceph-mon-lv."
   "host (Optional)", "plain", "xsd:string", "The name of host this ceph mon belongs to."
   "ceph_mon_gib (Optional)", "plain", "xsd:integer", "The ceph-mon-lv size in GiB, for Ceph backend only."
   "ceph_mon_dev (Optional)", "plain", "xsd:string", "[Deprecated] The disk device on both controllers that cgts-vg will be extended to create ceph-mon-lv."
   "ceph_mon_dev_ctrl0 (Optional)", "plain", "xsd:string", "[Deprecated] The disk device on controller-0 that cgts-vg will be extended to create ceph-mon-lv."
   "ceph_mon_dev_ctrl1 (Optional)", "plain", "xsd:string", "[Deprecated] The disk device on controller-1 that cgts-vg will be extended to create ceph-mon-lv."
   "uuid (Optional)", "plain", "csapi:UUID", "The UUID of this ceph monitor."
   "isystem_uuid (Optional)", "plain", "csapi:UUID", "The System UUID which the storage backend belongs to."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
       "ceph_mon_dev_ctrl0": null,
       "ceph_mon_dev_ctrl1": null,
       "ceph_mon_gib": 20,
       "created_at": "2016-12-08T17:48:06.623435+00:00",
       "device_node": null,
       "device_path": null,
       "hostname": "controller-0",
       "links": [
           {
               "href": "http://10.10.20.2:6385/v1/ceph_mon/9608cc7f-ace6-4fc7-8eb8-01cfebf6906e",
               "rel": "self"
           },
           {
               "href": "http://10.10.20.2:6385/ceph_mon/9608cc7f-ace6-4fc7-8eb8-01cfebf6906e",
               "rel": "bookmark"
           }
       ],
       "updated_at": null,
       "uuid": "9608cc7f-ace6-4fc7-8eb8-01cfebf6906e"
   }

This operation does not accept a request body.

*************************
Modifies a Ceph monitor
*************************

.. rest_method:: PATCH /v1/ceph_mon/​{ceph_mon_id}​

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "ceph_mon_id", "URI", "csapi:UUID", "The unique identifier of Ceph monitor."
   "device_node (Optional)", "plain", "xsd:string", "[Deprecated] The disk device node on the host that cgts-vg will be extended to create ceph-mon-lv."
   "device_path (Optional)", "plain", "xsd:string", "[Deprecated] The disk device path on the host that cgts-vg will be extended to create ceph-mon-lv."
   "host (Optional)", "plain", "xsd:string", "The name of host this ceph mon belongs to."
   "ceph_mon_gib (Optional)", "plain", "xsd:integer", "The ceph-mon-lv size in GiB, for Ceph backend only."
   "ceph_mon_dev (Optional)", "plain", "xsd:string", "[Deprecated] The disk device on both controllers that cgts-vg will be extended to create ceph-mon-lv."
   "ceph_mon_dev_ctrl0 (Optional)", "plain", "xsd:string", "[Deprecated] The disk device on controller-0 that cgts-vg will be extended to create ceph-mon-lv."
   "ceph_mon_dev_ctrl1 (Optional)", "plain", "xsd:string", "[Deprecated] The disk device on controller-1 that cgts-vg will be extended to create ceph-mon-lv."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "device_node (Optional)", "plain", "xsd:string", "[Deprecated] The disk device node on the host that cgts-vg will be extended to create ceph-mon-lv."
   "device_path (Optional)", "plain", "xsd:string", "[Deprecated] The disk device path on the host that cgts-vg will be extended to create ceph-mon-lv."
   "host (Optional)", "plain", "xsd:string", "The name of host this ceph mon belongs to."
   "ceph_mon_gib (Optional)", "plain", "xsd:integer", "The ceph-mon-lv size in GiB, for Ceph backend only."
   "ceph_mon_dev (Optional)", "plain", "xsd:string", "[Deprecated] The disk device on both controllers that cgts-vg will be extended to create ceph-mon-lv."
   "ceph_mon_dev_ctrl0 (Optional)", "plain", "xsd:string", "[Deprecated] The disk device on controller-0 that cgts-vg will be extended to create ceph-mon-lv."
   "ceph_mon_dev_ctrl1 (Optional)", "plain", "xsd:string", "[Deprecated] The disk device on controller-1 that cgts-vg will be extended to create ceph-mon-lv."
   "uuid (Optional)", "plain", "csapi:UUID", "The UUID of this ceph monitor."
   "isystem_uuid (Optional)", "plain", "csapi:UUID", "The System UUID which the storage backend belongs to."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   [
           {
           "path": "/ceph_mon_gib",
           "value": "35",
           "op": "replace"
           },
           {
           "path": "/controller",
           "value": "controller-0",
           "op": "replace"
           }
   ]

::

   {
     "ceph_mon_dev_ctrl1": null,
     "uuid": "9608cc7f-ace6-4fc7-8eb8-01cfebf6906e",
     "links": [
       {
         "href": "http://10.10.20.2:6385/v1/ceph_mon/9608cc7f-ace6-4fc7-8eb8-01cfebf6906e",
         "rel": "self"
       },
       {
         "href": "http://10.10.20.2:6385/ceph_mon/9608cc7f-ace6-4fc7-8eb8-01cfebf6906e",
         "rel": "bookmark"
       }
     ],
     "ceph_mon_gib": 35,
     "created_at": "2016-12-08T17:48:06.623435+00:00",
     "hostname": "controller-0",
     "updated_at": null,
     "device_node": null,
     "device_path": null,
     "ceph_mon_dev_ctrl0": null
   }

---------------------------------
System Certificate Configuration
---------------------------------

These APIs allow for the display and configuration of Host certificates
which include SSL, Murano, Docker Registry, Openstack and
Trusted Platform Module(TPM) certificates.

****************************
Install System Certificate
****************************

.. rest_method:: POST /v1/certificate/certificate_install

Accepts a PEM file containing the X509 certificate.

For security reasons, the original certificate, containing the private
key, will be removed, once the private key is processed.

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
badMediaType (415)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "Content-Type multipart/form-data", "plain", "xsd:string", "The content of a file. e.g. if using curl, this would be specified as: curl -F name=@full_path_of_filename <div class=""example""><pre>file=@/home/wrsroot/server-with-key.pem </pre></div>"
   "passphrase (Optional)", "plain", "xsd:string", "The passphrase for the PEM file."
   "mode (Optional)", "plain", "xsd:string", "This parameter specifies the type of System certificate. Possible values are: <emphasis xmlns=""http://docbook.org/ns/docbook"">ssl, tpm_mode, murano, murano_ca, docker_registry, openstack, openstack_ca</emphasis>. Default: <emphasis xmlns=""http://docbook.org/ns/docbook"">ssl</emphasis>"

************************************
List installed System Certificates
************************************

.. rest_method:: GET /v1/certificate

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

This operation does not accept a request body.

***********************************************************************************************************************
Shows attributes of the Certificate configuration, including additional details if available for that certificate mode
***********************************************************************************************************************

.. rest_method:: GET /v1/certificate/​{uuid}​

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "uuid", "URI", "csapi:UUID", "The unique identifier of the Certificate configuration."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
       "uuid": "ada8f12c-0ab2-49b7-bad9-946e34cedd69",
       "certtype": "tpm_mode",
       "expiry_date": "2018-03-27T18:15:23+00:00",
       "signature": "ssl_14615813356245445293",
       "start_date": "2017-03-27T18:15:23+00:00",
       "issuer": null,
       "details": {
           "state" : {
               "controller-0": "tpm-config-applied",
               "controller-1": "tpm-config-applied"
           }
       }
   }

This operation does not accept a request body.

----------------------
Custom Firewall Rules
----------------------

These APIs allow for the installation of custom firewall rules.

*******************************
Install custom firewall rules
*******************************

.. rest_method:: POST /v1/firewallrules

Accepts a file containing the custom OAM firewall rules compatible with
the Linux Netfilter framework.

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
badMediaType (415)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "Content-Type multipart/form-data", "plain", "xsd:string", "The content of a file. e.g. if using curl, this would be specified as: curl -F name=@full_path_of_filename"

*****************************
Shows custom firewall rules
*****************************

.. rest_method:: GET /v1/firewallrules

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "firewall_sig (Optional)", "plain", "xsd:string", "The signature of the custom firewall rules."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
     "firewallrules": [
       {
         "firewall_sig": "ab9695c4ef143d72317a860c6db7f699",
         "uuid": "bc276605-7ae2-476a-a8c0-01f097f5177e",
         "updated_at": "2018-03-02T15:59:14.114812+00:00"
       }
     ]
   }

This operation does not accept a request body.









