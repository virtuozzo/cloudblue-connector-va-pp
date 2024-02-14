<!--
# ******************************************************************************
# Copyright (c) 2020-2023, Virtuozzo International GmbH.
# This source code is distributed under MIT software license.
# ******************************************************************************
-->

# cloudblue-connector
This repository contains applications that connects CloudBlue Connect API with virtual infrastructure managed by OpenStack API. All functions are provided by three applications
 - cloudblue-fulfillments - processes Fulfillments, creates and manages Domains, Projects and Users.
 - cloudblue-usage - sends usage report for active Assets.
 - cloudblue-usage-files - confirms processed usage files.
 - cloudblue-password-manager - set and encrypt passwords for OnApp and CloudBlue api and store it into connector database.

## Configuration
Connector accepts configuration file in json format. Next parameters are expected to be set in the config file:
 - pva_socket - Virtuozzo Automator UNIX socket.
 - pva_connect_timeout - Max time (in seconds) while connector wait response from Virtuozzo Automator.
 - pva_socket_read_delay - Delay between reading data frame from Virtuozzo Automator response.
 - keystone_endpoint - is the same Url as default power panel url, including keystone port and endpoint.
   - **Example:** http://power-panel.com:35357/v3
 - pp_url - is the same Url as default power panel url, including api endpoint.
   - **Example:** http://power-panel.com/api/v1
 - pp_login - Power panel admin user name
 - misc - additional configuration options to define connector behavior:
   - hidePasswordsInLog - wipe plain-text passwords Connector events output.
     (default: _true_)
   - testMarketplaceId - ID of Marketplace, to place asset requests for evaluation. If not set, all asset requests from all Marketplaces will be processed regardless of **testMode** setting.   
   - testMode - test mode enabled or not.
     If set to _true_, requests made in **testMarketplaceId** will be processed only.
     If set to _false_, requests made in **testMarketplaceId** will be ignored.
     (default: _false_)
 - apiEndpoint - CloudBlue Connect API endpoint url.
 - products - list of product IDs from CloudBlue Connect.
 - report_usage - list of product IDs with PAYG resource model from CloudBlue Connect.
 - templates - set of template IDs that are used when Fulfillment is confirmed of cancelled.
 - For security reasons connector do not store passwords in plain text. For specifying PowerPanel password and CloudBlue api token use **cloudblue-password-manager**
 
The repository contains configuration example:
 - config.json.example

Processing applications take configuration parameters from /etc/cloudblue-connector/config.json file.

## Logging
By default, Connector prints all events to console. This behavior can be changed with modification of configuration file.

The repository contains configuration example with time-rotating file handle in addition to console handle:
 - config-logging.json.example

For more details about logging facilities please refer to standard library documentation https://docs.python.org/2.7/library/logging.html

Processing applications take logging configuration parameters from /etc/cloudblue-connector/config-logging.json file, if exists.

## Installation
List of python dependencies provided in requirements.txt file.

Repository contains setup.py files that can be used with python pip/easy_install.
