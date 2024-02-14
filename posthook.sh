#!/bin/bash

# $1 - subscription_id
# $2 - action ['purchase', 'resume', 'change', 'suspend', 'cancel']
# $3 - action result ['success', 'fail']

LOGFILE="/var/log/cloudblue-connector/post_hook.log"
TIMESTAMP=`date "+%Y-%m-%d %H:%M:%S"`

echo "[${TIMESTAMP}]: $1 $2 $3" >> ${LOGFILE}
exit 0
