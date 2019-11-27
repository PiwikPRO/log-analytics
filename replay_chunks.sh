#!/usr/bin/env bash

set -e

prefix="split_a"
token_auth=""

function log {
    logger -t $0[$$] "${1?empty msg}"
    echo " [+] $(date) -- ${1}"
}

function is_redis_above_threshold {
    local sum_requests=0
    local redis_servers="10.2.10.4 10.2.10.5 10.2.10.6"
    local redis_db="601"
    for server in ${redis_servers}; do
        for queue in $(redis-cli -h ${server} -n ${redis_db} keys "trackingQueue*") ; do
            requests=$(redis-cli -h ${server} -n ${redis_db} LLEN $queue)
            sum_requests=$(($sum_requests+$requests))
        done
        log "${server} sum requests: $sum_requests"
        if [ ${sum_requests} -gt ${1} ]; then
            return 0
        fi
    done
    return 1
}

proc_dir="processed"
if [ ! -d ${proc_dir} ]; then
    mkdir ${proc_dir}
fi

for i in $(ls ${prefix}*); do
    if [ -f /tmp/abort ]; then
       log "Found /tmp/abort. Exiting."
       exit -1
    fi

    while is_redis_above_threshold ${threshold:=5000}; do
        log "waiting while redis is above threshold ${threshold}"
        log "to override on the fly: echo 3000 > /tmp/threshold"
        sleep 60
        threshold=$(cat /tmp/threshold)
    done

    log "Started processing file ${i?emty file}"
    python piwik-log-analytics/import_logs.py ${i?empty file} \
		--url=https://piwik.becop.nl \
		--replay-tracking \
		--token-auth=${token_auth?empty token}\
		--recorders=1 \
		--recorder-max-payload-size=100
    log "Finished processing file $i"
    mv ${i} ${proc_dir}
done
