#!/usr/bin/env bash
# --------------------------------------------------------------------------------------------------
#
# Developed by Valentin Todorov
#
# --------------------------------------------------------------------------------------------------

# PURPOSE: This script has multiple functions:
#     1) Modifies the Snort timestamp to epoch
#     2) Compares the differences between the historical Snort records and copies the new records to a file
#     3) Copies the files with the newest and all the records from Snort to the shared folder on the AWS instance


# version="1.4.0"


if [ -f /var/log/snort/alert_json.txt ]; then

    # Modify the Snort timestamp to epoch
    /bin/python /opt/scripts/snort_log_converter.py

    # Compare the differences and copy the file
    /bin/sort /var/log/snort/alert_json_reduced.txt > /var/log/snort/alert_json_reduced.txt.s
    /bin/sort /var/log/snort/alert_json_reduced_base.txt > /var/log/snort/alert_json_reduced_base.txt.s

    /bin/comm -23 /var/log/snort/alert_json_reduced.txt.s /var/log/snort/alert_json_reduced_base.txt.s > /var/log/snort/alert_json_reduced_new.txt

    # Add the latest snort records to the base
    cat /var/log/snort/alert_json_reduced_new.txt >> /var/log/snort/alert_json_reduced_base.txt

    # Copy the files with the newest and all the records from Snort
    \cp /var/log/snort/alert_json_reduced.txt /var/www/html/secret/logs/snort/alert_json_reduced.txt
    \cp /var/log/snort/alert_json_reduced_new.txt /var/www/html/secret/logs/snort/alert_json_reduced_new.txt

fi