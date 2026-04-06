#!/bin/bash

./sysinfo.sh > sysinfo.html
sudo cp sysinfo.html /var/www/html/index.html
