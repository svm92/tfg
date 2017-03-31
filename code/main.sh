#!/bin/bash

python /home/samuel/Escritorio/webscan.py
cd /home/samuel/test-report-skeleton
gitbook pdf ./ "./scan report.pdf"
