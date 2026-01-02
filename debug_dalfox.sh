#!/bin/bash
echo "http://testphp.vulnweb.com/listproducts.php?cat=1" > test_vuln.txt
dalfox file test_vuln.txt --format json --silence --skip-bav --worker 1
