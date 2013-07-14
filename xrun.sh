#!/bin/bash 

year=2005
month=5

while [[ $year -lt 2014 ]] 
do
    month=5
    while [[ $month -lt 13 ]]
    do
        echo "STARTING $year $month"
        # python parser_driver.py -y $year -m $month
        echo "ENDING $year $month"
        ((month+=12))
    done
    ((year++))
done

