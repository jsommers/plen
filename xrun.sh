#!/bin/bash 

year=2005
month=1

while [[ $year -lt 2014 ]] 
do
    month=1
    while [[ $month -lt 13 ]]
    do
        echo "STARTING $year $month"
        python parser_driver.py -y $year -m $month
        echo "ENDING $year $month"
        ((month+=1))
    done
    ((year++))
done


mkdir output/0721_notrunc
mv hopsrtts* output/0721_notrunc


year=2005
month=1

while [[ $year -lt 2014 ]] 
do
    month=1
    while [[ $month -lt 13 ]]
    do
        echo "STARTING $year $month"
        python parser_driver.py -c -y $year -m $month
        echo "ENDING $year $month"
        ((month+=1))
    done
    ((year++))
done

mkdir output/0721_yestrunc
mv hopsrtts* output/0721_yestrunc
