# SOHO Firewall Activity Analysis

USING Python 3.8 with SQLAnarchy imported:

1 - PARSE exported csv logs from the FREE Syslog Watcher 4.5.2 application

2 - LOAD parsed logs into MySQL 5.7.20-log activity table

3 - LOAD unique sources from parsed logs into lookup table
        a) New entries into lookup table will have a NULL COUNTRY value

4 - Convert ASN country Alpha-2 code to full country name
   
5 - SET full county names in lookup table  

     a) If ASN Alpha2 is returned, but code not in COUNTRIES list, 
        its ALPHA-2 code is entered into lookup table to resolve later
     b) If ASN Alpha2 is NOT returned, '' is entered as Country name in db for that ip
     c) If error during source ip lookup, exception message is entered as country name

6 - Visuals of firewall activity saved in output directory

src folder contains: 

        1. Python files need to run analysis

sample folder contains: 

        1. One day of my firewall log (onedaylog.csv)
        2. Plotting examples


