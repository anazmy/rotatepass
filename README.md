`rotatepass` a script to rotate passwords on servers concurently, and to save them

- Starting point, you will need a file that has a list of all hostnames (one per line) and run the script as below:
~~~
#  genpass.py -i serverlist
~~~

- If you need to update all servers' passwords just run
~~~
#  genpass.py -u
~~~

- To update just a subset of servers, point the script to a file containing these hostnames
~~~
#  genpass.py --list list_of_failed_server.txt
~~~

- To update a single server
~~~
#  genpass.py -t server.example.com
~~~

- To get list of servers/passwords printed on stdout.
~~~
#  genpass.py -d
~~~
