`rotatepass` a script to rotate passwords on servers concurently, and to save them in an encrypted file.

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


~~~
# rotatepass.py -h
usage: rotatepass.py [-h] [-f FORKS] [-p]
                     (-u | -t HOST | -d | -i INIT_LIST | -l LIST)

This script mass generates and resets a user password on hostnames specified,
and saves them to a file.

optional arguments:
  -h, --help            show this help message and exit
  -f FORKS, --forks FORKS
                        Number of parallel runs, the higher the value, the
                        faster the passwords reset. Keep an eye on load.
  -p, --plain           Save the hosts' file in plaintext. WARNING: Secure
                        handling of the file is the user's responsibility
  -u, --updateall       This will reset passwords on all servers
  -t HOST, --target HOST
                        Reset password on the target host and update the
                        servers' file.
  -d, --decrypt         Decrypt hosts' file and print it to stdout
  -i INIT_LIST, --init INIT_LIST
                        Initial hosts' file, expects path to a plaintext file
                        with one IP/FQDN per line. WARNING: existing hosts
                        file will be overwritten
  -l LIST, --list LIST  List of hosts to process, expects path to a plaintext
                        file with one IP/FQDN per line. New entries will be
                        added to existing hosts file.
~~~
