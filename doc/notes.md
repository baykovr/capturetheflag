###### Some Incomprehensible Notes

A few gdb snippets

    gdb -tui binary
	b main      # set break at main
	ctrl+x && 2 # set stupid displays tuff
	r           # run
	bt          # backtrace 

	%esp 
	x/40x %esp  # show memory starting at esp for 40 bytes
    x/100x $esp # same thing, for 100 bytes


Useful tools 

    file
    string
    objdump -D
    strace



To dissable address randomization

    echo 0 > /proc/sys/kernel/randomize_va_space

run on start with init.d

    sudo touch /etc/init.d/myprog

sigkill something

    kill -9 $PID 

watch for connections using tcpdump

    tcpdump -i eth0 port 22 or 21 or 20

While we are waiting for the contest machine to open we try to connect every 5 seconds
you could of course change it to 1 or nothing.

    while true; do $(ssh group5@REDACTED-IP -p 8888); sleep 5; done 

This will allow you to monitor kernel messages, useful in conjunction with the custom kernel module

    watch -n 0.1 "dmesg | tail -n $((LINES-6))"
